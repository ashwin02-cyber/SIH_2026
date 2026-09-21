"""
traffic_features.py
-------------------
Shared feature extraction for training (batch_extract.py / train_model.py) and
inference (predict.py). Training and inference MUST use this one module, or
the model would be fed features it was not trained on.

Design decisions (all deliberate, see ml-engineer/README.md):

1. ESP-only view. A passive observer of an IPsec link sees encrypted ESP
   packets (IP protocol 50, or ESP-in-UDP/4500), plus IKE control traffic.
   In the testbed captures, tunnel-mode files also contain the *decrypted*
   inner packets (tcpdump on the peer's eth0 sees them after decryption).
   Those would never be visible on the wire, so they are excluded.
   IKE packets are excluded too: they are not the data-channel traffic being
   classified. If a pcap has no ESP at all (e.g. plain traffic), all IP
   packets are used and the result says so (`esp_only=False`).

2. Fixed time windows. Traffic is cut into WINDOW_SEC-second windows measured
   from the first packet. The old whole-capture features (packet_count,
   total_bytes, duration) mostly reflected *when tcpdump was told to stop*
   (e.g. `-c 20` for ICMP, `-c 5000` for file transfer), which lets a model
   "cheat" by learning the capture limit instead of the traffic behaviour.
   Those three features are gone. Rates (packets/s, bytes/s) are computed
   over the fixed window length so they do not depend on capture length.
"""

import statistics
import struct
from collections import defaultdict

from scapy.all import IP, UDP, PcapReader

WINDOW_SEC = 1.0
MIN_PACKETS_PER_WINDOW = 2

FEATURE_COLS = [
    "pkts_per_sec", "bytes_per_sec",
    "mean_size", "std_size", "min_size", "max_size", "median_size",
    "mean_inter_arrival", "std_inter_arrival", "max_inter_arrival",
    "fwd_packet_ratio", "fwd_byte_ratio",
]

FEATURE_DESCRIPTIONS = {
    "pkts_per_sec": "how many packets per second",
    "bytes_per_sec": "data rate (bytes per second)",
    "mean_size": "average packet size",
    "std_size": "variation in packet sizes",
    "min_size": "smallest packet size",
    "max_size": "largest packet size",
    "median_size": "typical (median) packet size",
    "mean_inter_arrival": "average gap between packets",
    "std_inter_arrival": "variation in the gap between packets",
    "max_inter_arrival": "longest pause between packets",
    "fwd_packet_ratio": "share of packets sent in the first direction",
    "fwd_byte_ratio": "share of bytes sent in the first direction",
}

IKE_PORTS = (500, 4500)


def _ip_size(pkt) -> int:
    """Link-independent packet size: the IP total length."""
    ln = pkt[IP].len
    return int(ln) if ln else len(pkt)


def _is_esp(pkt) -> bool:
    if pkt[IP].proto == 50:
        return True
    if UDP in pkt and 4500 in (pkt[UDP].sport, pkt[UDP].dport):
        raw = bytes(pkt[UDP].payload)
        return len(raw) >= 8 and raw[:4] != b"\x00\x00\x00\x00"  # zero marker => IKE, not ESP
    return False


def _esp_fields(pkt):
    """ESP header fields of an ESP packet, for the passive fingerprinting / sequence analysis:
    spi and seq (first 8 bytes of the ESP header) and esp_len = length of the ESP packet (IP payload,
    i.e. header + IV + encrypted data + ICV). None values if the header is too short to read."""
    ihl = int(pkt[IP].ihl or 5) * 4
    esp_len = max(0, int(pkt[IP].len or 0) - ihl) if pkt[IP].len else None
    payload = bytes(pkt[IP].payload)
    if pkt[IP].proto != 50 and UDP in pkt:  # ESP-in-UDP (NAT-T): the ESP header follows the 8-byte UDP header
        payload = payload[8:]
        esp_len = esp_len - 8 if esp_len is not None else None
    if len(payload) < 8:
        return {"spi": None, "seq": None, "esp_len": esp_len}
    spi, seq = struct.unpack("!II", payload[:8])
    return {"spi": spi, "seq": seq, "esp_len": esp_len}


def _is_ike(pkt) -> bool:
    return UDP in pkt and (pkt[UDP].sport in IKE_PORTS or pkt[UDP].dport in IKE_PORTS) and not _is_esp(pkt)


def read_packets(pcap_path):
    """Read IP packets from a pcap. Returns (packets, esp_only, truncated).

    packets: list of {"src","dst","size","time"} sorted by time. ESP records also carry "spi", "seq" and
    "esp_len" (used by esp_fingerprint.py and esp_sequence.py; the window features ignore them).
    Raises ValueError if the file is not a readable capture.
    """
    try:
        fh = open(pcap_path, "rb")
    except OSError as e:
        raise ValueError(f"Cannot read capture file: {e}") from e

    esp, other = [], []
    truncated = False
    try:
        try:
            reader = PcapReader(fh)
        except Exception as e:  # scapy raises several types for bad headers
            raise ValueError(f"Not a readable pcap/pcapng file: {e}") from e
        while True:
            try:
                pkt = reader.read_packet()
            except EOFError:
                break
            except Exception:
                truncated = True
                break
            if pkt is None:
                break
            if IP not in pkt:
                continue
            rec = {"src": pkt[IP].src, "dst": pkt[IP].dst, "size": _ip_size(pkt), "time": float(pkt.time)}
            if _is_esp(pkt):
                rec.update(_esp_fields(pkt))
                esp.append(rec)
            elif not _is_ike(pkt):
                other.append(rec)
    finally:
        fh.close()  # Scapy leaks the handle on bad headers; Windows then cannot delete the file

    if esp:
        packets, esp_only = esp, True
    else:
        packets, esp_only = other, False
    packets.sort(key=lambda p: p["time"])
    return packets, esp_only, truncated


def window_features(packets, first_src, index, window_sec=WINDOW_SEC):
    """Features for one window's packets (already sorted by time)."""
    sizes = [p["size"] for p in packets]
    times = [p["time"] for p in packets]
    gaps = [b - a for a, b in zip(times[:-1], times[1:])]
    fwd = [p for p in packets if p["src"] == first_src]
    total_bytes = sum(sizes)
    fwd_bytes = sum(p["size"] for p in fwd)
    return {
        "window_index": index,
        "start_offset_sec": index * window_sec,
        "n_packets": len(packets),
        "n_bytes": total_bytes,
        "pkts_per_sec": len(packets) / window_sec,
        "bytes_per_sec": total_bytes / window_sec,
        "mean_size": statistics.mean(sizes),
        "std_size": statistics.stdev(sizes) if len(sizes) > 1 else 0.0,
        "min_size": min(sizes),
        "max_size": max(sizes),
        "median_size": statistics.median(sizes),
        "mean_inter_arrival": statistics.mean(gaps) if gaps else 0.0,
        "std_inter_arrival": statistics.stdev(gaps) if len(gaps) > 1 else 0.0,
        "max_inter_arrival": max(gaps) if gaps else 0.0,
        "fwd_packet_ratio": len(fwd) / len(packets),
        "fwd_byte_ratio": fwd_bytes / total_bytes if total_bytes else 0.0,
    }


def windows_from_packets(packets, window_sec=WINDOW_SEC, min_packets=MIN_PACKETS_PER_WINDOW):
    """Cut a packet list into fixed windows and compute the features. Returns (windows, n_total, n_dropped).
    Used by extract_windows and by the defence simulator (which changes the packets first)."""
    if not packets:
        return [], 0, 0
    packets = sorted(packets, key=lambda p: p["time"])
    t0, first_src = packets[0]["time"], packets[0]["src"]
    buckets = defaultdict(list)
    for p in packets:
        buckets[int((p["time"] - t0) // window_sec)].append(p)
    windows, dropped = [], 0
    for idx in sorted(buckets):
        if len(buckets[idx]) < min_packets:
            dropped += 1
            continue
        windows.append(window_features(buckets[idx], first_src, idx, window_sec))
    return windows, len(buckets), dropped


def extract_windows(pcap_path, window_sec=WINDOW_SEC, min_packets=MIN_PACKETS_PER_WINDOW):
    """pcap -> list of per-window feature dicts plus capture-level info.

    Returns (windows, info). `info` has: esp_only, truncated, n_packets,
    total_bytes, span_sec, first_src, n_windows_total, n_windows_dropped.
    """
    packets, esp_only, truncated = read_packets(pcap_path)
    info = {
        "esp_only": esp_only,
        "truncated": truncated,
        "n_packets": len(packets),
        "total_bytes": sum(p["size"] for p in packets),
        "span_sec": (packets[-1]["time"] - packets[0]["time"]) if len(packets) > 1 else 0.0,
        "first_src": packets[0]["src"] if packets else None,
        "n_windows_total": 0,
        "n_windows_dropped": 0,
    }
    windows, total, dropped = windows_from_packets(packets, window_sec, min_packets)
    info["n_windows_total"], info["n_windows_dropped"] = total, dropped
    return windows, info
