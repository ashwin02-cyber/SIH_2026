"""
feature_extraction.py
----------------------
ML Engineer starter script — SIH 2026 (PS 26160)
 
Purpose:
    Read a .pcap file, group packets into flows, and compute numeric
    features (size, timing, direction stats) that describe each flow.
    These features are what the Random Forest / XGBoost model will
    later learn from to guess traffic type (web/VoIP/video/ICMP/file transfer).
 
Usage:
    python feature_extraction.py <path_to_pcap> <label> <output_csv>
 
    Example:
    python feature_extraction.py sample.pcap web_browsing features.csv
 
Notes:
    - Works on ANY pcap (encrypted ESP or plain traffic) — for practice,
      you can use non-VPN captures now and swap in real ESP pcaps later.
    - "Flow" here = one direction-agnostic conversation between two IPs.
    - Label is set manually by you, since you know what traffic you generated.
"""
 
import sys
import statistics
from collections import defaultdict
import pandas as pd
from scapy.all import rdpcap, IP
 
 
def extract_flows(pcap_path):
    """
    Reads a pcap and groups packets into flows keyed by
    an unordered (ip_a, ip_b) pair, so both directions of
    a conversation land in the same flow.
    """
    packets = rdpcap(pcap_path)
    flows = defaultdict(list)
 
    for pkt in packets:
        if IP not in pkt:
            continue  # skip non-IP packets (e.g. ARP)
 
        src = pkt[IP].src
        dst = pkt[IP].dst
        size = len(pkt)
        timestamp = float(pkt.time)
 
        # Unordered key so both directions map to same flow
        flow_key = tuple(sorted([src, dst]))
 
        flows[flow_key].append({
            "src": src,
            "dst": dst,
            "size": size,
            "time": timestamp
        })
 
    return flows
 
 
def compute_features(flow_packets, label):
    """
    Given a list of packet dicts for one flow, compute summary
    statistics that describe the flow's behavior.
    """
    if len(flow_packets) < 2:
        return None  # not enough packets to compute meaningful stats
 
    # Sort by time to compute inter-arrival times correctly
    flow_packets = sorted(flow_packets, key=lambda p: p["time"])
 
    sizes = [p["size"] for p in flow_packets]
    times = [p["time"] for p in flow_packets]
 
    # Inter-arrival times between consecutive packets
    inter_arrival = [t2 - t1 for t1, t2 in zip(times[:-1], times[1:])]
 
    # Direction: use first-seen src as "forward" direction
    first_src = flow_packets[0]["src"]
    fwd_count = sum(1 for p in flow_packets if p["src"] == first_src)
    bwd_count = len(flow_packets) - fwd_count
 
    duration = times[-1] - times[0] if len(times) > 1 else 0.0001
    total_bytes = sum(sizes)
 
    features = {
        "label": label,
        "packet_count": len(flow_packets),
        "total_bytes": total_bytes,
        "duration_sec": duration,
        "bytes_per_sec": total_bytes / duration if duration > 0 else 0,
        "mean_size": statistics.mean(sizes),
        "std_size": statistics.stdev(sizes) if len(sizes) > 1 else 0,
        "min_size": min(sizes),
        "max_size": max(sizes),
        "mean_inter_arrival": statistics.mean(inter_arrival) if inter_arrival else 0,
        "std_inter_arrival": statistics.stdev(inter_arrival) if len(inter_arrival) > 1 else 0,
        "fwd_packet_ratio": fwd_count / len(flow_packets),
        "bwd_packet_ratio": bwd_count / len(flow_packets),
    }
 
    return features
 
 
def process_pcap(pcap_path, label):
    """
    Full pipeline: pcap -> flows -> feature rows.
    Returns a list of feature dicts (one per flow).
    """
    flows = extract_flows(pcap_path)
    rows = []
 
    for flow_key, packets in flows.items():
        feats = compute_features(packets, label)
        if feats:
            rows.append(feats)
 
    return rows
 
 
def main():
    if len(sys.argv) != 4:
        print("Usage: python feature_extraction.py <pcap_path> <label> <output_csv>")
        sys.exit(1)
 
    pcap_path = sys.argv[1]
    label = sys.argv[2]
    output_csv = sys.argv[3]
 
    print(f"Reading {pcap_path} ...")
    rows = process_pcap(pcap_path, label)
 
    if not rows:
        print("No flows with enough packets were found. Try a longer/busier capture.")
        sys.exit(1)
 
    df = pd.DataFrame(rows)
 
    # Append to existing CSV if it exists, else create new
    try:
        existing = pd.read_csv(output_csv)
        df = pd.concat([existing, df], ignore_index=True)
    except FileNotFoundError:
        pass
 
    df.to_csv(output_csv, index=False)
    print(f"Wrote {len(rows)} flow(s) to {output_csv}")
    print(df.tail(len(rows)))
 
 
if __name__ == "__main__":
    main()