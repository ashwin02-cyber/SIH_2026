"""Tests for traffic_features: ESP-only filtering and fixed time windows (hand-built packets)."""
import pytest
from scapy.all import Ether, IP, TCP, UDP, Raw, wrpcap
from scapy.layers.ipsec import ESP

import traffic_features as tf

A, B = "10.10.0.10", "10.10.0.20"


def esp(t, size_payload, src=A, dst=B):
    p = Ether() / IP(src=src, dst=dst, proto=50) / ESP(spi=0x100, seq=1) / Raw(b"x" * size_payload)
    p.time = t
    return p


def plain_tcp(t):
    p = Ether() / IP(src=A, dst=B) / TCP(sport=1234, dport=80) / Raw(b"secret")
    p.time = t
    return p


def ike(t):
    p = Ether() / IP(src=A, dst=B) / UDP(sport=500, dport=500) / Raw(b"\x11" * 80)
    p.time = t
    return p


def test_windows_are_fixed_length_and_counts_are_right(tmp_path):
    # window 0: 3 packets, window 1: 1 packet (dropped, < 2), window 2: 2 packets
    pk = [esp(0.0, 100), esp(0.2, 100, src=B, dst=A), esp(0.9, 200),
          esp(1.5, 100),
          esp(2.1, 300), esp(2.6, 300, src=B, dst=A)]
    f = tmp_path / "t.pcap"; wrpcap(str(f), pk)
    windows, info = tf.extract_windows(str(f))

    assert [w["window_index"] for w in windows] == [0, 2]
    assert [w["n_packets"] for w in windows] == [3, 2]
    assert info["n_windows_total"] == 3 and info["n_windows_dropped"] == 1
    w0 = windows[0]
    assert w0["pkts_per_sec"] == pytest.approx(3.0)             # 3 packets / 1 s window
    assert w0["start_offset_sec"] == 0.0 and windows[1]["start_offset_sec"] == 2.0
    assert w0["fwd_packet_ratio"] == pytest.approx(2 / 3)       # 2 of 3 from the first sender
    assert w0["min_size"] < w0["max_size"]
    assert w0["max_inter_arrival"] == pytest.approx(0.7, abs=1e-3)


def test_only_esp_is_used_when_present(tmp_path):
    """Decrypted plaintext duplicates and IKE must not be counted (a wire observer never sees plaintext)."""
    pk = [esp(0.0, 100), plain_tcp(0.05), esp(0.3, 100), plain_tcp(0.35), ike(0.4), esp(0.6, 100)]
    f = tmp_path / "t.pcap"; wrpcap(str(f), pk)
    windows, info = tf.extract_windows(str(f))
    assert info["esp_only"] is True
    assert info["n_packets"] == 3
    assert windows[0]["n_packets"] == 3


def test_falls_back_to_all_ip_when_no_esp(tmp_path):
    pk = [plain_tcp(0.0), plain_tcp(0.2), ike(0.3)]
    f = tmp_path / "t.pcap"; wrpcap(str(f), pk)
    windows, info = tf.extract_windows(str(f))
    assert info["esp_only"] is False
    assert info["n_packets"] == 2  # IKE excluded, TCP kept


def test_no_capture_length_features_are_emitted(tmp_path):
    f = tmp_path / "t.pcap"; wrpcap(str(f), [esp(0.0, 100), esp(0.5, 100)])
    windows, _ = tf.extract_windows(str(f))
    for banned in ("packet_count", "total_bytes", "duration_sec"):
        assert banned not in windows[0]
    assert set(tf.FEATURE_COLS) <= set(windows[0])


def test_empty_and_garbage(tmp_path, fixture_path):
    from scapy.all import ARP
    f = tmp_path / "arp.pcap"; wrpcap(str(f), [Ether() / ARP()])
    assert tf.extract_windows(str(f))[0] == []
    with pytest.raises(ValueError):
        tf.extract_windows(fixture_path("SYNTHETIC_not_a_pcap.pcap"))
