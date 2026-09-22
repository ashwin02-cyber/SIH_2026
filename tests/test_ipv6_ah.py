"""IPv6 and AH support (Stage 8).

Every capture used here is a SYNTHETIC fixture built by tests/make_ipv6_ah_fixtures.py (hand-made with Scapy, NOT a
real capture). The real testbed data is IPv4 ESP only; the regression tests at the bottom pin that behaviour."""
import os

import pytest
from fastapi.testclient import TestClient

import esp_analysis as ea
import main
import traffic_features as tf
from contract import validate_response
from conftest import FIXTURES, SAMPLES
from ike_parser import parse_ike_handshake

client = TestClient(main.app)


def fx(name):
    return os.path.join(FIXTURES, name)


def read(name):
    packets, ipsec_only, truncated = tf.read_packets(fx(name))
    assert not truncated
    return packets, ipsec_only


def analyze_api(name):
    with open(fx(name), "rb") as fh:
        r = client.post("/analyze", files={"file": (name, fh, "application/octet-stream")})
    assert r.status_code == 200, r.text
    body = r.json()
    assert validate_response(body) == []
    return body


# ---------------------------------------------------------------------------------------------- reader
def test_ipv6_esp_fields_are_read():
    packets, ipsec_only = read("SYNTHETIC_ipv6_esp.pcap")
    assert ipsec_only and len(packets) == 80
    p = packets[0]
    assert (p["ipsec_proto"], p["ip_version"]) == ("ESP", 6)
    assert p["spi"] == 0x6001 and p["seq"] == 1
    assert p["esp_len"] == 48                       # 40 payload bytes + 8-byte ESP header
    assert p["size"] == 40 + 48                     # IPv6: 40-byte header + payload length
    assert {q["spi"] for q in packets} == {0x6001, 0x6002}


def test_ipv6_extension_header_is_excluded_from_esp_length():
    packets, _ = read("SYNTHETIC_ipv6_esp_ext_header.pcap")
    assert {p["esp_len"] for p in packets} == {64 + 8}      # NOT 64 + 8 + 8 (destination-options header)
    assert all(p["spi"] == 0x6101 for p in packets)
    assert [p["seq"] for p in packets] == list(range(1, 13))


def test_natt_esp_in_udp4500_is_read_as_esp():
    packets, ipsec_only = read("SYNTHETIC_natt_esp_udp4500.pcap")
    assert ipsec_only and len(packets) == 15
    assert all(p["ipsec_proto"] == "ESP" and p["spi"] == 0x0C001 for p in packets)
    assert packets[0]["esp_len"] == 48 + 8 and packets[1]["esp_len"] == 52 + 8     # UDP header excluded


@pytest.mark.parametrize("name,ver", [("SYNTHETIC_ipv4_ah.pcap", 4), ("SYNTHETIC_ipv6_ah.pcap", 6)])
def test_ah_fields_are_read(name, ver):
    packets, ipsec_only = read(name)
    assert ipsec_only and len(packets) == 30
    assert all(p["ipsec_proto"] == "AH" and p["ip_version"] == ver for p in packets)
    assert all(p["esp_len"] is None and p["ah_len"] for p in packets)
    assert {p["spi"] for p in packets} == {(0xA001 if ver == 4 else 0xA101) + k for k in (0, 1)}
    assert packets[0]["seq"] == 1 and packets[2]["seq"] == 2


def test_ipv6_ike_is_not_counted_as_traffic():
    packets, ipsec_only = read("SYNTHETIC_ipv6_ike_sa_init.pcap")
    assert packets == [] and ipsec_only is False


# ---------------------------------------------------------------------------------------------- features
def test_ipv6_windows_work_and_use_ip_length():
    packets, _ = read("SYNTHETIC_ipv6_esp.pcap")
    windows, n_total, n_dropped = tf.windows_from_packets(packets, 1.0, 1)
    assert windows and n_total >= len(windows) and n_dropped == 0
    assert all(set(tf.FEATURE_COLS) <= set(w) for w in windows)
    assert all(w["min_size"] >= 81 for w in windows)        # 40-byte IPv6 header + 8-byte ESP header + 33-byte shortest payload


# ---------------------------------------------------------------------------------------------- IKE over IPv6
def test_ipv6_ike_sa_init_is_parsed():
    r = parse_ike_handshake(fx("SYNTHETIC_ipv6_ike_sa_init.pcap"))
    assert r["ike_version"] == "2.0" and r["handshake"]["ike_sa_init_seen"] is True
    assert r["ike_sa"]["cipher"] == "AES-GCM-16" and r["ike_sa"]["key_length_bits"] == 256 and r["ike_sa"]["dh_group"] == 19
    assert r["handshake"]["sa_source"] == "responder-selected"


# ---------------------------------------------------------------------------------------------- analysis
def test_ipv6_esp_analysis_counts_protocols_and_sequences():
    res = ea.analyze_pcap(fx("SYNTHETIC_ipv6_esp.pcap"))
    assert res["fingerprint"]["protocols"] == {"ESP": 80, "AH": 0, "IPv6": 80}
    assert res["fingerprint"]["ah_only"] is False
    assert len(res["sequence"]["sas"]) == 2
    assert res["sequence"]["replay_protection"]["status"] == "evidence_present"


def test_ah_only_analysis_flags_no_encryption():
    res = ea.analyze_pcap(fx("SYNTHETIC_ipv4_ah.pcap"))
    assert res["fingerprint"]["ah_only"] is True
    assert res["fingerprint"]["protocols"]["AH"] == 30 and res["fingerprint"]["protocols"]["ESP"] == 0
    assert res["fingerprint"]["cipher_family"]["value"] == "undetermined"     # AH sizes say nothing about a cipher
    assert {s["protocol"] for s in res["sequence"]["sas"]} == {"AH"}


def test_mixed_esp_and_ah_keeps_the_sas_apart():
    res = ea.analyze_pcap(fx("SYNTHETIC_ipv4_esp_and_ah.pcap"))
    assert res["fingerprint"]["protocols"]["ESP"] == 15 and res["fingerprint"]["protocols"]["AH"] == 15
    assert res["fingerprint"]["ah_only"] is False
    assert sorted(s["protocol"] for s in res["sequence"]["sas"]) == ["AH", "ESP"]
    assert res["sequence"]["replay_protection"]["status"] == "evidence_present"


# ---------------------------------------------------------------------------------------------- API + contract
def test_api_ah_only_is_reported_as_unencrypted():
    body = analyze_api("SYNTHETIC_ipv4_ah.pcap")
    assert body["cipher"] == "NONE"
    assert body["risk_level"] == "HIGH" and body["score"] < 50
    by = {f["id"]: f for f in body["assessment"]["findings"]}
    assert by["protocol"]["value"].startswith("AH") and by["protocol"]["status"] == "observed"
    assert by["cipher"]["rating"] == "weak" and by["cipher"]["status"] == "observed"
    assert body["assessment"]["metadata_exposure"]["score"] == 100
    top = body["recommendations"]["items"][0]
    assert top["priority"] == "Critical" and "AH" in top["title"]


def test_api_mixed_esp_and_ah_gets_a_low_priority_note():
    body = analyze_api("SYNTHETIC_ipv4_esp_and_ah.pcap")
    by = {f["id"]: f for f in body["assessment"]["findings"]}
    assert by["protocol"]["value"] == "ESP + AH"
    assert any(i["id"] == "protocol" and i["priority"] == "Low" for i in body["recommendations"]["items"])
    assert body["cipher"] != "NONE"


@pytest.mark.parametrize("name", ["SYNTHETIC_ipv6_esp.pcap", "SYNTHETIC_ipv6_esp_ext_header.pcap", "SYNTHETIC_natt_esp_udp4500.pcap",
                                  "SYNTHETIC_ipv6_ah.pcap", "SYNTHETIC_ipv6_ike_sa_init.pcap"])
def test_api_accepts_each_synthetic_fixture(name):
    body = analyze_api(name)
    assert body["assessment"]["completeness_pct"] < 100      # nothing here is a complete picture
    if body["score"] is None:                                       # too little known to score at all: reported as UNKNOWN, never as LOW
        assert body["risk_level"] == "UNKNOWN"
    else:
        assert body["score"] <= body["assessment"]["score_cap"]


def test_api_ipv6_ike_reads_cipher_and_dh_as_observed():
    body = analyze_api("SYNTHETIC_ipv6_ike_sa_init.pcap")
    by = {f["id"]: f for f in body["assessment"]["findings"]}
    assert by["dh_group"]["status"] == "observed" and by["cipher"]["status"] == "observed"


# ---------------------------------------------------------------------------------------------- regression (real IPv4 ESP)
def test_real_ipv4_esp_capture_is_unchanged():
    name = "aes128gcm16-dh19-tunnel-pfs-on__web_run1.pcap"
    packets, ipsec_only, _ = tf.read_packets(os.path.join(SAMPLES, name))
    assert ipsec_only and packets
    assert all(p["ipsec_proto"] == "ESP" and p["ip_version"] == 4 for p in packets)
    res = ea.analyze_packets(packets, ipsec_only)
    assert res["fingerprint"]["protocols"]["AH"] == 0 and res["fingerprint"]["ah_only"] is False
    assert res["fingerprint"]["cipher_family"]["value"].startswith("GCM")
