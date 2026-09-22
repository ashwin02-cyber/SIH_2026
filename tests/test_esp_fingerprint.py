"""Passive ESP fingerprinting (ml-engineer/esp_fingerprint.py).

The length lists in this file are SYNTHETIC numbers built from the ESP packet layout (RFC 4303); they are
labelled synthetic and are not captures. Real captures come from data/samples/ (real testbed files)."""
import json
import os
import shutil

import pandas as pd
import pytest

import esp_fingerprint as fp
import traffic_features as tf
from conftest import ROOT, SAMPLES

ML = os.path.join(ROOT, "ml-engineer")


# --- SYNTHETIC lengths -------------------------------------------------------------------------
def synthetic_cbc(payloads, icv=16):
    """SYNTHETIC ESP lengths for AES-CBC: 8 + IV 16 + pad16(payload + 2) + ICV."""
    return [8 + 16 + ((p + 2 + 15) // 16) * 16 + icv for p in payloads]


def synthetic_gcm(payloads, icv=16):
    """SYNTHETIC ESP lengths for AES-GCM: 8 + IV 8 + pad4(payload + 2) + ICV."""
    return [8 + 8 + ((p + 2 + 3) // 4) * 4 + icv for p in payloads]


PAYLOADS = [40, 52, 64, 100, 128, 300, 576, 1000, 1200, 1400, 33, 77, 91, 500, 61]


def test_synthetic_cbc_is_one_residue_class_and_gcm_is_not():
    cbc, gcm = synthetic_cbc(PAYLOADS), synthetic_gcm(PAYLOADS)
    assert {l % 16 for l in cbc} == {8}
    assert len({l % 16 for l in gcm}) >= 2


def test_rule_recognises_cbc_like_stream():
    r = fp.infer_cipher_family(synthetic_cbc(PAYLOADS))
    assert r["value"].startswith("CBC") and r["confidence"] >= 0.9


def test_rule_recognises_gcm_like_stream():
    r = fp.infer_cipher_family(synthetic_gcm(PAYLOADS))
    assert r["value"].startswith("GCM") and r["confidence"] >= 0.9 and "residue classes" in r["evidence"]


def test_rule_abstains_on_constant_size_stream():
    for lengths in (synthetic_cbc([84] * 20), synthetic_gcm([84] * 20)):
        r = fp.infer_cipher_family(lengths)
        assert r["value"] == "undetermined" and "same length" in r["evidence"]


def test_rule_abstains_with_too_little_evidence():
    assert fp.infer_cipher_family(synthetic_cbc(PAYLOADS[:5]))["value"] == "undetermined"      # 5 packets
    two_sizes = fp.infer_cipher_family(synthetic_cbc([64, 128] * 10))
    assert two_sizes["value"] == "undetermined" and two_sizes["leaning"] == "CBC-like"          # 2 distinct sizes only
    assert fp.infer_cipher_family([101] * 20)["value"] == "undetermined"                        # not 4-aligned


@pytest.mark.parametrize("icv,expected", [(16, 16), (12, 12), (24, 24)])
def test_integrity_tag_candidates_for_cbc(icv, expected):
    lengths = synthetic_cbc(PAYLOADS, icv=icv)
    fam = fp.infer_cipher_family(lengths)
    tag = fp.infer_integrity_tag(lengths, fam)
    assert expected in [c["bytes"] for c in tag["candidates"]]


def test_integrity_tag_not_observable_for_gcm():
    lengths = synthetic_gcm(PAYLOADS)
    tag = fp.infer_integrity_tag(lengths, fp.infer_cipher_family(lengths))
    assert tag["value"] is None and tag["candidates"] == [] and "not observable" in tag["evidence"]


def test_not_observable_list_is_explicit():
    text = " ".join(fp.NOT_OBSERVABLE)
    for needle in ("AES-128 vs AES-256", "Diffie-Hellman", "Forward Secrecy", "Authentication"):
        assert needle in text


# --- REAL captures ------------------------------------------------------------------------------
def real(name):
    return fp.fingerprint_pcap(os.path.join(SAMPLES, name))


def test_real_gcm_capture():
    r = real("aes128gcm16-dh19-tunnel-pfs-on__web_run1.pcap")
    assert r["cipher_family"]["value"].startswith("GCM")
    assert r["mode"]["value"] == "tunnel"  # read from packet sizes, the file name says the same but is not used
    assert r["integrity_tag"]["value"] is None


def test_real_cbc_capture_and_tag_candidates():
    r = real("aes128-dh2-transport-pfs-off__video_run1.pcap")
    assert r["cipher_family"]["value"].startswith("CBC")
    assert 16 in [c["bytes"] for c in r["integrity_tag"]["candidates"]]
    assert r["mode"]["value"] == "transport"


def test_real_constant_size_ping_is_undetermined_for_cipher():
    r = real("aes128-dh2-transport-pfs-off__icmp_run1.pcap")
    assert r["cipher_family"]["value"] == "undetermined"
    assert r["distinct_sizes"] == 1


def test_fingerprint_ignores_file_name(tmp_path):
    src = os.path.join(SAMPLES, "aes128-dh2-transport-pfs-off__video_run1.pcap")
    dst = tmp_path / "zz_totally_unrelated_name.pcap"
    shutil.copy(src, dst)
    assert fp.fingerprint_pcap(str(dst)) == fp.fingerprint_pcap(src)


def test_fingerprint_without_esp(tmp_path):
    from scapy.all import Ether, IP, TCP, wrpcap
    p = str(tmp_path / "SYNTHETIC_no_esp_tcp.pcap")   # synthetic: plain TCP packets, no ESP
    wrpcap(p, [Ether() / IP(src="1.1.1.1", dst="2.2.2.2") / TCP() for _ in range(3)])
    r = fp.fingerprint_pcap(p)
    assert r["esp_packets"] == 0 and r["cipher_family"]["value"] == "undetermined" and r["mode"]["value"] == "undetermined"


# --- the evaluation numbers that the docs quote -------------------------------------------------
def test_metrics_file_matches_the_committed_features():
    m = json.load(open(os.path.join(ML, "esp_fingerprint_metrics.json"), encoding="utf-8"))
    df = pd.read_csv(os.path.join(ML, "esp_fingerprint_features.csv"))
    assert m["captures"] == len(df) == 180 and m["configs"] == 36
    rule = m["cipher_family_rule"]["overall"]
    assert rule["accuracy_when_committed"] == 1.0 and rule["committed"] == 144
    mode = m["tunnel_vs_transport"]
    assert mode["accuracy"] > 0.9 and mode["accuracy_when_committed"] >= 0.99
    assert mode["shuffled_label_accuracy"]["mean"] < 0.6   # chance level: the pipeline does not leak
    # the features CSV holds no file names as features
    assert not {"file", "combo", "cipher", "true_mode"} & set(fp.MODE_FEATURES)


def test_window_features_unchanged_by_the_reader_extension():
    """Adding ESP header fields to the packet records must not change the classifier's features."""
    saved = pd.read_csv(os.path.join(ROOT, "ml-engineer", "features_windowed.csv"))
    name = "aes128gcm16-dh19-tunnel-pfs-on__web_run1.pcap"
    windows, _ = tf.extract_windows(os.path.join(SAMPLES, name))
    ref = saved[saved["filename"] == name].sort_values("window_index")
    assert len(ref) == len(windows) > 5
    for w, (_, row) in zip(windows, ref.iterrows()):
        for k in tf.FEATURE_COLS:
            assert w[k] == pytest.approx(row[k], rel=1e-9, abs=1e-9)
