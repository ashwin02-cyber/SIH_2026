"""SPI / sequence-number analysis (ml-engineer/esp_sequence.py).

The SYNTHETIC_esp_*.pcap fixtures are hand-built with a KNOWN behaviour (tests/make_esp_fixtures.py); they are
NOT real captures. The real-capture tests use data/samples/ (real testbed files)."""
import os

import pytest

import esp_analysis as ea
import esp_sequence as es
from conftest import FIXTURES, SAMPLES


def seq(name, folder=FIXTURES):
    return ea.analyze_pcap(os.path.join(folder, name))["sequence"]


def rec(t, seq_, spi=1, src="a", dst="b"):
    return {"time": t, "seq": seq_, "spi": spi, "src": src, "dst": dst}


# ---------------------------------------------------------------------------------------------- SYNTHETIC
def test_clean_streams_give_replay_evidence():
    r = seq("SYNTHETIC_esp_clean_two_sas.pcap")
    assert len(r["sas"]) == 2 and all(s["monotonic"] and s["starts_at_beginning"] for s in r["sas"])
    assert r["replay_protection"]["status"] == "evidence_present"
    assert r["rekey_events"] == []
    assert r["sa_lifetime"]["observable"] is False and "not observable in this capture" in r["sa_lifetime"]["note"]


def test_duplicates_gaps_and_reordering_are_counted():
    r = seq("SYNTHETIC_esp_anomalies.pcap")
    (sa,) = r["sas"]
    assert sa["duplicates"] == 2          # seq 20 and 21 repeated
    assert sa["out_of_order"] == 1        # seq 12 arrives late (it was in the 11-14 gap)
    assert sa["gap_events"] >= 1
    assert sa["never_seen_sequence_numbers"] == 3   # 11, 13, 14 never arrive; 12 did arrive late
    assert r["replay_protection"]["status"] == "anomalies_observed"


def test_rekey_with_observed_start_gives_a_lifetime_estimate():
    r = seq("SYNTHETIC_esp_rekey_observed.pcap")
    kinds = {e["kind"] for e in r["rekey_events"]}
    assert kinds == {"probable rekey"} and len(r["rekey_events"]) == 2          # both directions rekey
    assert {e["old_spi"] for e in r["rekey_events"]} == {"0x00001001", "0x00002001"}
    life = r["sa_lifetime"]
    assert life["observable"] is True and life["estimate_seconds"] == pytest.approx(25.0, abs=0.1)
    assert "not the configured lifetime" in life["note"]


def test_rekey_when_the_old_sa_started_before_the_capture_gives_only_a_lower_bound():
    r = seq("SYNTHETIC_esp_rekey_start_not_observed.pcap")
    assert len(r["rekey_events"]) == 1 and r["rekey_events"][0]["old_sa_started_in_capture"] is False
    life = r["sa_lifetime"]
    assert life["observable"] is False and life["estimate_seconds"] is None
    assert life["lower_bound_seconds"] == pytest.approx(10.0, abs=0.1)


def test_overlapping_spis_are_not_called_a_rekey():
    r = seq("SYNTHETIC_esp_parallel_sas.pcap")
    assert [e["kind"] for e in r["rekey_events"]] == ["parallel SA (not a rekey)"]
    assert r["sa_lifetime"]["observable"] is False


# ---------------------------------------------------------------------------------------------- in-memory edge cases
def test_no_esp_packets():
    r = es.analyze_sequences([])
    assert r["replay_protection"]["status"] == "not_observable" and r["sa_lifetime"]["observable"] is False


def test_too_few_packets_to_judge():
    r = es.analyze_sequences([rec(0.0, 1), rec(0.1, 2)])
    assert r["replay_protection"]["status"] == "not_observable"


def test_32bit_rollover_is_not_an_anomaly():
    seqs = [0xFFFFFFFD, 0xFFFFFFFE, 0xFFFFFFFF, 1, 2, 3]
    r = es.analyze_sequences([rec(i * 0.1, s) for i, s in enumerate(seqs)])
    assert r["sas"][0]["rollovers"] == 1 and r["sas"][0]["duplicates"] == 0 and r["sas"][0]["out_of_order"] == 0


def test_limits_are_always_stated():
    text = " ".join(es.analyze_sequences([rec(i * 0.1, i + 1) for i in range(10)])["replay_protection"]["limits"])
    assert "receiver" in text and "not observable" in text


# ---------------------------------------------------------------------------------------------- REAL captures
def test_real_web_capture_has_replay_evidence_and_no_observable_lifetime():
    r = seq("aes128gcm16-dh19-tunnel-pfs-on__web_run1.pcap", SAMPLES)
    assert r["replay_protection"]["status"] == "evidence_present"
    assert len(r["sas"]) == 2 and not any(s["starts_at_beginning"] for s in r["sas"])   # tunnel was up long before the capture
    assert r["rekey_events"] == [] and r["sa_lifetime"]["observable"] is False


def test_real_video_capture_shows_reordering_but_no_duplicates():
    r = seq("aes128-dh2-transport-pfs-off__video_run1.pcap", SAMPLES)
    assert sum(s["duplicates"] for s in r["sas"]) == 0
    assert sum(s["out_of_order"] for s in r["sas"]) > 0
    assert r["replay_protection"]["status"] == "evidence_present_reordered"


def test_real_handshake_capture_has_no_esp():
    r = seq("aes128-dh2-transport-pfs-off__handshake.pcap", SAMPLES)
    assert r["esp_packets"] == 0 and r["replay_protection"]["status"] == "not_observable"
