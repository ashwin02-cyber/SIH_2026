"""Replay mode: stream a capture file in time order through the analyzer (ml-engineer/replay_stream.py, POST /replay).
Packet records built in this file are SYNTHETIC (hand-made numbers)."""
import json
import os

import pytest
from fastapi.testclient import TestClient

import main
import replay_stream as rs
from contract import validate_response
from conftest import SAMPLES

client = TestClient(main.app)
WEB = "aes128gcm16-dh19-tunnel-pfs-on__web_run1.pcap"
PING = "aes128-dh2-transport-pfs-off__icmp_run1.pcap"


def stream(url, **kw):
    with client.stream("POST", url, **kw) as r:
        assert r.status_code == 200, r.text
        assert r.headers["content-type"].startswith("application/x-ndjson")
        return [json.loads(line) for line in r.iter_lines() if line]


def synthetic_packets(per_window, sizes):
    """SYNTHETIC ESP packet records: per_window[i] packets in second i, lengths cycling through `sizes`."""
    out, n = [], 0
    for w, count in enumerate(per_window):
        for j in range(count):
            n += 1
            out.append({"src": "a" if n % 2 else "b", "dst": "b" if n % 2 else "a", "size": sizes[n % len(sizes)] + 20,
                        "time": 1000.0 + w + j * (0.9 / max(count, 1)), "spi": 7 if n % 2 else 8, "seq": n, "esp_len": sizes[n % len(sizes)]})
    return out


# ---------------------------------------------------------------------------------------------- API
def test_replay_streams_start_windows_end_final_in_time_order():
    evs = stream(f"/replay/sample/{WEB}?pace=0")
    types = [e["type"] for e in evs]
    assert types[0] == "start" and types[-2:] == ["end", "final"] and set(types[1:-2]) == {"window"}
    assert "not live sniffing" in evs[0]["label"] and "REPLAY" in evs[0]["label"]
    wins = [e for e in evs if e["type"] == "window"]
    assert len(wins) == evs[0]["total_windows"] == evs[-2]["windows_replayed"] > 5
    assert [w["index"] for w in wins] == list(range(1, len(wins) + 1))
    starts = [w["start_sec"] for w in wins]
    assert starts == sorted(starts) and len(set(starts)) == len(starts)
    so_far = [w["so_far"]["packets"] for w in wins]
    assert so_far == sorted(so_far) and so_far[-1] == evs[0]["packets_total"] == sum(w["packets"] for w in wins)


def test_final_event_is_the_complete_valid_analysis_and_matches_analyze():
    final = stream(f"/replay/sample/{WEB}?pace=0")[-1]["analysis"]
    direct = client.post(f"/analyze/sample/{WEB}").json()
    assert validate_response(final) == []
    assert final == direct                                 # replay adds progress; it never changes the answer


def test_running_verdict_agrees_with_the_final_class_at_the_end():
    evs = stream(f"/replay/sample/{WEB}?pace=0")
    last = [e for e in evs if e["type"] == "window"][-1]["so_far"]["verdict"]
    assert last["class"] == evs[-1]["analysis"]["traffic"]["class"] == "web_browsing"
    assert last["windows_classified"] > 5 and last["confidence"] > 0.9


def test_ping_replay_never_claims_a_cipher_family():
    """A constant-size ping stream carries no cipher evidence at any point of the replay."""
    wins = [e for e in stream(f"/replay/sample/{PING}?pace=0") if e["type"] == "window"]
    assert all((w["so_far"]["cipher_family"] or {}).get("value") == "undetermined" for w in wins)


def test_upload_replay_works_and_cleans_up(tmp_path):
    with open(os.path.join(SAMPLES, WEB), "rb") as f:
        evs = stream("/replay?pace=0", files={"file": ("anything.pcap", f, "application/octet-stream")})
    assert evs[0]["filename"] == "anything.pcap" and evs[-1]["type"] == "final"
    assert evs[-1]["analysis"]["filename"] == "anything.pcap"


def test_bad_inputs_are_rejected_before_streaming():
    assert client.post("/replay", files={"file": ("x.txt", b"hello")}).status_code == 400
    assert client.post("/replay", files={"file": ("x.pcap", b"")}).status_code == 400
    r = client.post("/replay", files={"file": ("x.pcap", b"not a capture at all")})
    assert r.status_code == 400 and "valid capture" in r.json()["detail"]
    assert client.post("/replay/sample/nope.pcap").status_code == 404
    assert client.post("/replay/sample/..%2F..%2Frequirements.txt").status_code == 404


# ---------------------------------------------------------------------------------------------- the generator
def test_evidence_grows_during_the_replay():
    """SYNTHETIC packets: 5 packets in the first second, then 40 per second with varied AEAD-style lengths.
    Early on there is too little to infer a cipher family; later there is."""
    pk = synthetic_packets([5, 40, 40, 40], sizes=[100, 136, 172, 204, 440, 716])
    wins = [e for e in rs.replay_events(pk, True, "synthetic", pace=0) if e["type"] == "window"]
    assert wins[0]["so_far"]["cipher_family"]["value"] == "undetermined" and "only 5" in wins[0]["so_far"]["cipher_family"]["evidence"]
    assert wins[-1]["so_far"]["cipher_family"]["value"].startswith("GCM")
    assert wins[0]["so_far"]["verdict"]["class"] is not None       # 5 packets is enough for one window
    assert wins[-1]["so_far"]["verdict"]["windows_classified"] > wins[0]["so_far"]["verdict"]["windows_classified"]


def test_a_second_with_a_single_packet_is_not_classified():
    pk = synthetic_packets([1, 30, 30], sizes=[100, 200])
    wins = [e for e in rs.replay_events(pk, True, "synthetic", pace=0) if e["type"] == "window"]
    assert wins[0]["window"] is None and wins[0]["so_far"]["verdict"]["class"] is None
    assert wins[1]["window"] is not None


def test_pace_is_clamped_and_windows_are_capped(monkeypatch):
    slept = []
    monkeypatch.setattr(rs.time, "sleep", lambda s: slept.append(s))
    pk = synthetic_packets([10] * 6, sizes=[100, 200, 300])
    evs = list(rs.replay_events(pk, True, "synthetic", pace=99, max_windows=3))
    assert slept and max(slept) == rs.MAX_PACE
    assert evs[0]["truncated"] is True and evs[-1]["truncated"] is True and len([e for e in evs if e["type"] == "window"]) == 3


def test_empty_capture_replays_nothing():
    evs = list(rs.replay_events([], True, "synthetic", pace=0))
    assert [e["type"] for e in evs] == ["start", "end"] and evs[0]["total_windows"] == 0


def test_no_esp_means_no_esp_inference():
    pk = synthetic_packets([10, 10], sizes=[100, 200])
    wins = [e for e in rs.replay_events(pk, False, "synthetic", pace=0) if e["type"] == "window"]
    assert all(w["so_far"]["cipher_family"] is None and w["so_far"]["mode"] is None for w in wins)
