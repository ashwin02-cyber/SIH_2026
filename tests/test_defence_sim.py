"""What-if defence simulator (ml-engineer/defence_sim.py, defence_capture.py).
Packet lists below are SYNTHETIC (hand-made numbers), used to check the arithmetic of each defence."""
import json
import os

import pytest

import defence_capture as dc
import defence_sim as ds
import traffic_features as tf
from conftest import ROOT, SAMPLES

ML = os.path.join(ROOT, "ml-engineer")
METRICS = json.load(open(os.path.join(ML, "defence_metrics.json"), encoding="utf-8"))


def pk(sizes, dt=0.1, t0=1000.0):
    """SYNTHETIC packet records alternating between two hosts."""
    return [{"src": "a" if i % 2 == 0 else "b", "dst": "b" if i % 2 == 0 else "a", "size": s, "time": t0 + i * dt} for i, s in enumerate(sizes)]


def test_pad_buckets_rounds_up_to_the_next_bucket_and_never_shrinks():
    out, cost = ds.apply("pad_buckets", pk([60, 128, 129, 500, 1200, 1500]))
    assert [p["size"] for p in out] == [128, 128, 256, 512, 1500, 1500]
    assert cost["bandwidth_overhead_pct"] > 0 and cost["mean_added_delay_ms"] == 0


def test_pad_mtu_makes_every_packet_full_size():
    out, cost = ds.apply("pad_mtu", pk([60, 700, 1400]))
    assert {p["size"] for p in out} == {1500}
    assert cost["bandwidth_overhead_pct"] == pytest.approx(100.0 * (4500 - 2160) / 2160, abs=0.1)


def test_dummy_traffic_adds_packets_at_a_constant_rate_and_costs_bandwidth():
    base = pk([100] * 50, dt=0.1)                        # 5 s of traffic
    out, cost = ds.apply("dummy", base)
    added = [p for p in out if p["dummy"]]
    assert len(out) == len(base) + len(added) and abs(len(added) - 4.9 * ds.DUMMY_PPS) <= 2
    assert all(p["size"] == ds.DUMMY_SIZE for p in added) and cost["extra_packets"] == len(added)
    assert cost["bandwidth_overhead_pct"] > 100


def test_delay_never_sends_a_packet_earlier():
    base = pk([100] * 200)
    out, cost = ds.apply("delay", base)
    assert all(p["time"] >= p["t_orig"] for p in out) and cost["mean_added_delay_ms"] > 0
    assert cost["bandwidth_overhead_pct"] == 0


def test_shaping_puts_packets_on_slot_boundaries():
    out, cost = ds.apply("shape", pk([100] * 50, dt=0.037))
    t0 = min(p["time"] for p in out)
    assert all(((p["time"] - t0) / ds.SLOT) == pytest.approx(round((p["time"] - t0) / ds.SLOT), abs=1e-6) for p in out)
    assert all(p["time"] >= p["t_orig"] - 1e-9 for p in out) and cost["mean_added_delay_ms"] > 0


def test_defences_are_deterministic_and_do_not_modify_the_input():
    base = pk([100, 900, 300] * 40)
    snapshot = [dict(p) for p in base]
    a, _ = ds.apply("combined", base, seed=3)
    b, _ = ds.apply("combined", base, seed=3)
    assert a == b and base == snapshot


def test_all_documented_defences_exist():
    assert list(ds.DEFENCES) == ["pad_buckets", "pad_mtu", "dummy", "delay", "shape", "combined"]
    assert all(d["description"] and d["label"] for d in ds.DEFENCES.values())


def test_windowing_helper_matches_extract_windows():
    name = "aes128-dh2-transport-pfs-off__voip_run1.pcap"
    packets, _, _ = tf.read_packets(os.path.join(SAMPLES, name))
    w1, _, _ = tf.windows_from_packets(packets)
    w2, _ = tf.extract_windows(os.path.join(SAMPLES, name))
    assert w1 == w2


# ------------------------------------------------------------------------------------------------- per capture
def test_simulation_of_a_real_capture_is_labelled_a_simulation():
    r = dc.simulate_capture(os.path.join(SAMPLES, "aes128gcm16-dh19-tunnel-pfs-on__web_run1.pcap"))
    assert r["available"] and r["label"].startswith("SIMULATION") and "nothing was re-sent" in r["label"]
    assert r["baseline"]["class"] == "web_browsing"
    assert [d["id"] for d in r["defences"]] == list(ds.DEFENCES)
    for d in r["defences"]:
        assert set(d["cost"]) == {"bandwidth_overhead_pct", "extra_packets", "mean_added_delay_ms"}
        assert d["changes_answer"] == (d["result"] is None or d["result"]["class"] != r["baseline"]["class"])
    assert r["population"]["what"].startswith("SIMULATED")


def test_padding_a_bulk_transfer_costs_little_but_padding_a_ping_costs_a_lot():
    ping = dc.simulate_capture(os.path.join(SAMPLES, "aes128-dh2-transport-pfs-off__icmp_run1.pcap"))
    web = dc.simulate_capture(os.path.join(SAMPLES, "aes128gcm16-dh19-tunnel-pfs-on__web_run1.pcap"))
    cost = lambda r: next(d for d in r["defences"] if d["id"] == "pad_mtu")["cost"]["bandwidth_overhead_pct"]
    assert cost(ping) > cost(web) > 100


def test_too_sparse_capture_is_reported_not_crashed(tmp_path):
    from scapy.all import Ether, IP, Raw, wrpcap
    from scapy.layers.ipsec import ESP
    p = str(tmp_path / "SYNTHETIC_sparse.pcap")
    wrpcap(p, [Ether(src="02:00:00:00:00:01", dst="02:00:00:00:00:02") / IP(src="1.1.1.1", dst="2.2.2.2", proto=50) / ESP(spi=1, seq=1) / Raw(b"x" * 40)])
    assert dc.simulate_capture(p)["available"] is False


# ------------------------------------------------------------------------------------------------- population numbers
def test_population_metrics_are_labelled_and_include_both_attackers():
    assert set(METRICS["attackers"]) == {"non_adaptive", "adaptive"}
    assert set(METRICS["defences"]) == set(ds.DEFENCES)
    assert METRICS["baseline"]["non_adaptive_capture_accuracy"] >= 0.99
    for name, r in METRICS["defences"].items():
        assert 0 <= r["non_adaptive_capture_accuracy"] <= 1 and 0 <= r["adaptive_capture_accuracy"] <= 1
        assert r["adaptive_capture_accuracy"] >= r["non_adaptive_capture_accuracy"] - 0.02, name   # knowing the defence never hurts the attacker
        assert r["cost"]["bandwidth_overhead_pct_median"] >= 0


def test_an_honest_finding_a_defence_that_only_fools_a_naive_attacker():
    d = METRICS["defences"]
    assert d["pad_mtu"]["non_adaptive_capture_accuracy"] < 0.6 < d["pad_mtu"]["adaptive_capture_accuracy"]
    assert d["pad_mtu"]["cost"]["bandwidth_overhead_pct_median"] > 100
    assert d["pad_buckets"]["non_adaptive_capture_accuracy"] > 0.95      # cheap bucket padding does not hide the traffic type


def test_api_response_carries_the_simulation():
    from fastapi.testclient import TestClient
    import main
    body = TestClient(main.app).post(f"/analyze/sample/aes128gcm16-dh19-tunnel-pfs-on__web_run1.pcap").json()
    sim = body["details"]["defence_simulation"]
    assert sim["available"] and sim["label"].startswith("SIMULATION")
