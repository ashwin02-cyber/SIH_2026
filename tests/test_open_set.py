"""Calibration and open-set rejection (ml-engineer/open_set.py, predict.py).

The streams built by `synthetic_stream()` are SYNTHETIC packets made for these tests (not captures)."""
import json
import os
import random

import numpy as np
import pandas as pd
import pytest
from scapy.all import Ether, IP, Raw, wrpcap
from scapy.layers.ipsec import ESP

import open_set as osr
import predict
from contract import build_response, validate_response
from conftest import ROOT, SAMPLES

ML = os.path.join(ROOT, "ml-engineer")
METRICS = json.load(open(os.path.join(ML, "open_set_metrics.json"), encoding="utf-8"))


# ---------------------------------------------------------------------------------------------- calibration maths
def test_temperature_never_changes_the_winning_class():
    rng = np.random.RandomState(0)
    p = rng.dirichlet(np.ones(5), size=200)
    for T in (0.3, 1.0, 2.5):
        assert (osr.temperature_scale(p, T).argmax(axis=1) == p.argmax(axis=1)).all()


def test_temperature_one_is_identity_and_higher_softens():
    p = np.array([[0.7, 0.2, 0.1]])
    assert osr.temperature_scale(p, 1.0) == pytest.approx(p, abs=1e-6)
    assert osr.temperature_scale(p, 3.0).max() < 0.7 < osr.temperature_scale(p, 0.5).max()


def test_fit_temperature_softens_an_overconfident_model():
    rng = np.random.RandomState(1)
    y = rng.randint(0, 3, 600)
    wrong = rng.rand(600) < 0.3                                   # 30% of the confident predictions are wrong
    pred = np.where(wrong, (y + 1) % 3, y)
    p = np.full((600, 3), 0.02)
    p[np.arange(600), pred] = 0.96
    assert osr.fit_temperature(p, y) > 1.5


def test_ece_is_zero_for_a_calibrated_and_large_for_an_overconfident_model():
    y = np.array([0] * 50 + [1] * 50)
    perfect = np.where(np.eye(2)[y] == 1, 1.0, 0.0)
    assert osr.ece(perfect, y) == pytest.approx(0.0, abs=1e-9)
    wrong = np.where(np.eye(2)[1 - y] == 1, 0.99, 0.01)
    assert osr.ece(wrong, y) > 0.9


def test_decision_rule_uses_either_signal():
    assert osr.decide(0.99, 0.1, 0.9, 0.5) == (False, None)
    rej, why = osr.decide(0.5, 0.1, 0.9, 0.5)
    assert rej and "confidence" in why
    rej, why = osr.decide(0.99, 2.0, 0.9, 0.5)
    assert rej and "unlike anything" in why


def test_novelty_distance_is_small_for_reference_points_and_large_for_far_ones():
    df = pd.read_csv(os.path.join(ML, "features_windowed.csv"))
    nov = osr.Novelty(df.sample(300, random_state=0), predict.FEATURE_COLS)
    near = nov.distance(df.sample(300, random_state=0)[predict.FEATURE_COLS])
    far = df[predict.FEATURE_COLS].sample(5, random_state=1) * 50
    # the score is the MEAN distance to the 5 nearest reference windows: small for familiar points, large for far ones
    assert np.median(near) < 0.1 and nov.distance(far).min() > 1.0 > np.median(near)


# ---------------------------------------------------------------------------------------------- the real numbers
def test_temperature_is_floored_at_one_and_the_reason_is_recorded():
    c = METRICS["calibration"]
    assert c["temperature"] >= 1.0 and c["argmax_unchanged_by_calibration"] is True
    assert "over-confident" in c["temperature_note"] and c["temperature_fitted"] < 1.0


def test_calibration_error_is_small_on_unseen_configurations():
    assert METRICS["calibration"]["window_level"]["ece"]["after"] < 0.05


def test_held_out_class_experiment_covers_all_five_classes_and_rejects_them():
    loco = METRICS["leave_one_class_out"]
    assert set(loco) == {"file_transfer", "icmp", "video_streaming", "voip", "web_browsing"}
    for cls, r in loco.items():
        assert r["unknown_rejected_combined"] >= 0.9, cls
        assert r["known_accepted"] >= 0.85, cls            # the price: some known captures are rejected too
        assert r["auroc_novelty"] > 0.95 and r["auroc_confidence"] > 0.95
    assert 0.9 <= METRICS["mean_known_accepted"] <= 0.99   # ~95% by construction, never 100%: rejection is not free


def test_thresholds_come_from_known_classes_not_the_held_out_one():
    assert METRICS["method"].find("known classes only") > 0
    assert 0.5 < METRICS["thresholds"]["tau_conf"] < 1.0 and METRICS["thresholds"]["tau_dist"] > 0


# ---------------------------------------------------------------------------------------------- end to end
def synthetic_stream(path, kind):
    """SYNTHETIC ESP streams that look like none of the five trained traffic types."""
    def esp(t, src, dst, spi, seq, size):
        p = Ether(src="02:00:00:00:00:01", dst="02:00:00:00:00:02") / IP(src=src, dst=dst, proto=50) / ESP(spi=spi, seq=seq) / Raw(bytes([0x11]) * size)
        p.time = t
        return p
    if kind == "periodic":
        pk = [esp(i / 150.0, "10.0.0.1", "10.0.0.2", 0x77, i + 1, 900) for i in range(900)]
    else:
        rng = random.Random(1)
        pk = [esp(i * 0.01, "10.0.0.1" if i % 2 else "10.0.0.2", "10.0.0.2" if i % 2 else "10.0.0.1", 5 + i % 2, i // 2 + 1, rng.randint(60, 1400))
              for i in range(600)]
    wrpcap(str(path), pk)


@pytest.mark.parametrize("kind", ["periodic", "random"])
def test_synthetic_unlike_traffic_is_reported_as_unrecognised(tmp_path, kind):
    p = tmp_path / f"SYNTHETIC_{kind}.pcap"
    synthetic_stream(p, kind)
    r = predict.predict_from_pcap(str(p))
    assert r["class"] == "unrecognised" and r["rejected"] is True
    assert r["nearest_class"] in {"web_browsing", "video_streaming", "voip", "file_transfer", "icmp"}
    assert r["rejection_reason"] and any(a["name"] == "Unrecognised traffic" for a in r["anomalies"])


def test_known_real_traffic_is_still_recognised():
    for name, cls in [("aes128gcm16-dh19-tunnel-pfs-on__web_run1.pcap", "web_browsing"), ("aes128-dh2-transport-pfs-off__voip_run1.pcap", "voip"),
                      ("aes128-dh2-transport-pfs-off__video_run1.pcap", "video_streaming"), ("aes128-dh2-transport-pfs-off__icmp_run1.pcap", "icmp")]:
        r = predict.predict_from_pcap(os.path.join(SAMPLES, name))
        assert r["class"] == cls and r["rejected"] is False, name


def test_incomplete_transfer_excerpt_is_no_longer_a_confident_guess():
    """The real 300-packet excerpt of a file transfer (whose head looks like something else) used to be a 46% guess."""
    r = predict.predict_from_pcap(os.path.join(SAMPLES, "aes128-dh2-transport-pfs-off__file_transfer_run1.pcap"))
    assert r["rejected"] is True and r["class"] == "unrecognised" and r["nearest_class"] == "file_transfer"


def test_contract_reports_unrecognised_traffic_honestly(tmp_path):
    p = tmp_path / "SYNTHETIC_periodic.pcap"
    synthetic_stream(p, "periodic")
    ml = predict.predict_from_pcap(str(p))
    resp = build_response("capture.pcap", None, ml)
    assert validate_response(resp) == []
    t = resp["traffic"]
    assert t["class"] == "unrecognised" and t["label"] == "Unrecognised traffic" and t["nearest_label"] and t["rejection_reason"]
    assert any("unrecognised" in line for line in resp["explanation"])
    exposure = {i["what"]: i["points"] for i in resp["assessment"]["metadata_exposure"]["items"]}
    assert exposure["Traffic type"] == 0     # an unrecognised pattern is not counted as a leaked traffic type
