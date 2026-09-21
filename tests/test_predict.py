"""Tests for the ML side: SHAP shape handling, predict_from_features, predict_from_pcap."""
import os

import numpy as np
import pandas as pd
import pytest

import predict
from conftest import SAMPLES


def _row(**over):
    base = {c: 1.0 for c in predict.FEATURE_COLS}
    base.update(over)
    return base


# ---- SHAP array handling ----------------------------------------------------

def test_shap_matrix_keeps_feature_axis_for_rows_features_classes():
    """The (1, 12, 5) case that used to be flattened and zipped with 12 names."""
    arr = np.arange(1 * 12 * 5, dtype=float).reshape(1, 12, 5)
    out = predict.shap_matrix(arr, n_features=12)
    assert out.shape == (1, 12, 5)
    # feature 3, class 2 stays feature 3, class 2
    assert out[0, 3, 2] == arr[0, 3, 2]


def test_shap_matrix_transposes_rows_classes_features():
    arr = np.arange(1 * 5 * 12, dtype=float).reshape(1, 5, 12)
    out = predict.shap_matrix(arr, n_features=12)
    assert out.shape == (1, 12, 5)
    assert out[0, 3, 2] == arr[0, 2, 3]


def test_shap_matrix_accepts_list_of_class_arrays():
    lst = [np.full((1, 12), float(k)) for k in range(5)]
    out = predict.shap_matrix(lst, n_features=12)
    assert out.shape == (1, 12, 5)
    assert out[0, 7, 4] == 4.0


def test_shap_matrix_rejects_unmatched_shape():
    with pytest.raises(ValueError):
        predict.shap_matrix(np.zeros((1, 7, 5)), n_features=12)


def test_explanation_matches_direct_shap_for_predicted_class():
    import shap
    df = pd.DataFrame([_row(mean_size=900.0, std_size=400.0, bytes_per_sec=2e5)])[predict.FEATURE_COLS]
    exp = predict.explain_prediction(df)
    assert 1 <= len(exp) <= 3
    assert "error" not in exp[0]

    cls = int(np.argmax(predict.model.predict_proba(df)[0]))
    direct = predict.shap_matrix(shap.TreeExplainer(predict.model).shap_values(df), len(predict.FEATURE_COLS))
    for item in exp:
        assert item["feature"] in predict.FEATURE_COLS
        idx = predict.FEATURE_COLS.index(item["feature"])
        assert item["shap_value"] == pytest.approx(round(float(direct[0, idx, cls]), 4), abs=1e-4)
        assert item["value"] == pytest.approx(df[item["feature"]].iloc[0], abs=1e-3)
    # sorted by absolute contribution
    mags = [abs(e["shap_value"]) for e in exp]
    assert mags == sorted(mags, reverse=True)


# ---- predict_from_features --------------------------------------------------

def test_predict_from_features_returns_a_result():
    out = predict.predict_from_features(_row())
    assert out is not None
    assert out["class"] in predict.le.classes_
    assert 0.0 <= out["confidence"] <= 1.0
    assert sum(out["probabilities"].values()) == pytest.approx(1.0, abs=1e-3)
    assert out["confidence"] == max(out["probabilities"].values())


def test_predict_from_features_rejects_missing_columns():
    row = _row()
    del row[predict.FEATURE_COLS[0]]
    with pytest.raises(ValueError):
        predict.predict_from_features(row)


# ---- predict_from_pcap on real sample captures ------------------------------

@pytest.mark.parametrize("name", [
    "aes128gcm16-dh19-tunnel-pfs-on__web_run1.pcap",
    "aes128-dh2-transport-pfs-off__icmp_run1.pcap",
])
def test_predict_from_pcap_shape(name):
    out = predict.predict_from_pcap(os.path.join(SAMPLES, name))
    assert "error" not in out
    assert out["class"] in predict.le.classes_
    assert 0.0 <= out["confidence"] <= 1.0
    assert out["timeline"], "timeline must not be empty"
    assert all("class" in seg and "confidence" in seg for seg in out["timeline"])
    assert all(e["feature"] in predict.FEATURE_COLS for e in out["explanation"] if "feature" in e)


def test_predict_from_pcap_without_ip_traffic(tmp_path):
    from scapy.all import Ether, ARP, wrpcap
    p = tmp_path / "arp.pcap"
    wrpcap(str(p), [Ether() / ARP()])
    assert "error" in predict.predict_from_pcap(str(p))
