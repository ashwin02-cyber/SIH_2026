"""
predict.py
----------
ML Engineer - SIH 2026 (PS 26160)

Classifies the traffic inside an IPsec capture (web / video / VoIP / file
transfer / ICMP) from the *shape* of the encrypted ESP traffic, in fixed
time windows, and adds:
    1. SHAP explainability   - which features pushed towards the predicted class
    2. Anomaly / threat flags - simple, conservative rules
    3. A time-window timeline - the class of each 1-second window

Usage (Backend Developer):
    from predict import predict_from_pcap
    result = predict_from_pcap("capture.pcap")
"""

import os
import warnings

import joblib
import numpy as np
import pandas as pd
import shap

import open_set as osr
from traffic_features import (FEATURE_COLS, FEATURE_DESCRIPTIONS, MIN_PACKETS_PER_WINDOW,
                              WINDOW_SEC, extract_windows)

warnings.filterwarnings("ignore", category=UserWarning)

# ── Load model and label encoder ─────────────────────────────────────────────
MODEL_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "models", "traffic_classifier.pkl")
ENCODER_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "models", "label_encoder.pkl")

model = joblib.load(MODEL_PATH)
le = joblib.load(ENCODER_PATH)

# The saved model must have been trained on exactly these columns (in order).
if hasattr(model, "feature_names_in_") and list(model.feature_names_in_) != FEATURE_COLS:
    raise RuntimeError("models/traffic_classifier.pkl was trained on different features than "
                       "traffic_features.FEATURE_COLS - re-run batch_extract.py and train_model.py")

# Calibration + open-set rejection (train_open_set.py). If the file is missing the classifier behaves as before
# (no rejection).
OPEN_SET_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "models", "open_set.pkl")
_open_set = joblib.load(OPEN_SET_PATH) if os.path.exists(OPEN_SET_PATH) else None
_novelty = osr.Novelty.from_dict(_open_set["novelty"]) if _open_set else None

MAX_SHAP_WINDOWS = 80  # explain at most this many windows (evenly sampled) to keep /analyze fast

# ── Innovation 2: anomaly rules (capture level, deliberately conservative) ───
# Each rule gets (capture_info, windows_df, mean_confidence).
ANOMALY_RULES = [
    {
        "name": "Large data volume",
        "severity": "MEDIUM",
        "condition": lambda c, w, conf: c["total_bytes"] > 5_000_000,
        "description": "More than 5 MB crossed the tunnel in this capture. Normal for a bulk file "
                       "transfer, but worth checking if it was not expected.",
    },
    {
        "name": "High throughput burst",
        "severity": "MEDIUM",
        "condition": lambda c, w, conf: w["bytes_per_sec"].max() > 1_000_000,
        "description": "At least one 1-second window carried over 1 MB/s, which points to a bulk "
                       "transfer rather than interactive traffic.",
    },
    {
        "name": "Large average packet size",
        "severity": "LOW",
        "condition": lambda c, w, conf: c["total_bytes"] / max(c["n_packets"], 1) > 1400,
        "description": "Packets are close to full-size on average, typical of bulk transfers "
                       "(or of tunnelling one protocol inside another).",
    },
    {
        "name": "One-way traffic",
        "severity": "MEDIUM",
        "condition": lambda c, w, conf: c["n_packets"] >= 20 and (c["fwd_ratio"] > 0.95 or c["fwd_ratio"] < 0.05),
        "description": "Almost all packets travel in one direction, which can indicate an upload or "
                       "a beacon rather than a two-way conversation.",
    },
    {
        "name": "Very long session",
        "severity": "LOW",
        "condition": lambda c, w, conf: c["span_sec"] > 3600,
        "description": "The capture spans more than one hour, so this is a persistent connection.",
    },
    {
        "name": "Low classification confidence",
        "severity": "LOW",
        "condition": lambda c, w, conf: conf < 0.6,
        "description": "The traffic does not closely match any of the five trained traffic types, so "
                       "the label should be treated as a rough guess.",
    },
    {
        "name": "No ESP traffic found",
        "severity": "LOW",
        "condition": lambda c, w, conf: not c["esp_only"],
        "description": "No encrypted ESP packets were found, so all IP traffic was analysed. The model "
                       "was trained on ESP traffic only and is unvalidated for plain traffic.",
    },
]


def detect_anomalies(capture, windows_df, mean_confidence):
    """Returns the triggered rules as [{name, severity, description}]."""
    triggered = []
    for rule in ANOMALY_RULES:
        try:
            if rule["condition"](capture, windows_df, mean_confidence):
                triggered.append({"name": rule["name"], "severity": rule["severity"],
                                  "description": rule["description"]})
        except Exception:
            continue
    return triggered


# ── Innovation 1: SHAP Explainability ────────────────────────────────────────
_explainer = None


def _get_explainer():
    global _explainer
    if _explainer is None:
        _explainer = shap.TreeExplainer(model)
    return _explainer


def shap_matrix(shap_values, n_features):
    """Normalise whatever shap returns into an array of shape
    (n_rows, n_features, n_classes).

    Depending on the shap version / model, shap_values is either
      * a list of n_classes arrays, each (n_rows, n_features), or
      * one ndarray (n_rows, n_features, n_classes), or
      * one ndarray (n_rows, n_classes, n_features), or
      * one ndarray (n_rows, n_features) for a single output.
    Getting the axes wrong silently pairs feature names with the wrong
    numbers (the old code flattened a (1, 12, 5) array and zipped it with 12
    names), so the feature axis is located explicitly here.
    """
    if isinstance(shap_values, list):
        return np.stack([np.asarray(sv) for sv in shap_values], axis=-1)
    arr = np.asarray(shap_values)
    if arr.ndim == 2:
        return arr[:, :, np.newaxis]
    if arr.ndim != 3:
        raise ValueError(f"Unexpected SHAP output shape {arr.shape}")
    if arr.shape[1] == n_features:
        return arr
    if arr.shape[2] == n_features:
        return np.transpose(arr, (0, 2, 1))
    raise ValueError(f"SHAP output {arr.shape} does not match {n_features} features")


def _influence(mag):
    return "high" if mag > 0.1 else "medium" if mag > 0.01 else "low"


def explain_prediction(feature_df, class_index=None, top_n=3):
    """
    SHAP explanation of what pushed the model towards a class.

    `feature_df` has the model's FEATURE_COLS as columns and one or more rows
    (windows). `class_index` is the position of the class in model.classes_;
    it defaults to the class with the highest average probability.

    With several rows the signed SHAP values are averaged per feature, so
    the result describes the capture as a whole. Each item carries the signed
    contribution (positive = pushed towards the class), the typical (median)
    feature value and a ready-to-show sentence in `text`.
    """
    try:
        cols = list(feature_df.columns)
        sv = shap_matrix(_get_explainer().shap_values(feature_df), len(cols))
        if class_index is None:
            class_index = int(np.argmax(model.predict_proba(feature_df).mean(axis=0)))
        contrib = sv[:, :, class_index].mean(axis=0)
        class_name = str(le.inverse_transform([model.classes_[class_index]])[0])

        ranked = sorted(zip(cols, contrib), key=lambda x: abs(x[1]), reverse=True)
        explanation = []
        for feature, c in ranked[:top_n]:
            value = float(feature_df[feature].median())
            direction = "towards" if c >= 0 else "away from"
            desc = FEATURE_DESCRIPTIONS.get(feature, feature)
            explanation.append({
                "feature": feature,
                "description": desc,
                "value": round(value, 4),
                "shap_value": round(float(c), 4),
                "direction": direction,
                "influence": _influence(abs(float(c))),
                "text": f"{desc[0].upper()}{desc[1:]} (typically {value:.4g}) pushed the prediction "
                        f"{direction} '{class_name.replace('_', ' ')}'.",
            })
        return explanation

    except Exception as e:
        return [{"error": f"SHAP explanation failed: {str(e)}"}]


# ── Innovation 3: time-window timeline ───────────────────────────────────────
def build_timeline(windows_df, predictions, confidences):
    """One entry per fixed time window, in time order."""
    timeline = []
    for (_, w), pred, conf in zip(windows_df.iterrows(), predictions, confidences):
        start = float(w["start_offset_sec"])
        timeline.append({
            "window": int(w["window_index"]) + 1,
            "start_sec": round(start, 2),
            "end_sec": round(start + WINDOW_SEC, 2),
            "class": pred,
            "confidence": round(float(conf), 4),
            "packets": int(w["n_packets"]),
            "bytes": int(w["n_bytes"]),
            "packets_per_sec": round(float(w["pkts_per_sec"]), 2),
            "bytes_per_sec": round(float(w["bytes_per_sec"]), 1),
        })
    return timeline


# ── Main prediction function ──────────────────────────────────────────────────
def predict_from_pcap(pcap_path):
    """
    Main function for the Backend Developer.

    Input:  path to a .pcap / .pcapng file
    Output: dict with the predicted class, confidence, per-class probabilities,
            SHAP explanation, anomalies and the time-window timeline.
            {"error": "..."} when there is nothing to classify.
    Raises ValueError if the file is not a readable capture.
    """
    windows, info = extract_windows(pcap_path)

    if info["n_packets"] == 0:
        return {"error": "No IP packets found in this capture"}
    if not windows:
        return {"error": f"Capture too sparse to classify: no {WINDOW_SEC:g}-second window contained "
                         f"at least {MIN_PACKETS_PER_WINDOW} packets"}

    wdf = pd.DataFrame(windows)
    X = wdf[FEATURE_COLS]
    proba = model.predict_proba(X)
    if _open_set:
        proba = osr.temperature_scale(proba, _open_set["temperature"])   # calibrated; never changes the winning class
    classes = le.inverse_transform(model.classes_).tolist()

    window_pred = [classes[i] for i in proba.argmax(axis=1)]
    window_conf = proba.max(axis=1)

    mean_proba = proba.mean(axis=0)
    class_index = int(np.argmax(mean_proba))
    nearest_class = classes[class_index]
    confidence = float(mean_proba[class_index])

    # open-set rejection: low calibrated confidence OR a pattern unlike anything in the training windows
    novelty = None
    rejected, rejection_reason = False, None
    if _open_set:
        capture_distance = float(np.median(_novelty.distance(X)))
        rejected, rejection_reason = osr.decide(confidence, capture_distance, _open_set["tau_conf"], _open_set["tau_dist"])
        novelty = {"distance": round(capture_distance, 4), "distance_threshold": round(_open_set["tau_dist"], 4),
                   "confidence_threshold": round(_open_set["tau_conf"], 4)}
    predicted_class = "unrecognised" if rejected else nearest_class

    # SHAP on an evenly spaced subset of windows, for the predicted class
    step = max(1, len(X) // MAX_SHAP_WINDOWS)
    explanation = explain_prediction(X.iloc[::step], class_index=class_index)

    fwd_pkts = float(np.average(wdf["fwd_packet_ratio"], weights=wdf["n_packets"]))
    capture = {**info, "fwd_ratio": fwd_pkts}
    anomalies = detect_anomalies(capture, wdf, confidence)
    if rejected:
        anomalies.append({"name": "Unrecognised traffic", "severity": "MEDIUM",
                          "description": f"The traffic does not match any trained traffic type: {rejection_reason}. "
                                         f"The closest type is {nearest_class.replace('_', ' ')}, but it is not reported as the answer."})

    warnings_out = []
    if not info["esp_only"]:
        warnings_out.append("No ESP packets were found; all IP traffic was analysed instead. The model "
                            "was trained on ESP traffic only.")
    if info["truncated"]:
        warnings_out.append("The capture file is truncated; only the readable part was analysed.")
    if info["span_sec"] < WINDOW_SEC:
        warnings_out.append(f"The capture is shorter than one {WINDOW_SEC:g}-second window "
                            f"({info['span_sec']:.2f}s), so the timeline has a single point.")

    return {
        "class": predicted_class,
        "confidence": round(confidence, 4),
        "class_probabilities": {c: round(float(p), 4) for c, p in zip(classes, mean_proba)},
        "nearest_class": nearest_class,
        "rejected": rejected,
        "rejection_reason": rejection_reason,
        "novelty": novelty,
        "calibration": {"temperature": _open_set["temperature"]} if _open_set else None,
        "windows_analyzed": len(windows),
        "window_sec": WINDOW_SEC,
        "esp_only": info["esp_only"],
        "capture": {"packets": info["n_packets"], "bytes": info["total_bytes"],
                    "span_sec": round(info["span_sec"], 3), "truncated": info["truncated"],
                    "windows_dropped": info["n_windows_dropped"]},
        "explanation": explanation,
        "anomalies": anomalies,
        "timeline": build_timeline(wdf, window_pred, window_conf),
        "warnings": warnings_out,
    }


def predict_from_features(feature_dict):
    """Simple single-row prediction.

    feature_dict must contain every column in FEATURE_COLS.
    Returns {"class": str, "confidence": float, "probabilities": {class: p}}.
    """
    missing = [c for c in FEATURE_COLS if c not in feature_dict]
    if missing:
        raise ValueError(f"Missing feature(s): {', '.join(missing)}")
    df = pd.DataFrame([feature_dict])[FEATURE_COLS]
    probabilities = model.predict_proba(df)[0]
    best = int(np.argmax(probabilities))
    labels = le.inverse_transform(model.classes_).tolist()
    return {
        "class": labels[best],
        "confidence": round(float(probabilities[best]), 4),
        "probabilities": {lab: round(float(p), 4) for lab, p in zip(labels, probabilities)},
    }


if __name__ == "__main__":
    import json
    import sys

    if len(sys.argv) != 2:
        sys.exit("Usage: python predict.py <capture.pcap>")
    print(json.dumps(predict_from_pcap(sys.argv[1]), indent=2))
