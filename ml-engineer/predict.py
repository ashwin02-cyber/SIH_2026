"""
predict.py
----------
ML Engineer - SIH 2026 (PS 26160)

Innovations:
    1. SHAP Explainability  — explains WHY the model made each decision
    2. Anomaly/Threat Detection — flags suspicious VPN behavior
    3. Traffic Timeline — shows how traffic type changes over time in a session

Usage (Backend Developer):
    from predict import predict_from_pcap
    result = predict_from_pcap("capture.pcap")
"""

import joblib
import pandas as pd
import statistics
import shap
import numpy as np
from collections import defaultdict, Counter
from scapy.all import rdpcap, IP
import os

# ── Load model and label encoder ─────────────────────────────────────────────
MODEL_PATH = os.path.join(os.path.dirname(__file__), "models", "traffic_classifier.pkl")
ENCODER_PATH = os.path.join(os.path.dirname(__file__), "models", "label_encoder.pkl")

model = joblib.load(MODEL_PATH)
le = joblib.load(ENCODER_PATH)

FEATURE_COLS = [
    'packet_count', 'total_bytes', 'duration_sec', 'bytes_per_sec',
    'mean_size', 'std_size', 'min_size', 'max_size',
    'mean_inter_arrival', 'std_inter_arrival',
    'fwd_packet_ratio', 'bwd_packet_ratio'
]

# Human-readable feature descriptions
FEATURE_DESCRIPTIONS = {
    'packet_count':       'number of packets in flow',
    'total_bytes':        'total data transferred',
    'duration_sec':       'how long the flow lasted',
    'bytes_per_sec':      'data transfer speed',
    'mean_size':          'average packet size',
    'std_size':           'variation in packet sizes',
    'min_size':           'smallest packet size',
    'max_size':           'largest packet size',
    'mean_inter_arrival': 'average time between packets',
    'std_inter_arrival':  'variation in packet timing',
    'fwd_packet_ratio':   'ratio of outgoing packets',
    'bwd_packet_ratio':   'ratio of incoming packets',
}

# ── Anomaly thresholds ────────────────────────────────────────────────────────
ANOMALY_RULES = [
    {
        "name": "Large data exfiltration",
        "condition": lambda f: f["total_bytes"] > 5_000_000,
        "severity": "HIGH",
        "description": "Unusually large data transfer — possible data exfiltration"
    },
    {
        "name": "High speed transfer",
        "condition": lambda f: f["bytes_per_sec"] > 1_000_000,
        "severity": "MEDIUM",
        "description": "Very high throughput — possible bulk data transfer or attack"
    },
    {
        "name": "Abnormal packet size",
        "condition": lambda f: f["mean_size"] > 1400,
        "severity": "LOW",
        "description": "Unusually large average packet size — may indicate tunneling or evasion"
    },
    {
        "name": "One-way traffic",
        "condition": lambda f: f["fwd_packet_ratio"] > 0.95 or f["bwd_packet_ratio"] > 0.95,
        "severity": "MEDIUM",
        "description": "Almost entirely one-directional traffic — possible data upload or C2 beacon"
    },
    {
        "name": "Very long session",
        "condition": lambda f: f["duration_sec"] > 3600,
        "severity": "LOW",
        "description": "Session lasted over 1 hour — possible persistent connection"
    },
]


# ── Core packet processing ────────────────────────────────────────────────────
def extract_flows(pcap_path):
    """Read pcap and group packets into flows with timestamps."""
    packets = rdpcap(pcap_path)
    flows = defaultdict(list)

    for pkt in packets:
        if IP not in pkt:
            continue
        src = pkt[IP].src
        dst = pkt[IP].dst
        size = len(pkt)
        timestamp = float(pkt.time)
        flow_key = tuple(sorted([src, dst]))
        flows[flow_key].append({
            "src": src, "dst": dst,
            "size": size, "time": timestamp
        })

    return flows


def compute_features(flow_packets):
    """Compute numeric features for one flow."""
    if len(flow_packets) < 2:
        return None

    flow_packets = sorted(flow_packets, key=lambda p: p["time"])
    sizes = [p["size"] for p in flow_packets]
    times = [p["time"] for p in flow_packets]
    inter_arrival = [t2 - t1 for t1, t2 in zip(times[:-1], times[1:])]
    first_src = flow_packets[0]["src"]
    fwd_count = sum(1 for p in flow_packets if p["src"] == first_src)
    bwd_count = len(flow_packets) - fwd_count
    duration = times[-1] - times[0] if len(times) > 1 else 0.0001
    total_bytes = sum(sizes)

    return {
        'packet_count': len(flow_packets),
        'total_bytes': total_bytes,
        'duration_sec': duration,
        'bytes_per_sec': total_bytes / duration if duration > 0 else 0,
        'mean_size': statistics.mean(sizes),
        'std_size': statistics.stdev(sizes) if len(sizes) > 1 else 0,
        'min_size': min(sizes),
        'max_size': max(sizes),
        'mean_inter_arrival': statistics.mean(inter_arrival) if inter_arrival else 0,
        'std_inter_arrival': statistics.stdev(inter_arrival) if len(inter_arrival) > 1 else 0,
        'fwd_packet_ratio': fwd_count / len(flow_packets),
        'bwd_packet_ratio': bwd_count / len(flow_packets),
        '_start_time': times[0],  # used for timeline, not fed to model
    }


# ── Innovation 1: SHAP Explainability ────────────────────────────────────────
def explain_prediction(feature_row_df):
    """
    Uses SHAP to explain which features most influenced the prediction.
    Returns top 3 features with human-readable descriptions.
    """
    try:
        explainer = shap.TreeExplainer(model)
        shap_values = explainer.shap_values(feature_row_df)

        # shap_values shape: (n_classes, n_rows, n_features) for XGBoost
        # Get absolute mean SHAP value per feature across all classes
        if isinstance(shap_values, list):
            mean_abs_shap = np.mean(
                [np.abs(sv) for sv in shap_values], axis=0
            ).flatten()
        else:
            mean_abs_shap = np.abs(shap_values).mean(axis=0).flatten()

        # Rank features by importance
        feature_importance = sorted(
            zip(FEATURE_COLS, mean_abs_shap),
            key=lambda x: x[1], reverse=True
        )

        # Build human-readable explanation
        explanation = []
        for feature, importance in feature_importance[:3]:
            value = float(feature_row_df[feature].iloc[0])
            level = "high" if importance > 0.1 else "medium" if importance > 0.01 else "low"
            explanation.append({
                "feature": feature,
                "description": FEATURE_DESCRIPTIONS[feature],
                "value": round(value, 4),
                "influence": level
            })

        return explanation

    except Exception as e:
        return [{"error": f"SHAP explanation failed: {str(e)}"}]


# ── Innovation 2: Anomaly Detection ──────────────────────────────────────────
def detect_anomalies(feature_dict):
    """
    Checks flow features against anomaly rules.
    Returns list of triggered anomalies.
    """
    triggered = []
    for rule in ANOMALY_RULES:
        try:
            if rule["condition"](feature_dict):
                triggered.append({
                    "name": rule["name"],
                    "severity": rule["severity"],
                    "description": rule["description"]
                })
        except Exception:
            continue
    return triggered


# ── Innovation 3: Traffic Timeline ───────────────────────────────────────────
def build_timeline(all_features, predictions, confidences):
    """
    Sorts flows by start time and builds a timeline showing
    how traffic type changed during the session.
    """
    timeline = []
    combined = sorted(
        zip(all_features, predictions, confidences),
        key=lambda x: x[0].get('_start_time', 0)
    )

    for i, (feats, pred, conf) in enumerate(combined):
        timeline.append({
            "segment": i + 1,
            "start_time_offset_sec": round(
                feats.get('_start_time', 0) - combined[0][0].get('_start_time', 0), 2
            ),
            "class": pred,
            "confidence": round(conf, 4),
            "packets": feats['packet_count'],
            "bytes": feats['total_bytes']
        })

    return timeline


# ── Main prediction function ──────────────────────────────────────────────────
def predict_from_pcap(pcap_path):
    """
    Main function for Backend Developer to call.

    Input:  path to a .pcap file
    Output: full analysis dict with class, confidence,
            SHAP explanation, anomalies, and traffic timeline
    """
    flows = extract_flows(pcap_path)

    if not flows:
        return {"error": "No IP flows found in pcap"}

    all_features = []
    for flow_key, packets in flows.items():
        feats = compute_features(packets)
        if feats:
            all_features.append(feats)

    if not all_features:
        return {"error": "Flows too short to extract features"}

    # Build feature dataframe (exclude _start_time from model input)
    df = pd.DataFrame(all_features)[FEATURE_COLS]

    # Predict all flows
    predictions_encoded = model.predict(df)
    probabilities = model.predict_proba(df)

    predictions = le.inverse_transform(predictions_encoded).tolist()
    confidences = probabilities.max(axis=1).tolist()

    # Overall prediction = most common class
    most_common_encoded = Counter(predictions_encoded).most_common(1)[0][0]
    predicted_class = le.inverse_transform([most_common_encoded])[0]
    class_index = list(model.classes_).index(most_common_encoded)
    avg_confidence = float(probabilities[:, class_index].mean())

    # SHAP explanation for the dominant flow (largest packet count)
    dominant_idx = max(range(len(all_features)),
                       key=lambda i: all_features[i]['packet_count'])
    dominant_row = df.iloc[[dominant_idx]]
    explanation = explain_prediction(dominant_row)

    # Anomaly detection on dominant flow
    anomalies = detect_anomalies(all_features[dominant_idx])

    # Traffic timeline
    timeline = build_timeline(all_features, predictions, confidences)

    return {
        "class": predicted_class,
        "confidence": round(avg_confidence, 4),
        "flows_analyzed": len(all_features),

        "explanation": explanation,        # Innovation 1: SHAP
        "anomalies": anomalies,            # Innovation 2: Threat detection
        "timeline": timeline               # Innovation 3: Traffic timeline
    }


def predict_from_features(feature_dict):
    """Simple single-row prediction for Backend Developer."""
    df = pd.DataFrame([feature_dict])[FEATURE_COLS]
    prediction = model.predict(df)[0]
    probabilities = model.predict_proba(df)[0]
    confidence = float(probabilities.max())