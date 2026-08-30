"""
predict.py
----------
ML Engineer - SIH 2026 (PS 26160)

Purpose:
    This is the handoff file for the Backend Developer.
    Give them this file + the models/ folder.
    They call predict_from_pcap() or predict_from_features()
    and get back a traffic class + confidence score.

Usage (Backend Developer calls it like this):
    from predict import predict_from_pcap
    result = predict_from_pcap("path/to/capture.pcap")
    print(result)
    # Output: {"class": "web_browsing", "confidence": 0.87}
"""

import joblib
import pandas as pd
import statistics
from collections import defaultdict
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


def extract_flows(pcap_path):
    """Read pcap and group packets into flows."""
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
            "src": src,
            "dst": dst,
            "size": size,
            "time": timestamp
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
    }


def predict_from_pcap(pcap_path):
    """
    Main function for Backend Developer to call.
    
    Input:  path to a .pcap file (string)
    Output: dict with predicted class and confidence score
    
    Example:
        result = predict_from_pcap("capture.pcap")
        # {"class": "web_browsing", "confidence": 0.87}
    """
    flows = extract_flows(pcap_path)

    if not flows:
        return {"class": "unknown", "confidence": 0.0, "error": "No IP flows found in pcap"}

    # Compute features for all flows
    all_features = []
    for flow_key, packets in flows.items():
        feats = compute_features(packets)
        if feats:
            all_features.append(feats)

    if not all_features:
        return {"class": "unknown", "confidence": 0.0, "error": "Flows too short to extract features"}

    # Predict each flow and pick the most common prediction
    df = pd.DataFrame(all_features)[FEATURE_COLS]
    predictions = model.predict(df)
    probabilities = model.predict_proba(df)

    # Find most common predicted class across all flows
    from collections import Counter
    most_common_encoded = Counter(predictions).most_common(1)[0][0]

    # Get average confidence for the most common class
    class_index = list(model.classes_).index(most_common_encoded)
    avg_confidence = float(probabilities[:, class_index].mean())

    predicted_class = le.inverse_transform([most_common_encoded])[0]

    return {
        "class": predicted_class,
        "confidence": round(avg_confidence, 4),
        "flows_analyzed": len(all_features)
    }


def predict_from_features(feature_dict):
    """
    Alternative function — Backend Developer can call this
    if they already have extracted features (no pcap needed).
    
    Input:  dict with all 12 feature keys
    Output: dict with predicted class and confidence score
    
    Example:
        result = predict_from_features({
            "packet_count": 42,
            "total_bytes": 5000,
            ... (all 12 features)
        })
    """
    df = pd.DataFrame([feature_dict])[FEATURE_COLS]
    prediction = model.predict(df)[0]
    probabilities = model.predict_proba(df)[0]
    confidence = float(probabilities.max())
    predicted_class = le.inverse_transform([prediction])[0]

    return {
        "class": predicted_class,
        "confidence": round(confidence, 4)
    }


# ── Quick test when run directly ──────────────────────────────────────────────
if __name__ == "__main__":
    import sys

    if len(sys.argv) < 2:
        print("Usage: python predict.py <path_to_pcap>")
        print("\nRunning self-test with dummy features...")

        # Test predict_from_features with a dummy row
        test_features = {
            'packet_count': 50,
            'total_bytes': 25000,
            'duration_sec': 5.0,
            'bytes_per_sec': 5000,
            'mean_size': 500,
            'std_size': 100,
            'min_size': 64,
            'max_size': 1400,
            'mean_inter_arrival': 0.1,
            'std_inter_arrival': 0.05,
            'fwd_packet_ratio': 0.6,
            'bwd_packet_ratio': 0.4
        }
        result = predict_from_features(test_features)
        print(f"Self-test result: {result}")

    else:
        pcap_path = sys.argv[1]
        print(f"Predicting traffic type for: {pcap_path}")
        result = predict_from_pcap(pcap_path)
        print(f"Result: {result}")