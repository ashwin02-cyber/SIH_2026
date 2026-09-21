"""
defence_capture.py
------------------
What-if simulation of the traffic-analysis defences (defence_sim.py) on ONE capture, for the API / dashboard /
reports: what would the classifier say if this capture had been padded, mixed with dummy traffic or delayed,
and what would that cost?

    THIS IS A SIMULATION at the feature level, not a change to the real traffic. The classifier used is the
    shipped one (trained on clean traffic), i.e. a NON-ADAPTIVE attacker; the population-level numbers next to it
    (defence_metrics.json) include the ADAPTIVE attacker who retrains on defended traffic.
"""

import json
import os

import pandas as pd

import defence_sim as ds
import predict
import traffic_features as tf

HERE = os.path.dirname(os.path.abspath(__file__))
METRICS_PATH = os.path.join(HERE, "defence_metrics.json")

LABEL = ("SIMULATION - the packets of this capture were rewritten at the feature level; nothing was re-sent and no gateway was configured. "
         "The classifier shown is the one trained on clean traffic (a non-adaptive attacker).")


def _classify(packets):
    windows, _, _ = tf.windows_from_packets(packets)
    if not windows:
        return None
    c = predict.classify_windows(pd.DataFrame(windows))
    return {"class": c["predicted_class"], "nearest_class": c["nearest_class"], "confidence": round(c["confidence"], 3),
            "rejected": c["rejected"], "windows": len(windows)}


def population_metrics():
    try:
        with open(METRICS_PATH, encoding="utf-8") as f:
            return json.load(f)
    except (OSError, ValueError):
        return None


def simulate_packets(packets):
    base = _classify(packets)
    if base is None:
        return {"available": False, "label": LABEL, "reason": "the capture is too sparse to classify even before any defence"}
    rows = []
    for name, d in ds.DEFENCES.items():
        defended, cost = ds.apply(name, packets, seed=0)
        res = _classify(defended)
        rows.append({"id": name, "label": d["label"], "description": d["description"], "cost": cost,
                     "result": res, "changes_answer": (res is None) or res["class"] != base["class"]})
    return {"available": True, "label": LABEL, "baseline": base, "defences": rows, "population": population_metrics()}


def simulate_capture(path):
    """Raises ValueError if the file is not a readable capture."""
    packets, esp_only, _ = tf.read_packets(path)
    if not packets:
        return {"available": False, "label": LABEL, "reason": "no IP packets in this capture"}
    return simulate_packets(packets)
