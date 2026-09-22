"""
replay_stream.py
----------------
REPLAY of a capture file in time order, one event per second of capture time (a "window"), so a dashboard can update
progressively.

    THIS IS A REPLAY OF A FILE, NOT LIVE SNIFFING. Nothing is captured from a network; the packets of an existing
    pcap are simply fed through the analyzer in the order they were recorded.

Every event carries a running verdict computed ONLY from the packets seen so far, so the evidence really grows during
the replay: the cipher-family and tunnel/transport inferences appear once enough packets have been seen, and the
sequence-number evidence firms up. The traffic class is the mean of the calibrated window probabilities so far, with
the same open-set rule as the full analysis.
"""

import time
from collections import defaultdict

import numpy as np
import pandas as pd

import esp_fingerprint as fp
import esp_sequence as es
import open_set as osr
import predict
import traffic_features as tf

REPLAY_LABEL = ("REPLAY of a capture file, in time order. This is not live sniffing: nothing is captured from a network; "
                "the recorded packets are fed through the analyzer one second at a time.")
MAX_WINDOWS = 300
MAX_PACE = 2.0


def _running_verdict(probas, dists, classes):
    if not probas:
        return {"class": None, "confidence": None, "rejected": False, "nearest_class": None, "probabilities": {}, "windows_classified": 0}
    mean = np.mean(probas, axis=0)
    idx = int(np.argmax(mean))
    conf = float(mean[idx])
    rejected, reason = False, None
    if predict._open_set:
        rejected, reason = osr.decide(conf, float(np.median(dists)), predict._open_set["tau_conf"], predict._open_set["tau_dist"])
    return {"class": "unrecognised" if rejected else classes[idx], "confidence": round(conf, 4), "rejected": rejected,
            "rejection_reason": reason, "nearest_class": classes[idx],
            "probabilities": {c: round(float(p), 4) for c, p in zip(classes, mean)}, "windows_classified": len(probas)}


def replay_events(packets, esp_only, filename, pace=0.15, max_windows=MAX_WINDOWS):
    """Generator of JSON-serialisable events: one 'start', one 'window' per second of traffic, one 'end'
    (the API adds the final full analysis after it). `pace` = seconds of wall-clock time between windows."""
    pace = max(0.0, min(float(pace), MAX_PACE))
    packets = sorted(packets, key=lambda p: p["time"])
    classes = predict.le.inverse_transform(predict.model.classes_).tolist()
    if not packets:
        yield {"type": "start", "filename": filename, "label": REPLAY_LABEL, "total_windows": 0, "span_sec": 0.0}
        yield {"type": "end", "windows_replayed": 0, "truncated": False}
        return

    t0, first_src = packets[0]["time"], packets[0]["src"]
    buckets = defaultdict(list)
    for p in packets:
        buckets[int((p["time"] - t0) // tf.WINDOW_SEC)].append(p)
    indices = sorted(buckets)
    truncated = len(indices) > max_windows
    indices = indices[:max_windows]
    yield {"type": "start", "filename": filename, "label": REPLAY_LABEL, "total_windows": len(indices), "truncated": truncated,
           "span_sec": round(packets[-1]["time"] - t0, 3), "window_sec": tf.WINDOW_SEC, "packets_total": len(packets), "esp_only": esp_only}

    seen, probas, dists = [], [], []
    for n, idx in enumerate(indices, 1):
        wp = buckets[idx]
        seen += wp
        window = None
        if len(wp) >= tf.MIN_PACKETS_PER_WINDOW:
            feats = tf.window_features(wp, first_src, idx)
            X = pd.DataFrame([feats])[tf.FEATURE_COLS]
            pr = predict.model.predict_proba(X)
            if predict._open_set:
                pr = osr.temperature_scale(pr, predict._open_set["temperature"])
                dists.append(float(predict._novelty.distance(X)[0]))
            probas.append(pr[0])
            j = int(np.argmax(pr[0]))
            window = {"class": classes[j], "confidence": round(float(pr[0][j]), 4)}
        esp_so_far = seen if esp_only else []
        fingerprint = fp.fingerprint_packets(esp_so_far) if esp_so_far else None
        seq = es.analyze_sequences(esp_so_far)
        yield {
            "type": "window", "index": n, "start_sec": round(idx * tf.WINDOW_SEC, 3), "end_sec": round((idx + 1) * tf.WINDOW_SEC, 3),
            "packets": len(wp), "bytes": int(sum(p["size"] for p in wp)), "window": window,
            "so_far": {
                "packets": len(seen), "bytes": int(sum(p["size"] for p in seen)),
                "verdict": _running_verdict(probas, dists, classes),
                "cipher_family": (fingerprint or {}).get("cipher_family"),
                "mode": (fingerprint or {}).get("mode"),
                "replay_protection": {"status": seq["replay_protection"]["status"], "evidence": seq["replay_protection"]["evidence"]},
                "sas_seen": len(seq["sas"]), "rekeys_seen": len(seq["rekey_events"]),
            },
        }
        if pace:
            time.sleep(pace)
    yield {"type": "end", "windows_replayed": len(indices), "truncated": truncated}
