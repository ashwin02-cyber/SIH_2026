"""
esp_fingerprint.py
------------------
PASSIVE fingerprinting of an IPsec ESP stream from packet SIZES only: what can an eavesdropper infer about
the cipher family, the integrity-tag length and tunnel-vs-transport mode without any key and without reading
the IKE negotiation?

The function never sees a file name or a manifest label. Labels are used only by train_esp_fingerprint.py to
train and to EVALUATE the tunnel/transport model.

WHAT IS INFERRED, AND WHY IT WORKS
    ESP packet = SPI(4) + sequence(4) + IV + encrypted(payload + padding + 2 trailer bytes) + ICV.

    * AES-CBC (16-byte IV, block-aligned): the encrypted part is padded to a multiple of 16, so with a fixed
      ICV every ESP packet has the SAME length modulo 16. AES-GCM / other AEAD or counter-mode ciphers only
      pad to 4 bytes, so different packet sizes land in several residue classes. Several residue classes
      therefore rule out 16-byte-block CBC; a single class over many distinct sizes is (statistical) evidence
      for CBC. A stream where every packet has ONE size (e.g. ping) tells us nothing.
    * Integrity tag length (CBC only): length mod 16 = (8 + ICV) mod 16 when the IV is 16 bytes, which narrows
      the ICV to a few standard values. For GCM the ICV (8/12/16) does not change the 4-byte alignment, so it is
      NOT observable.
    * Tunnel vs transport: tunnel mode carries an extra inner IP header (20 bytes) in every packet. There is
      no exact rule without knowing the inner traffic, so this is a trained classifier on size statistics
      (evaluated with cross-validation grouped by VPN configuration).

NOT OBSERVABLE PASSIVELY (returned in `not_observable`): AES-128 vs AES-256, the Diffie-Hellman group, whether
PFS is used, the authentication method, the anti-replay window setting on the receiver.
"""

import os
from collections import Counter

import numpy as np

HERE = os.path.dirname(os.path.abspath(__file__))
MODE_MODEL_PATH = os.path.join(HERE, "models", "esp_mode_classifier.pkl")

MIN_PACKETS = 10
CONF_MIN = 0.80            # below this the answer is reported as "undetermined"
MODE_CONF_MIN = 0.75

# ICV lengths (bytes) that produce a given (length mod 16) for AES-CBC with a 16-byte IV:  (8 + ICV) mod 16
ICV_BY_RESIDUE = {
    8: [(16, "HMAC-SHA2-256-128"), (32, "HMAC-SHA2-512-256")],
    4: [(12, "HMAC-SHA1-96 / AES-XCBC-96 / HMAC-MD5-96")],
    0: [(24, "HMAC-SHA2-384-192")],
    12: [(20, "HMAC-SHA1-160 (untruncated)")],
}

NOT_OBSERVABLE = [
    "AES-128 vs AES-256 (key length does not change packet sizes)",
    "Diffie-Hellman group (only visible in the cleartext IKE_SA_INIT)",
    "Perfect Forward Secrecy (negotiated inside encrypted IKE messages)",
    "Authentication method (pre-shared key vs certificate: encrypted IKE_AUTH)",
    "Receiver's anti-replay window setting",
]

MODE_FEATURES = ["min_len", "p05_len", "p25_len", "p50_len", "p75_len", "p95_len", "max_len", "mean_len", "std_len",
                 "frac_res0", "frac_res4", "frac_res8", "frac_res12", "multi_size"]


def esp_lengths(packets):
    """ESP packet lengths (bytes from the SPI onwards) of the records that have one."""
    return [int(p["esp_len"]) for p in packets if p.get("esp_len") is not None]


def residue_histogram(lengths):
    return dict(sorted(Counter(l % 16 for l in lengths).items()))


# ----------------------------------------------------------------------------------------------- cipher family
def infer_cipher_family(lengths):
    n = len(lengths)
    out = {"value": "undetermined", "confidence": None, "evidence": "", "leaning": None}
    if n < MIN_PACKETS:
        out["evidence"] = f"only {n} ESP packets (need at least {MIN_PACKETS})"
        return out
    if any(l % 4 for l in lengths):
        out["evidence"] = "some ESP lengths are not multiples of 4 - not a clean ESP stream"
        return out
    hist = residue_histogram(lengths)
    sizes = len(set(lengths))
    if len(hist) >= 2:
        out.update(value="GCM-like (AEAD / not 16-byte block aligned)", confidence=0.97,
                   evidence=f"packet lengths fall into {len(hist)} different residue classes mod 16 {hist}; "
                            "16-byte-block CBC cannot produce that (one SA assumed)")
        return out
    (res,) = hist.keys()
    if sizes < 2:
        out["evidence"] = f"every packet has the same length ({lengths[0]} bytes): a constant-size stream cannot tell CBC from GCM"
        return out
    lr = 4.0 ** (sizes - 1)              # a 4-aligned AEAD would land in one class only 1/4 of the time per new size
    conf = lr / (1.0 + lr)
    if conf > CONF_MIN:
        out.update(value="CBC-like (16-byte block aligned)", confidence=round(conf, 3),
                   evidence=f"all {n} packets have length = {res} (mod 16) over {sizes} distinct sizes; an AEAD cipher "
                            f"would show several classes (heuristic likelihood, assumes even spread of padding)")
    else:
        out.update(leaning="CBC-like", confidence=round(conf, 3),
                   evidence=f"all packets share one residue class ({res} mod 16) but only {sizes} distinct sizes - too little evidence")
    return out


def infer_integrity_tag(lengths, family):
    """ICV length candidates for CBC-like streams; not observable for GCM-like or undetermined streams."""
    if not family["value"].startswith("CBC"):
        return {"value": None, "candidates": [], "evidence": "not observable from packet sizes for this stream "
                "(for AEAD ciphers the 8/12/16-byte tag does not change the 4-byte alignment)"}
    (res,) = residue_histogram(lengths).keys()
    cands = ICV_BY_RESIDUE.get(res, [])
    return {"value": cands[0][0] if len(cands) == 1 else None,
            "candidates": [{"bytes": b, "algorithm": a} for b, a in cands],
            "evidence": f"length mod 16 = {res} => ICV mod 16 = {(res - 8) % 16} (assumes AES-CBC with a 16-byte IV)"}


# ----------------------------------------------------------------------------------------------- mode
def mode_feature_vector(lengths):
    a = np.asarray(lengths, dtype=float)
    res = np.asarray([l % 16 for l in lengths])
    q = np.percentile(a, [5, 25, 50, 75, 95])
    return {"min_len": a.min(), "p05_len": q[0], "p25_len": q[1], "p50_len": q[2], "p75_len": q[3], "p95_len": q[4],
            "max_len": a.max(), "mean_len": a.mean(), "std_len": a.std(),
            "frac_res0": float((res == 0).mean()), "frac_res4": float((res == 4).mean()),
            "frac_res8": float((res == 8).mean()), "frac_res12": float((res == 12).mean()),
            "multi_size": float(len(set(lengths)) > 1)}


_mode_model = None


def _load_mode_model():
    global _mode_model
    if _mode_model is None and os.path.exists(MODE_MODEL_PATH):
        import joblib
        _mode_model = joblib.load(MODE_MODEL_PATH)
    return _mode_model


def infer_mode(lengths):
    out = {"value": "undetermined", "confidence": None, "evidence": ""}
    if len(lengths) < MIN_PACKETS:
        out["evidence"] = f"only {len(lengths)} ESP packets (need at least {MIN_PACKETS})"
        return out
    model = _load_mode_model()
    if model is None:
        out["evidence"] = "tunnel/transport model not available (run ml-engineer/train_esp_fingerprint.py)"
        return out
    import pandas as pd
    X = pd.DataFrame([mode_feature_vector(lengths)])[MODE_FEATURES]
    proba = model.predict_proba(X)[0]
    best = int(np.argmax(proba))
    label, conf = str(model.classes_[best]), float(proba[best])
    if conf < MODE_CONF_MIN:
        out.update(leaning=label, confidence=round(conf, 3),
                   evidence="packet-size statistics do not separate tunnel from transport mode clearly for this stream")
    else:
        out.update(value=label, confidence=round(conf, 3),
                   evidence="learned from packet-size statistics (tunnel mode adds an inner IP header to every packet); "
                            "trained on scripted lab traffic")
    return out


# ----------------------------------------------------------------------------------------------- public API
def fingerprint_packets(packets):
    """packets: reader records (traffic_features.read_packets). Only the ESP length is used."""
    lengths = esp_lengths(packets)
    family = infer_cipher_family(lengths)
    return {
        "esp_packets": len(lengths),
        "distinct_sizes": len(set(lengths)),
        "residues_mod16": residue_histogram(lengths) if lengths else {},
        "cipher_family": family,
        "integrity_tag": infer_integrity_tag(lengths, family) if lengths else
        {"value": None, "candidates": [], "evidence": "no ESP packets"},
        "mode": infer_mode(lengths),
        "not_observable": NOT_OBSERVABLE,
        "method": "packet sizes only (no file names, no keys, no IKE)",
    }


def no_esp_result():
    return {"esp_packets": 0, "cipher_family": {"value": "undetermined", "confidence": None, "evidence": "no ESP packets in this capture"},
            "integrity_tag": {"value": None, "candidates": [], "evidence": "no ESP packets"},
            "mode": {"value": "undetermined", "confidence": None, "evidence": "no ESP packets in this capture"},
            "distinct_sizes": 0, "residues_mod16": {}, "not_observable": NOT_OBSERVABLE,
            "method": "packet sizes only (no file names, no keys, no IKE)"}


def fingerprint_pcap(path):
    import traffic_features as tf
    packets, esp_only, _ = tf.read_packets(path)
    return fingerprint_packets(packets) if esp_only else no_esp_result()


if __name__ == "__main__":
    import json
    import sys
    print(json.dumps(fingerprint_pcap(sys.argv[1]), indent=2))
