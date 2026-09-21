"""
open_set.py
-----------
Calibrated confidence and open-set rejection for the traffic classifier.

    * TEMPERATURE SCALING: one number T fitted on out-of-fold probabilities (test configurations unseen in
      training) so that the reported confidence matches how often the model is actually right.
      p' = softmax(log(p) / T). It never changes which class wins, only how sure the model claims to be.
    * NOVELTY DISTANCE: mean distance of a window's features to its 5 nearest TRAINING windows (features are
      log-scaled and standardised). A random forest can be confidently wrong on a pattern unlike anything it was
      trained on; this distance is large exactly then.
    * REJECTION: a capture is reported as "unrecognised traffic" when its calibrated confidence is below
      tau_conf OR its median novelty distance is above tau_dist. Both thresholds are chosen from KNOWN classes
      only (so that ~95% of known captures are accepted) - never tuned against the class used to test rejection.

Shared by train_open_set.py (fit + evaluate) and predict.py (use).
"""

import numpy as np
from scipy.optimize import minimize_scalar
from sklearn.neighbors import NearestNeighbors

LOG_FEATURES = ["pkts_per_sec", "bytes_per_sec", "mean_size", "std_size", "min_size", "max_size", "median_size"]
TIME_FEATURES = ["mean_inter_arrival", "std_inter_arrival", "max_inter_arrival"]
K_NEIGHBOURS = 5
EPS = 1e-6


def transform(X, cols):
    """Log-scale heavy-tailed features (sizes, rates, gaps in ms) so distances are not dominated by one of them."""
    out = np.empty((len(X), len(cols)), dtype=float)
    for j, c in enumerate(cols):
        v = np.asarray(X[c], dtype=float)
        out[:, j] = np.log1p(v) if c in LOG_FEATURES else np.log1p(v * 1000.0) if c in TIME_FEATURES else v
    return out


# ---------------------------------------------------------------------------------------------- calibration
def temperature_scale(proba, T):
    z = np.log(np.clip(proba, EPS, 1.0)) / T
    z -= z.max(axis=1, keepdims=True)
    e = np.exp(z)
    return e / e.sum(axis=1, keepdims=True)


def nll(proba, y):
    return float(-np.mean(np.log(np.clip(proba[np.arange(len(y)), y], EPS, 1.0))))


def fit_temperature(proba, y):
    res = minimize_scalar(lambda T: nll(temperature_scale(proba, T), y), bounds=(0.05, 5.0), method="bounded")
    return float(res.x)


def brier(proba, y):
    onehot = np.zeros_like(proba)
    onehot[np.arange(len(y)), y] = 1.0
    return float(np.mean(np.sum((proba - onehot) ** 2, axis=1)))


def ece(proba, y, bins=10):
    """Expected calibration error of the top-class confidence."""
    conf, pred = proba.max(axis=1), proba.argmax(axis=1)
    correct = (pred == y).astype(float)
    edges = np.linspace(0.0, 1.0, bins + 1)
    total = 0.0
    for lo, hi in zip(edges[:-1], edges[1:]):
        m = (conf > lo) & (conf <= hi) if lo > 0 else (conf >= lo) & (conf <= hi)
        if m.any():
            total += m.mean() * abs(correct[m].mean() - conf[m].mean())
    return float(total)


# ---------------------------------------------------------------------------------------------- novelty
class Novelty:
    """Mean distance to the k nearest reference windows (standardised, log-scaled features)."""

    def __init__(self, reference_df, cols, k=K_NEIGHBOURS):
        self.cols, self.k = list(cols), k
        R = transform(reference_df, self.cols)
        self.mean, self.std = R.mean(axis=0), R.std(axis=0) + 1e-9
        self.reference = (R - self.mean) / self.std
        self.nn = NearestNeighbors(n_neighbors=min(k, len(self.reference))).fit(self.reference)

    def distance(self, X):
        Z = (transform(X, self.cols) - self.mean) / self.std
        d, _ = self.nn.kneighbors(Z)
        return d.mean(axis=1)

    def to_dict(self):
        return {"cols": self.cols, "k": self.k, "mean": self.mean, "std": self.std, "reference": self.reference}

    @classmethod
    def from_dict(cls, d):
        obj = cls.__new__(cls)
        obj.cols, obj.k, obj.mean, obj.std, obj.reference = d["cols"], d["k"], d["mean"], d["std"], d["reference"]
        obj.nn = NearestNeighbors(n_neighbors=min(obj.k, len(obj.reference))).fit(obj.reference)
        return obj


# ---------------------------------------------------------------------------------------------- decision
def choose_thresholds(known_conf, known_dist, target_accept=0.95):
    """Split the allowed rejection of KNOWN captures evenly between the two signals."""
    tail = (1.0 - target_accept) / 2.0
    return {"tau_conf": float(np.quantile(known_conf, tail)), "tau_dist": float(np.quantile(known_dist, 1.0 - tail)),
            "target_accept": target_accept}


def decide(conf, dist, tau_conf, tau_dist):
    """Returns (rejected, reason)."""
    reasons = []
    if conf < tau_conf:
        reasons.append(f"confidence {conf:.0%} is below the threshold {tau_conf:.0%}")
    if dist > tau_dist:
        reasons.append(f"the traffic pattern is unlike anything in the training data (novelty {dist:.2f} > {tau_dist:.2f})")
    return bool(reasons), "; ".join(reasons) or None
