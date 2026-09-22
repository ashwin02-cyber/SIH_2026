"""
train_open_set.py
-----------------
Fits and honestly evaluates calibration + open-set rejection (open_set.py) on features_windowed.csv.

    python train_open_set.py

Outputs: models/open_set.pkl (temperature, thresholds, novelty reference), open_set_metrics.json

Evaluation (all on configurations unseen during training: StratifiedGroupKFold by VPN config)
  * CALIBRATION: NLL, Brier score and expected calibration error of out-of-fold predictions, before vs after
    temperature scaling (window and capture level).
  * OPEN-SET: for each of the 5 traffic classes in turn, the model is trained WITHOUT that class and then shown
    captures of it. Thresholds come from the known classes only (95% of known captures accepted). We report how
    many unknown captures are rejected, for the confidence signal, the novelty signal and both together, plus
    threshold-free AUROC, and compare with the old rule (uncalibrated confidence < 60%).
"""

import json
import os
import sys
import warnings

import joblib
import numpy as np
import pandas as pd
from sklearn.metrics import roc_auc_score
from sklearn.model_selection import StratifiedGroupKFold
from sklearn.preprocessing import LabelEncoder

warnings.filterwarnings("ignore")
HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import open_set as osr  # noqa: E402
from train_model import make_model  # noqa: E402
from traffic_features import FEATURE_COLS  # noqa: E402

SEED, N_SPLITS = 42, 6
OLD_RULE_CONF = 0.6


def fit_rf(train):
    return make_model("random_forest").fit(train[FEATURE_COLS], train["y"])


def capture_agg(df, proba, dist):
    """Per capture: mean probability vector and median window novelty."""
    d = pd.DataFrame(proba)
    d["file"], d["y"], d["dist"] = df["filename"].to_numpy(), df["y"].to_numpy(), dist
    g = d.groupby("file")
    mean = g[list(range(proba.shape[1]))].mean()
    return mean.to_numpy(), g["y"].first().loc[mean.index].to_numpy(), g["dist"].median().loc[mean.index].to_numpy(), list(mean.index)


def oof(df, classes_train, n_classes):
    """Out-of-fold raw probabilities (columns = all n_classes) and novelty distances for every window.
    Only classes in classes_train are used for training (open-set experiments drop one)."""
    proba = np.zeros((len(df), n_classes))
    dist = np.zeros(len(df))
    fold = np.zeros(len(df), dtype=int)
    cv = StratifiedGroupKFold(N_SPLITS, shuffle=True, random_state=SEED)
    for k, (tr, te) in enumerate(cv.split(df[FEATURE_COLS], df["y"], df["combo"])):
        train = df.iloc[tr]
        train = train[train["y"].isin(classes_train)]
        m = fit_rf(train)
        proba[np.ix_(te, m.classes_)] = m.predict_proba(df.iloc[te][FEATURE_COLS])
        dist[te] = osr.Novelty(train, FEATURE_COLS).distance(df.iloc[te][FEATURE_COLS])
        fold[te] = k
    return proba, dist, fold


def main():
    df = pd.read_csv(os.path.join(HERE, "features_windowed.csv"))
    le = LabelEncoder()
    df["y"] = le.fit_transform(df["label"])
    classes = list(le.classes_)
    n = len(classes)
    y = df["y"].to_numpy()

    # ------------------------------------------------------------------ calibration on all 5 classes
    proba, dist, _ = oof(df, list(range(n)), n)
    T_fit = osr.fit_temperature(proba, y)
    T = max(1.0, T_fit)      # POLICY: calibration may soften confidences, never sharpen them (see caveats)
    cal = osr.temperature_scale(proba, T)
    cm_raw, cy, cd, _ = capture_agg(df, proba, dist)
    cm_cal, _, _, _ = capture_agg(df, cal, dist)
    calibration = {
        "temperature": T, "temperature_fitted": T_fit,
        "temperature_note": "the unconstrained fit runs to the lower bound of the search range because the model is almost always right on "
                            "unseen configurations; sharpening confidences from 180 lab captures would be over-confident, so T is floored at 1.0",
        "window_level": {k: {"before": fn(proba, y), "after": fn(cal, y)} for k, fn in
                         (("nll", osr.nll), ("brier", osr.brier), ("ece", osr.ece))},
        "capture_level": {k: {"before": fn(cm_raw, cy), "after": fn(cm_cal, cy)} for k, fn in
                          (("nll", osr.nll), ("brier", osr.brier), ("ece", osr.ece))},
        "mean_confidence_window": {"before": float(proba.max(axis=1).mean()), "after": float(cal.max(axis=1).mean())},
        "accuracy_window": float((cal.argmax(axis=1) == y).mean()),
        "argmax_unchanged_by_calibration": bool((cal.argmax(axis=1) == proba.argmax(axis=1)).all()),
    }
    thr = osr.choose_thresholds(cm_cal.max(axis=1), cd)
    known_accept = float(np.mean((cm_cal.max(axis=1) >= thr["tau_conf"]) & (cd <= thr["tau_dist"])))
    print(f"T = {T:.3f}; thresholds {thr}; known captures accepted (in-sample of thresholds) {known_accept:.1%}")
    print("ECE window before/after:", round(calibration["window_level"]["ece"]["before"], 4), round(calibration["window_level"]["ece"]["after"], 4))

    # ------------------------------------------------------------------ open-set: hold one class out entirely
    loco = {}
    for held, cls in enumerate(classes):
        known_cls = [c for c in range(n) if c != held]
        p, d, _ = oof(df, known_cls, n)
        km = (y != held)
        T_c = max(1.0, osr.fit_temperature(p[km][:, known_cls], np.searchsorted(known_cls, y[km])))
        pc = p.copy()
        pc[:, known_cls] = osr.temperature_scale(p[:, known_cls], T_c)
        cm_c, cy_c, cd_c, _ = capture_agg(df, pc, d)
        cm_r, _, _, _ = capture_agg(df, p, d)
        conf, conf_raw = cm_c.max(axis=1), cm_r.max(axis=1)
        known, unk = cy_c != held, cy_c == held
        t = osr.choose_thresholds(conf[known], cd_c[known])
        rej_conf, rej_dist = conf < t["tau_conf"], cd_c > t["tau_dist"]
        rej = rej_conf | rej_dist
        loco[cls] = {
            "unknown_captures": int(unk.sum()), "known_captures": int(known.sum()), "temperature": T_c,
            "tau_conf": t["tau_conf"], "tau_dist": t["tau_dist"],
            "known_accepted": float((~rej[known]).mean()),
            "unknown_rejected_combined": float(rej[unk].mean()),
            "unknown_rejected_confidence_only": float(rej_conf[unk].mean()),
            "unknown_rejected_novelty_only": float(rej_dist[unk].mean()),
            "old_rule_unknown_flagged": float((conf_raw[unk] < OLD_RULE_CONF).mean()),
            "old_rule_known_flagged": float((conf_raw[known] < OLD_RULE_CONF).mean()),
            "auroc_confidence": float(roc_auc_score(unk, -conf)), "auroc_novelty": float(roc_auc_score(unk, cd_c)),
            "known_accuracy_when_accepted": float((cm_c.argmax(axis=1)[known & ~rej] == cy_c[known & ~rej]).mean()),
        }
        r = loco[cls]
        print(f"hold out {cls:16s} unknown rejected {r['unknown_rejected_combined']:.0%} (conf {r['unknown_rejected_confidence_only']:.0%}, "
              f"novelty {r['unknown_rejected_novelty_only']:.0%}) | known accepted {r['known_accepted']:.0%} | AUROC conf {r['auroc_confidence']:.2f} novelty {r['auroc_novelty']:.2f} | old rule {r['old_rule_unknown_flagged']:.0%}")
    mean_rej = float(np.mean([v["unknown_rejected_combined"] for v in loco.values()]))
    print(f"mean unknown rejection across held-out classes: {mean_rej:.0%}")

    # ------------------------------------------------------------------ the shipped artefact (all five classes)
    novelty = osr.Novelty(df, FEATURE_COLS)
    joblib.dump({"temperature": T, "tau_conf": thr["tau_conf"], "tau_dist": thr["tau_dist"], "novelty": novelty.to_dict(),
                 "classes": classes}, os.path.join(HERE, "models", "open_set.pkl"))

    metrics = {
        "what": "calibrated confidence and open-set rejection for the traffic classifier",
        "method": "temperature scaling on out-of-fold probabilities; rejection = low calibrated confidence OR high novelty (5-NN distance), "
                  "thresholds from known classes only (target 95% of known captures accepted)",
        "calibration": calibration, "thresholds": thr, "known_accepted_in_sample": known_accept,
        "leave_one_class_out": loco, "mean_unknown_rejection": mean_rej,
        "mean_known_accepted": float(np.mean([v["known_accepted"] for v in loco.values()])),
        "caveats": [
            "Five scripted traffic classes from one lab; 'unknown' here means a scripted class the model never saw, not arbitrary real traffic.",
            "Thresholds for the shipped model come from the same out-of-fold captures they are evaluated on, so known-capture acceptance (~95%) holds by construction; "
            "the held-out-class rejection numbers are the honest ones (the held-out class never influences its thresholds).",
            "Calibration was measured on clean, unseen-configuration captures only; under degraded captures (see ACCURACY_REPORT.md: 200 ms jitter, 10-packet captures) accuracy is lower, so confidence there is an upper bound.",
            "The two signals overlap: novelty distance catches patterns unlike the training windows, confidence catches ambiguity between known classes.",
        ],
    }
    with open(os.path.join(HERE, "open_set_metrics.json"), "w", encoding="utf-8") as f:
        json.dump(metrics, f, indent=2)


if __name__ == "__main__":
    main()
