"""
train_model.py
--------------
Trains and honestly evaluates the traffic classifier on features_windowed.csv
(produced by batch_extract.py).

Evaluation protocol
    * StratifiedGroupKFold, grouped by VPN CONFIG (36 groups: cipher x DH x
      mode x pfs). Every window of a config is in the same fold, so the model
      is always tested on VPN configurations it has never seen in training.
      (A random row split, as used before, lets near-identical windows of the
      same capture land in both train and test and inflates accuracy.)
    * Window-level metrics AND capture-level metrics (windows of one capture
      are combined by averaging their class probabilities).
    * Sanity checks: majority-class baseline, a label-shuffled run (should be
      near chance), and an ablation that removes the rate features.

Outputs
    models/traffic_classifier.pkl, models/label_encoder.pkl
    metrics.json, confusion_matrix.png, feature_importance.csv

Usage:  python train_model.py [--csv features_windowed.csv]
"""

import argparse
import json
import os
import platform
import sys
import warnings
from datetime import datetime, timezone

import joblib
import matplotlib
import numpy as np
import pandas as pd
import seaborn as sns
import sklearn
import xgboost as xgb
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import (accuracy_score, balanced_accuracy_score, classification_report,
                             confusion_matrix, f1_score)
from sklearn.model_selection import StratifiedGroupKFold
from sklearn.preprocessing import LabelEncoder
from sklearn.utils.class_weight import compute_sample_weight

matplotlib.use("Agg")
import matplotlib.pyplot as plt  # noqa: E402

warnings.filterwarnings("ignore")
HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
from traffic_features import FEATURE_COLS, MIN_PACKETS_PER_WINDOW, WINDOW_SEC  # noqa: E402

SEED = 42
N_SPLITS = 6
RATE_FEATURES = ["pkts_per_sec", "bytes_per_sec"]


def make_model(kind):
    if kind == "random_forest":
        return RandomForestClassifier(n_estimators=300, class_weight="balanced_subsample",
                                      random_state=SEED, n_jobs=-1)
    return xgb.XGBClassifier(n_estimators=200, max_depth=4, learning_rate=0.1, subsample=0.9,
                             random_state=SEED, eval_metric="mlogloss", verbosity=0, n_jobs=4)


def fit(model, X, y):
    if isinstance(model, xgb.XGBClassifier):
        model.fit(X, y, sample_weight=compute_sample_weight("balanced", y))
    else:
        model.fit(X, y)
    return model


def cross_validate(kind, X, y, groups, files, n_classes):
    """Grouped out-of-fold predictions. Returns (proba[n_rows, n_classes], fold_scores)."""
    proba = np.zeros((len(y), n_classes))
    fold_scores = []
    cv = StratifiedGroupKFold(n_splits=N_SPLITS, shuffle=True, random_state=SEED)
    for k, (tr, te) in enumerate(cv.split(X, y, groups)):
        assert not set(groups[tr]) & set(groups[te]), "a VPN config leaked across train/test"
        m = fit(make_model(kind), X.iloc[tr], y[tr])
        p = m.predict_proba(X.iloc[te])
        proba[np.ix_(te, m.classes_)] = p
        pred = m.classes_[p.argmax(axis=1)]
        fold_scores.append({"fold": k + 1, "test_configs": int(len(set(groups[te]))),
                            "test_windows": int(len(te)),
                            "accuracy": round(float(accuracy_score(y[te], pred)), 4),
                            "macro_f1": round(float(f1_score(y[te], pred, average="macro")), 4)})
    return proba, fold_scores


def capture_level(proba, y, files):
    """Combine windows of the same capture: mean probability -> argmax."""
    df = pd.DataFrame(proba)
    df["file"], df["y"] = files, y
    agg = df.groupby("file").agg({**{c: "mean" for c in range(proba.shape[1])}, "y": "first"})
    return agg["y"].to_numpy(), agg[list(range(proba.shape[1]))].to_numpy().argmax(axis=1)


def summarize(y, pred, classes):
    return {
        "accuracy": round(float(accuracy_score(y, pred)), 4),
        "balanced_accuracy": round(float(balanced_accuracy_score(y, pred)), 4),
        "macro_f1": round(float(f1_score(y, pred, average="macro")), 4),
        "per_class": classification_report(y, pred, target_names=classes, output_dict=True, zero_division=0),
        "confusion_matrix": confusion_matrix(y, pred, labels=range(len(classes))).tolist(),
    }


def evaluate(kind, df, cols, y, groups, classes, label=""):
    proba, folds = cross_validate(kind, df[cols], y, groups, df["filename"].to_numpy(), len(classes))
    win_pred = proba.argmax(axis=1)
    cap_y, cap_pred = capture_level(proba, y, df["filename"].to_numpy())
    res = {"window_level": summarize(y, win_pred, classes),
           "capture_level": summarize(cap_y, cap_pred, classes),
           "folds": folds, "n_windows": int(len(y)), "n_captures": int(len(cap_y)),
           "_oof_window_pred": win_pred}
    print(f"{label or kind:28s} window acc {res['window_level']['accuracy']:.3f} "
          f"(bal {res['window_level']['balanced_accuracy']:.3f}, F1 {res['window_level']['macro_f1']:.3f}) | "
          f"capture acc {res['capture_level']['accuracy']:.3f}")
    return res


def plot_confusion(res, classes, path, title):
    fig, axes = plt.subplots(1, 2, figsize=(16, 6.2))
    for ax, level, name in ((axes[0], "window_level", "Per 1-second window"),
                            (axes[1], "capture_level", "Per capture (windows combined)")):
        cm = np.array(res[level]["confusion_matrix"])
        sns.heatmap(cm, annot=True, fmt="d", cmap="Blues", xticklabels=classes, yticklabels=classes,
                    ax=ax, cbar=False)
        ax.set_title(f"{name}\naccuracy {res[level]['accuracy']:.1%}, macro-F1 {res[level]['macro_f1']:.2f}")
        ax.set_xlabel("Predicted")
        ax.set_ylabel("Actual")
        ax.tick_params(axis="x", rotation=30)
        ax.tick_params(axis="y", rotation=0)
    fig.suptitle(title, fontsize=11)
    fig.tight_layout()
    fig.savefig(path, dpi=130)
    plt.close(fig)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--csv", default=os.path.join(HERE, "features_windowed.csv"))
    ap.add_argument("--plot-only", action="store_true",
                    help="redraw confusion_matrix.png from metrics.json without retraining")
    args = ap.parse_args()

    if args.plot_only:
        with open(os.path.join(HERE, "metrics.json"), encoding="utf-8") as f:
            saved = json.load(f)
        sel = saved["evaluation"]["selected"]
        plot_confusion(sel, saved["classes"], os.path.join(HERE, "confusion_matrix.png"),
                       f"{saved['selected_model']} - grouped {N_SPLITS}-fold CV by VPN config (out-of-fold predictions; "
                       f"{sel['n_windows']} windows / {sel['n_captures']} captures)")
        print("Redrew confusion_matrix.png from metrics.json")
        return

    df = pd.read_csv(args.csv)
    print(f"Loaded {len(df)} windows from {df['filename'].nunique()} captures, "
          f"{df['combo'].nunique()} VPN configs")
    print(df.groupby("label").size().to_string(), "\n")

    le = LabelEncoder()
    y = le.fit_transform(df["label"])
    classes = list(le.classes_)
    groups = df["combo"].to_numpy()
    cols = list(FEATURE_COLS)
    forbidden = {"packet_count", "total_bytes", "duration_sec"}
    assert not forbidden & set(cols), "capture-length features must not be used"

    results = {k: evaluate(k, df, cols, y, groups, classes) for k in ("random_forest", "xgboost")}
    best_kind = max(results, key=lambda k: results[k]["window_level"]["macro_f1"])
    print(f"\nBest by window-level macro-F1: {best_kind}\n")

    # ---- sanity checks -------------------------------------------------
    majority = float(pd.Series(y).value_counts(normalize=True).max())
    rng = np.random.RandomState(SEED)
    shuffled = evaluate(best_kind, df, cols, rng.permutation(y), groups, classes, "label-shuffled (chance)")
    no_rate = evaluate(best_kind, df, [c for c in cols if c not in RATE_FEATURES], y, groups, classes,
                       "ablation: no rate features")
    checks = {
        "majority_class_window_accuracy": round(majority, 4),
        "label_shuffled_window_accuracy": shuffled["window_level"]["accuracy"],
        "label_shuffled_capture_accuracy": shuffled["capture_level"]["accuracy"],
        "without_rate_features": {"window_accuracy": no_rate["window_level"]["accuracy"],
                                  "window_macro_f1": no_rate["window_level"]["macro_f1"],
                                  "capture_accuracy": no_rate["capture_level"]["accuracy"]},
    }

    oof = results[best_kind]["_oof_window_pred"]
    n_pk = df["n_packets"].to_numpy()
    buckets = {"2-3 packets": (n_pk >= 2) & (n_pk <= 3), "4-10 packets": (n_pk >= 4) & (n_pk <= 10),
               "11-50 packets": (n_pk >= 11) & (n_pk <= 50), ">50 packets": n_pk > 50}
    checks["window_accuracy_by_packets_in_window"] = {
        name: {"windows": int(mask.sum()),
               "accuracy": round(float(accuracy_score(y[mask], oof[mask])), 4) if mask.any() else None}
        for name, mask in buckets.items()}
    for r in results.values():
        r.pop("_oof_window_pred", None)

    # ---- final model on all data ---------------------------------------
    final = fit(make_model(best_kind), df[cols], y)
    os.makedirs(os.path.join(HERE, "models"), exist_ok=True)
    joblib.dump(final, os.path.join(HERE, "models", "traffic_classifier.pkl"))
    joblib.dump(le, os.path.join(HERE, "models", "label_encoder.pkl"))

    imp = pd.DataFrame({"feature": cols, "importance": final.feature_importances_}) \
        .sort_values("importance", ascending=False)
    imp.to_csv(os.path.join(HERE, "feature_importance.csv"), index=False)

    best = results[best_kind]
    plot_confusion(best, classes, os.path.join(HERE, "confusion_matrix.png"),
                   f"{best_kind} - grouped {N_SPLITS}-fold CV by VPN config (out-of-fold predictions; "
                   f"{best['n_windows']} windows / {best['n_captures']} captures)")

    metrics = {
        "generated_utc": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "selected_model": best_kind,
        "classes": classes,
        "features": cols,
        "window_sec": WINDOW_SEC,
        "min_packets_per_window": MIN_PACKETS_PER_WINDOW,
        "dropped_features": sorted(forbidden),
        "data": {"windows": int(len(df)), "captures": int(df["filename"].nunique()),
                 "vpn_configs": int(df["combo"].nunique()),
                 "windows_per_class": df.groupby("label").size().to_dict(),
                 "esp_only": bool(df["esp_only"].all())},
        "evaluation": {
            "method": f"StratifiedGroupKFold(n_splits={N_SPLITS}), grouped by VPN config, seed {SEED}; "
                      "out-of-fold predictions",
            "candidates": {k: {"window_level": {m: v["window_level"][m] for m in ("accuracy", "balanced_accuracy", "macro_f1")},
                               "capture_level": {m: v["capture_level"][m] for m in
                                                 ("accuracy", "balanced_accuracy", "macro_f1")}}
                           for k, v in results.items()},
            "selected": best,
            "sanity_checks": checks,
        },
        "top_features": imp.head(6).round(4).to_dict(orient="records"),
        "caveats": [
            "One capture per (config, class): 36 configs x 5 classes, generated by scripted tools in a Docker testbed.",
            "Generators are synthetic (ping, scp, curl loops, ffmpeg range requests, SIPp signalling only, no RTP).",
            "Captures were stopped by packet count, so file_transfer/voip/video are <2 s long: they yield 1-2 windows each.",
            "Results say how well the model separates THESE five scripted traffic types on unseen VPN configs, "
            "not how it would do on real user traffic.",
        ],
        "environment": {"python": platform.python_version(), "scikit_learn": sklearn.__version__,
                        "xgboost": xgb.__version__, "numpy": np.__version__, "pandas": pd.__version__},
    }
    with open(os.path.join(HERE, "metrics.json"), "w", encoding="utf-8") as f:
        json.dump(metrics, f, indent=2)

    print("\nPer-class (window level, out-of-fold):")
    for name in classes:
        r = best["window_level"]["per_class"][name]
        print(f"  {name:16s} precision {r['precision']:.2f} recall {r['recall']:.2f} "
              f"f1 {r['f1-score']:.2f} (n={int(r['support'])})")
    print("Saved models/, metrics.json, confusion_matrix.png, feature_importance.csv")
    print(f"REAL ACCURACY (unseen VPN configs): window {best['window_level']['accuracy']:.1%}, "
          f"capture {best['capture_level']['accuracy']:.1%}")


if __name__ == "__main__":
    main()
