"""
evaluate_defences.py
--------------------
Population-level result of the what-if defence simulation (defence_sim.py) on the 180 lab captures.

    python evaluate_defences.py [--pcap-dir DIR] [--cache FILE]     -> defence_metrics.json

For every defence and every VPN configuration held out by StratifiedGroupKFold (unseen in training):
  NON-ADAPTIVE attacker : classifier trained on CLEAN traffic of the other configs, shown DEFENDED traffic.
  ADAPTIVE attacker     : classifier retrained on DEFENDED traffic of the other configs (knows the defence).
Both are scored per capture (windows' probabilities averaged). The cost of each defence is reported next to
the accuracy: a defence that costs 500% bandwidth is not a free win.

THIS IS A SIMULATION at the feature level (see defence_sim.py), not a measurement on a real gateway.
"""

import argparse
import glob
import json
import os
import pickle
import sys
import warnings
import zlib
from collections import defaultdict

import numpy as np
import pandas as pd
from sklearn.model_selection import StratifiedGroupKFold
from sklearn.preprocessing import LabelEncoder

warnings.filterwarnings("ignore")
HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import defence_sim as ds  # noqa: E402
import traffic_features as tf  # noqa: E402
from batch_extract import find_pcap_dir  # noqa: E402
from train_model import make_model  # noqa: E402

SEED, N_SPLITS = 42, 6
FEATURES = list(tf.FEATURE_COLS)


def load_packets(pcap_dir, files, cache):
    if cache and os.path.exists(cache):
        return pickle.load(open(cache, "rb"))
    out = {}
    for i, f in enumerate(files, 1):
        pk, _, _ = tf.read_packets(os.path.join(pcap_dir, f))
        out[f] = {"packets": pk}
        if i % 30 == 0:
            print(f"read {i}/{len(files)} pcaps", flush=True)
    if cache:
        pickle.dump(out, open(cache, "wb"))
    return out


def windows_frame(files, packets_by_file, meta, defence=None):
    """Feature rows for the given captures, optionally after a defence; also collects the cost per capture."""
    rows, costs = [], []
    for f in files:
        pk = packets_by_file[f]["packets"]
        oh = None
        if defence:
            pk, oh = ds.apply(defence, pk, seed=zlib.crc32(f.encode()) % 10_000)
            costs.append(oh)
        wins, _, _ = tf.windows_from_packets(pk)
        for w in wins:
            rows.append({"file": f, "y": meta[f]["y"], **{k: w[k] for k in FEATURES}})
    return pd.DataFrame(rows), costs


def capture_acc(df, proba):
    d = pd.DataFrame(proba)
    d["file"], d["y"] = df["file"].to_numpy(), df["y"].to_numpy()
    g = d.groupby("file")
    mean = g[list(range(proba.shape[1]))].mean()
    y = g["y"].first().loc[mean.index].to_numpy()
    return float((mean.to_numpy().argmax(axis=1) == y).mean()), len(y)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--pcap-dir")
    ap.add_argument("--cache")
    args = ap.parse_args()

    clean = pd.read_csv(os.path.join(HERE, "features_windowed.csv"))
    le = LabelEncoder()
    clean["y"] = le.fit_transform(clean["label"])
    clean = clean.rename(columns={"filename": "file"})
    files = sorted(clean["file"].unique())
    meta = {f: {"y": int(clean.loc[clean["file"] == f, "y"].iloc[0]), "combo": clean.loc[clean["file"] == f, "combo"].iloc[0]} for f in files}
    packets = load_packets(find_pcap_dir(args.pcap_dir), files, args.cache)
    n_classes = len(le.classes_)

    cv = StratifiedGroupKFold(N_SPLITS, shuffle=True, random_state=SEED)
    folds = []
    for tr, te in cv.split(clean[FEATURES], clean["y"], clean["combo"]):
        folds.append((sorted(clean.iloc[tr]["file"].unique()), sorted(clean.iloc[te]["file"].unique())))
    fold_models = [make_model("random_forest").fit(clean[clean["file"].isin(tr)][FEATURES], clean[clean["file"].isin(tr)]["y"]) for tr, _ in folds]

    def score(defence):
        na_p, na_df, ad_p, ad_df, costs, win_ok, win_n = [], [], [], [], [], 0, 0
        for k, (tr, te) in enumerate(folds):
            te_df, c = windows_frame(te, packets, meta, defence)
            costs += c
            if te_df.empty:
                continue
            p = np.zeros((len(te_df), n_classes))
            p[:, fold_models[k].classes_] = fold_models[k].predict_proba(te_df[FEATURES])
            na_p.append(p); na_df.append(te_df)
            if defence:
                tr_df, _ = windows_frame(tr, packets, meta, defence)
                m = make_model("random_forest").fit(tr_df[FEATURES], tr_df["y"])
                q = np.zeros((len(te_df), n_classes)); q[:, m.classes_] = m.predict_proba(te_df[FEATURES])
                ad_p.append(q); ad_df.append(te_df)
        NP, ND = np.vstack(na_p), pd.concat(na_df, ignore_index=True)
        out = {"non_adaptive_capture_accuracy": capture_acc(ND, NP)[0], "non_adaptive_window_accuracy": float((NP.argmax(axis=1) == ND["y"].to_numpy()).mean()),
               "captures_classified": capture_acc(ND, NP)[1], "windows": int(len(ND))}
        if defence:
            AP, AD = np.vstack(ad_p), pd.concat(ad_df, ignore_index=True)
            out["adaptive_capture_accuracy"] = capture_acc(AD, AP)[0]
            out["adaptive_window_accuracy"] = float((AP.argmax(axis=1) == AD["y"].to_numpy()).mean())
            out["cost"] = {"bandwidth_overhead_pct_mean": round(float(np.mean([c["bandwidth_overhead_pct"] for c in costs])), 1),
                           "bandwidth_overhead_pct_median": round(float(np.median([c["bandwidth_overhead_pct"] for c in costs])), 1),
                           "mean_added_delay_ms": round(float(np.mean([c["mean_added_delay_ms"] for c in costs])), 1)}
        return out

    results = {"none": score(None)}
    print("no defence: capture accuracy", round(results["none"]["non_adaptive_capture_accuracy"], 3), flush=True)
    for name, d in ds.DEFENCES.items():
        results[name] = {"label": d["label"], "description": d["description"], **score(name)}
        r = results[name]
        print(f"{name:12s} non-adaptive {r['non_adaptive_capture_accuracy']:.1%} | adaptive {r['adaptive_capture_accuracy']:.1%} | "
              f"bandwidth +{r['cost']['bandwidth_overhead_pct_median']}% (median) | delay {r['cost']['mean_added_delay_ms']} ms", flush=True)

    metrics = {
        "what": "SIMULATED traffic-analysis defences at the feature level (not a measurement on a real gateway)",
        "attackers": {"non_adaptive": "classifier trained on clean traffic of other configs, shown defended traffic of unseen configs",
                      "adaptive": "classifier retrained on defended traffic of other configs (knows the defence), tested on unseen configs"},
        "chance_level_capture_accuracy": 1 / n_classes,
        "captures": len(files), "configs": len(set(m["combo"] for m in meta.values())),
        "baseline": results["none"], "defences": {k: v for k, v in results.items() if k != "none"},
        "caveats": [
            "Feature-level simulation on scripted lab traffic: real padding/dummy-traffic implementations differ in detail.",
            "The adaptive attacker uses the same 12 window features; a stronger attacker (sequence models, longer windows) may do better.",
            "Captures are short (file transfer, VoIP and video < 2 s), which limits how well dummy traffic and shaping can be judged.",
            "Costs are per capture and depend on how busy the capture is: padding a ping stream costs a lot, padding a bulk transfer almost nothing.",
        ],
    }
    with open(os.path.join(HERE, "defence_metrics.json"), "w", encoding="utf-8") as f:
        json.dump(metrics, f, indent=2)


if __name__ == "__main__":
    main()
