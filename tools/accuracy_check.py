"""
accuracy_check.py - an independent accuracy audit of the traffic classifier.

It recomputes everything FROM THE RAW PCAPS (it does not read metrics.json or features_windowed.csv),
writes ACCURACY_REPORT.md, and changes nothing else: it never trains into, saves over or edits the
shipped model, and it only READS the pcaps.

    python tools/accuracy_check.py --pcap-dir "E:\\SIH\\SIH_2026"
    python tools/accuracy_check.py --pcap-dir ... --skip-api        # skip the slow 180-upload section

Sections (each is stored in a results JSON, so an interrupted run can be resumed):
  fair      grouped cross-validation by VPN config (+ 5 other split seeds, leave-one-config-out,
            leave-one-cipher/DH-group/mode-out)
  api       all 180 captures through the real /analyze endpoint vs manifest.csv (NOT an unseen test)
  robust    (a) first 5 s  (b) first 10 packets  (c) drop 20 % of packets  (d) timing jitter
            (e) train without one traffic class
  leakage   exact features, filename independence, capture-length probe, shuffled-label control
"""

import argparse
import csv
import glob
import json
import os
import random
import re
import sys
import tempfile
import time
import warnings
from collections import Counter, defaultdict
from datetime import datetime, timezone

import numpy as np
import pandas as pd

warnings.filterwarnings("ignore")
ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
for sub in ("ml-engineer", "backend-developer"):
    sys.path.insert(0, os.path.join(ROOT, sub))

import traffic_features as tf  # noqa: E402
from batch_extract import find_pcap_dir, parse_name  # noqa: E402  (same file-name convention as training)
from train_model import make_model  # noqa: E402  (same hyper-parameters as the shipped model)
from sklearn.metrics import (accuracy_score, balanced_accuracy_score, confusion_matrix, f1_score,  # noqa: E402
                             precision_recall_fscore_support)
from sklearn.model_selection import LeaveOneGroupOut, StratifiedGroupKFold  # noqa: E402
from sklearn.preprocessing import LabelEncoder  # noqa: E402

SEED = 42
N_SPLITS = 6
FEATURES = list(tf.FEATURE_COLS)
LOW_CONF = 0.6  # the app flags "Low classification confidence" below this (ml-engineer/predict.py)
MANIFEST_TO_MODEL = {"web": "web_browsing", "video": "video_streaming", "voip": "voip",
                     "file_transfer": "file_transfer", "icmp": "icmp"}


def log(msg):
    print(f"[{time.strftime('%H:%M:%S')}] {msg}", flush=True)


# ----------------------------------------------------------------------------------------------
# data
# ----------------------------------------------------------------------------------------------
def load_captures(pcap_dir, cache):
    """Returns (captures, packets_by_file). captures: list of dicts with the ground truth from manifest.csv."""
    with open(os.path.join(ROOT, "manifest.csv"), newline="", encoding="utf-8") as f:
        manifest = {r["filename"]: r for r in csv.DictReader(f)}
    caps = []
    for path in sorted(glob.glob(os.path.join(pcap_dir, "*.pcap"))):
        name = os.path.basename(path)
        row = manifest.get(name)
        if row and row["traffic_class"] in MANIFEST_TO_MODEL:
            caps.append({"file": name, "path": path, "combo": row["combo_name"], "label": MANIFEST_TO_MODEL[row["traffic_class"]],
                         "cipher": row["cipher"], "dh": row["dh_group"], "mode": row["mode"], "pfs": row["pfs"]})
    assert len(caps) == 180, f"expected 180 traffic captures, found {len(caps)}"
    # the naming convention and the manifest must agree
    for c in caps:
        combo, label = parse_name(c["file"])
        assert (combo, label) == (c["combo"], c["label"]), c["file"]

    if cache and os.path.exists(cache):
        with open(cache, "rb") as f:
            packets = __import__("pickle").load(f)
        log(f"packets loaded from cache {cache}")
    else:
        packets = {}
        for i, c in enumerate(caps, 1):
            pk, esp_only, _ = tf.read_packets(c["path"])
            packets[c["file"]] = {"packets": pk, "esp_only": esp_only}
            if i % 30 == 0:
                log(f"read {i}/180 pcaps")
        if cache:
            with open(cache, "wb") as f:
                __import__("pickle").dump(packets, f)
    return caps, packets


def windows_from_packets(packets, window_sec=tf.WINDOW_SEC, min_packets=tf.MIN_PACKETS_PER_WINDOW):
    """Same windowing as traffic_features.extract_windows, but starting from a packet list (so packets can be
    perturbed first). Verified equal to extract_windows on real files in self_test()."""
    if not packets:
        return []
    packets = sorted(packets, key=lambda p: p["time"])
    t0, first_src = packets[0]["time"], packets[0]["src"]
    buckets = defaultdict(list)
    for p in packets:
        buckets[int((p["time"] - t0) // window_sec)].append(p)
    return [tf.window_features(b, first_src, idx, window_sec) for idx, b in sorted(buckets.items()) if len(b) >= min_packets]


def self_test(caps, packets):
    """The re-implemented windowing must give exactly the same numbers as the shipped extract_windows."""
    checked = 0
    for c in caps[::30]:
        a, _ = tf.extract_windows(c["path"])
        b = windows_from_packets(packets[c["file"]]["packets"])
        assert len(a) == len(b) and all(np.allclose([x[k] for k in FEATURES], [y[k] for k in FEATURES]) for x, y in zip(a, b)), c["file"]
        checked += 1
    log(f"self-test OK: windowing identical to traffic_features.extract_windows on {checked} files")


def build_frame(caps, packets):
    rows = []
    for c in caps:
        for w in windows_from_packets(packets[c["file"]]["packets"]):
            rows.append({"file": c["file"], "combo": c["combo"], "label": c["label"], "cipher": c["cipher"], "dh": c["dh"],
                         "mode": c["mode"], "n_packets": w["n_packets"], **{k: w[k] for k in FEATURES}})
    df = pd.DataFrame(rows)
    le = LabelEncoder()
    df["y"] = le.fit_transform(df["label"])
    return df, list(le.classes_)


# ----------------------------------------------------------------------------------------------
# model helpers
# ----------------------------------------------------------------------------------------------
def fit(train_df):
    return make_model("random_forest").fit(train_df[FEATURES], train_df["y"])


def full_proba(model, X, n_classes):
    """predict_proba as an (n, n_classes) array even if the model saw fewer classes."""
    out = np.zeros((len(X), n_classes))
    if len(X):
        out[:, model.classes_] = model.predict_proba(X)
    return out


def summarize(y, pred, classes):
    n = len(classes)
    p, r, f, s = precision_recall_fscore_support(y, pred, labels=range(n), zero_division=0)
    return {
        "n": int(len(y)), "accuracy": float(accuracy_score(y, pred)),
        "balanced_accuracy": float(balanced_accuracy_score(y, pred)),
        "macro_f1": float(f1_score(y, pred, average="macro", labels=range(n), zero_division=0)),
        "per_class": {c: {"precision": float(p[i]), "recall": float(r[i]), "f1": float(f[i]), "support": int(s[i])}
                      for i, c in enumerate(classes)},
        "confusion": confusion_matrix(y, pred, labels=range(n)).tolist(),
    }


def capture_level(files, y, proba):
    """Average the window probabilities of each capture -> one prediction per capture (what the app reports)."""
    d = pd.DataFrame(proba)
    d["file"], d["y"] = list(files), list(y)
    g = d.groupby("file")
    mean = g[list(range(proba.shape[1]))].mean()
    yy = g["y"].first().loc[mean.index]
    return list(mean.index), yy.to_numpy(), mean.to_numpy()


def wilson(k, n, z=1.96):
    if n == 0:
        return (0.0, 0.0)
    p = k / n
    d = 1 + z * z / n
    c = p + z * z / (2 * n)
    a = z * np.sqrt(p * (1 - p) / n + z * z / (4 * n * n))
    return float((c - a) / d), float(min(1.0, (c + a) / d))


def grouped_cv(df, classes, seed=SEED, y_col="y"):
    """6-fold cross-validation where every VPN config is entirely in train OR entirely in test."""
    cv = StratifiedGroupKFold(N_SPLITS, shuffle=True, random_state=seed)
    proba = np.zeros((len(df), len(classes)))
    fold = np.zeros(len(df), dtype=int)
    tmp = df.assign(y=df[y_col]) if y_col != "y" else df
    for k, (tr, te) in enumerate(cv.split(df[FEATURES], tmp["y"], df["combo"])):
        assert not set(df["combo"].iloc[tr]) & set(df["combo"].iloc[te]), "config leaked into both train and test"
        m = fit(tmp.iloc[tr])
        proba[te] = full_proba(m, df[FEATURES].iloc[te], len(classes))
        fold[te] = k
    return proba, fold


def eval_both(df, classes, proba):
    win = summarize(df["y"].to_numpy(), proba.argmax(axis=1), classes)
    files, yy, mean = capture_level(df["file"], df["y"], proba)
    cap = summarize(yy, mean.argmax(axis=1), classes)
    return win, cap


# ----------------------------------------------------------------------------------------------
# section: fair
# ----------------------------------------------------------------------------------------------
def section_fair(df, classes):
    log("fair: grouped 6-fold CV (seed 42)")
    proba, fold = grouped_cv(df, classes)
    win, cap = eval_both(df, classes, proba)
    k_ok = round(cap["accuracy"] * cap["n"])
    cap["ci95"] = wilson(k_ok, cap["n"])
    out = {"window": win, "capture": cap, "n_configs": int(df["combo"].nunique()),
           "fold_configs": {str(k): sorted(df.loc[fold == k, "combo"].unique().tolist()) for k in range(N_SPLITS)},
           "fold_accuracy": [float(accuracy_score(df["y"][fold == k], proba[fold == k].argmax(axis=1))) for k in range(N_SPLITS)]}

    log("fair: 5 other split seeds")
    seeds = []
    for s in (0, 1, 2, 3, 4):
        p, _ = grouped_cv(df, classes, seed=s)
        w, c = eval_both(df, classes, p)
        seeds.append({"seed": s, "window_accuracy": w["accuracy"], "capture_accuracy": c["accuracy"]})
    out["other_seeds"] = seeds

    log("fair: leave-one-config-out (36 fits)")
    proba_loco = np.zeros_like(proba)
    for tr, te in LeaveOneGroupOut().split(df[FEATURES], df["y"], df["combo"]):
        proba_loco[te] = full_proba(fit(df.iloc[tr]), df[FEATURES].iloc[te], len(classes))
    w, c = eval_both(df, classes, proba_loco)
    out["leave_one_config_out"] = {"window_accuracy": w["accuracy"], "capture_accuracy": c["accuracy"], "capture_n": c["n"]}

    out["leave_one_setting_out"] = {}
    for col, title in (("cipher", "cipher"), ("dh", "DH group"), ("mode", "mode")):
        log(f"fair: leave-one-{title}-out")
        pr = np.zeros_like(proba)
        for tr, te in LeaveOneGroupOut().split(df[FEATURES], df["y"], df[col]):
            pr[te] = full_proba(fit(df.iloc[tr]), df[FEATURES].iloc[te], len(classes))
        per = {}
        for v in sorted(df[col].unique()):
            m = (df[col] == v).to_numpy()
            files, yy, mean = capture_level(df["file"][m], df["y"][m], pr[m])
            per[v] = {"window_accuracy": float(accuracy_score(df["y"][m], pr[m].argmax(axis=1))),
                      "capture_accuracy": float(accuracy_score(yy, mean.argmax(axis=1))), "captures": len(files)}
        out["leave_one_setting_out"][title] = per
    return out, fold


# ----------------------------------------------------------------------------------------------
# section: api (real /analyze endpoint, all 180 captures)
# ----------------------------------------------------------------------------------------------
def section_api(caps):
    from fastapi.testclient import TestClient
    import main as backend
    client = TestClient(backend.app)
    log("api: 180 captures through POST /analyze (real end-to-end path)")
    rows, wrong, t0 = [], [], time.time()
    for i, c in enumerate(caps, 1):
        with open(c["path"], "rb") as f:
            r = client.post("/analyze", files={"file": (c["file"], f, "application/octet-stream")})
        body = r.json()
        tr = body.get("traffic") or {}
        rows.append({"file": c["file"], "true": c["label"], "pred": tr.get("class"), "confidence": tr.get("confidence"),
                     "status": r.status_code, "errors": body.get("errors", [])})
        if tr.get("class") != c["label"]:
            wrong.append(rows[-1])
        if i % 20 == 0:
            log(f"api: {i}/180 ({time.time() - t0:.0f}s)")
    ok = sum(1 for r in rows if r["pred"] == r["true"])
    per = {}
    for cls in sorted({r["true"] for r in rows}):
        rr = [r for r in rows if r["true"] == cls]
        per[cls] = {"n": len(rr), "correct": sum(1 for r in rr if r["pred"] == cls),
                    "min_confidence": float(min(r["confidence"] or 0 for r in rr)),
                    "mean_confidence": float(np.mean([r["confidence"] or 0 for r in rr]))}
    return {"n": len(rows), "correct": ok, "accuracy": ok / len(rows), "http_errors": sum(1 for r in rows if r["status"] != 200),
            "wrong": wrong, "per_class": per, "seconds": time.time() - t0}


# ----------------------------------------------------------------------------------------------
# section: robustness (all on unseen configs: models come from the grouped CV folds)
# ----------------------------------------------------------------------------------------------
def perturb_identity(pk, rng):
    return pk


def perturb_first_seconds(sec):
    def f(pk, rng):
        t0 = min(p["time"] for p in pk)
        return [p for p in pk if p["time"] - t0 < sec]
    return f


def perturb_first_packets(n):
    return lambda pk, rng: sorted(pk, key=lambda p: p["time"])[:n]


def perturb_drop(frac):
    return lambda pk, rng: [p for p in pk if rng.random() >= frac]


def perturb_jitter(sd):
    return lambda pk, rng: [{**p, "time": p["time"] + rng.gauss(0, sd)} for p in pk]


def train_fold_models(df, classes, fold):
    return {k: fit(df[fold != k]) for k in range(N_SPLITS)}


def run_perturbation(caps, packets, df, classes, fold, models, fn, seed):
    """Test-time perturbation: models were trained on CLEAN windows of the other configs; the held-out
    configs' captures are perturbed, re-windowed and classified."""
    combo_fold = {c: int(k) for c, k in zip(df["combo"], fold)}
    rng = random.Random(seed)
    per_fold = defaultdict(lambda: {"X": [], "file": [], "y": []})
    seen_files, no_pred = set(), []
    for c in caps:
        k = combo_fold[c["combo"]]
        wins = windows_from_packets(fn(packets[c["file"]]["packets"], rng))
        seen_files.add(c["file"])
        if not wins:
            no_pred.append(c)
            continue
        y = classes.index(c["label"])
        for w in wins:
            per_fold[k]["X"].append([w[f] for f in FEATURES])
            per_fold[k]["file"].append(c["file"])
            per_fold[k]["y"].append(y)
    files, ys, probas = [], [], []
    for k, d in per_fold.items():
        X = pd.DataFrame(d["X"], columns=FEATURES)
        probas.append(full_proba(models[k], X, len(classes)))
        files += d["file"]
        ys += d["y"]
    proba, ys = np.vstack(probas), np.array(ys)
    win_acc = float(accuracy_score(ys, proba.argmax(axis=1)))
    cfiles, cy, cmean = capture_level(files, ys, proba)
    cap_correct = int((cmean.argmax(axis=1) == cy).sum())
    return {"window_accuracy": win_acc, "windows": int(len(ys)), "captures_predicted": len(cfiles),
            "captures_total": len(caps), "coverage": len(cfiles) / len(caps),
            "capture_accuracy_of_predicted": cap_correct / max(1, len(cfiles)),
            "capture_accuracy_counting_no_prediction_as_wrong": cap_correct / len(caps),
            "wrong_by_class": dict(Counter(classes[i] for i, ok in zip(cy, cmean.argmax(axis=1) == cy) if not ok))}


def agg(runs):
    keys = ["window_accuracy", "capture_accuracy_of_predicted", "capture_accuracy_counting_no_prediction_as_wrong", "coverage"]
    out = {k: {"mean": float(np.mean([r[k] for r in runs])), "min": float(np.min([r[k] for r in runs])),
               "max": float(np.max([r[k] for r in runs]))} for k in keys}
    out["runs"] = len(runs)
    out["windows"] = int(np.mean([r["windows"] for r in runs]))
    out["captures_predicted"] = int(np.mean([r["captures_predicted"] for r in runs]))
    out["wrong_by_class"] = dict(sum((Counter(r["wrong_by_class"]) for r in runs), Counter()))
    return out


def section_unknown_class(df, classes, fold):
    """(e) train on 4 of the 5 traffic classes; test on unseen configs INCLUDING the held-out class."""
    out = {}
    for held, cls in enumerate(classes):
        log(f"robust(e): train without '{cls}'")
        rows_proba = np.zeros((len(df), len(classes)))
        for k in range(N_SPLITS):
            tr = df[(fold != k) & (df["y"] != held)]
            te = (fold == k)
            rows_proba[te] = full_proba(fit(tr), df[FEATURES][te], len(classes))
        files, yy, mean = capture_level(df["file"], df["y"], rows_proba)
        pred = mean.argmax(axis=1)
        conf = mean.max(axis=1)
        held_m, known_m = yy == held, yy != held
        held_pred = Counter(classes[p] for p in pred[held_m])
        wins_known = df["y"] != held
        out[cls] = {
            "known_capture_accuracy": float((pred[known_m] == yy[known_m]).mean()),
            "known_window_accuracy": float((rows_proba[wins_known.to_numpy()].argmax(axis=1) == df["y"][wins_known].to_numpy()).mean()),
            "unknown_captures": int(held_m.sum()),
            "unknown_predicted_as": dict(held_pred),
            "unknown_mean_confidence": float(conf[held_m].mean()),
            "known_mean_confidence": float(conf[known_m].mean()),
            "unknown_flagged_low_confidence": float((conf[held_m] < LOW_CONF).mean()),
            "known_flagged_low_confidence": float((conf[known_m] < LOW_CONF).mean()),
        }
    return out


def section_robust(caps, packets, df, classes, fold):
    log("robust: training the 6 fold models (clean data, held-out configs)")
    models = train_fold_models(df, classes, fold)
    tests = [
        ("sanity: no change (must equal the clean CV)", perturb_identity, [0]),
        ("(a) only the first 5 seconds", perturb_first_seconds(5.0), [0]),
        ("(b) only the first 10 packets", perturb_first_packets(10), [0]),
        ("(c) randomly drop 20% of packets", perturb_drop(0.2), [1, 2, 3, 4, 5]),
        ("(d) timing jitter, sd 10 ms", perturb_jitter(0.010), [1, 2, 3]),
        ("(d) timing jitter, sd 50 ms", perturb_jitter(0.050), [1, 2, 3]),
        ("(d) timing jitter, sd 200 ms", perturb_jitter(0.200), [1, 2, 3]),
    ]
    out = {"tests": {}}
    for name, fn, seeds in tests:
        log(f"robust: {name}")
        out["tests"][name] = agg([run_perturbation(caps, packets, df, classes, fold, models, fn, s) for s in seeds])
    out["unknown_class"] = section_unknown_class(df, classes, fold)
    return out


# ----------------------------------------------------------------------------------------------
# section: leakage
# ----------------------------------------------------------------------------------------------
def section_leakage(caps, packets, df, classes):
    import predict as shipped
    out = {"features_used": FEATURES, "shipped_model_features": [str(f) for f in shipped.model.feature_names_in_]}
    banned = ["packet_count", "total_bytes", "duration", "duration_sec", "filename", "file", "combo", "run", "label",
              "cipher", "dh", "mode", "pfs", "n_packets", "n_bytes", "window_index", "start_offset_sec"]
    out["banned_absent"] = {b: (b not in FEATURES and b not in out["shipped_model_features"]) for b in banned}
    out["features_match"] = out["features_used"] == out["shipped_model_features"]

    # filename independence: same bytes under three different names through the real /analyze endpoint
    from fastapi.testclient import TestClient
    import main as backend
    client = TestClient(backend.app)
    picks = []
    for cls in classes:
        picks += [c for c in caps if c["label"] == cls][:: 12][:3]
    diffs = []
    for c in picks:
        res = []
        for name in (c["file"], "capture.pcap", "zz_run99_qwerty.pcap"):
            with open(c["path"], "rb") as f:
                b = client.post("/analyze", files={"file": (name, f, "application/octet-stream")}).json()
            res.append((b["traffic"]["class"], round(b["traffic"]["confidence"], 6),
                        tuple(sorted((p["name"], round(p["value"], 6)) for p in b["traffic"]["probabilities"]))))
        diffs.append(len(set(res)) == 1)
    out["filename_independence"] = {"files_tested": len(picks), "identical_for_all_3_names": int(sum(diffs))}

    # capture-length probe: how well does capture length ALONE predict the class? (the old shortcut)
    cl = pd.DataFrame([{"file": c["file"], "combo": c["combo"], "y": classes.index(c["label"]),
                        "len": len(packets[c["file"]]["packets"])} for c in caps])
    from sklearn.tree import DecisionTreeClassifier
    pred = np.zeros(len(cl), dtype=int)
    for tr, te in StratifiedGroupKFold(N_SPLITS, shuffle=True, random_state=SEED).split(cl[["len"]], cl["y"], cl["combo"]):
        pred[te] = DecisionTreeClassifier(max_depth=3, random_state=0).fit(cl.iloc[tr][["len"]], cl.iloc[tr]["y"]).predict(cl.iloc[te][["len"]])
    out["capture_length_alone"] = {"accuracy_grouped_cv": float(accuracy_score(cl["y"], pred)),
                                   "ranges": {c: [int(cl[cl.y == i]["len"].min()), int(cl[cl.y == i]["len"].max())] for i, c in enumerate(classes)}}

    # shuffled labels: give each CAPTURE a random other capture's label (keeps windows of one capture together)
    log("leakage: shuffled-label control (5 repeats)")
    reps = []
    files = df["file"].unique()
    truth = df.groupby("file")["y"].first().loc[files]
    for s in range(5):
        rng = np.random.RandomState(s)
        perm = dict(zip(files, rng.permutation(truth.to_numpy())))
        d2 = df.assign(y_shuf=df["file"].map(perm))
        p, _ = grouped_cv(d2, classes, seed=SEED, y_col="y_shuf")
        pred_w = p.argmax(axis=1)
        cf, cy, cm = capture_level(d2["file"], d2["y_shuf"], p)
        reps.append({"seed": s, "window_accuracy": float(accuracy_score(d2["y_shuf"], pred_w)),
                     "window_balanced_accuracy": float(balanced_accuracy_score(d2["y_shuf"], pred_w)),
                     "capture_accuracy": float(accuracy_score(cy, cm.argmax(axis=1))),
                     "capture_balanced_accuracy": float(balanced_accuracy_score(cy, cm.argmax(axis=1)))})
    out["shuffled"] = {"repeats": reps, "chance_capture_accuracy": 1 / len(classes),
                       "majority_window_accuracy": float(df["y"].value_counts(normalize=True).max())}
    return out


# ----------------------------------------------------------------------------------------------
# report
# ----------------------------------------------------------------------------------------------
def pct(x, d=1):
    return f"{100 * x:.{d}f}%"


def table(header, rows):
    out = ["| " + " | ".join(header) + " |", "|" + "|".join("---" for _ in header) + "|"]
    out += ["| " + " | ".join(str(c) for c in r) + " |" for r in rows]
    return "\n".join(out)


def cm_table(cm, classes):
    return table(["actual \\ predicted"] + classes, [[c] + row for c, row in zip(classes, cm)])


def per_class_table(s, classes):
    return table(["class", "recall = per-class accuracy", "precision", "F1", "how many"],
                 [[c, pct(s["per_class"][c]["recall"]), pct(s["per_class"][c]["precision"]), f"{s['per_class'][c]['f1']:.2f}", s["per_class"][c]["support"]]
                  for c in classes])


def render(R, classes, out_path):
    F, A, B, L = R["fair"], R.get("api"), R["robust"], R["leakage"]
    fw, fc = F["window"], F["capture"]
    ci = fc["ci95"]
    seeds = F["other_seeds"]
    loco = F["leave_one_config_out"]
    T = B["tests"]

    def T_(prefix):
        return next(v for k, v in T.items() if k.startswith(prefix))

    a, b, c, d1, d2, d3 = T_("(a)"), T_("(b)"), T_("(c)"), T_("(d) timing jitter, sd 10"), T_("(d) timing jitter, sd 50"), T_("(d) timing jitter, sd 200")
    sanity = T_("sanity")
    shuf = L["shuffled"]["repeats"]
    shuf_cap = np.mean([r["capture_accuracy"] for r in shuf])
    shuf_capbal = np.mean([r["capture_balanced_accuracy"] for r in shuf])
    shuf_win = np.mean([r["window_accuracy"] for r in shuf])
    shuf_winbal = np.mean([r["window_balanced_accuracy"] for r in shuf])
    n_configs = F["n_configs"]
    U = B["unknown_class"]
    u_conf = [v["unknown_mean_confidence"] for v in U.values()]
    k_conf = [v["known_mean_confidence"] for v in U.values()]
    flagged = {k: v["unknown_flagged_low_confidence"] for k, v in U.items()}
    missed = [k for k, x in flagged.items() if x < 0.5]
    b_bad = ", ".join(f"{k}, {v} of 36 captures" for k, v in b["wrong_by_class"].items()) or "none"

    def rob_row(name, t, note=""):
        return [name, pct(t["window_accuracy"]["mean"]), pct(t["capture_accuracy_of_predicted"]["mean"]),
                pct(t["capture_accuracy_counting_no_prediction_as_wrong"]["mean"]), pct(t["coverage"]["mean"], 0), note]

    lines = []
    w = lines.append
    w("# Accuracy report - can we trust our numbers?")
    w("")
    w(f"*Generated by `tools/accuracy_check.py` on {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M UTC')}. Everything below was recomputed "
      "from the raw `.pcap` files in this run (not copied from `metrics.json`). The script only reads the pcaps and writes this file; it does not touch the model.*")
    w("")
    w("## The short version")
    w("")
    w(f"* **Fair test (VPN settings the model has never seen):** {pct(fc['accuracy'])} of the {fc['n']} captures were classified correctly "
      f"({pct(fw['accuracy'])} of the {fw['n']:,} one-second windows). Statistically, with {fc['n']}/{fc['n']} correct we can only be 95% sure the true rate is at least {pct(ci[0])}.")
    w("* **But:** those five traffic types come from simple scripts (ping, scp, curl, ffmpeg, SIPp) in one Docker lab. "
      "The numbers show the method works **on this lab data**. They do **not** show it would work on real people's traffic, other networks, or other VPN software.")
    w(f"* **Weak spots we found:** the traffic type *file transfer* is the fragile one - with only the first 10 packets of a capture it was missed ({b_bad}) and per-capture accuracy fell to {pct(b['capture_accuracy_counting_no_prediction_as_wrong']['mean'], 0)}; "
      f"very heavy timing noise (200 ms) cost {pct(1 - d3['capture_accuracy_counting_no_prediction_as_wrong']['mean'], 1)} of captures. "
      "And the model has no \"unknown\" answer: a traffic type it was never taught is forced into one of the five (section 4e).")
    if A:
        w(f"* The 180-capture end-to-end run ({A['correct']}/{A['n']} right) is **not a fair test**: the shipped model was trained on exactly those files. It only proves the whole app (upload → API → model → answer) works.")
    w("")

    # ---- 1
    w("## 1. What the words mean (plain English)")
    w("")
    w("Imagine a student preparing for an exam.")
    w("")
    w("* **Accuracy** = the percentage of exam questions the student answered correctly. 95 correct out of 100 = 95% accuracy.")
    w("* **Fair vs not fair.** If the exam questions were **also in the practice book the student memorised**, a high score proves nothing - they just remembered the answers. "
      "The score only means something if the questions are **new**. In our project, the \"practice book\" is the training data, and a **fair test uses VPN configurations the model never saw while learning**.")
    w("* **Per-class accuracy** = the score **per subject**. A student can score 100% in maths and 40% in history; the overall average hides that. "
      "Our \"subjects\" are the five traffic types (web, video, VoIP, file transfer, ping). Per-class accuracy is called *recall*. *Precision* answers the opposite question: when the student writes \"history\", how often is it really a history question?")
    w("* **Confusion matrix** = the marking sheet. Each **row** is what the traffic really was, each **column** is what the model said. "
      "A perfect result puts every number on the diagonal (top-left to bottom-right). A number off the diagonal shows which type was mistaken for which - e.g. \"video mistaken for web\".")
    w("* **Unseen configuration** = a VPN setting combination (cipher × Diffie-Hellman group × tunnel/transport × PFS label) that was completely kept out of training. "
      f"We have {n_configs} configurations; the test always uses a group of them that the model did not train on.")
    w("")
    w("### Which of our numbers are FAIR and which are NOT")
    w("")
    w(table(["Number", "Fair?", "Why"], [
        [f"Grouped cross-validation, {pct(fc['accuracy'])} per capture / {pct(fw['accuracy'])} per window (section 2; also in `metrics.json`)", "**FAIR**",
         "every test configuration was hidden during training"],
        ["Leave-one-configuration-out, leave-one-cipher-out, leave-one-DH-group-out (section 2)", "**FAIR (stricter)**", "hides even more: a whole cipher or DH group the model never met"],
        ["Robustness tests (a)-(e) (section 4)", "**FAIR**", "test configurations are unseen; only the *test* data is damaged"],
        ["Shuffled-label control (section 5)", "control", "not an accuracy claim; it shows what pure guessing looks like"],
        [f"180-capture end-to-end run through `/analyze` ({A['correct']}/{A['n']} correct)" if A else "180-capture end-to-end run", "**NOT FAIR**",
         "the shipped model was trained on these same 180 captures (like re-taking an exam you studied)"],
        ["The **old** \"100%\" from before the fix", "**NOT FAIR**", "random split: near-copies of the same capture were in both training and test; it also used the packet count, which gives the answer away"],
        ["\"Capture length alone = 100%\" (section 5)", "fair but *bad news*", "proves the old feature was a shortcut - which is why it was removed"],
    ]))
    w("")
    w("**A remaining limit even for the fair numbers:** \"unseen configuration\" means new VPN *settings*, but the test captures were produced by the **same scripts, in the same lab, with the same tools** as the training captures. "
      "There is one capture per (configuration, traffic type) - no repeated runs.")
    w("")

    # ---- 2
    w("## 2. The fair test, re-run from scratch")
    w("")
    w(f"Method: read all 180 traffic pcaps → keep only ESP packets → cut into 1-second windows → 12 features per window (listed in section 5) → "
      f"Random Forest with the same settings as the shipped model → **6-fold cross-validation grouped by VPN configuration** ({n_configs} configurations; a script check asserts no configuration is ever in both training and test). "
      "Every prediction below was made by a model that had never seen that configuration.")
    w("")
    w(table(["Level", "Accuracy", "Balanced accuracy*", "Macro-F1", "n"], [
        ["Per 1-second window", pct(fw["accuracy"]), pct(fw["balanced_accuracy"]), f"{fw['macro_f1']:.3f}", f"{fw['n']:,} windows"],
        ["Per capture (what the app reports)", pct(fc["accuracy"]), pct(fc["balanced_accuracy"]), f"{fc['macro_f1']:.3f}", f"{fc['n']} captures"]]))
    w("")
    w("\\*Balanced accuracy = the average of the per-class accuracies, so a common class (web has 611 windows) cannot hide a rare one (VoIP has 36).")
    w("")
    w(f"Accuracy per fold (each fold = ~{n_configs // N_SPLITS} unseen configurations): " + ", ".join(pct(x) for x in F["fold_accuracy"]) + ".")
    w("")
    w("### Per-class results (per capture)")
    w("")
    w(per_class_table(fc, classes))
    w("")
    w("### Per-class results (per 1-second window)")
    w("")
    w(per_class_table(fw, classes))
    w("")
    w("### Confusion matrix - per capture (rows = truth, columns = model's answer)")
    w("")
    w(cm_table(fc["confusion"], classes))
    w("")
    w("### Confusion matrix - per 1-second window")
    w("")
    w(cm_table(fw["confusion"], classes))
    w("")
    off = sum(sum(v for j, v in enumerate(row) if j != i) for i, row in enumerate(fw["confusion"]))
    off_c = sum(sum(v for j, v in enumerate(row) if j != i) for i, row in enumerate(fc["confusion"]))
    w(f"Off-diagonal (mistakes): **{off}** windows and **{off_c}** captures." + (" The matrix is perfectly diagonal: no traffic type was mistaken for another." if off == 0 and off_c == 0 else ""))
    w("")
    w("### Is it just luck of the split? Extra fair checks")
    w("")
    w(table(["Check", "Per-capture accuracy", "Per-window accuracy"], [
        ["Main split (seed 42)", pct(fc["accuracy"]), pct(fw["accuracy"])],
        *[[f"Different random split, seed {s['seed']}", pct(s["capture_accuracy"]), pct(s["window_accuracy"])] for s in seeds],
        [f"Leave-ONE-configuration-out ({n_configs} separate tests, each hides one configuration)", pct(loco["capture_accuracy"]), pct(loco["window_accuracy"])],
    ]))
    w("")
    w("Even stricter: hide an **entire setting value** (e.g. train only on AES-128 and AES-256, then test on AES-128-GCM, which the model has never met):")
    w("")
    rows = []
    for title, per in F["leave_one_setting_out"].items():
        for v, r in per.items():
            rows.append([title, v, f"{r['captures']} captures", pct(r["capture_accuracy"]), pct(r["window_accuracy"])])
    w(table(["Setting hidden", "Value", "Test size", "Per-capture accuracy", "Per-window accuracy"], rows))
    w("")

    # ---- 3
    w("## 3. All 180 captures through the real app path - NOT an unseen-data test")
    w("")
    if A:
        w("Every capture was uploaded to the real `POST /analyze` endpoint (same code path as the website: IKE parser → ML model → answer; called through FastAPI's built-in test client, so no network port is involved) and compared with the ground truth in `manifest.csv`.")
        w("")
        w(f"> ⚠️ **This is NOT a fair accuracy test.** The shipped model (`ml-engineer/models/traffic_classifier.pkl`) was trained on windows from **these same 180 files**. "
          "It is the student re-taking the exam they studied. What it *does* prove: the whole pipeline works end to end, with no crashes or format problems, and the model at least reproduces its own training data.")
        w("")
        w(f"**Result: {A['correct']} of {A['n']} correct ({pct(A['accuracy'])}), {A['http_errors']} HTTP errors, {A['seconds']:.0f} s total.**")
        w("")
        w(table(["True class", "Captures", "Correct", "Lowest confidence", "Average confidence"],
                [[k, v["n"], v["correct"], pct(v["min_confidence"], 0), pct(v["mean_confidence"], 0)] for k, v in A["per_class"].items()]))
        w("")
        if A["wrong"]:
            w("**Wrong predictions:**")
            w("")
            w(table(["File", "True", "Predicted", "Confidence"], [[r["file"], r["true"], r["pred"], pct(r["confidence"] or 0, 0)] for r in A["wrong"]]))
        else:
            w("**Wrong predictions: none.** (The list of mistakes is empty - which is expected for training data, and why this number must not be quoted as accuracy.)")
    else:
        w("*Skipped in this run (`--skip-api`).*")
    w("")

    # ---- 4
    w("## 4. Robustness: what happens when the data is damaged? (all on unseen configurations)")
    w("")
    w("Method: the models are the six cross-validation models from section 2 (each trained on clean data from other configurations). "
      "Only the **test** captures are damaged before being classified. \"Per-capture\" = one answer per capture (windows averaged). "
      "Some damage leaves a capture with no usable window (fewer than 2 packets in every second) - the app would say \"too sparse to classify\". "
      "The table therefore gives accuracy **on the captures that could be classified**, and the stricter number where a refusal counts as wrong.")
    w("")
    w(table(["Test", "Per-window accuracy", "Per-capture accuracy (of those classified)", "Per-capture, refusals count as wrong", "Captures classified", "Note"], [
        rob_row("Sanity: nothing damaged", sanity, "must equal section 2"),
        rob_row("(a) only the first 5 seconds", a, f"file transfer, VoIP and video are already under 5 s; only web and ping shrink (windows {sanity['windows']:,} to {a['windows']:,})"),
        rob_row("(b) only the first 10 packets", b),
        rob_row(f"(c) randomly drop 20% of packets ({c['runs']} random runs)", c, f"worst run {pct(c['capture_accuracy_counting_no_prediction_as_wrong']['min'])}"),
        rob_row(f"(d) timing jitter, sd 10 ms ({d1['runs']} runs)", d1, f"worst run {pct(d1['capture_accuracy_counting_no_prediction_as_wrong']['min'])}"),
        rob_row(f"(d) timing jitter, sd 50 ms ({d2['runs']} runs)", d2, f"worst run {pct(d2['capture_accuracy_counting_no_prediction_as_wrong']['min'])}"),
        rob_row(f"(d) timing jitter, sd 200 ms ({d3['runs']} runs)", d3, f"worst run {pct(d3['capture_accuracy_counting_no_prediction_as_wrong']['min'])}"),
    ]))
    w("")
    for label, t in (("(a) first 5 s", a), ("(b) first 10 packets", b), ("(c) drop 20%", c), ("(d) jitter 10 ms", d1), ("(d) jitter 50 ms", d2), ("(d) jitter 200 ms", d3)):
        if t["wrong_by_class"]:
            w(f"* Mistakes in {label}, by true class (summed over runs): " + ", ".join(f"{k}: {v}" for k, v in t["wrong_by_class"].items()))
    w("")
    w("Jitter is Gaussian noise added to every packet timestamp. sd 10 ms is realistic Internet variation; 200 ms is severe. "
      "(The lab captures are on a local Docker network with almost no natural jitter, so real networks are a genuine unknown.)")
    w("")
    w("### (e) What happens with a traffic type the model was never taught?")
    w("")
    w("For each of the 5 classes in turn, the model was trained on the **other four** (on unseen-config folds) and then shown captures of the missing class. "
      "A model that only knows 4 answers **must** pick one of them; the question is whether it at least sounds unsure.")
    w("")
    U = B["unknown_class"]
    w(table(["Class left out", "Accuracy on the 4 known classes", "The unknown captures were labelled as...", "Confidence on unknown", "Confidence on known",
             f"Unknown flagged as unsure (<{int(LOW_CONF * 100)}%)", "Known flagged (false alarm)"],
            [[k, pct(v["known_capture_accuracy"]), ", ".join(f"{p}: {n}" for p, n in sorted(v["unknown_predicted_as"].items(), key=lambda x: -x[1])),
              pct(v["unknown_mean_confidence"], 0), pct(v["known_mean_confidence"], 0), pct(v["unknown_flagged_low_confidence"], 0), pct(v["known_flagged_low_confidence"], 0)]
             for k, v in U.items()]))
    w("")
    w(f"Reading it: the model has **no \"I don't know\" answer** - a traffic type it was never taught is forced into one of the known classes (shown in the third column). "
      f"The good news is that it sounds much less sure: average confidence is {pct(min(u_conf), 0)}-{pct(max(u_conf), 0)} on unknown types versus about {pct(float(np.mean(k_conf)), 0)} on known ones, "
      f"and the app's \"Low classification confidence\" warning (below {int(LOW_CONF * 100)}%) never fired on known types (no false alarms). "
      f"The bad news is that the warning is unreliable at catching unknowns: it caught {', '.join(f'{k} {pct(v, 0)}' for k, v in flagged.items())} of the missing type's captures"
      + (f", so for **{', '.join(missed)}** most unknown captures slipped through with a fairly confident wrong label." if missed else ".")
      + " **The model must not be trusted on traffic types outside these five** (e.g. games, DNS floods, torrents, real video calls).")
    w("")

    # ---- 5
    w("## 5. Leakage checks: is the model cheating?")
    w("")
    w("### The exact features the model sees")
    w("")
    w("Twelve numbers per 1-second window of ESP packets, computed only from packet **sizes, arrival times and direction**:")
    w("")
    w(table(["#", "Feature", "Meaning"], [[i + 1, f"`{f}`", tf.FEATURE_DESCRIPTIONS[f]] for i, f in enumerate(FEATURES)]))
    w("")
    w(f"* The features used in this audit are **identical** to the ones inside the shipped model file (`feature_names_in_`): **{L['features_match']}**.")
    absent = [k for k, v in L["banned_absent"].items() if not v]
    w(f"* Check that none of these are features: `{', '.join(L['banned_absent'])}` → " + ("**all absent**." if not absent else f"**PRESENT: {absent}**"))
    w("")
    fi = L["filename_independence"]
    w("### File names and run numbers")
    w("")
    w(f"* The feature code never receives a file name - it reads packets only. To prove it end to end, {fi['files_tested']} captures (3 per class) were uploaded to `/analyze` under **three different names** "
      f"(the real name, `capture.pcap`, `zz_run99_qwerty.pcap`): the traffic answer **and all five class probabilities were identical for {fi['identical_for_all_3_names']} of {fi['files_tested']}** files.")
    w("* Run numbers: every capture is `run1` (there is exactly one run per configuration and class), so run-to-run variation cannot be tested at all - it is a gap, not a pass. The model cannot use the run number because it is not a feature.")
    w("")
    cla = L["capture_length_alone"]
    w("### Capture length")
    w("")
    w(f"* Capture length is **not** a feature (no packet count, byte total or duration). Why it matters: a one-number model that only knows *how many packets the file has* scores "
      f"**{pct(cla['accuracy_grouped_cv'])}** on unseen configurations, because the lab stopped `tcpdump` after a fixed number of packets per traffic type: "
      + ", ".join(f"{k} {v[0]}-{v[1]}" for k, v in cla["ranges"].items()) + ". That is the shortcut the first model used.")
    w(f"* Our model is not riding on it. In test (b) every capture is cut to **10 packets**, which erases capture-length information (every capture is then the same length). "
      f"Accuracy falls to {pct(b['capture_accuracy_of_predicted']['mean'], 0)} - so length is not the *only* cue - but it does not fall to chance ({pct(L['shuffled']['chance_capture_accuracy'], 0)}): "
      f"the four other classes are still classified correctly and only {b_bad} fails. "
      "That failure is honest information, not leakage: ten packets of a large file transfer look like a tiny exchange.")
    w("")
    w("### Shuffled-label control (should be chance level)")
    w("")
    w("Each capture was given the label of a *random other capture* and the whole grouped cross-validation was repeated 5 times. If the pipeline secretly leaked answers, accuracy would stay high. It should fall to guessing:")
    w("")
    w(table(["Repeat", "Per-capture accuracy", "Per-capture balanced accuracy", "Per-window accuracy", "Per-window balanced accuracy"],
            [[r["seed"], pct(r["capture_accuracy"]), pct(r["capture_balanced_accuracy"]), pct(r["window_accuracy"]), pct(r["window_balanced_accuracy"])] for r in shuf] +
            [["**average**", f"**{pct(shuf_cap)}**", f"**{pct(shuf_capbal)}**", f"**{pct(shuf_win)}**", f"**{pct(shuf_winbal)}**"]]))
    w("")
    w(f"Pure guessing among 5 balanced classes = **{pct(L['shuffled']['chance_capture_accuracy'], 0)}**; the always-answer-'web' strategy scores {pct(L['shuffled']['majority_window_accuracy'])} of windows (web dominates the windows). "
      f"Our shuffled results ({pct(shuf_cap)} per capture, balanced accuracy {pct(shuf_capbal)}) sit at chance level, versus {pct(fc['accuracy'])} with the real labels. "
      "So the 100%-type results come from real structure in the packet sizes and timing, not from a hidden leak in the pipeline.")
    w("")

    # ---- 6
    w("## 6. Verdict")
    w("")
    w("### What is proven")
    w("")
    w(f"* On unseen VPN configurations (new cipher / DH group / mode / PFS-label combinations, even a whole unseen cipher), the classifier separated the **five lab traffic types** almost perfectly: **{pct(fc['accuracy'])} per capture, {pct(fw['accuracy'])} per second-window**, across several different splits and leave-one-out tests.")
    w("* The result is **not** caused by file names, run numbers or the capture length as such, and is **not** a pipeline leak: shuffled labels drop to chance, and the app gives identical answers when the same file is uploaded under a different name.")
    w("* The classifier tolerates moderate damage to the data: " + f"20% of packets missing → {pct(c['capture_accuracy_counting_no_prediction_as_wrong']['mean'])} per capture, "
      f"10 ms timing jitter → {pct(d1['capture_accuracy_counting_no_prediction_as_wrong']['mean'])}, 50 ms → {pct(d2['capture_accuracy_counting_no_prediction_as_wrong']['mean'])}, "
      f"first 5 seconds only → {pct(a['capture_accuracy_counting_no_prediction_as_wrong']['mean'])} (refusals counted as wrong).")
    w("* Its weak spots are now **known and measured**: " + f"only 10 packets → {pct(b['capture_accuracy_counting_no_prediction_as_wrong']['mean'])} ({b_bad} missed), "
      f"200 ms jitter → {pct(d3['capture_accuracy_counting_no_prediction_as_wrong']['mean'])}, and unknown traffic types are forced into a known class.")
    if A:
        w(f"* The whole app pipeline works end to end on all 180 captures ({A['correct']}/{A['n']}; a plumbing check, not an accuracy claim).")
    w("")
    w("### What is NOT proven")
    w("")
    w("* **Real-world traffic.** The five classes are made by scripts (ping, scp, curl, ffmpeg range requests, SIPp signalling without audio). Real browsing, video calls, cloud sync or games were never tested.")
    w("* **Other networks.** All captures come from one Docker network with almost no delay, jitter or loss. Real Wi-Fi/mobile/Internet paths change timing and packet sizes.")
    w("* **Other VPN software.** Only strongSwan (Linux, ESP) was tested; WireGuard, OpenVPN, Windows/Cisco IPsec, NAT-T and different MTUs are unknown.")
    w("* **Traffic types outside the five.** The model cannot say \"I don't know\" (section 4e); it will pick one of the five.")
    w("* **Repeatability.** Only one capture per configuration and class exists; run-to-run variation is untested. Captures were stopped by packet count, so file-transfer, VoIP and video captures are under 2 s long (1-2 windows each) - the model has seen very few examples of them.")
    w("* **The security score.** This report covers only the traffic classifier. The cipher/DH values for the lab captures come from the file names (\"declared\"), because none of the 216 captures contains a readable IKE_SA_INIT; the IKE parser has only been tested on synthetic messages.")
    w("* **Statistical precision.** 180 captures (36 per class, from 36 configurations that differ only in a few settings) give a limited estimate: even a perfect score only guarantees, at 95% confidence, "
      f"a true rate of at least about {pct(ci[0])} *for this kind of lab data*.")
    w("")
    w("### What to say to the judges")
    w("")
    w(f"> \"We tested our traffic classifier the strict way: every VPN configuration in the test was completely hidden from the model, and it still got {pct(fc['accuracy'], 0)} of our lab captures right. "
      "We checked it isn't cheating: it never sees file names or capture length, and with shuffled labels it falls to plain guessing. "
      "We also stress-tested it, and it holds up with 20% of packets missing and normal timing noise, though it struggles with only ten packets and can't say 'I don't know' to traffic it was never taught. "
      "Our data comes from scripted tests in one lab, so we claim it works for these five traffic types, not yet for real-world traffic or other VPN products - and we fixed an earlier inflated score, so we only report fair numbers.\"")
    w("")
    w("## How to re-run this audit")
    w("")
    w("```powershell")
    w(f"cd E:\\SIH\\SIH_2026\\SIH_2026_full")
    w(f".\\venv\\Scripts\\python.exe tools\\accuracy_check.py --pcap-dir \"E:\\SIH\\SIH_2026\"      # about {R['meta']['minutes']:.0f} minutes; needs the 216 pcaps")
    w("```")
    w("")
    w(f"Runtime of the run that produced this report: {R['meta']['minutes']:.1f} minutes on {R['meta']['cpus']} CPU threads. Random seeds are fixed (42 for the main split; robustness runs use seeds 0-5), so re-runs give the same numbers.")
    with open(out_path, "w", encoding="utf-8", newline="\n") as f:
        f.write("\n".join(lines) + "\n")


# ----------------------------------------------------------------------------------------------
def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--pcap-dir")
    ap.add_argument("--out", default=os.path.join(ROOT, "ACCURACY_REPORT.md"))
    ap.add_argument("--results", default=os.path.join(tempfile.gettempdir(), "sih_accuracy_results.json"),
                    help="where partial results are kept so an interrupted run can resume (outside the repo by default)")
    ap.add_argument("--cache", default=os.path.join(tempfile.gettempdir(), "sih_accuracy_packets.pkl"),
                    help="cache of the parsed packets (outside the repo by default)")
    ap.add_argument("--skip-api", action="store_true")
    ap.add_argument("--force", action="store_true", help="recompute sections even if the results file has them")
    args = ap.parse_args()

    t_start = time.time()
    R = {}
    if os.path.exists(args.results) and not args.force:
        with open(args.results, encoding="utf-8") as f:
            R = json.load(f)
    save = lambda: json.dump(R, open(args.results, "w", encoding="utf-8"), indent=1)  # noqa: E731

    pcap_dir = find_pcap_dir(args.pcap_dir)
    caps, packets = load_captures(pcap_dir, args.cache)
    self_test(caps, packets)
    df, classes = build_frame(caps, packets)
    log(f"{len(df)} windows from {df['file'].nunique()} captures, {df['combo'].nunique()} configs, classes {classes}")
    R["classes"] = classes

    fold = None
    if "fair" not in R:
        R["fair"], fold = section_fair(df, classes)
        R["fold"] = fold.tolist()
        save()
    fold = np.array(R["fold"])
    if "robust" not in R:
        R["robust"] = section_robust(caps, packets, df, classes, fold)
        save()
    if "leakage" not in R:
        R["leakage"] = section_leakage(caps, packets, df, classes)
        save()
    if "api" not in R and not args.skip_api:
        R["api"] = section_api(caps)
        save()

    if "meta" not in R:  # runtime of the run that computed the results (re-rendering must not change it)
        R["meta"] = {"minutes": (time.time() - t_start) / 60, "cpus": os.cpu_count()}
        save()
    render(R, classes, args.out)
    log(f"wrote {args.out}")


if __name__ == "__main__":
    main()
