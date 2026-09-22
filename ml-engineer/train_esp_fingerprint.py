"""
train_esp_fingerprint.py
------------------------
Builds and honestly evaluates the passive ESP fingerprinting (esp_fingerprint.py).

    python train_esp_fingerprint.py [--pcap-dir DIR]

Ground truth (cipher family, mode) comes from manifest.csv and is used ONLY here, to train the tunnel/transport
model and to score both inferences. esp_fingerprint.py itself never sees a label or a file name.

Evaluation
  * cipher family (CBC-like vs GCM-like): a physical RULE with no fitted parameters, scored on all 180 captures,
    reported per traffic class with coverage (how often it commits to an answer) and accuracy when it does.
  * integrity tag length: is the true ICV among the rule's candidates (CBC-like answers only)?
  * tunnel vs transport: RandomForest on packet-size statistics, StratifiedGroupKFold(6) GROUPED BY VPN CONFIG
    (every test configuration unseen), plus a label-shuffled control.

Outputs: models/esp_mode_classifier.pkl, esp_fingerprint_features.csv, esp_fingerprint_metrics.json
"""

import argparse
import csv
import glob
import json
import os
import sys
import warnings
from collections import Counter, defaultdict

import joblib
import numpy as np
import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import accuracy_score, confusion_matrix
from sklearn.model_selection import StratifiedGroupKFold

warnings.filterwarnings("ignore")
HERE = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.abspath(os.path.join(HERE, ".."))
sys.path.insert(0, HERE)
import esp_fingerprint as fp  # noqa: E402
import traffic_features as tf  # noqa: E402
from batch_extract import find_pcap_dir  # noqa: E402

SEED = 42
TRAFFIC = {"web", "video", "voip", "file_transfer", "icmp"}


def family_of(cipher):
    return "GCM-like" if "gcm" in cipher else "CBC-like"


def build_table(pcap_dir):
    with open(os.path.join(REPO, "manifest.csv"), newline="", encoding="utf-8") as f:
        manifest = {r["filename"]: r for r in csv.DictReader(f)}
    rows = []
    for path in sorted(glob.glob(os.path.join(pcap_dir, "*.pcap"))):
        name = os.path.basename(path)
        m = manifest.get(name)
        if not m or m["traffic_class"] not in TRAFFIC:
            continue
        packets, esp_only, _ = tf.read_packets(path)
        lengths = fp.esp_lengths(packets)
        rule = fp.infer_cipher_family(lengths)
        tag = fp.infer_integrity_tag(lengths, rule)
        rows.append({"file": name, "combo": m["combo_name"], "traffic": m["traffic_class"], "cipher": m["cipher"],
                     "true_family": family_of(m["cipher"]), "true_mode": m["mode"],
                     "n_packets": len(lengths), "distinct_sizes": len(set(lengths)),
                     "rule_family": rule["value"], "rule_conf": rule["confidence"] or 0.0,
                     "rule_leaning": rule.get("leaning") or "",
                     "icv_candidates": ";".join(str(c["bytes"]) for c in tag["candidates"]),
                     **fp.mode_feature_vector(lengths)})
        if len(rows) % 30 == 0:
            print(f"read {len(rows)} captures", flush=True)
    return pd.DataFrame(rows)


def evaluate_rule(df):
    out = {"by_traffic": {}, "overall": {}}
    def block(d):
        det = d[d["rule_family"] != "undetermined"]
        pred = det["rule_family"].str.split(" ").str[0].map({"CBC-like": "CBC-like", "GCM-like": "GCM-like"})
        correct = int((pred == det["true_family"]).sum())
        return {"captures": int(len(d)), "committed": int(len(det)), "coverage": len(det) / max(1, len(d)),
                "correct_when_committed": correct, "accuracy_when_committed": correct / max(1, len(det)),
                "wrong": [{"file": r.file, "truth": r.true_family, "said": r.rule_family, "distinct_sizes": int(r.distinct_sizes)}
                          for r in det.itertuples() if not str(r.rule_family).startswith(r.true_family)]}
    for t, d in df.groupby("traffic"):
        out["by_traffic"][t] = block(d)
    out["overall"] = block(df)
    # integrity tag: the true ICV (sha256-128 => 16 bytes) must be among the candidates for CBC-like answers
    cbc = df[df["rule_family"].str.startswith("CBC") & (df["true_family"] == "CBC-like")]
    ok = sum(1 for r in cbc.itertuples() if "16" in str(r.icv_candidates).split(";"))
    out["icv"] = {"cbc_captures_answered": int(len(cbc)), "true_icv_16_in_candidates": int(ok),
                  "note": "every CBC config in the testbed uses HMAC-SHA2-256-128 (16-byte ICV)"}
    return out


def evaluate_mode(df):
    X, y, groups = df[fp.MODE_FEATURES], df["true_mode"].to_numpy(), df["combo"].to_numpy()

    def cv(labels):
        proba = np.zeros((len(df), 2))
        for tr, te in StratifiedGroupKFold(6, shuffle=True, random_state=SEED).split(X, labels, groups):
            assert not set(groups[tr]) & set(groups[te])
            m = RandomForestClassifier(300, class_weight="balanced_subsample", random_state=SEED, n_jobs=-1).fit(X.iloc[tr], labels[tr])
            proba[te] = m.predict_proba(X.iloc[te])
        return proba, sorted(set(labels))
    proba, classes = cv(y)
    pred = np.array(classes)[proba.argmax(axis=1)]
    conf = proba.max(axis=1)
    committed = conf >= fp.MODE_CONF_MIN
    res = {"classes": classes, "accuracy": float(accuracy_score(y, pred)),
           "confusion": confusion_matrix(y, pred, labels=classes).tolist(),
           "coverage_at_threshold": float(committed.mean()), "threshold": fp.MODE_CONF_MIN,
           "accuracy_when_committed": float(accuracy_score(y[committed], pred[committed])) if committed.any() else None,
           "by_traffic": {}, "by_family": {}}
    for t in sorted(df["traffic"].unique()):
        m = (df["traffic"] == t).to_numpy()
        res["by_traffic"][t] = {"accuracy": float(accuracy_score(y[m], pred[m])), "captures": int(m.sum()),
                                "coverage": float(committed[m].mean())}
    for fam in sorted(df["true_family"].unique()):
        m = (df["true_family"] == fam).to_numpy()
        res["by_family"][fam] = {"accuracy": float(accuracy_score(y[m], pred[m])), "captures": int(m.sum())}
    rng = np.random.RandomState(0)
    shuf_accs = []
    for s in range(5):
        perm = dict(zip(df["file"], rng.permutation(y)))
        ys = df["file"].map(perm).to_numpy()
        p, cl = cv(ys)
        shuf_accs.append(float(accuracy_score(ys, np.array(cl)[p.argmax(axis=1)])))
    res["shuffled_label_accuracy"] = {"mean": float(np.mean(shuf_accs)), "runs": shuf_accs, "chance": 0.5}
    res["majority_baseline"] = float(pd.Series(y).value_counts(normalize=True).max())
    return res


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--pcap-dir")
    ap.add_argument("--from-csv", action="store_true", help="skip reading pcaps, use esp_fingerprint_features.csv")
    args = ap.parse_args()
    csv_path = os.path.join(HERE, "esp_fingerprint_features.csv")
    if args.from_csv:
        df = pd.read_csv(csv_path)
    else:
        df = build_table(find_pcap_dir(args.pcap_dir))
        df.to_csv(csv_path, index=False)
    print(f"{len(df)} captures, {df['combo'].nunique()} configs")

    rule = evaluate_rule(df)
    mode = evaluate_mode(df)
    final = RandomForestClassifier(300, class_weight="balanced_subsample", random_state=SEED, n_jobs=-1).fit(df[fp.MODE_FEATURES], df["true_mode"])
    joblib.dump(final, fp.MODE_MODEL_PATH)

    metrics = {
        "what": "passive ESP fingerprinting from packet sizes only",
        "captures": int(len(df)), "configs": int(df["combo"].nunique()),
        "cipher_family_rule": rule, "tunnel_vs_transport": mode,
        "not_observable_passively": fp.NOT_OBSERVABLE,
        "caveats": [
            "Lab data: scripted traffic, one strongSwan version, all CBC configs use HMAC-SHA2-256-128, one capture per (config, class).",
            "The tunnel/transport model learns lab-specific size patterns (the inner IP header adds 20 bytes); it is not a physical law for arbitrary traffic.",
            "Constant-size streams (ping) carry no cipher-family evidence; the rule abstains on them.",
            "Cipher family from residues assumes one SA and AES-CBC with a 16-byte IV.",
        ],
    }
    with open(os.path.join(HERE, "esp_fingerprint_metrics.json"), "w", encoding="utf-8") as f:
        json.dump(metrics, f, indent=2)

    o = rule["overall"]
    print(f"CIPHER FAMILY RULE: committed on {o['committed']}/{o['captures']} captures, correct when committed "
          f"{o['correct_when_committed']}/{o['committed']} ({o['accuracy_when_committed']:.1%})")
    for t, b in rule["by_traffic"].items():
        print(f"   {t:14s} coverage {b['coverage']:.0%}  accuracy when committed {b['accuracy_when_committed']:.0%}  wrong={len(b['wrong'])}")
    print("ICV:", rule["icv"])
    print(f"TUNNEL vs TRANSPORT (grouped CV): accuracy {mode['accuracy']:.1%}; committed {mode['coverage_at_threshold']:.0%} "
          f"at conf>={fp.MODE_CONF_MIN}, accuracy when committed {mode['accuracy_when_committed']:.1%}")
    for t, b in mode["by_traffic"].items():
        print(f"   {t:14s} accuracy {b['accuracy']:.0%}")
    print("   by true family:", {k: round(v['accuracy'], 3) for k, v in mode["by_family"].items()})
    print("   shuffled-label control:", round(mode["shuffled_label_accuracy"]["mean"], 3), "majority baseline", round(mode["majority_baseline"], 3))


if __name__ == "__main__":
    main()
