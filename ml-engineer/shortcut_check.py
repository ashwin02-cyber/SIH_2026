"""
shortcut_check.py
-----------------
Quantifies the "packet_count shortcut" that motivated the fixed-window
features. For every labelled capture it takes ONE number - how many IP packets
the file contains (what the old `packet_count` feature measured) - and checks
how well a depth-limited decision tree predicts the traffic class from that
alone, with the same config-grouped cross-validation used in train_model.py.

Because the testbed stopped tcpdump after a fixed number of packets per traffic
type (-c 20 for ICMP, 300 web, 500 video, 40 VoIP, 5000 file transfer), the
count identifies the class without looking at any traffic behaviour.

Usage: python shortcut_check.py [--pcap-dir DIR]     -> shortcut_check.json
"""
import argparse
import glob
import json
import os
import sys
import warnings

import numpy as np
import pandas as pd
from scapy.all import IP, PcapReader
from sklearn.metrics import accuracy_score
from sklearn.model_selection import StratifiedGroupKFold
from sklearn.tree import DecisionTreeClassifier

warnings.filterwarnings("ignore")
HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
from batch_extract import find_pcap_dir, parse_name  # noqa: E402


def count_ip_packets(path):
    n = 0
    with PcapReader(path) as r:
        for p in r:
            n += IP in p
    return n


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--pcap-dir")
    args = ap.parse_args()
    d = find_pcap_dir(args.pcap_dir)
    rows = []
    for f in sorted(glob.glob(os.path.join(d, "*.pcap"))):
        combo, label = parse_name(f)
        if label:
            rows.append({"combo": combo, "label": label, "packet_count": count_ip_packets(f)})
    df = pd.DataFrame(rows)
    y, g = df["label"].to_numpy(), df["combo"].to_numpy()

    pred = np.empty(len(y), dtype=object)
    cv = StratifiedGroupKFold(n_splits=6, shuffle=True, random_state=42)
    for tr, te in cv.split(df[["packet_count"]], y, g):
        m = DecisionTreeClassifier(max_depth=3, random_state=42).fit(df.iloc[tr][["packet_count"]], y[tr])
        pred[te] = m.predict(df.iloc[te][["packet_count"]])
    acc = float(accuracy_score(y, pred))

    out = {"captures": len(df), "accuracy_from_packet_count_alone_grouped_cv": round(acc, 4),
           "packet_count_range_per_class": {k: [int(v.min()), int(v.max())]
                                            for k, v in df.groupby("label")["packet_count"]}}
    with open(os.path.join(HERE, "shortcut_check.json"), "w") as f:
        json.dump(out, f, indent=2)
    print(json.dumps(out, indent=2))


if __name__ == "__main__":
    main()
