"""
batch_extract.py
----------------
Turns the labelled traffic pcaps (36 VPN configs x 5 traffic classes) into a
table of fixed-time-window features: ml-engineer/features_windowed.csv.

Usage:
    python batch_extract.py [--pcap-dir DIR] [--out features_windowed.csv]

The pcap directory is (in order): --pcap-dir, $SIH_PCAP_DIR, <repo>/real_captures,
or the folder above the repo if that is where the pcaps were copied. Labels come
from the file name  <config>__<class>_run<N>.pcap  (the same convention as
manifest.csv). Files that are not traffic captures (e.g. *__handshake.pcap) are
skipped.
"""

import argparse
import glob
import os
import sys
import time

import pandas as pd

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from traffic_features import FEATURE_COLS, WINDOW_SEC, extract_windows  # noqa: E402

HERE = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.abspath(os.path.join(HERE, ".."))

LABEL_MAP = {
    "file_transfer": "file_transfer",
    "icmp": "icmp",
    "video": "video_streaming",
    "voip": "voip",
    "web": "web_browsing",
}


def find_pcap_dir(cli_value=None):
    candidates = [cli_value, os.environ.get("SIH_PCAP_DIR"),
                  os.path.join(REPO, "real_captures"), os.path.dirname(REPO)]
    for c in candidates:
        if c and glob.glob(os.path.join(c, "*__*_run*.pcap")):
            return c
    raise SystemExit("No traffic pcaps found. Pass --pcap-dir or set SIH_PCAP_DIR "
                     "(files look like aes128-dh14-tunnel-pfs-on__web_run1.pcap).")


def parse_name(filename):
    """'<combo>__<class>_run<N>.pcap' -> (combo, label) or (None, None)."""
    base = os.path.basename(filename)
    if "__" not in base:
        return None, None
    combo, rest = base.split("__", 1)
    for key, label in LABEL_MAP.items():
        if rest.startswith(key + "_run"):
            return combo, label
    return None, None


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--pcap-dir")
    ap.add_argument("--out", default=os.path.join(HERE, "features_windowed.csv"))
    args = ap.parse_args()

    pcap_dir = find_pcap_dir(args.pcap_dir)
    files = sorted(glob.glob(os.path.join(pcap_dir, "*.pcap")))
    print(f"Reading pcaps from {pcap_dir} ({len(files)} files), window = {WINDOW_SEC}s")

    rows, skipped, start = [], 0, time.time()
    for i, path in enumerate(files, 1):
        combo, label = parse_name(path)
        if label is None:
            skipped += 1
            continue
        try:
            windows, info = extract_windows(path)
        except ValueError as e:
            print(f"[{i}] SKIP {os.path.basename(path)}: {e}")
            skipped += 1
            continue
        for w in windows:
            rows.append({"combo": combo, "filename": os.path.basename(path), "label": label,
                         "esp_only": info["esp_only"], **w})
        print(f"[{i}/{len(files)}] {label:16s} {len(windows):3d} windows "
              f"(dropped {info['n_windows_dropped']}) esp_only={info['esp_only']} {os.path.basename(path)}")

    df = pd.DataFrame(rows)
    df.to_csv(args.out, index=False)
    print(f"\nWrote {len(df)} windows from {df['filename'].nunique()} captures to {args.out} "
          f"({skipped} files skipped, {time.time() - start:.0f}s)")
    print(df.groupby("label").size().to_string())
    missing = [c for c in FEATURE_COLS if c not in df.columns]
    assert not missing, missing


if __name__ == "__main__":
    main()
