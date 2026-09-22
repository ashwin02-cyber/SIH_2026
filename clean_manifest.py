"""Deduplicate manifest.csv (keep the LAST row per filename) and make sure the
provenance columns exist. Rows written by the first version of the testbed
(before the capture/PFS fixes) get:

    capture_stop    = packet-count   (tcpdump -c N, not a time limit)
    config_version  = v1-pfs-identical  (pfs-on and pfs-off configs were identical,
                                         so the 'pfs' column does NOT describe the capture)

Usage: python clean_manifest.py
"""
import csv
import os

MANIFEST_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "manifest.csv")
COLUMNS = ["filename", "combo_name", "cipher", "mode", "dh_group", "pfs", "traffic_class", "timestamp",
           "notes", "capture_stop", "capture_seconds", "config_version"]

rows = {}
with open(MANIFEST_PATH, newline="", encoding="utf-8") as f:
    for r in csv.DictReader(f):
        rows[r["filename"]] = r  # later rows overwrite earlier ones

for r in rows.values():
    if not r.get("config_version"):
        r["capture_stop"] = "packet-count"
        r["capture_seconds"] = ""
        r["config_version"] = "v1-pfs-identical"

with open(MANIFEST_PATH, "w", newline="", encoding="utf-8") as f:
    w = csv.DictWriter(f, fieldnames=COLUMNS, restval="")
    w.writeheader()
    w.writerows(rows.values())

print(f"Manifest cleaned: {len(rows)} unique files.")
