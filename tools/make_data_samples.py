"""
make_data_samples.py - rebuilds data/samples/ and data/manifest.csv from the full capture set.

The full dataset (216 pcaps, ~500 MB) is NOT in the repo. data/samples/ holds a handful of small,
REAL captures copied unmodified from it, so the app and tests can run without the big files -
except the file-transfer sample, whose original is ~4-6 MB: only a 300-packet slice of the bulk phase is kept
(cut with Scapy, packets untouched) and the manifest says so.

    python tools/make_data_samples.py --pcap-dir <folder with the 216 pcaps>
"""

import argparse
import csv
import os
import shutil
import sys

from scapy.all import PcapReader, PcapWriter

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
OUT = os.path.join(ROOT, "data", "samples")

COPY = [
    "aes128gcm16-dh19-tunnel-pfs-on__icmp_run1.pcap",
    "aes128gcm16-dh19-tunnel-pfs-on__voip_run1.pcap",
    "aes128gcm16-dh19-tunnel-pfs-on__web_run1.pcap",
    "aes128gcm16-dh19-tunnel-pfs-on__handshake.pcap",
    "aes128-dh2-transport-pfs-off__icmp_run1.pcap",
    "aes128-dh2-transport-pfs-off__voip_run1.pcap",
    "aes128-dh2-transport-pfs-off__web_run1.pcap",
    "aes128-dh2-transport-pfs-off__video_run1.pcap",
    "aes128-dh2-transport-pfs-off__handshake.pcap",
]
# (file, first packet index, number of packets): a slice from the bulk-transfer phase.
# The first ~300 packets are ssh/scp negotiation and look like something else to the classifier.
CUT = [("aes128-dh2-transport-pfs-off__file_transfer_run1.pcap", 1000, 300)]


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--pcap-dir", required=True)
    args = ap.parse_args()
    os.makedirs(OUT, exist_ok=True)

    for name in COPY:
        shutil.copyfile(os.path.join(args.pcap_dir, name), os.path.join(OUT, name))

    notes = {}
    for name, start, n in CUT:
        with PcapReader(os.path.join(args.pcap_dir, name)) as r, PcapWriter(os.path.join(OUT, name), sync=True) as w:
            for i, pkt in enumerate(r):
                if i >= start + n:
                    break
                if i >= start:
                    w.write(pkt)
        notes[name] = f"excerpt: packets {start}-{start + n - 1} of the original capture (bulk-transfer phase)"

    with open(os.path.join(ROOT, "manifest.csv"), newline="", encoding="utf-8") as f:
        full = {r["filename"]: r for r in csv.DictReader(f)}
    rows = []
    for name in sorted(os.listdir(OUT)):
        if not name.endswith(".pcap"):
            continue
        row = dict(full[name])
        if name in notes:
            row["notes"] = (row.get("notes", "") + "; " if row.get("notes") else "") + notes[name]
        rows.append(row)
    with open(os.path.join(ROOT, "data", "manifest.csv"), "w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=list(rows[0].keys()))
        w.writeheader()
        w.writerows(rows)
    print(f"{len(rows)} samples in {OUT}")


if __name__ == "__main__":
    sys.exit(main())
