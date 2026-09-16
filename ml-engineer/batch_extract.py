"""
batch_extract.py
----------------
Processes all 180 real pcaps from real_captures/ folder
Extracts features from each and saves to features_real.csv
Uses filename to determine traffic class label
"""

import os
import pandas as pd
from feature_extraction import process_pcap

# Folder containing real pcaps
PCAP_FOLDER = "real_captures"
OUTPUT_CSV = "features_real.csv"

# Map filename keywords to traffic class labels
LABEL_MAP = {
    "file_transfer": "file_transfer",
    "icmp": "icmp",
    "video": "video_streaming",
    "voip": "voip",
    "web": "web_browsing"
}

def get_label_from_filename(filename):
    """Extract traffic class from pcap filename."""
    filename_lower = filename.lower()
    for keyword, label in LABEL_MAP.items():
        if f"__{keyword}_" in filename_lower or f"__{keyword}r" in filename_lower:
            return label
    return None

def main():
    pcap_files = [f for f in os.listdir(PCAP_FOLDER) if f.endswith('.pcap')]
    print(f"Found {len(pcap_files)} pcap files\n")

    all_rows = []
    skipped = 0
    processed = 0

    for i, filename in enumerate(sorted(pcap_files)):
        label = get_label_from_filename(filename)
        if not label:
            print(f"[{i+1}] SKIPPED (no label found): {filename}")
            skipped += 1
            continue

        pcap_path = os.path.join(PCAP_FOLDER, filename)
        try:
            rows = process_pcap(pcap_path, label)
            if rows:
                all_rows.extend(rows)
                processed += 1
                print(f"[{i+1}] OK — {label:20s} — {len(rows)} flows — {filename}")
            else:
                print(f"[{i+1}] EMPTY (no flows) — {filename}")
                skipped += 1
        except Exception as e:
            print(f"[{i+1}] ERROR — {filename} — {e}")
            skipped += 1

    # Save to CSV
    if all_rows:
        df = pd.DataFrame(all_rows)
        df.to_csv(OUTPUT_CSV, index=False)
        print(f"\n✅ Done!")
        print(f"   Processed: {processed} pcaps")
        print(f"   Skipped:   {skipped} pcaps")
        print(f"   Total rows: {len(df)}")
        print(f"\nClass distribution:")
        print(df.groupby('label').size())
    else:
        print("No rows extracted!")

if __name__ == "__main__":
    main()