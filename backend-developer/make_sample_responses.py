"""
make_sample_responses.py
Regenerates the frontend's bundled sample analyses from REAL API output.

The React app ships two sample responses (so it can show a full dashboard even
when the backend is not running). They are not hand-written mock numbers: they are
what POST /analyze returns for two of the real sample captures in data/samples/.
Rerun this after changing the models or the scoring, then rebuild the frontend:

    cd backend-developer
    python make_sample_responses.py
"""

import json
import os
import sys
import warnings

warnings.filterwarnings("ignore")
HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)

from main import SAMPLES_DIR, analyze_path  # noqa: E402

OUT_DIR = os.path.join(HERE, "..", "frontend-developer", "src", "data")
SAMPLES = {
    "sample_strong.json": "aes128gcm16-dh19-tunnel-pfs-on__web_run1.pcap",
    "sample_weak.json": "aes128-dh2-transport-pfs-off__icmp_run1.pcap",
}

if __name__ == "__main__":
    os.makedirs(OUT_DIR, exist_ok=True)
    for out_name, pcap in SAMPLES.items():
        resp = analyze_path(os.path.join(SAMPLES_DIR, pcap), pcap)
        with open(os.path.join(OUT_DIR, out_name), "w", encoding="utf-8") as f:
            json.dump(resp, f, indent=1)
        print(f"{out_name}: {pcap} -> score {resp['score']} {resp['risk_level']}, {resp['traffic']['label']}")
