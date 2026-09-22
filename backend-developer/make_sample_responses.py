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

from contract import _cipher_string, _dh_string, _pfs_string  # noqa: E402
from main import SAMPLES_DIR, analyze_path  # noqa: E402
from scoring_engine import score_ike_facts  # noqa: E402

OUT_DIR = os.path.join(HERE, "..", "frontend-developer", "src", "data")
SAMPLES = {
    "sample_strong.json": "aes128gcm16-dh19-tunnel-pfs-on__web_run1.pcap",
    "sample_weak.json": "aes128-dh2-transport-pfs-off__icmp_run1.pcap",
}

# The "Compare against a weak setup" card uses a FIXED REFERENCE configuration, not a capture, so its
# PFS is defined (off) rather than unknown. It is scored by the real scoring engine, so the number is
# consistent with the values shown (PFS off is rated weak).
WEAK_REFERENCE = {"cipher": "AES-CBC", "key_length_bits": 128, "dh_group": 2, "mode": "transport", "pfs": False}


def weak_reference():
    r = WEAK_REFERENCE
    facts = {"ike_version": "unknown", "mode": r["mode"], "warnings": [],
             "ike_sa": {"cipher": r["cipher"], "key_length_bits": r["key_length_bits"], "dh_group": r["dh_group"]},
             "esp_sa": {"pfs": r["pfs"]}}
    risk = score_ike_facts(facts)
    return {
        "label": "Weak reference example",
        "note": "A fixed reference configuration (not a capture): AES-CBC-128, DH group 2, transport mode, PFS off.",
        "score": risk["overall_score"],
        "risk_level": risk["risk_level"],
        "cipher": _cipher_string(r["cipher"], r["key_length_bits"]),
        "mode": r["mode"],
        "dh_group": _dh_string(r["dh_group"]),
        "pfs": _pfs_string(r["pfs"]),
    }


if __name__ == "__main__":
    os.makedirs(OUT_DIR, exist_ok=True)
    with open(os.path.join(OUT_DIR, "weak_reference.json"), "w", encoding="utf-8") as f:
        json.dump(weak_reference(), f, indent=1)
    print("weak_reference.json:", weak_reference())
    for out_name, pcap in SAMPLES.items():
        resp = analyze_path(os.path.join(SAMPLES_DIR, pcap), pcap)
        with open(os.path.join(OUT_DIR, out_name), "w", encoding="utf-8") as f:
            json.dump(resp, f, indent=1)
        print(f"{out_name}: {pcap} -> score {resp['score']} {resp['risk_level']}, {resp['traffic']['label']}")
