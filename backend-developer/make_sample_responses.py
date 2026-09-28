"""
make_sample_responses.py
Regenerates the frontend's bundled sample analyses from REAL API output.

The React app ships ten sample responses (so it can show a full dashboard even
when the backend is not running). They are not hand-written mock numbers: they are
what POST /analyze returns for ten of the real captures in real_captures/ (read
directly from there, not from data/samples/, so this never collides with the
fixture pcaps that data/samples/ already holds for other tests).
Rerun this after changing the models or the scoring, then rebuild the frontend:

    cd backend-developer
    python make_sample_responses.py
"""

import json
import os
import re
import sys
import warnings

warnings.filterwarnings("ignore")
HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)

from contract import _cipher_string, _dh_string, _pfs_string  # noqa: E402
from main import analyze_path  # noqa: E402
from scoring_engine import score_ike_facts  # noqa: E402

OUT_DIR = os.path.join(HERE, "..", "frontend-developer", "src", "data")
REAL_CAPTURES_DIR = os.path.join(HERE, "..", "real_captures")

# Ten real sample captures, one JSON file each, numbered sample_1_*.json .. sample_10_*.json.
# The slug after the number is the pcap's own config name (cipher-dh-mode-pfs), so the
# filename alone tells you what's inside without opening it.
SAMPLE_PCAPS = [
    "aes256-dh2-tunnel-pfs-off__handshake.pcap",
    "aes128-dh14-tunnel-pfs-on__handshake.pcap",
    "aes128gcm16-dh19-transport-pfs-off__handshake.pcap",
    "aes256-dh14-tunnel-pfs-on__handshake.pcap",
    "aes128-dh2-transport-pfs-off__handshake.pcap",
    "aes256-dh19-tunnel-pfs-off__handshake.pcap",
    "aes128gcm16-dh2-tunnel-pfs-on__handshake.pcap",
    "aes128-dh19-transport-pfs-on__handshake.pcap",
    "aes256-dh14-transport-pfs-on__handshake.pcap",
    "aes128gcm16-dh14-tunnel-pfs-off__handshake.pcap",
]


def _out_name(index, pcap):
    slug = re.sub(r"_run\d+\.pcap$", "", pcap).replace(".pcap", "")
    return f"sample_{index}_{slug}.json"


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


def build_sample_files_entry(index, out_name, pcap, resp):
    traffic = resp.get("traffic") or {}
    return {
        "id": index,
        "file": out_name,
        "pcap": pcap,
        "title": re.sub(r"(_run\d+)?\.pcap$", "", pcap).replace("__handshake", "").replace("__", " — ")
                   .replace("-", " ").replace("pfs ", "PFS "),
        "cipher": resp["cipher"],
        "dh_group": resp["dh_group"],
        "mode": resp["mode"],
        "pfs": resp["pfs"],
        "traffic_label": traffic.get("label"),
        "ml_confidence": traffic.get("confidence"),
        "risk_level": resp["risk_level"],
        "score": resp["score"],
    }


if __name__ == "__main__":
    os.makedirs(OUT_DIR, exist_ok=True)
    with open(os.path.join(OUT_DIR, "weak_reference.json"), "w", encoding="utf-8") as f:
        json.dump(weak_reference(), f, indent=1)
    print("weak_reference.json:", weak_reference())

    sample_files = []
    for i, pcap in enumerate(SAMPLE_PCAPS, start=1):
        out_name = _out_name(i, pcap)
        resp = analyze_path(os.path.join(REAL_CAPTURES_DIR, pcap), pcap)
        with open(os.path.join(OUT_DIR, out_name), "w", encoding="utf-8") as f:
            json.dump(resp, f, indent=1)
        traffic_label = resp["traffic"]["label"] if resp["traffic"] else "no traffic classified"
        print(f"{out_name}: {pcap} -> score {resp['score']} {resp['risk_level']}, {traffic_label}")
        sample_files.append(build_sample_files_entry(i, out_name, pcap, resp))

    with open(os.path.join(OUT_DIR, "sampleFiles.json"), "w", encoding="utf-8") as f:
        json.dump(sample_files, f, indent=1)
    print(f"sampleFiles.json: {len(sample_files)} entries")
