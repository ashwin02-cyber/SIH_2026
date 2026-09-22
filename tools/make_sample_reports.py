"""
make_sample_reports.py - creates the sample security assessment in docs/sample_reports/ from a REAL capture.

    python tools/make_sample_reports.py

It analyses data/samples/aes128-dh2-transport-pfs-off__web_run1.pcap (a real testbed capture) with the
same code path the API uses, then renders the executive and technical reports (PDF + HTML).
"""
import json
import os
import sys
import warnings

warnings.filterwarnings("ignore")
ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
for sub in ("backend-developer", "ml-engineer", "reports"):
    sys.path.insert(0, os.path.join(ROOT, sub))

from main import analyze_path  # noqa: E402
from report_builder import render_report  # noqa: E402

PCAP = "aes128-dh2-transport-pfs-off__web_run1.pcap"
OUT = os.path.join(ROOT, "docs", "sample_reports")


def main():
    os.makedirs(OUT, exist_ok=True)
    analysis = analyze_path(os.path.join(ROOT, "data", "samples", PCAP), PCAP)
    with open(os.path.join(OUT, "analysis.json"), "w", encoding="utf-8") as f:
        json.dump(analysis, f, indent=1)
    for kind in ("executive", "technical"):
        for fmt in ("pdf", "html"):
            blob, _ = render_report(analysis, kind, fmt)
            with open(os.path.join(OUT, f"sample-{kind}.{fmt}"), "wb") as f:
                f.write(blob)
    print(f"score {analysis['score']} {analysis['risk_level']} ({analysis['score_basis']}), "
          f"traffic {analysis['traffic']['label']}; wrote {OUT}")


if __name__ == "__main__":
    main()
