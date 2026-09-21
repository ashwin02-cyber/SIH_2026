"""make_diagram.py - draws docs/architecture.png (used by the docs and the slide deck)."""
import os

import matplotlib

matplotlib.use("Agg")
import matplotlib.pyplot as plt  # noqa: E402
from matplotlib.patches import FancyArrowPatch, FancyBboxPatch  # noqa: E402

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
OUT = os.path.join(ROOT, "docs", "architecture.png")

INK, MUTED = "#14203a", "#5b6479"
BLUE, GREEN, AMBER, PURPLE, GREY = "#dbe9f6", "#dcf1e4", "#fbeccb", "#e7defa", "#eceff5"


def box(ax, x, y, w, h, title, lines=(), fc=BLUE, ec="#7a8aa8"):
    ax.add_patch(FancyBboxPatch((x, y), w, h, boxstyle="round,pad=0.02,rounding_size=0.12", fc=fc, ec=ec, lw=1.2))
    ax.text(x + w / 2, y + h - 0.22, title, ha="center", va="top", fontsize=10.5, fontweight="bold", color=INK)
    for i, line in enumerate(lines):
        ax.text(x + w / 2, y + h - 0.62 - i * 0.3, line, ha="center", va="top", fontsize=8.2, color=MUTED)


def arrow(ax, x1, y1, x2, y2, label="", both=False, rad=0.0):
    ax.add_patch(FancyArrowPatch((x1, y1), (x2, y2), arrowstyle="<|-|>" if both else "-|>", mutation_scale=14,
                                 lw=1.6, color=INK, connectionstyle=f"arc3,rad={rad}"))
    if label:
        ax.text((x1 + x2) / 2, (y1 + y2) / 2 + 0.18, label, ha="center", fontsize=8, color=INK)


def main():
    fig, ax = plt.subplots(figsize=(13, 7.2))
    ax.set_xlim(0, 13)
    ax.set_ylim(0, 7.2)
    ax.axis("off")

    ax.text(0.2, 6.95, "IPsec VPN Analyzer - architecture", fontsize=15, fontweight="bold", color=INK, va="top")

    # ---- offline: dataset + training --------------------------------------------------------
    ax.text(0.2, 6.35, "OFFLINE: build the dataset and train the model", fontsize=9.5, color=MUTED, fontweight="bold")
    box(ax, 0.2, 4.55, 2.9, 1.65, "strongSwan testbed", ["2 peers in Docker", "36 configs (cipher x DH x", "mode x PFS), 5 traffic types"], AMBER)
    box(ax, 3.7, 4.55, 2.6, 1.65, "Labelled pcaps", ["216 captures + manifest.csv", "tcpdump before tunnel up,", "stopped by time (30 s)"], GREY)
    box(ax, 6.9, 4.55, 3.0, 1.65, "Feature extraction", ["ESP packets only, 1 s windows,", "12 features (no packet_count)", "traffic_features.py"], GREEN)
    box(ax, 10.4, 4.55, 2.4, 1.65, "Training", ["Random Forest, CV grouped", "by VPN config", "-> models + metrics.json"], PURPLE)
    arrow(ax, 3.1, 5.37, 3.7, 5.37)
    arrow(ax, 6.3, 5.37, 6.9, 5.37)
    arrow(ax, 9.9, 5.37, 10.4, 5.37)

    # ---- online: the app ----------------------------------------------------------------------
    ax.text(0.2, 4.1, "ONLINE: analyse an uploaded capture", fontsize=9.5, color=MUTED, fontweight="bold")
    box(ax, 0.2, 0.35, 3.1, 3.4, "React dashboard", ["Upload .pcap / try a sample", "Risk gauge, threat matrix", "Traffic chart + timeline", "Plain-English toggle",
                                                     "Report download", "(Vercel / Netlify)"], BLUE)
    ax.add_patch(FancyBboxPatch((4.4, 0.35), 8.4, 3.4, boxstyle="round,pad=0.02,rounding_size=0.12", fc="white", ec="#7a8aa8", lw=1.2, ls="--"))
    ax.text(8.6, 3.55, "FastAPI backend  (Render / Railway)", ha="center", va="top", fontsize=10.5, fontweight="bold", color=INK)
    box(ax, 4.6, 1.95, 2.5, 1.2, "ike_parser", ["IKE_SA_INIT: cipher, DH,", "observed vs unknown"], GREEN)
    box(ax, 7.4, 1.95, 2.3, 1.2, "scoring_engine", ["0-100 score, LOW/MED/HIGH"], GREEN)
    box(ax, 10.0, 1.95, 2.6, 1.2, "predict (ML)", ["traffic class, SHAP,", "anomalies, timeline"], PURPLE)
    box(ax, 4.6, 0.5, 4.0, 1.1, "contract.py", ["ONE response shape; every value tagged", "observed / declared / unknown"], AMBER)
    box(ax, 8.9, 0.5, 3.7, 1.1, "report_builder", ["Jinja2 -> HTML -> PDF", "executive + technical"], BLUE)
    arrow(ax, 3.3, 2.0, 4.4, 2.0, "POST /analyze", both=True)
    arrow(ax, 6.1, 1.95, 6.1, 1.6)
    arrow(ax, 8.55, 1.95, 7.6, 1.6)
    arrow(ax, 11.3, 1.95, 8.3, 1.45, rad=0.15)
    arrow(ax, 8.6, 1.05, 8.9, 1.05)

    # models feed the backend
    arrow(ax, 11.6, 4.55, 11.3, 3.15, "models", rad=-0.1)

    fig.savefig(OUT, dpi=140, bbox_inches="tight", facecolor="white")
    print("wrote", OUT)


if __name__ == "__main__":
    main()
