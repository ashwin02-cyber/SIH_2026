"""
report_builder.py
Turns an analysis (the /analyze contract response) into an executive or technical
report:   Jinja2 template  ->  HTML  ->  PDF.

PDF engine: xhtml2pdf (pure Python on top of ReportLab). It was chosen because it needs
no system libraries, so it installs with plain `pip install` on Windows, Linux and on
Render/Railway. (WeasyPrint needs GTK/Pango on Windows; wkhtmltopdf and headless
Chrome are separate programs to install.)  The HTML files are self-contained (charts
are embedded as data: URIs) and open in any browser.

    from report_builder import render_report
    data, media_type = render_report(analysis, "executive", "pdf")   # bytes, "application/pdf"

CLI:
    python report_builder.py analysis.json out_dir      # writes executive+technical .html/.pdf
"""

import base64
import io
import json
import os
import re
import sys
from datetime import datetime, timezone

import matplotlib

matplotlib.use("Agg")
import matplotlib.pyplot as plt  # noqa: E402
from jinja2 import Environment, FileSystemLoader, select_autoescape  # noqa: E402

HERE = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.abspath(os.path.join(HERE, ".."))
METRICS_PATH = os.path.join(REPO, "ml-engineer", "metrics.json")

RISK_COLOR = {"LOW": "#2e7d32", "MEDIUM": "#b26a00", "HIGH": "#c62828", "UNKNOWN": "#616161"}
RATING_COLOR = {"strong": "#2e7d32", "medium": "#b26a00", "weak": "#c62828", "unknown": "#616161", "info": "#2b7bb9"}
CLASS_COLOR = {"web_browsing": "#2b7bb9", "video_streaming": "#7c4dcc", "voip": "#1e9e73",
               "file_transfer": "#d19a00", "icmp": "#d64545"}
RATING_POINTS = {"weak": 0, "medium": 60, "strong": 100}

_env = Environment(loader=FileSystemLoader(os.path.join(HERE, "templates")),
                   autoescape=select_autoescape(["html", "j2"]))

_REPLACEMENTS = {"→": "->", "≥": ">=", "≤": "<=", "‘": "'", "’": "'", "“": '"',
                 "”": '"', "…": "...", "×": "x", "✓": "yes", "•": "-"}


def _safe(text):
    """The PDF engine uses the standard Latin-1 fonts: swap the few characters outside them."""
    if not isinstance(text, str):
        return text
    for a, b in _REPLACEMENTS.items():
        text = text.replace(a, b)
    return text


def _png_data_uri(fig):
    buf = io.BytesIO()
    fig.savefig(buf, format="png", dpi=150, bbox_inches="tight", facecolor="white")
    plt.close(fig)
    return "data:image/png;base64," + base64.b64encode(buf.getvalue()).decode("ascii")


def timeline_chart(analysis):
    tl = analysis.get("timeline") or []
    if not tl:
        return None
    fig, ax = plt.subplots(figsize=(7.2, 2.3))
    ax.bar([t["start_sec"] for t in tl], [t["confidence"] for t in tl], width=0.85 * (tl[0]["end_sec"] - tl[0]["start_sec"]),
           align="edge", color=[CLASS_COLOR.get(t["class"], "#2b7bb9") for t in tl])
    ax.set_ylim(0, 1.05)
    ax.set_ylabel("Model confidence")
    ax.set_xlabel("Seconds from start of capture")
    ax.spines[["top", "right"]].set_visible(False)
    seen = list(dict.fromkeys((t["class"], t["label"]) for t in tl))
    ax.legend(handles=[plt.Rectangle((0, 0), 1, 1, color=CLASS_COLOR.get(c, "#2b7bb9")) for c, _ in seen],
              labels=[label for _, label in seen], fontsize=8, loc="lower right", ncol=len(seen), frameon=False)
    return _png_data_uri(fig)


def probability_chart(analysis):
    traffic = analysis.get("traffic")
    if not traffic:
        return None
    probs = list(reversed(traffic["probabilities"]))
    fig, ax = plt.subplots(figsize=(6.0, 2.0))
    ax.barh([p["name"] for p in probs], [p["value"] for p in probs],
            color=["#2b7bb9" if i == len(probs) - 1 else "#a9c7df" for i in range(len(probs))])
    ax.set_xlim(0, 1)
    ax.set_xlabel("Average probability across time windows")
    ax.spines[["top", "right"]].set_visible(False)
    return _png_data_uri(fig)


def recommendations(analysis):
    """Deterministic, rule-based advice derived from the ratings (no free-text generation)."""
    recs = []
    by = {b["factor"]: b for b in analysis["breakdown"]}
    dh, cipher, pfs, mode = by.get("DH group"), by.get("Cipher"), by.get("PFS"), by.get("Mode")
    if dh and dh["rating"] == "weak":
        recs.append(("High", f"The key-exchange group, {dh['value']}, is too small for modern threats. "
                             "Switch to DH group 14 at minimum, preferably an elliptic-curve group (19, 20 or 21)."))
    elif dh and dh["rating"] == "medium":
        recs.append(("Medium", f"The key-exchange group, {dh['value']}, is acceptable today but has little safety "
                               "margin. Consider an elliptic-curve group (19 or higher)."))
    if cipher and cipher["rating"] == "weak":
        recs.append(("High", f"Replace the cipher, {cipher['value']}, with AES-GCM."))
    elif cipher and cipher["rating"] == "medium":
        recs.append(("Medium", f"Prefer an AES-GCM cipher over {cipher['value']}: it protects integrity as well as "
                               "confidentiality and needs no separate HMAC."))
    if pfs and pfs["rating"] == "weak":
        recs.append(("High", "Enable Perfect Forward Secrecy so a leaked key cannot expose past traffic."))
    elif pfs and pfs["rating"] == "unknown":
        recs.append(("Medium", "Confirm in the VPN gateway configuration that Perfect Forward Secrecy is enabled. "
                               "It cannot be seen in a passive capture."))
    if mode and mode["value"] == "transport":
        recs.append(("Low", "Transport mode leaves the original IP header visible. Use tunnel mode for "
                            "gateway-to-gateway links unless transport mode is required."))
    if analysis["score_basis"] in ("declared", "mixed"):
        recs.append(("Medium", "Repeat the analysis with a capture that includes the IKE negotiation (start the "
                               "capture before the tunnel comes up), so the settings are read from the traffic "
                               "itself instead of from the file name."))
    if any(a["severity"] in ("HIGH", "MEDIUM") for a in analysis["anomalies"]):
        recs.append(("Medium", "Review the flagged traffic anomalies and confirm the activity was expected."))
    if not recs:
        recs.append(("Low", "No changes needed for the factors that could be checked. Re-run the analysis after "
                            "any configuration change."))
    return recs


def _load_metrics():
    try:
        with open(METRICS_PATH, encoding="utf-8") as f:
            return json.load(f)
    except (OSError, ValueError):
        return None


def _score_rows(analysis):
    rated = [b for b in analysis["breakdown"] if b["weight"] > 0 and b["rating"] != "unknown"]
    total = sum(b["weight"] for b in rated) or 1.0
    rows = []
    for b in analysis["breakdown"]:
        if b["weight"] > 0 and b["rating"] != "unknown":
            pts = RATING_POINTS[b["rating"]]
            contribution = round(pts * b["weight"] / total, 1)
        else:
            pts, contribution = None, None
        rows.append({**b, "points": pts, "contribution": contribution})
    return rows


def build_context(analysis, generated_at=None):
    ts = generated_at or datetime.now(timezone.utc)
    ctx = {
        "a": analysis,
        "generated": ts.strftime("%Y-%m-%d %H:%M UTC"),
        "risk_color": RISK_COLOR[analysis["risk_level"]],
        "rating_color": RATING_COLOR,
        "recommendations": recommendations(analysis),
        "timeline_img": timeline_chart(analysis),
        "prob_img": probability_chart(analysis),
        "score_rows": _score_rows(analysis),
        "metrics": _load_metrics(),
    }
    return ctx


def render_html(analysis, kind, generated_at=None):
    if kind not in ("executive", "technical"):
        raise ValueError("kind must be 'executive' or 'technical'")
    html = _env.get_template(f"{kind}.html.j2").render(**build_context(analysis, generated_at))
    return _safe(html)


def html_to_pdf(html):
    from xhtml2pdf import pisa
    out = io.BytesIO()
    result = pisa.CreatePDF(src=html, dest=out, encoding="utf-8")
    if result.err:
        raise RuntimeError(f"PDF generation reported {result.err} error(s)")
    return out.getvalue()


def render_report(analysis, kind, fmt, generated_at=None):
    """Returns (bytes, media_type)."""
    html = render_html(analysis, kind, generated_at)
    if fmt == "html":
        return html.encode("utf-8"), "text/html; charset=utf-8"
    if fmt == "pdf":
        return html_to_pdf(html), "application/pdf"
    raise ValueError("fmt must be 'html' or 'pdf'")


if __name__ == "__main__":
    if len(sys.argv) != 3:
        sys.exit("Usage: python report_builder.py analysis.json out_dir")
    with open(sys.argv[1], encoding="utf-8") as f:
        data = json.load(f)
    os.makedirs(sys.argv[2], exist_ok=True)
    base = re.sub(r"\.[^.]+$", "", data["filename"])
    for k in ("executive", "technical"):
        for fm in ("html", "pdf"):
            blob, _ = render_report(data, k, fm)
            path = os.path.join(sys.argv[2], f"{base}-{k}.{fm}")
            with open(path, "wb") as out:
                out.write(blob)
            print("wrote", path)
