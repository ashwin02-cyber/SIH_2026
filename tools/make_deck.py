"""
make_deck.py - builds docs/IPsec_VPN_Analyzer_Deck.pptx with python-pptx.

Numbers on the slides are read from ml-engineer/metrics.json and shortcut_check.json, so they
cannot drift from the real results. Images come from docs/ (architecture, screenshots).

    python tools/make_deck.py
"""
import json
import os

import fitz  # PyMuPDF (dev requirement) - only used to turn the sample report page into a picture
from PIL import Image
from pptx import Presentation
from pptx.dml.color import RGBColor
from pptx.enum.text import PP_ALIGN
from pptx.util import Emu, Inches, Pt

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
DOCS = os.path.join(ROOT, "docs")
OUT = os.path.join(DOCS, "IPsec_VPN_Analyzer_Deck.pptx")

NAVY, BLUE, INK, MUTED = RGBColor(0x14, 0x20, 0x3A), RGBColor(0x2B, 0x7B, 0xB9), RGBColor(0x1D, 0x24, 0x33), RGBColor(0x5B, 0x64, 0x79)
WHITE, PALE, AMBER, RED = RGBColor(255, 255, 255), RGBColor(0xEE, 0xF1, 0xF7), RGBColor(0xB2, 0x6A, 0x00), RGBColor(0xC6, 0x28, 0x28)
W, H = Inches(13.333), Inches(7.5)


def load_json(*parts):
    with open(os.path.join(ROOT, *parts), encoding="utf-8") as f:
        return json.load(f)


def prepare_images():
    """Crop the dashboard screenshot and render page 1 of the sample executive report."""
    shots = os.path.join(DOCS, "screenshots")
    im = Image.open(os.path.join(shots, "03-weak-icmp.png"))
    im.crop((0, 0, im.width, min(im.height, 1040))).save(os.path.join(shots, "dashboard-top.png"))
    pdf = fitz.open(os.path.join(DOCS, "sample_reports", "sample-executive.pdf"))
    pdf[0].get_pixmap(dpi=110).save(os.path.join(shots, "report-executive-p1.png"))
    return {"dashboard": os.path.join(shots, "dashboard-top.png"),
            "report": os.path.join(shots, "report-executive-p1.png"),
            "arch": os.path.join(DOCS, "architecture.png"),
            "cm": os.path.join(ROOT, "ml-engineer", "confusion_matrix.png")}


class Deck:
    def __init__(self):
        self.prs = Presentation()
        self.prs.slide_width, self.prs.slide_height = W, H
        self.blank = self.prs.slide_layouts[6]

    def slide(self, title, notes, subtitle=None):
        s = self.prs.slides.add_slide(self.blank)
        band = s.shapes.add_shape(1, 0, 0, W, Inches(1.15))
        band.fill.solid(); band.fill.fore_color.rgb = NAVY; band.line.fill.background()
        self.text(s, title, 0.5, 0.18, 12.3, 0.8, size=30, bold=True, color=WHITE)
        if subtitle:
            self.text(s, subtitle, 0.5, 1.25, 12.3, 0.5, size=16, color=MUTED)
        s.notes_slide.notes_text_frame.text = notes
        return s

    def text(self, s, text, x, y, w, h, size=18, bold=False, color=INK, align=None):
        tb = s.shapes.add_textbox(Inches(x), Inches(y), Inches(w), Inches(h))
        tf = tb.text_frame; tf.word_wrap = True
        p = tf.paragraphs[0]; p.text = text
        p.font.size, p.font.bold, p.font.color.rgb = Pt(size), bold, color
        if align:
            p.alignment = align
        return tb

    def bullets(self, s, items, x, y, w, h, size=18):
        tb = s.shapes.add_textbox(Inches(x), Inches(y), Inches(w), Inches(h))
        tf = tb.text_frame; tf.word_wrap = True
        for i, item in enumerate(items):
            p = tf.paragraphs[0] if i == 0 else tf.add_paragraph()
            bold, _, rest = item.partition("||")
            if rest:
                r1 = p.add_run(); r1.text = bold.strip().rstrip(":") + ": "; r1.font.bold = True; r1.font.size = Pt(size); r1.font.color.rgb = INK
                r2 = p.add_run(); r2.text = rest.strip(); r2.font.size = Pt(size); r2.font.color.rgb = INK
            else:
                r = p.add_run(); r.text = item; r.font.size = Pt(size); r.font.color.rgb = INK
            p.space_after = Pt(9)
        return tb

    def image(self, s, path, x, y, max_w, max_h):
        """Place an image scaled to fit inside the box, centred horizontally in it."""
        w, h = Image.open(path).size
        scale = min(max_w / w, max_h / h)
        pw, ph = w * scale, h * scale
        return s.shapes.add_picture(path, Inches(x + (max_w - pw) / 2), Inches(y), Inches(pw), Inches(ph))

    def table(self, s, rows, x, y, w, col_w, size=15):
        t = s.shapes.add_table(len(rows), len(rows[0]), Inches(x), Inches(y), Inches(w), Inches(0.42 * len(rows))).table
        for j, cw in enumerate(col_w):
            t.columns[j].width = Inches(cw)
        for i, row in enumerate(rows):
            for j, val in enumerate(row):
                c = t.cell(i, j); c.text = str(val)
                for p in c.text_frame.paragraphs:
                    p.font.size = Pt(size); p.font.bold = (i == 0)
                    p.font.color.rgb = WHITE if i == 0 else INK
                c.fill.solid(); c.fill.fore_color.rgb = BLUE if i == 0 else (PALE if i % 2 else WHITE)


def pct(x):
    return f"{x * 100 + 1e-9:.1f}".rstrip("0").rstrip(".") + " %"


def main():
    m, sc = load_json("ml-engineer", "metrics.json"), load_json("ml-engineer", "shortcut_check.json")
    img = prepare_images()
    ev, chk = m["evaluation"]["selected"], m["evaluation"]["sanity_checks"]
    d = Deck()

    # 1 title
    s = d.prs.slides.add_slide(d.blank)
    bg = s.shapes.add_shape(1, 0, 0, W, H); bg.fill.solid(); bg.fill.fore_color.rgb = NAVY; bg.line.fill.background()
    d.text(s, "IPsec VPN Traffic Analyzer", 0.8, 2.3, 11.7, 1.2, size=48, bold=True, color=WHITE)
    d.text(s, "Rate a VPN's security and see what runs inside it, from one packet capture", 0.8, 3.6, 11.7, 0.9, size=22, color=RGBColor(0xC9, 0xD6, 0xEA))
    d.text(s, "Smart India Hackathon 2026  |  Problem Statement 26160", 0.8, 5.6, 11.7, 0.5, size=16, color=RGBColor(0xC9, 0xD6, 0xEA))
    s.notes_slide.notes_text_frame.text = ("Introduce the team and the problem statement. One sentence: we analyse an IPsec capture and answer "
                                           "two questions - how well is it secured, and what traffic is inside it - without decrypting anything.")

    # 2 problem
    s = d.slide("The problem: encrypted does not mean understood",
                "IPsec hides the payload. But defenders still need to know if the VPN is configured safely, and what kind of traffic crosses it. Both must be answered from a passive capture.")
    d.bullets(s, ["Is the VPN configured well?||  Cipher, key exchange group, forward secrecy, tunnel vs transport mode.",
                  "What is inside the tunnel?||  Web, video, voice, file transfer, ping - without decrypting.",
                  "Hard part:||  only the first IKE message (IKE_SA_INIT) is readable; everything after it is encrypted.",
                  "Our stance:||  never present a guess as a measurement - every value is tagged observed / declared / unknown."],
             0.7, 1.7, 12, 4.8, size=22)

    # 3 solution
    s = d.slide("What we built", "Walk through the four capabilities and the dashboard.")
    d.bullets(s, ["Security score 0-100||  LOW / MEDIUM / HIGH, capped by assessment completeness so unknowns never read as 100 / LOW",
                  "Passive ESP fingerprint||  cipher family, integrity-tag candidates, tunnel vs transport, replay and rekey evidence - from sizes and sequence numbers only",
                  "Traffic classification||  Random Forest on 1-second windows, calibrated confidence, 'unrecognised' for unknown traffic",
                  "Recommendations||  prioritised fixes, a generated strongSwan snippet (unverified), before / after score",
                  "What-if + replay||  defence simulator; replay of a capture file (not live sniffing)",
                  "Reports||  executive summary and technical report, HTML and PDF; plain-English mode"],
             0.7, 1.6, 12, 5.2, size=20)

    # 4 architecture
    s = d.slide("Architecture", "Offline: testbed to pcaps to features to a trained model. Online: React talks to FastAPI; the backend combines the IKE parser, scoring, the ML model and the report builder behind one API contract.")
    d.image(s, img["arch"], 0.6, 1.35, 12.1, 5.9)

    # 5 security score
    s = d.slide("How the security score works",
                "The parser walks the IKE_SA_INIT exchange by hand from RFC 7296 and validates every header. Values that are not visible stay unknown: excluded from the base score (never counted as weak) but they lower the completeness percentage and therefore the cap.")
    d.table(s, [["Factor", "Weight", "Strong", "Medium", "Weak"],
                ["Cipher", "0.4", "AES-GCM, AES-256", "AES-CBC-128", "3DES"],
                ["DH group", "0.4", "19, 20, 21, 31, 16", "14, 15", "1, 2, 5"],
                ["PFS", "0.2", "fresh DH", "-", "none"]],
            0.7, 1.7, 12, [2.2, 1.4, 3.2, 2.6, 2.6], size=16)
    d.bullets(s, ["Base score = weighted average of the rated factors; risk: >= 80 LOW, >= 50 MEDIUM, else HIGH",
                  "Assessment completeness: every finding is observed / inferred / declared / unknown; the final score is capped at 35 + 65 x completeness",
                  "Real finding: none of our 216 captures contains a readable IKE_SA_INIT, so a real testbed file reads 64 / MEDIUM (44 % complete), not 100 / LOW"],
             0.7, 3.8, 12, 3.2, size=19)

    # 6 ML
    s = d.slide("Traffic classification: what we feed the model",
                "Only ESP packets, because that is what an eavesdropper sees. Decrypted duplicates in tunnel-mode captures are removed. Windows are fixed at one second. We removed packet_count, total_bytes and duration.")
    d.bullets(s, [f"{len(m['features'])} features per {m['window_sec']:g}-second window||  packets/s, bytes/s, packet-size stats, inter-arrival stats, direction ratios",
                  "ESP only||  IKE and the decrypted copies present in tunnel-mode files are excluded",
                  "Dropped on purpose||  packet_count, total_bytes, duration: they reflect when tcpdump stopped",
                  f"Data||  {m['data']['captures']} captures, {m['data']['windows']:,} windows, {m['data']['vpn_configs']} VPN configurations",
                  f"Model||  {m['selected_model'].replace('_', ' ').title()}, class-weighted; SHAP explains each prediction"],
             0.7, 1.7, 12, 5, size=21)

    # 7 evaluation
    s = d.slide("Honest evaluation: tested on VPN configs it never saw",
                "Cross-validation is grouped by VPN configuration so every test fold contains unseen configurations. The 100 percent says the five scripted traffic types are easy to tell apart. It is not a claim about real user traffic.")
    d.table(s, [["Check", "Result"],
                ["Random Forest, per 1-second window", pct(ev["window_level"]["accuracy"])],
                ["Random Forest, per capture", pct(ev["capture_level"]["accuracy"])],
                ["Majority-class baseline (window)", pct(chk["majority_class_window_accuracy"])],
                ["Shuffled labels (window)", pct(chk["label_shuffled_window_accuracy"])],
                ["Without rate features", pct(chk["without_rate_features"]["window_accuracy"])],
                ["OLD shortcut: packet_count alone", pct(sc["accuracy_from_packet_count_alone_grouped_cv"])]],
            0.5, 1.5, 5.5, [3.7, 1.8], size=14)
    d.image(s, img["cm"], 6.2, 1.5, 6.9, 3.6)
    d.text(s, "Very high because the scripted traffic types differ a lot; lab data, not real-world proof.", 0.5, 5.1, 12.3, 0.9, size=17, bold=True, color=AMBER)

    # 8 findings
    s = d.slide("What we found in our own data",
                "These are the things a reviewer would otherwise discover. We found them, fixed what we could, and documented the rest.")
    d.bullets(s, ["No readable IKE_SA_INIT||  the 'handshake' captures held only encrypted keep-alives; most likely tcpdump was killed by a container restart",
                  "PFS labels meaningless||  pfs-on and pfs-off configs were byte-identical; template fixed",
                  "The 100 % was a shortcut||  capture length (tcpdump -c N) alone predicts the class",
                  "Plaintext leaked into captures||  tunnel-mode files include decrypted copies; ESP-only now",
                  "Fixed testbed not yet re-run||  Docker was unavailable; command order is tested with a fake Docker"],
             0.7, 1.7, 12, 5.2, size=20)

    fpm = load_json("ml-engineer", "esp_fingerprint_metrics.json")
    osm = load_json("ml-engineer", "open_set_metrics.json")
    dfm = load_json("ml-engineer", "defence_metrics.json")
    ru, md = fpm["cipher_family_rule"]["overall"], fpm["tunnel_vs_transport"]

    # 8b passive fingerprint
    s = d.slide("New: passive ESP fingerprinting from sizes only",
                "No file names, no keys. The ESP length modulo 16 separates CBC (one residue) from GCM (several). The rule abstains on constant-size streams such as ICMP instead of guessing. Say clearly what is not observable: AES-128 vs 256, PFS, authentication method, lifetime unless a rekey is seen.")
    d.table(s, [["Passive inference (grouped CV, 180 captures)", "Result"],
                ["Cipher family: answered / correct when answered", f"{ru['committed']} / {ru['correct_when_committed']}  ({pct(ru['accuracy_when_committed'])})"],
                ["Cipher family: abstains (all ICMP, constant size)", f"{ru['captures'] - ru['committed']} captures"],
                ["Tunnel vs transport: accuracy (all)", pct(md["accuracy"])],
                ["Tunnel vs transport: when it commits (coverage)", f"{pct(md['accuracy_when_committed'])}  ({pct(md['coverage_at_threshold'])})"],
                ["Shuffled-label control (chance 50 %)", pct(md["shuffled_label_accuracy"]["mean"])]],
            0.5, 1.5, 7.6, [5.2, 2.4], size=14)
    d.bullets(s, ["Also||  SPI / sequence analysis: replay evidence, gaps, duplicates, reordering, rekeys",
                  "Not observable||  AES-128 vs 256, PFS, auth method, SA lifetime without a rekey: reported unknown",
                  "Lab data||  scripted traffic, one strongSwan version"],
             8.3, 1.5, 4.7, 4.5, size=16)

    # 8c confidence + defences
    s = d.slide("New: honest confidence, and a defence what-if",
                "Calibration can only soften confidence (temperature floored at 1). Open-set test: each traffic class was held out entirely and shown as unknown traffic. The defence table is a simulation: padding and dummy traffic fool a naive attacker, but an attacker who retrains is back to about 100 percent on this data.")
    rows = [["Defence (simulated)", "Naive attacker", "Adaptive", "Extra bandwidth"]]
    for k in ("pad_buckets", "pad_mtu", "dummy", "delay", "combined"):
        b = dfm["defences"][k]
        rows.append([b["label"], pct(b["non_adaptive_capture_accuracy"]), pct(b["adaptive_capture_accuracy"]), f"+{b['cost']['bandwidth_overhead_pct_median']:.0f} %"])
    d.table(s, rows, 0.5, 1.5, 7.9, [3.2, 1.6, 1.4, 1.7], size=13)
    d.bullets(s, [f"Unrecognised traffic||  {pct(osm['mean_unknown_rejection'])} of held-out-class captures rejected; {pct(osm['mean_known_accepted'])} of known accepted",
                  "Lab limit||  five very different classes; real unknowns will be harder",
                  "Defences||  no defence stopped an adaptive attacker here"],
             8.6, 1.5, 4.4, 4.5, size=15)

    # 9 dashboard
    s = d.slide("The dashboard", "Live demo: upload a capture, read the gauge, threat matrix, traffic chart and timeline. The yellow badges show which values came from the file name.")
    d.image(s, img["dashboard"], 0.4, 1.3, 12.5, 6.0)

    # 10 reports
    s = d.slide("Real reports, generated on demand", "One click generates an executive summary or a technical report as HTML or PDF (Jinja2 to HTML to PDF with xhtml2pdf, no system dependencies).")
    d.image(s, img["report"], 0.6, 1.3, 5.2, 6.0)
    d.bullets(s, ["Executive summary||  risk box, plain-language settings table, rule-based recommendations, what the report cannot tell you",
                  "Technical report||  score arithmetic, IKE parse facts, class probabilities, SHAP, timeline, anomalies, model validation",
                  "Windows-safe||  pure-Python PDF engine: installs with pip, runs on hosting"],
             6.2, 1.7, 6.6, 5, size=19)

    # 11 quality + deployment
    s = d.slide("Quality and deployment",
                "Everything runs locally and in Docker; deployment configs are provided. Deploying needs the team's own Vercel and Render logins, and we say so.")
    d.bullets(s, ["Automated tests||  243 pytest tests (synthetic IKE / ESP / IPv6 / AH fixtures, scoring, ML, API, replay, reports, testbed) + real-browser end-to-end check",
                  "One API contract||  schema 1.1: score + cap, findings with status, recommendations, fingerprint, sequence, defence simulation",
                  "Packaging||  Dockerfiles, docker-compose, Render / Railway / Vercel / Netlify configs, click-by-click DEPLOY.md",
                  "Measured||  ~320 MB RAM for the API after an analysis plus a PDF report"],
             0.7, 1.7, 12, 5, size=20)

    # 12 limits / next
    s = d.slide("Limitations and next steps", "Be upfront: this is a lab dataset. The next milestone is re-running the fixed testbed.")
    d.bullets(s, ["Limits||  one capture per config and class; scripted traffic; short captures for file transfer, VoIP, video; SIP only for VoIP",
                  "Synthetic only||  IKE_SA_INIT, IPv6, AH and rekey behaviour are tested on hand-built fixtures; strongSwan snippet not run (no Docker)",
                  "Replay, not live||  replay mode streams a capture file; live sniffing is not implemented",
                  "Next||  re-run the fixed testbed (real handshakes, real PFS labels, 30 s captures, repeats)",
                  "Next||  non-scripted traffic, IKEv1, authentication and rate limiting for a public deployment"],
             0.7, 1.7, 12, 5, size=21)

    d.prs.save(OUT)
    print("wrote", OUT, f"({len(d.prs.slides)} slides)")


if __name__ == "__main__":
    main()
