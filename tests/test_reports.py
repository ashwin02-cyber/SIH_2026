"""Report generation: Jinja2 -> HTML -> PDF, for both audiences."""
import io
import json
import os
from datetime import datetime, timezone

import pytest
from fastapi.testclient import TestClient
from pypdf import PdfReader

import main
from conftest import ROOT, SAMPLES
from report_builder import recommendations, render_html, render_report

DATA = os.path.join(ROOT, "frontend-developer", "src", "data")
FIXED = datetime(2026, 1, 2, 3, 4, tzinfo=timezone.utc)


def load(name):
    with open(os.path.join(DATA, name), encoding="utf-8") as f:
        return json.load(f)


def pdf_text(blob):
    return "\n".join(p.extract_text() for p in PdfReader(io.BytesIO(blob)).pages)


@pytest.mark.parametrize("kind", ["executive", "technical"])
def test_pdf_is_a_real_pdf_with_the_key_facts(kind):
    a = load("sample_weak.json")
    blob, media = render_report(a, kind, "pdf", generated_at=FIXED)
    assert media == "application/pdf" and blob[:5] == b"%PDF-"
    text = pdf_text(blob)
    assert a["filename"] in text
    assert "HIGH" in text and "30" in text
    assert "AES-CBC-128" in text and "1024-bit" in text
    assert "2026-01-02 03:04 UTC" in text


def test_technical_report_has_the_technical_sections():
    a = load("sample_strong.json")
    text = pdf_text(render_report(a, "technical", "pdf", generated_at=FIXED)[0])
    for needle in ["Score breakdown", "IKE handshake analysis", "Timeline", "SHAP", "Model validation",
                   "IKE_SA_INIT captured", "Random Forest"]:
        assert needle in text, needle
    # real, current metrics are quoted (not typed in by hand)
    metrics = json.load(open(os.path.join(ROOT, "ml-engineer", "metrics.json")))
    acc = round(metrics["evaluation"]["selected"]["window_level"]["accuracy"] * 100, 1)
    assert f"{acc:g}%" in text or f"{acc}%" in text


def test_html_is_self_contained_and_escaped():
    a = load("sample_strong.json")
    a["filename"] = "<script>alert(1)</script>.pcap"
    html = render_html(a, "technical", generated_at=FIXED)
    assert "<script>alert(1)</script>" not in html and "&lt;script&gt;" in html
    assert 'src="data:image/png;base64,' in html and "http://" not in html.replace("http://www.w3.org", "")


def test_declared_basis_is_disclosed_in_both_reports():
    a = load("sample_strong.json")
    assert a["score_basis"] == "declared"
    for kind in ("executive", "technical"):
        html = render_html(a, kind, generated_at=FIXED)
        assert "declared" in html.lower() and "file name" in html.lower()


def test_unknown_analysis_still_renders():
    from contract import build_response
    a = build_response("capture.pcap", None, None, errors=["Traffic classification: No IP packets found"])
    for kind in ("executive", "technical"):
        blob, _ = render_report(a, kind, "pdf", generated_at=FIXED)
        text = pdf_text(blob)
        assert "UNKNOWN" in text and "No IP packets found" in text
        assert "Traceback" not in text


def test_recommendations_follow_ratings():
    weak = recommendations(load("sample_weak.json"))
    text = " ".join(t for _, t in weak)
    assert any(p == "High" for p, _ in weak) and "elliptic-curve" in text and "Perfect Forward Secrecy" in text
    assert "tunnel mode" in text
    strong = " ".join(t for _, t in recommendations(load("sample_strong.json")))
    assert "weak Diffie-Hellman" not in strong


def test_reports_contain_recommendations_snippet_and_before_after():
    a = load("sample_weak.json")
    text = pdf_text(render_report(a, "technical", "pdf", generated_at=FIXED)[0])
    for needle in ("Recommendations and secure configuration", "keyexchange=ikev2", "aes256gcm16", "NOT verified", "Before / after"):
        assert needle in text, needle
    ex = pdf_text(render_report(a, "executive", "pdf", generated_at=FIXED)[0])
    assert "projection, not a measurement" in ex and "cannot reach 100" in ex


def test_report_endpoint_returns_downloadable_files():
    client = TestClient(main.app)
    a = load("sample_strong.json")
    for kind in ("executive", "technical"):
        r = client.post(f"/report/{kind}.pdf", json=a)
        assert r.status_code == 200 and r.content[:5] == b"%PDF-"
        assert "attachment" in r.headers["content-disposition"] and kind in r.headers["content-disposition"]
    r = client.post("/report/executive.html", json=a)
    assert r.status_code == 200 and "text/html" in r.headers["content-type"]
    assert client.post("/report/secret.pdf", json=a).status_code == 404
    assert client.post("/report/executive.docx", json=a).status_code == 404
    assert client.post("/report/executive.pdf", json={"nonsense": 1}).status_code == 422


def test_technical_report_has_the_labelled_defence_simulation():
    from fastapi.testclient import TestClient
    import main
    a = TestClient(main.app).post("/analyze/sample/aes128gcm16-dh19-tunnel-pfs-on__web_run1.pcap").json()
    text = pdf_text(render_report(a, "technical", "pdf", generated_at=FIXED)[0])
    for needle in ("Defence what-if (SIMULATION)", "nothing was re-sent", "Adaptive attacker", "Naive attacker", "Bandwidth"):
        assert needle in text, needle
