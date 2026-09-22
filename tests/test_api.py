"""End-to-end tests of the FastAPI app (real sample captures, real models)."""
import os

from fastapi.testclient import TestClient

import main
from contract import validate_response
from conftest import SAMPLES, FIXTURES

client = TestClient(main.app)
WEB = "aes128gcm16-dh19-tunnel-pfs-on__web_run1.pcap"
ICMP_WEAK = "aes128-dh2-transport-pfs-off__icmp_run1.pcap"


def upload(path, name=None, content_type="application/octet-stream"):
    with open(path, "rb") as f:
        return client.post("/analyze", files={"file": (name or os.path.basename(path), f, content_type)})


def test_health():
    r = client.get("/health")
    assert r.status_code == 200
    body = r.json()
    assert body["status"] == "ok" and body["ml_model_loaded"] is True and body["ml_import_error"] is None


def test_analyze_real_capture_returns_valid_contract():
    r = upload(os.path.join(SAMPLES, WEB))
    assert r.status_code == 200
    body = r.json()
    assert validate_response(body) == []
    assert body["traffic"]["class"] == "web_browsing"
    assert body["model_confidence"] == body["traffic"]["confidence"] > 0.5
    assert body["timeline"] and body["errors"] == []


def test_declared_values_are_labelled_and_pfs_stays_unknown():
    """The real captures contain no cleartext IKE_SA_INIT, so cipher/DH come from the file name and are marked
    declared, never observed; the mode is inferred from packet sizes. PFS is unknowable (v1 configs were identical)."""
    body = upload(os.path.join(SAMPLES, WEB)).json()
    assert body["sources"] == {"cipher": "declared", "dh_group": "declared", "pfs": "unknown", "mode": "inferred"}
    assert body["score_basis"] == "declared"
    assert body["cipher"] == "AES-GCM-16-128"
    assert body["dh_group"].startswith("Group 19")
    assert body["mode"] == "tunnel" and body["pfs"] == "unknown"
    pfs = next(b for b in body["breakdown"] if b["factor"] == "PFS")
    assert pfs["rating"] == "unknown"
    assert any("file name" in line for line in body["explanation"])


def test_score_is_never_100_low_when_key_facts_are_unknown():
    body = upload(os.path.join(SAMPLES, WEB)).json()
    a = body["assessment"]
    assert body["raw_score"] == 100                     # the facts that ARE known are all strong ...
    assert a["completeness_pct"] < 69 and "Perfect Forward Secrecy" in a["unknown_facts"]
    assert body["score"] == a["score_cap"] < 80 and body["risk_level"] == "MEDIUM"   # ... but the score is capped
    assert a["score_capped"] is True
    assert any("capped" in line for line in body["explanation"])


def test_weak_config_gets_worse_score_than_strong():
    weak = upload(os.path.join(SAMPLES, ICMP_WEAK)).json()
    strong = upload(os.path.join(SAMPLES, WEB)).json()
    assert validate_response(weak) == []
    assert weak["score"] < strong["score"]
    assert weak["risk_level"] in ("MEDIUM", "HIGH")
    assert weak["mode"] == "transport" and weak["dh_group"].startswith("Group 2 ")


def test_without_a_declared_config_the_app_still_infers_from_packet_sizes():
    """Same bytes, an unrelated file name: nothing can be declared, but cipher family and mode are INFERRED from
    the packets (never from the name), the DH group stays unknown, and the score stays capped."""
    body = upload(os.path.join(SAMPLES, WEB), name="capture.pcap").json()
    assert validate_response(body) == []
    assert body["sources"] == {"cipher": "inferred", "dh_group": "unknown", "pfs": "unknown", "mode": "inferred"}
    assert body["mode"] == "tunnel" and "GCM" in body["cipher"] and "key length unknown" in body["cipher"]
    assert body["confidence"]["cipher"] >= 0.9 and body["confidence"]["mode"] >= 0.75
    assert body["score_basis"] == "inferred" and body["risk_level"] != "LOW" and body["score"] <= body["assessment"]["score_cap"]
    assert body["traffic"] is not None


def test_nothing_known_gives_unknown_risk_not_a_guess():
    """A real ping capture (constant packet size) under an unrelated name: nothing about the cipher can be inferred."""
    body = upload(os.path.join(SAMPLES, "aes128gcm16-dh19-tunnel-pfs-on__icmp_run1.pcap"), name="capture.pcap").json()
    assert validate_response(body) == []
    assert body["sources"]["cipher"] == "unknown" and body["sources"]["dh_group"] == "unknown"
    assert body["score"] is None and body["risk_level"] == "UNKNOWN" and body["score_basis"] == "none"
    assert body["cipher"] == "unknown" and body["dh_group"] == "unknown"


def test_inferred_fields_do_not_depend_on_the_file_name():
    a = upload(os.path.join(SAMPLES, WEB)).json()
    b = upload(os.path.join(SAMPLES, WEB), name="zz_unrelated_name.pcap").json()
    assert a["details"]["esp_fingerprint"] == b["details"]["esp_fingerprint"]
    assert a["details"]["esp_sequence"] == b["details"]["esp_sequence"]
    assert a["mode"] == b["mode"] and a["confidence"]["mode"] == b["confidence"]["mode"]


def test_synthetic_ike_sa_init_is_reported_as_observed():
    r = upload(os.path.join(FIXTURES, "SYNTHETIC_ike_sa_init_cbc128_dh2_natt.pcap"), name="synthetic.pcap")
    body = r.json()
    assert r.status_code == 200 and validate_response(body) == []
    assert body["sources"]["cipher"] == "observed" and body["sources"]["dh_group"] == "observed"
    assert body["cipher"] == "AES-CBC-128" and body["dh_group"].startswith("Group 2 ")
    assert body["mode"] == "unknown"


def test_rejects_wrong_extension_garbage_and_empty():
    assert client.post("/analyze", files={"file": ("x.txt", b"hello")}).status_code == 400
    assert client.post("/analyze", files={"file": ("x.pcap", b"")}).status_code == 400
    r = client.post("/analyze", files={"file": ("x.pcap", b"not a capture at all")})
    assert r.status_code == 400 and "valid capture" in r.json()["detail"]


def test_upload_size_limit(monkeypatch):
    monkeypatch.setattr(main, "MAX_UPLOAD_BYTES", 1000)
    r = client.post("/analyze", files={"file": ("x.pcap", b"\x00" * 5000)})
    assert r.status_code == 413


def test_sample_endpoints():
    names = client.get("/samples").json()["samples"]
    assert WEB in names
    r = client.post(f"/analyze/sample/{WEB}")
    assert r.status_code == 200 and validate_response(r.json()) == []
    assert client.post("/analyze/sample/..%2F..%2Frequirements.txt").status_code == 404
    assert client.post("/analyze/sample/nope.pcap").status_code == 404


def test_cors_header_present():
    r = client.options("/analyze", headers={"Origin": "http://localhost:5173",
                                            "Access-Control-Request-Method": "POST"})
    assert r.headers.get("access-control-allow-origin") in ("*", "http://localhost:5173")
