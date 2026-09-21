import copy

from contract import build_response, merge_facts, validate_response
from config_hint import declared_config_from_filename


def test_declared_config_parsing():
    d = declared_config_from_filename("aes256-dh14-transport-pfs-on__web_run1.pcap")
    assert (d["cipher"], d["key_length_bits"], d["dh_group"], d["mode"]) == ("AES-CBC", 256, 14, "transport")
    assert d["pfs"] is None  # pfs from file names is not trusted for the v1 dataset
    assert declared_config_from_filename("capture.pcap") is None
    assert declared_config_from_filename("aes999-dh14-tunnel-pfs-on__x.pcap") is None


def test_declared_pfs_only_when_explicitly_trusted(monkeypatch):
    monkeypatch.setenv("SIH_TRUST_DECLARED_PFS", "1")
    assert declared_config_from_filename("aes128-dh14-tunnel-pfs-on__x.pcap")["pfs"] is True
    assert declared_config_from_filename("aes128-dh14-tunnel-pfs-off__x.pcap")["pfs"] is False


def test_observed_beats_declared():
    ike = {"ike_version": "2.0", "mode": "unknown", "esp_sa": None,
           "ike_sa": {"cipher": "AES-GCM-16", "key_length_bits": 256, "dh_group": 19}}
    facts, src = merge_facts("aes128-dh2-tunnel-pfs-off__web_run1.pcap", ike)
    assert facts["ike_sa"]["cipher"] == "AES-GCM-16" and facts["ike_sa"]["dh_group"] == 19
    assert src["cipher"] == "observed" and src["dh_group"] == "observed" and src["mode"] == "declared"


def _minimal():
    return build_response("capture.pcap", None, None, errors=["boom"])


def test_response_valid_even_when_everything_failed():
    r = _minimal()
    assert validate_response(r) == []
    assert r["score"] is None and r["traffic"] is None and r["timeline"] == [] and r["errors"] == ["boom"]


def test_ml_error_becomes_error_string():
    r = build_response("capture.pcap", None, {"error": "No IP packets found in this capture"})
    assert validate_response(r) == []
    assert any("No IP packets" in e for e in r["errors"])


def test_validator_catches_problems():
    good = _minimal()
    for mutate, needle in [
        (lambda r: r.pop("score"), "missing key: score"),
        (lambda r: r.update(risk_level="SCARY"), "risk_level"),
        (lambda r: r.update(score=150, risk_level="LOW"), "range"),
        (lambda r: r.update(score=50), "inconsistent"),
        (lambda r: r.update(cipher=""), "empty"),
        (lambda r: r.update(explanation=[{"a": 1}]), "plain strings"),
        (lambda r: r["sources"].update(cipher="guessed"), "source"),
    ]:
        bad = copy.deepcopy(good)
        mutate(bad)
        assert any(needle in p for p in validate_response(bad)), needle
