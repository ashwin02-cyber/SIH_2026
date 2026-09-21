"""Assessment engine: findings with status tags, completeness and score cap, metadata exposure, compliance mapping."""
import pytest

import assessment as A
from contract import build_response, validate_response


def ctx(cipher=("AES-GCM-16", 256), dh=19, pfs=None, mode="tunnel", sources=None, fp=None, seq=None, traffic=None):
    facts = {"ike_version": "unknown", "mode": mode, "ike_sa": {"cipher": cipher[0] if cipher else None,
             "key_length_bits": cipher[1] if cipher else None, "dh_group": dh},
             "esp_sa": {"pfs": pfs} if pfs is not None else None}
    src = {"cipher": "observed" if cipher else "unknown", "dh_group": "observed" if dh else "unknown",
           "pfs": "observed" if pfs is not None else "unknown", "mode": "observed" if mode != "unknown" else "unknown"}
    src.update(sources or {})
    return {"facts": facts, "sources": src, "conf": {}, "ike": {}, "fp": fp, "seq": seq, "traffic": traffic,
            "ratings": {"cipher": "strong", "dh_group": "strong", "pfs": "strong" if pfs else "unknown"}}


def test_completeness_weights_sum_to_100():
    assert sum(w for _, w in A.FACTS.values()) == 100


def test_knowledge_fractions():
    assert A.knowledge("observed", None) == 1.0 and A.knowledge("declared", None) == 0.5 and A.knowledge("unknown", None) == 0.0
    assert A.knowledge("inferred", 0.8) == 0.8 and A.knowledge("inferred", 1.7) == 1.0


def test_everything_known_gives_full_completeness_and_no_cap():
    findings = [A.finding(fid, "x", "observed", 1.0, "strong") for fid in A.FACTS]
    pct, _ = A.completeness(findings)
    assert pct == 100.0
    final, cap, adj = A.apply_cap(100, pct, findings)
    assert (final, cap, adj) == (100, 100, [])


def test_unknown_facts_can_never_give_100_low():
    findings = [A.finding(fid, "x", "unknown") for fid in A.FACTS]
    pct, _ = A.completeness(findings)
    final, cap, _ = A.apply_cap(100, pct, findings)
    assert pct == 0 and cap == A.CAP_FLOOR and final == A.CAP_FLOOR < 50   # a perfect raw score is capped to HIGH-ish territory


@pytest.mark.parametrize("pct,expect_low_possible", [(30, False), (68, False), (70, True), (100, True)])
def test_low_risk_needs_enough_completeness(pct, expect_low_possible):
    final, cap, _ = A.apply_cap(100, pct, [])
    assert (final >= 80) is expect_low_possible


def test_cap_only_lowers_the_score():
    assert A.apply_cap(30, 34, [])[0] == 30
    assert A.apply_cap(None, 50, []) == (None, None, [])


def test_repeated_sequence_numbers_deduct_points():
    findings = [A.finding("replay", "x", "observed", 1.0, "weak")]
    final, cap, adj = A.apply_cap(80, 100, findings)
    assert final == 70 and adj[0]["points"] == -10


def test_every_finding_has_a_valid_status():
    fs = A.build_findings(ctx())
    assert {f["status"] for f in fs} <= {"observed", "inferred", "declared", "unknown"}
    assert {f["id"] for f in fs} == set(A.FACTS)
    unk = {f["id"] for f in fs if f["status"] == "unknown"}
    assert {"auth_method", "key_lifetime", "pfs"} <= unk


def test_key_lifetime_only_when_a_rekey_was_observed():
    seq = {"sa_lifetime": {"observable": True, "estimate_seconds": 25.0, "basis": "b", "note": "n"}, "replay_protection": {"status": "not_observable"}}
    f = {x["id"]: x for x in A.build_findings(ctx(seq=seq))}["key_lifetime"]
    assert f["status"] == "inferred" and f["rating"] == "strong" and "25" in f["value"]
    none = {"sa_lifetime": {"observable": False, "note": "not observable in this capture (no rekey ...)"}, "replay_protection": {"status": "not_observable"}}
    f = {x["id"]: x for x in A.build_findings(ctx(seq=none))}["key_lifetime"]
    assert f["status"] == "unknown" and "not observable in this capture" in f["evidence"]


def test_replay_finding_states_the_limit():
    seq = {"sa_lifetime": {"observable": False, "note": ""}, "replay_protection": {"status": "evidence_present", "evidence": "e"}}
    f = {x["id"]: x for x in A.build_findings(ctx(seq=seq))}["replay"]
    assert f["status"] == "inferred" and f["rating"] == "medium" and "receiver" in f["note"]
    dup = {"sa_lifetime": {"observable": False, "note": ""}, "replay_protection": {"status": "anomalies_observed", "evidence": "dup"}}
    assert {x["id"]: x for x in A.build_findings(ctx(seq=dup))}["replay"]["rating"] == "weak"


# ---------------------------------------------------------------------------------------------- metadata exposure
def test_exposure_counts_only_passive_inferences_and_bounds():
    e = A.metadata_exposure(ctx(fp={"esp_packets": 100, "mode": {"value": "tunnel", "confidence": 0.9},
                                     "cipher_family": {"value": "GCM-like", "confidence": 0.97}},
                                traffic={"class": "voip", "label": "VoIP", "confidence": 0.9}))
    assert 0 <= e["score"] <= 100 and sum(i["weight"] for i in e["items"]) == 100
    assert {i["what"]: i["learned"] for i in e["items"]}["Traffic type"].startswith("VoIP")
    nothing = A.metadata_exposure(ctx(fp={"esp_packets": 0}, mode="unknown", traffic=None))
    assert nothing["score"] < e["score"]


def test_unrecognised_traffic_is_not_counted_as_an_exposed_traffic_type():
    e = A.metadata_exposure(ctx(fp={"esp_packets": 50}, traffic={"class": "unrecognised", "label": "Unrecognised traffic", "confidence": 0.4}))
    assert {i["what"]: i["points"] for i in e["items"]}["Traffic type"] == 0


def test_tunnel_mode_exposes_less_than_transport_mode():
    fp = {"esp_packets": 50}
    tun = A.metadata_exposure(ctx(fp=fp, mode="tunnel"))["score"]
    trn = A.metadata_exposure(ctx(fp=fp, mode="transport"))["score"]
    assert tun < trn


# ---------------------------------------------------------------------------------------------- compliance
def checks(c):
    findings = A.build_findings(c)
    return {x["id"]: x for x in A.compliance(c, findings)["checks"]}


def test_compliance_is_labelled_as_a_guideline_mapping():
    comp = A.compliance(ctx(), A.build_findings(ctx()))
    assert "NOT a certification" in comp["label"]
    assert any("SP 800-77" in n for n in comp["not_evaluated"])


def test_weak_dh_group_fails_the_112_bit_check():
    assert checks(ctx(dh=2))["nist-112bit-kex"]["result"] == "does_not_meet"
    assert checks(ctx(dh=14))["nist-112bit-kex"]["result"] == "meets"
    assert checks(ctx(dh=19))["nist-112bit-kex"]["result"] == "meets"


def test_3des_fails_sp800_131a_and_aes_passes():
    assert checks(ctx(cipher=("3DES", None)))["nist-131a-tdea"]["result"] == "does_not_meet"
    assert checks(ctx(cipher=("AES-CBC", 128)))["nist-131a-tdea"]["result"] == "meets"
    assert checks(ctx(cipher=("AES-GCM-16", 128)))["rfc8221-esp-alg"]["result"] == "meets"


def test_unknown_inputs_cannot_be_assessed_never_guessed():
    c = ctx(cipher=None, dh=None)
    result = checks(c)
    assert all(v["result"] == "cannot_assess" for v in result.values())


def test_declared_inputs_are_marked_in_the_compliance_evidence():
    r = checks(ctx(dh=2, sources={"dh_group": "declared"}))["nist-112bit-kex"]
    assert r["input_status"] == "declared"


def test_rfc8247_group14_only():
    assert checks(ctx(dh=14))["rfc8247-group14"]["result"] == "meets"
    assert checks(ctx(dh=19))["rfc8247-group14"]["result"] == "cannot_assess"


# ---------------------------------------------------------------------------------------------- whole response
def test_response_with_nothing_is_valid_and_has_no_score():
    r = build_response("capture.pcap", None, None)
    assert validate_response(r) == [] and r["score"] is None and r["assessment"]["completeness_pct"] == 0


def test_validator_rejects_a_score_above_the_cap_and_low_with_low_completeness():
    r = build_response("aes128gcm16-dh19-tunnel-pfs-on__x.pcap", None, None)
    bad = dict(r, score=95, risk_level="LOW")
    assert any("cap" in p or "completeness" in p for p in validate_response(bad))
