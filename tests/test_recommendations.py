"""Recommendations, the generated strongSwan snippet and the before/after projection.
`facts()` below builds SYNTHETIC in-memory IKE facts (not captures) to drive specific situations."""
import re

import pytest

import recommendations as R
from contract import build_response, validate_response
from scoring_engine import score_ike_facts


def facts(cipher="AES-CBC", bits=128, dh=2, pfs=None):
    """SYNTHETIC parser output describing an observed IKE_SA_INIT (used only to drive the rules)."""
    return {"ike_version": "2.0", "mode": "unknown", "warnings": [],
            "ike_sa": {"cipher": cipher, "key_length_bits": bits, "dh_group": dh},
            "esp_sa": {"pfs": pfs} if pfs is not None else None,
            "handshake": {"ike_sa_init_seen": True}}


def recs(**kw):
    return build_response("synthetic.pcap", facts(**kw), None)["recommendations"]


def titles(r):
    return [i["title"] for i in r["items"]]


# ---------------------------------------------------------------------------------------------- the snippet
def test_snippet_is_consistent_and_secure():
    text = R.secure_ipsec_conf()
    p = R.parse_proposals(text)
    assert p == {"cipher": "AES-GCM-16", "key_length_bits": 256, "dh_group": 20, "pfs": True, "mode": "tunnel"}
    ike = re.search(r"^\s*ike=(\S+?)!", text, re.M).group(1)
    esp = re.search(r"^\s*esp=(\S+?)!", text, re.M).group(1)
    assert ike.split("-")[-1] == esp.split("-")[-1] == "ecp384"     # same group: PFS uses a strong group
    assert not re.search(r"modp1024|3des|md5|sha1\b|aes128-", text)
    for needle in ("keyexchange=ikev2", "ikelifetime=4h", "keylife=1h", "type=tunnel", "<THIS_GATEWAY_IP>"):
        assert needle in text


def test_snippet_supports_transport_mode_placeholder():
    assert "type=transport" in R.secure_ipsec_conf("transport")


def test_the_after_score_is_computed_from_the_snippet_itself():
    """Change the snippet's cipher and the 'after' raw score must follow (no separate hard-coded target)."""
    target, raw_after, passive, (review_score, _) = R._after({"traffic": None}, 30)
    assert raw_after == score_ike_facts({"ike_version": "2.0", "mode": "tunnel", "ike_sa": {"cipher": target["cipher"], "key_length_bits": target["key_length_bits"],
                                         "dh_group": target["dh_group"]}, "esp_sa": {"pfs": target["pfs"]}})["overall_score"] == 100


def test_snippet_is_marked_untested():
    r = recs()
    assert r["secure_config"]["verified"] is False and "NOT verified" in r["secure_config"]["note"]


# ---------------------------------------------------------------------------------------------- the rules
def test_weak_dh_and_missing_pfs_come_first():
    r = recs(dh=2, pfs=False)
    assert [i["priority"] for i in r["items"][:2]] == ["High", "High"]
    assert "weak Diffie-Hellman" in r["items"][0]["title"] or "Perfect Forward Secrecy" in r["items"][0]["title"]
    assert any("Perfect Forward Secrecy" in t for t in titles(r))


def test_3des_is_critical_and_first():
    r = recs(cipher="3DES", bits=None, dh=14, pfs=True)
    assert r["items"][0]["priority"] == "Critical" and "3DES" in r["items"][0]["title"]
    assert "NIST SP 800-131A Rev. 2" in r["items"][0]["standards"]


def test_cbc_gets_a_gcm_recommendation_gcm_does_not():
    assert any("AEAD" in t for t in titles(recs(cipher="AES-CBC", bits=256, dh=19, pfs=True)))
    assert not any("AEAD" in t or "3DES" in t for t in titles(recs(cipher="AES-GCM-16", bits=256, dh=19, pfs=True)))


def test_strong_observed_config_has_no_cipher_dh_or_pfs_recommendation():
    t = " ".join(titles(recs(cipher="AES-GCM-16", bits=256, dh=20, pfs=True)))
    assert "Diffie-Hellman" not in t and "AEAD" not in t and "Perfect Forward Secrecy" not in t


def test_unknown_facts_produce_confirm_recommendations_not_guesses():
    r = build_response("capture.pcap", None, None)["recommendations"]
    t = " ".join(titles(r))
    assert "Confirm the key-exchange group" in t and "Capture from before the tunnel comes up" in t
    assert all(i["based_on"]["status"] in ("unknown", "inferred", "observed", "declared") for i in r["items"])


def test_items_are_ranked_by_priority_with_unique_ranks():
    r = recs(dh=2, pfs=False)
    order = {"Critical": 0, "High": 1, "Medium": 2, "Low": 3}
    prios = [order[i["priority"]] for i in r["items"]]
    assert prios == sorted(prios) and [i["rank"] for i in r["items"]] == list(range(1, len(prios) + 1))


def test_every_item_says_what_it_rests_on():
    for i in recs(dh=2, pfs=False)["items"]:
        assert i["based_on"]["status"] in ("observed", "inferred", "declared", "unknown") and i["why"] and i["action"]


# ---------------------------------------------------------------------------------------------- before / after
def test_before_after_is_a_labelled_projection_and_consistent():
    resp = build_response("synthetic.pcap", facts(dh=2, pfs=False), None)
    ba = resp["recommendations"]["before_after"]
    assert "not a measurement" in ba["label"]
    assert ba["before"]["score"] == resp["score"]
    assert ba["after_passive_capture"]["score"] > ba["before"]["score"]
    # even a perfect configuration cannot reach 100 from a passive capture (PFS, auth, lifetime are invisible)
    assert ba["after_passive_capture"]["score"] < 100 and ba["after_passive_capture"]["completeness_pct"] < 100
    assert ba["after_config_review"]["score"] == 100 and ba["after_config_review"]["risk_level"] == "LOW"
    assert "passive capture" in ba["after_passive_capture"]["assumption"]


def test_response_with_recommendations_validates_and_rejects_verified_true():
    resp = build_response("synthetic.pcap", facts(), None)
    assert validate_response(resp) == []
    resp["recommendations"]["secure_config"]["verified"] = True
    assert any("verified" in p for p in validate_response(resp))
