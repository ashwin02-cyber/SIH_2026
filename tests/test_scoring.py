from scoring_engine import score_ike_facts


def facts(cipher="AES-GCM-16", bits=256, dh=19, esp=None, mode="unknown"):
    return {
        "ike_version": "2.0",
        "mode": mode,
        "ike_sa": {"cipher": cipher, "key_length_bits": bits, "dh_group": dh},
        "esp_sa": esp,
        "warnings": [],
    }


def test_strong_configuration_scores_low_risk():
    r = score_ike_facts(facts(esp={"cipher": "AES-GCM-16", "key_length_bits": 256, "dh_group": 19, "pfs": True}))
    assert r["overall_score"] == 100
    assert r["risk_level"] == "LOW"


def test_weak_configuration_scores_high_risk():
    r = score_ike_facts(facts(cipher="AES-CBC", bits=128, dh=2,
                              esp={"cipher": "AES-CBC", "key_length_bits": 128, "dh_group": None, "pfs": False}))
    assert r["factors"]["dh_group"]["rating"] == "weak"
    assert r["factors"]["pfs"]["rating"] == "weak"
    assert r["overall_score"] == round(60 * 0.4 / 1.0)  # only CBC-128 (medium) contributes
    assert r["risk_level"] == "HIGH"


def test_unknown_pfs_is_excluded_not_counted_as_weak():
    r = score_ike_facts(facts(cipher="AES-GCM-16", bits=256, dh=19, esp=None))
    assert r["factors"]["pfs"]["rating"] == "unknown"
    # cipher + dh are both strong; the unknown PFS must not drag the score down.
    assert r["overall_score"] == 100


def test_nothing_observed_gives_unknown_risk():
    r = score_ike_facts({"ike_version": "unknown", "mode": "unknown", "ike_sa": None, "esp_sa": None, "warnings": []})
    assert r["overall_score"] is None
    assert r["risk_level"] == "UNKNOWN"
    assert all(f["rating"] == "unknown" for f in r["factors"].values())


def test_missing_key_length_is_not_assumed_strong():
    r = score_ike_facts(facts(cipher="AES-CBC", bits=None, dh=14))
    assert r["factors"]["cipher"]["rating"] == "medium"


def test_dh_group_ratings():
    ratings = {g: score_ike_facts(facts(dh=g))["factors"]["dh_group"]["rating"] for g in (2, 14, 19, 999)}
    assert ratings == {2: "weak", 14: "medium", 19: "strong", 999: "unknown"}


def test_3des_is_weak():
    assert score_ike_facts(facts(cipher="3DES", bits=None))["factors"]["cipher"]["rating"] == "weak"


def test_mode_passthrough_is_not_defaulted():
    assert score_ike_facts(facts(mode="unknown"))["mode"] == "unknown"
    assert score_ike_facts(facts(mode="transport"))["mode"] == "transport"
