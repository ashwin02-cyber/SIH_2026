"""The sample analyses bundled in the React app must match the API contract exactly."""
import json
import os

import pytest

from contract import validate_response
from conftest import ROOT

DATA = os.path.join(ROOT, "frontend-developer", "src", "data")


@pytest.mark.parametrize("name", ["sample_strong.json", "sample_weak.json"])
def test_bundled_sample_matches_contract(name):
    with open(os.path.join(DATA, name), encoding="utf-8") as f:
        resp = json.load(f)
    assert validate_response(resp) == []
    assert resp["errors"] == []


def test_bundled_samples_are_regenerated_from_real_api_output():
    """Guards against hand-edited mocks: regenerate and compare."""
    from main import SAMPLES_DIR, analyze_path
    with open(os.path.join(DATA, "sample_weak.json"), encoding="utf-8") as f:
        saved = json.load(f)
    fresh = analyze_path(os.path.join(SAMPLES_DIR, saved["filename"]), saved["filename"])
    assert json.loads(json.dumps(fresh)) == saved, "run backend-developer/make_sample_responses.py"


# ---- the "Compare against a weak setup" card: a fixed reference configuration -------------

def _reference():
    with open(os.path.join(DATA, "weak_reference.json"), encoding="utf-8") as f:
        return json.load(f)


def test_weak_reference_has_pfs_off_and_a_consistent_score():
    from scoring_engine import score_ike_facts
    ref = _reference()
    assert ref["pfs"] == "disabled"  # shown as "off" by the card
    assert (ref["cipher"], ref["mode"]) == ("AES-CBC-128", "transport") and ref["dh_group"].startswith("Group 2 ")
    facts = {"ike_version": "unknown", "mode": "transport", "warnings": [],
             "ike_sa": {"cipher": "AES-CBC", "key_length_bits": 128, "dh_group": 2}, "esp_sa": {"pfs": False}}
    expected = score_ike_facts(facts)
    # PFS off is rated weak and counted, so the score must be lower than the capture-based weak sample (PFS unknown)
    assert (ref["score"], ref["risk_level"]) == (expected["overall_score"], expected["risk_level"]) == (24, "HIGH")
    with open(os.path.join(DATA, "sample_weak.json"), encoding="utf-8") as f:
        assert ref["score"] < json.load(f)["score"]


def test_weak_reference_is_regenerated_not_hand_edited():
    from make_sample_responses import weak_reference
    assert weak_reference() == _reference(), "run backend-developer/make_sample_responses.py"


def test_real_capture_pfs_stays_unknown_in_the_comparison_card_data():
    """The card shows the analysed capture's own `pfs` string. For the bundled real captures it is 'unknown'."""
    for name in ("sample_strong.json", "sample_weak.json"):
        with open(os.path.join(DATA, name), encoding="utf-8") as f:
            assert json.load(f)["pfs"] == "unknown"
