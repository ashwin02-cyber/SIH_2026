"""The sample analyses bundled in the React app must match the API contract exactly."""
import json
import os

import pytest

from contract import validate_response
from conftest import ROOT

DATA = os.path.join(ROOT, "frontend-developer", "src", "data")

with open(os.path.join(DATA, "sampleFiles.json"), encoding="utf-8") as _f:
    SAMPLE_FILES = json.load(_f)

SAMPLE_NAMES = [entry["file"] for entry in SAMPLE_FILES]


def test_sample_files_json_has_ten_entries_with_unique_ids():
    assert len(SAMPLE_FILES) == 10
    assert sorted(entry["id"] for entry in SAMPLE_FILES) == list(range(1, 11))


@pytest.mark.parametrize("name", SAMPLE_NAMES)
def test_bundled_sample_matches_contract(name):
    with open(os.path.join(DATA, name), encoding="utf-8") as f:
        resp = json.load(f)
    assert validate_response(resp) == []
    # These bundled samples are handshake-only captures (no ESP/application traffic), so traffic
    # classification honestly reports nothing to classify rather than guessing; that is the only
    # allowed "error".
    assert resp["errors"] == ["Traffic classification: No IP packets found in this capture"]
    assert resp["traffic"] is None


@pytest.mark.parametrize("name", SAMPLE_NAMES)
def test_bundled_samples_are_regenerated_from_real_api_output(name):
    """Guards against hand-edited mocks: regenerate and compare."""
    from main import analyze_path
    from make_sample_responses import REAL_CAPTURES_DIR
    with open(os.path.join(DATA, name), encoding="utf-8") as f:
        saved = json.load(f)
    fresh = analyze_path(os.path.join(REAL_CAPTURES_DIR, saved["filename"]), saved["filename"])
    assert json.loads(json.dumps(fresh)) == saved, "run backend-developer/make_sample_responses.py"


def test_sample_files_metadata_matches_its_analysis_json():
    """Guards against sampleFiles.json and the sample_N_*.json files drifting apart."""
    for entry in SAMPLE_FILES:
        with open(os.path.join(DATA, entry["file"]), encoding="utf-8") as f:
            resp = json.load(f)
        assert entry["cipher"] == resp["cipher"]
        assert entry["dh_group"] == resp["dh_group"]
        assert entry["mode"] == resp["mode"]
        assert entry["pfs"] == resp["pfs"]
        assert entry["risk_level"] == resp["risk_level"]
        assert entry["score"] == resp["score"]
        assert entry["traffic_label"] is None and resp["traffic"] is None
        assert entry["ml_confidence"] is None


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
    assert (ref["score"], ref["risk_level"]) == (expected["overall_score"], expected["risk_level"]) == (24, "HIGH")
    # PFS off is rated weak and counted, so the score must be lower than every bundled sample (PFS unknown)
    assert ref["score"] < min(entry["score"] for entry in SAMPLE_FILES)


def test_weak_reference_is_regenerated_not_hand_edited():
    from make_sample_responses import weak_reference
    assert weak_reference() == _reference(), "run backend-developer/make_sample_responses.py"


def test_real_capture_pfs_stays_unknown_in_the_comparison_card_data():
    """The card shows the analysed capture's own `pfs` string. For the bundled real captures it is 'unknown'."""
    for name in SAMPLE_NAMES:
        with open(os.path.join(DATA, name), encoding="utf-8") as f:
            assert json.load(f)["pfs"] == "unknown"
