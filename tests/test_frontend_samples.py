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
