import os
import sys
import warnings

warnings.filterwarnings("ignore")

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
for sub in ("backend-developer", "ml-engineer", "reports", "tests"):
    p = os.path.join(ROOT, sub)
    if p not in sys.path:
        sys.path.insert(0, p)

FIXTURES = os.path.join(ROOT, "tests", "fixtures")
SAMPLES = os.path.join(ROOT, "data", "samples")

import pytest  # noqa: E402


@pytest.fixture(scope="session", autouse=True)
def _build_fixtures():
    """Synthetic fixtures are generated (deterministically) if missing."""
    if not os.path.exists(os.path.join(FIXTURES, "SYNTHETIC_ike_sa_init_gcm256_dh19.pcap")):
        import make_fixtures
        make_fixtures.build()


@pytest.fixture
def fixture_path():
    return lambda name: os.path.join(FIXTURES, name)
