"""The generated strongSwan configs: PFS must really appear in the ESP proposal."""
import os
import re
import sys

import pytest

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
SCRIPTS = os.path.join(ROOT, "docker", "strongswan", "scripts")
sys.path.insert(0, SCRIPTS)
import generate_configs as gc  # noqa: E402

DH_NAME = {"dh2": "modp1024", "dh14": "modp2048", "dh19": "ecp256"}


@pytest.fixture(scope="module")
def rendered(tmp_path_factory):
    out = tmp_path_factory.mktemp("cfg")
    names = gc.render_all(str(out))
    return str(out), names


def _esp(path):
    return re.search(r"^\s*esp=(\S+)$", open(path).read(), re.M).group(1)


def test_36_configs(rendered):
    _, names = rendered
    assert len(names) == len(set(names)) == 36


def test_pfs_on_has_dh_group_in_esp_and_pfs_off_does_not(rendered):
    out, names = rendered
    for n in names:
        m = re.match(r"(aes\d+(?:gcm\d+)?)-(dh\d+)-(tunnel|transport)-pfs-(on|off)$", n)
        esp = _esp(os.path.join(out, n + ".conf"))
        if m.group(4) == "on":
            assert DH_NAME[m.group(2)] in esp, n
        else:
            assert not re.search(r"modp|ecp", esp), n
        assert esp.endswith("!")


def test_gcm_has_no_dangling_dash_or_hash(rendered):
    out, names = rendered
    for n in (x for x in names if x.startswith("aes128gcm16")):
        esp = _esp(os.path.join(out, n + ".conf"))
        assert "sha256" not in esp and "-!" not in esp, esp


def test_pfs_on_and_off_configs_now_differ(rendered):
    out, _ = rendered
    def body(name):
        return re.sub(r"^conn .*", "conn X", open(os.path.join(out, name + ".conf")).read(), flags=re.M)
    assert body("aes128-dh14-tunnel-pfs-on") != body("aes128-dh14-tunnel-pfs-off")


def test_mode_and_ike_line(rendered):
    out, _ = rendered
    txt = open(os.path.join(out, "aes256-dh19-transport-pfs-on.conf")).read()
    assert "type=transport" in txt and "ike=aes256-sha256-ecp256!" in txt
    assert "keylife=25s" in txt  # a rekey happens inside a 30 s capture


def test_committed_configs_match_generator(rendered):
    out, names = rendered
    committed = os.path.join(SCRIPTS, "generated_configs")
    for n in names:
        assert open(os.path.join(out, n + ".conf")).read() == \
               open(os.path.join(committed, n + ".conf")).read(), f"{n} is stale - rerun generate_configs.py"
