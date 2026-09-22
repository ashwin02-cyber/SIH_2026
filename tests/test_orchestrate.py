"""orchestrate.py with a FAKE Docker: checks command order and the time-based capture rules.
Nothing here talks to real containers."""
import csv
import os
import subprocess
import sys

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "traffic-engineer", "scripts"))
import orchestrate as o  # noqa: E402


class FakeDocker:
    def __init__(self):
        self.calls = []
        self.tcpdump_alive = False

    def run(self, cmd, timeout=None):
        self.calls.append(list(cmd))
        text = " ".join(cmd)
        rc, out = 0, ""
        if "timeout" in text and "tcpdump -U" in text:      # capture started (detached)
            self.tcpdump_alive = True
            self.polled = False
        elif text.endswith("pgrep -x tcpdump"):
            rc = 0 if self.tcpdump_alive else 1
            if self.tcpdump_alive and getattr(self, "polled", False):
                self.tcpdump_alive = False                   # exits by itself after its timeout
            self.polled = True
        elif text.endswith("ipsec status"):
            out = "aes128-dh14-tunnel-pfs-off[1]: ESTABLISHED 3 seconds ago\n  ...INSTALLED, TUNNEL"
        elif cmd[:2] == ["docker", "cp"]:
            open(cmd[3], "wb").write(b"\xd4\xc3\xb2\xa1" + b"\x00" * 40)  # tiny non-empty file
        return subprocess.CompletedProcess(cmd, rc, stdout=out, stderr="")


@pytest.fixture
def fake(tmp_path, monkeypatch):
    f = FakeDocker()
    monkeypatch.setattr(o, "run", f.run)
    monkeypatch.setattr(o.time, "sleep", lambda s: None)
    monkeypatch.setattr(o, "CAPTURES_DIR", str(tmp_path / "caps"))
    monkeypatch.setattr(o, "MANIFEST_PATH", str(tmp_path / "manifest.csv"))
    # do not overwrite the real peer configs
    monkeypatch.setattr(o, "CONFIGS_PEER_A", str(tmp_path / "a.conf"))
    monkeypatch.setattr(o, "CONFIGS_PEER_B", str(tmp_path / "b.conf"))
    return f


def idx(calls, needle):
    return next(i for i, c in enumerate(calls) if needle in " ".join(c))


def test_handshake_capture_starts_before_tunnel_teardown_and_reload(fake):
    assert o.switch_config("aes128-dh14-tunnel-pfs-on") is True
    calls = fake.calls
    start = idx(calls, "tcpdump -U -i eth0")
    assert start < idx(calls, "ipsec down")
    assert start < idx(calls, "ipsec reload")
    assert not any("restart" in c for c in calls if c[:2] == ["docker", "restart"]), "containers must not be restarted"


def test_captures_are_stopped_by_time_not_packet_count(fake):
    o.switch_config("aes128-dh14-tunnel-pfs-on")
    dumps = [" ".join(c) for c in fake.calls if "tcpdump" in " ".join(c) and "timeout" in " ".join(c)]
    assert dumps and all("timeout 20 tcpdump" in d for d in dumps)
    assert not any(" -c " in d.split("tcpdump", 1)[1] for d in dumps)


def test_traffic_capture_lasts_30_seconds(fake, monkeypatch):
    monkeypatch.setitem(o.GENERATORS, "icmp", lambda: None)
    assert o.run_combo("aes128-dh14-tunnel-pfs-on", classes=["icmp"]) is True
    traffic = [" ".join(c) for c in fake.calls if "timeout 30 tcpdump" in " ".join(c)]
    assert len(traffic) == 1 and " -c " not in traffic[0].split("tcpdump", 1)[1]
    assert os.path.exists(os.path.join(o.CAPTURES_DIR, "aes128-dh14-tunnel-pfs-on__icmp_run1.pcap"))


def test_manifest_upserts_instead_of_duplicating(tmp_path):
    m = str(tmp_path / "m.csv")
    o.log_capture("x__web_run1.pcap", "aes128-dh14-tunnel-pfs-on", "web", "run 1", manifest_path=m)
    o.log_capture("x__web_run1.pcap", "aes128-dh14-tunnel-pfs-on", "web", "run 1 again", manifest_path=m)
    o.log_capture("x__icmp_run1.pcap", "aes256-dh2-transport-pfs-off", "icmp", manifest_path=m)
    rows = list(csv.DictReader(open(m)))
    assert len(rows) == 2
    web = next(r for r in rows if r["traffic_class"] == "web")
    assert web["notes"] == "run 1 again" and web["capture_stop"] == "time" and web["pfs"] == "on"
    assert web["dh_group"] == "dh14" and web["mode"] == "tunnel" and web["cipher"] == "aes128"
    assert web["config_version"] == o.CONFIG_VERSION


def test_parse_combo():
    assert o.parse_combo("aes128gcm16-dh19-transport-pfs-off") == \
        {"cipher": "aes128gcm16", "dh": "dh19", "mode": "transport", "pfs": "off"}


def test_no_hard_coded_windows_paths():
    src = open(o.__file__).read()
    assert "E:\\" not in src and "E:/" not in src
