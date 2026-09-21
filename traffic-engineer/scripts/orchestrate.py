"""
orchestrate.py -- drives the strongSwan Docker testbed and records labelled pcaps.

    python orchestrate.py --list                      # show the 36 configs
    python orchestrate.py --combo aes128-dh14-tunnel-pfs-on
    python orchestrate.py --all                       # every config x every traffic class
    python orchestrate.py --all --classes icmp web    # only some traffic classes

Requires Docker with the `strongswan` compose stack running (peer-a, peer-b).
See traffic-engineer/readme.MD.

How captures are made (changed from the first version)
-------------------------------------------------------
* tcpdump is started BEFORE the tunnel is (re)negotiated, so the cleartext
  IKE_SA_INIT exchange is in the file. The old version started tcpdump inside
  peer-a and then ran `docker restart`, which killed tcpdump together with the
  container - the "handshake" pcaps only ever held later encrypted keep-alives.
  Containers are no longer restarted: the old connection is brought down and the
  new ipsec.conf is reloaded while tcpdump is already recording.
* Every capture is stopped by TIME (`timeout N tcpdump`), not by packet count.
  A packet-count limit (-c 20 / -c 5000 ...) leaked the traffic class into the
  data (the count alone predicted the class), see ml-engineer/shortcut_check.json.
* The manifest is updated in place (one row per file); re-running a capture
  replaces its row instead of appending a duplicate.

NOTE: this script has NOT been run against real containers in the environment it
was written in (Docker was not available). The command order is covered by
tests/test_orchestrate.py with a fake Docker; the strongSwan behaviour itself
still needs one real run.
"""

import argparse
import csv
import os
import re
import shutil
import subprocess
import sys
import time
from datetime import datetime

# ---------- CONFIG ----------
# Project root = two levels above this file, unless SIH_PROJECT_ROOT is set.
PROJECT_ROOT = os.environ.get("SIH_PROJECT_ROOT") or os.path.abspath(
    os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", ".."))
STRONGSWAN_DIR = os.path.join(PROJECT_ROOT, "docker", "strongswan")
GENERATED_CONFIGS_DIR = os.path.join(STRONGSWAN_DIR, "scripts", "generated_configs")
CONFIGS_PEER_A = os.path.join(STRONGSWAN_DIR, "configs", "peer-a", "ipsec.conf")
CONFIGS_PEER_B = os.path.join(STRONGSWAN_DIR, "configs", "peer-b", "ipsec.conf")
CAPTURES_DIR = os.environ.get("SIH_CAPTURES_DIR") or os.path.join(PROJECT_ROOT, "real_captures")
MANIFEST_PATH = os.path.join(PROJECT_ROOT, "manifest.csv")

PEER_A_IP = "10.10.0.10"
PEER_B_IP = "10.10.0.20"
ROOT_PASSWORD = os.environ.get("TESTBED_ROOT_PASSWORD", "test1234")  # throwaway lab containers only

TRAFFIC_CLASSES = ["icmp", "file_transfer", "web", "video", "voip"]

TRAFFIC_CAPTURE_SEC = 30      # every traffic capture lasts exactly this long
HANDSHAKE_CAPTURE_SEC = 20    # covers teardown + IKE_SA_INIT/IKE_AUTH + first ESP packets
CAPTURE_ATTACH_SEC = 2        # give tcpdump time to attach before anything else happens
TUNNEL_WAIT_SEC = 30
CONFIG_VERSION = "v2-pfs-in-esp"  # v1 = first dataset, pfs-on/pfs-off configs were identical

MANIFEST_COLUMNS = ["filename", "combo_name", "cipher", "mode", "dh_group", "pfs", "traffic_class",
                    "timestamp", "notes", "capture_stop", "capture_seconds", "config_version"]


def run(cmd, timeout=None):
    print(f"$ {' '.join(cmd)}")
    return subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)


def docker_exec(container, *args, timeout=60):
    return run(["docker", "exec", container] + list(args), timeout=timeout)


def parse_combo(combo_name):
    m = re.match(r"(aes\d+(?:gcm\d+)?)-dh(\d+)-(tunnel|transport)-pfs-(on|off)", combo_name)
    if not m:
        return {"cipher": combo_name, "dh": "", "mode": "", "pfs": ""}
    cipher, dh, mode, pfs = m.groups()
    return {"cipher": cipher, "dh": f"dh{dh}", "mode": mode, "pfs": pfs}


# ---------- MANIFEST ----------

def log_capture(filename, combo_name, traffic_class, notes="", capture_seconds=TRAFFIC_CAPTURE_SEC,
                manifest_path=None):
    """Insert or replace the manifest row for `filename` (one row per file)."""
    manifest_path = manifest_path or MANIFEST_PATH
    parsed = parse_combo(combo_name)
    new_row = {
        "filename": filename, "combo_name": combo_name, "cipher": parsed["cipher"], "mode": parsed["mode"],
        "dh_group": parsed["dh"], "pfs": parsed["pfs"], "traffic_class": traffic_class,
        "timestamp": datetime.now().isoformat(), "notes": notes, "capture_stop": "time",
        "capture_seconds": capture_seconds, "config_version": CONFIG_VERSION,
    }

    rows = {}
    if os.path.isfile(manifest_path):
        with open(manifest_path, newline="", encoding="utf-8") as f:
            for r in csv.DictReader(f):
                rows[r["filename"]] = r
    rows[filename] = new_row  # replaces an older row for the same file

    with open(manifest_path, "w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=MANIFEST_COLUMNS, restval="")
        w.writeheader()
        w.writerows(rows.values())
    print(f"Logged: {filename} -> {traffic_class} ({combo_name})")


# ---------- TOOLS ----------

def ensure_tools_installed():
    print("Ensuring required tools are installed on peer-a and peer-b (one-time)...")
    for peer in ["peer-a", "peer-b"]:
        docker_exec(peer, "sh", "-c", "echo 'nameserver 8.8.8.8' > /etc/resolv.conf")
        docker_exec(peer, "sh", "-c", "apt-get update -qq", timeout=120)
        docker_exec(peer, "sh", "-c",
                    "DEBIAN_FRONTEND=noninteractive NEEDRESTART_MODE=a NEEDRESTART_SUSPEND=1 "
                    "apt-get install -y -qq curl wget nginx openssh-server openssh-client ffmpeg python3 "
                    "sip-tester sshpass net-tools",
                    timeout=600)
    # ssh server + root login on peer-b
    docker_exec("peer-b", "sh", "-c", f"echo 'root:{ROOT_PASSWORD}' | chpasswd")
    docker_exec("peer-b", "sh", "-c",
                "sed -i 's/#PermitRootLogin prohibit-password/PermitRootLogin yes/' /etc/ssh/sshd_config; "
                "sed -i 's/#PasswordAuthentication yes/PasswordAuthentication yes/' /etc/ssh/sshd_config")
    docker_exec("peer-b", "sh", "-c", "mkdir -p /run/sshd && (service ssh restart || /usr/sbin/sshd)")
    docker_exec("peer-b", "sh", "-c", "nginx || true")
    check = docker_exec("peer-b", "sh", "-c", "ls /var/www/html/testvideo.mp4 2>/dev/null")
    if not check.stdout.strip():
        print("Generating test video on peer-b...")
        docker_exec("peer-b", "sh", "-c",
                    "ffmpeg -y -f lavfi -i testsrc=duration=30:size=640x480:rate=30 "
                    "-f lavfi -i sine=frequency=1000:duration=30 -c:v libx264 -c:a aac "
                    "/var/www/html/testvideo.mp4", timeout=120)
    print("Tool setup complete.")


# ---------- CAPTURE (time based) ----------

def tcpdump_running(peer):
    return docker_exec(peer, "pgrep", "-x", "tcpdump").returncode == 0


def start_capture(peer, remote_path, seconds):
    """Start tcpdump in the background inside `peer`; it stops itself after `seconds`
    (coreutils `timeout` sends SIGTERM, tcpdump flushes and exits cleanly)."""
    docker_exec(peer, "rm", "-f", remote_path)
    cmd = f"exec timeout {int(seconds)} tcpdump -U -i eth0 -w {remote_path}"
    run(["docker", "exec", "-d", peer, "sh", "-c", cmd])
    time.sleep(CAPTURE_ATTACH_SEC)  # let tcpdump attach before anything is sent
    if not tcpdump_running(peer):
        raise RuntimeError(f"tcpdump did not start on {peer}")


def finish_capture(peer, seconds, already_elapsed=0):
    """Wait until the time-limited tcpdump has exited."""
    remaining = max(0, int(seconds) - int(already_elapsed))
    time.sleep(remaining)
    for _ in range(15):  # grace period for the process to flush and exit
        if not tcpdump_running(peer):
            return
        time.sleep(1)
    docker_exec(peer, "pkill", "-TERM", "tcpdump")
    time.sleep(1)


def copy_pcap_out(peer, remote_path, combo_name, label):
    os.makedirs(CAPTURES_DIR, exist_ok=True)
    local_filename = f"{combo_name}__{label}.pcap"
    local_path = os.path.join(CAPTURES_DIR, local_filename)
    run(["docker", "cp", f"{peer}:{remote_path}", local_path])
    if not os.path.isfile(local_path) or os.path.getsize(local_path) < 24:
        raise RuntimeError(f"capture {local_filename} is missing or empty")
    return local_path, local_filename


# ---------- TUNNEL CONTROL ----------

def verify_tunnel():
    output = docker_exec("peer-a", "ipsec", "status").stdout
    ok = "ESTABLISHED" in output and "INSTALLED" in output
    if not ok:
        print("Tunnel NOT established:\n", output)
    return ok


def wait_for_tunnel(timeout_sec=TUNNEL_WAIT_SEC):
    for _ in range(max(1, int(timeout_sec // 2))):
        if verify_tunnel():
            return True
        time.sleep(2)
    return False


def active_connections(peer):
    """Names of connections currently listed by `ipsec status`, e.g. 'aes128-dh14-tunnel-pfs-on'."""
    out = docker_exec(peer, "ipsec", "status").stdout
    return sorted(set(re.findall(r"^\s*([\w-]+)\[\d+\]:", out, flags=re.M)))


def switch_config(combo_name):
    """Apply a config and capture the IKE negotiation. Returns True if the tunnel came up.

    Order matters: tcpdump is already recording when the old connection is torn down and
    the new one is negotiated.
    """
    src = os.path.join(GENERATED_CONFIGS_DIR, f"{combo_name}.conf")
    if not os.path.isfile(src):
        raise FileNotFoundError(f"Config not found: {src}")
    shutil.copy(src, CONFIGS_PEER_A)
    shutil.copy(src, CONFIGS_PEER_B)
    print(f"Applied config: {combo_name}")

    remote = "/tmp/handshake_capture.pcap"
    start_capture("peer-a", remote, HANDSHAKE_CAPTURE_SEC)          # 1. record first ...
    started = time.monotonic()

    for peer in ("peer-b", "peer-a"):                               # 2. ... then tear down ...
        for conn in active_connections(peer):
            docker_exec(peer, "ipsec", "down", conn)
    for peer in ("peer-b", "peer-a"):                               # 3. ... and renegotiate
        docker_exec(peer, "ipsec", "reload")
    up = wait_for_tunnel()
    if not up:
        docker_exec("peer-a", "ipsec", "up", combo_name)            # last resort: explicit initiate
        up = wait_for_tunnel(10)

    # services that do not depend on the tunnel restart (containers are no longer restarted)
    docker_exec("peer-b", "sh", "-c", "mkdir -p /run/sshd && (pgrep -x sshd >/dev/null || /usr/sbin/sshd)")
    docker_exec("peer-b", "sh", "-c", "pgrep -x nginx >/dev/null || nginx || true")

    finish_capture("peer-a", HANDSHAKE_CAPTURE_SEC, already_elapsed=time.monotonic() - started)
    _, local_filename = copy_pcap_out("peer-a", remote, combo_name, "handshake")
    log_capture(local_filename, combo_name, "handshake",
                notes="IKE negotiation captured from before teardown; tunnel up" if up else
                      "IKE negotiation captured; TUNNEL DID NOT COME UP",
                capture_seconds=HANDSHAKE_CAPTURE_SEC)
    print(f"Handshake captured: {local_filename}")
    return up


# ---------- TRAFFIC GENERATORS ----------

def gen_icmp():
    docker_exec("peer-a", "ping", "-c", "10", PEER_B_IP)


def gen_file_transfer():
    docker_exec("peer-a", "sh", "-c", "dd if=/dev/urandom of=/tmp/testfile_10MB bs=1M count=10")
    docker_exec("peer-a", "sh", "-c",
                f"sshpass -p {ROOT_PASSWORD} scp -o StrictHostKeyChecking=no /tmp/testfile_10MB root@{PEER_B_IP}:/tmp/",
                timeout=30)


def gen_web():
    script = (
        "import subprocess, random, time\n"
        f"url = 'http://{PEER_B_IP}/'\n"
        "for i in range(30):\n"
        "    subprocess.run(['curl', '-s', '-o', '/dev/null', url])\n"
        "    time.sleep(random.uniform(0.3, 1.0))\n"
    )
    docker_exec("peer-a", "python3", "-c", script, timeout=60)


def gen_video():
    script = (
        "import subprocess, time\n"
        f"url = 'http://{PEER_B_IP}/testvideo.mp4'\n"
        "chunk_size = 50000\n"
        "total_size = 455265\n"
        "start = 0\n"
        "while start < total_size:\n"
        "    end = min(start + chunk_size - 1, total_size - 1)\n"
        "    subprocess.run(['curl', '-s', '-o', '/dev/null', '-H', f'Range: bytes={start}-{end}', url])\n"
        "    time.sleep(0.3)\n"
        "    start += chunk_size\n"
    )
    docker_exec("peer-a", "python3", "-c", script, timeout=60)


def gen_voip():
    uas_proc = subprocess.Popen(
        ["docker", "exec", "peer-b", "sipp", "-sn", "uas"],
        stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    time.sleep(2)
    docker_exec("peer-a", "sipp", "-sn", "uac", PEER_B_IP, "-m", "5", timeout=30)
    uas_proc.terminate()


GENERATORS = {
    "icmp": gen_icmp,
    "file_transfer": gen_file_transfer,
    "web": gen_web,
    "video": gen_video,
    "voip": gen_voip,
}


def run_combo(combo_name, classes=None, repeat=1):
    classes = classes or TRAFFIC_CLASSES
    up = switch_config(combo_name)
    if not up or not verify_tunnel():
        print(f"SKIPPING {combo_name} -- tunnel failed to establish.")
        return False
    for tclass in classes:
        gen_func = GENERATORS[tclass]
        for rep in range(1, repeat + 1):
            remote_pcap = f"/tmp/{tclass}_capture.pcap"
            start_capture("peer-a", remote_pcap, TRAFFIC_CAPTURE_SEC)
            started = time.monotonic()
            try:
                gen_func()
            except Exception as e:  # keep the capture: a failed generator is visible in the data
                print(f"Traffic generation error ({tclass}): {e}")
            finish_capture("peer-a", TRAFFIC_CAPTURE_SEC, already_elapsed=time.monotonic() - started)
            _, local_filename = copy_pcap_out("peer-a", remote_pcap, combo_name, f"{tclass}_run{rep}")
            log_capture(local_filename, combo_name, tclass, notes=f"run {rep}")
            print(f"DONE: {combo_name} / {tclass} / run {rep}\n")
    return True


def all_combos():
    return sorted(f[:-5] for f in os.listdir(GENERATED_CONFIGS_DIR) if f.endswith(".conf"))


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--list", action="store_true", help="list available configs and exit")
    ap.add_argument("--all", action="store_true", help="run every config")
    ap.add_argument("--combo", nargs="+", help="run only these config names")
    ap.add_argument("--classes", nargs="+", choices=TRAFFIC_CLASSES, help="traffic classes (default: all)")
    ap.add_argument("--repeat", type=int, default=1)
    ap.add_argument("--skip-setup", action="store_true", help="do not apt-install tools on the peers")
    args = ap.parse_args(argv)

    combos = all_combos()
    if args.list:
        print("\n".join(combos))
        return 0
    if not (args.all or args.combo):
        ap.error("choose --all or --combo NAME [NAME ...] (or --list)")
    chosen = combos if args.all else args.combo
    unknown = [c for c in chosen if c not in combos]
    if unknown:
        ap.error(f"unknown config(s): {unknown}")

    os.makedirs(CAPTURES_DIR, exist_ok=True)
    print(f"Running {len(chosen)} config(s); captures -> {CAPTURES_DIR}; "
          f"each traffic capture lasts {TRAFFIC_CAPTURE_SEC}s")
    if not args.skip_setup:
        ensure_tools_installed()
    failed = [c for c in chosen if not run_combo(c, args.classes, args.repeat)]
    print(f"\nDone. {len(chosen) - len(failed)}/{len(chosen)} configs captured.")
    if failed:
        print("Failed (tunnel did not come up):", ", ".join(failed))
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
