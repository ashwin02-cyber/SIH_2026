import subprocess
import csv
import os
import re
import time
import shutil
from datetime import datetime

# ---------- CONFIG ----------
PROJECT_ROOT = r"E:\SIH_2026"
STRONGSWAN_DIR = os.path.join(PROJECT_ROOT, "docker", "strongswan")
GENERATED_CONFIGS_DIR = os.path.join(STRONGSWAN_DIR, "scripts", "generated_configs")
CONFIGS_PEER_A = os.path.join(STRONGSWAN_DIR, "configs", "peer-a", "ipsec.conf")
CONFIGS_PEER_B = os.path.join(STRONGSWAN_DIR, "configs", "peer-b", "ipsec.conf")
CAPTURES_DIR = os.path.join(PROJECT_ROOT, "real_captures")
MANIFEST_PATH = os.path.join(PROJECT_ROOT, "manifest.csv")

PEER_A_IP = "10.10.0.10"
PEER_B_IP = "10.10.0.20"
ROOT_PASSWORD = "test1234"  # must match what you set on peer-b earlier

TRAFFIC_CLASSES = ["icmp", "file_transfer", "web", "video", "voip"]

os.makedirs(CAPTURES_DIR, exist_ok=True)


def run(cmd, timeout=None):
    print(f"$ {' '.join(cmd)}")
    return subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)


def docker_exec(container, *args, timeout=60):
    cmd = ["docker", "exec", container] + list(args)
    return run(cmd, timeout=timeout)


def parse_combo(combo_name):
    m = re.match(r"(aes\d+(?:gcm\d+)?)-dh(\d+)-(tunnel|transport)-pfs-(on|off)", combo_name)
    if not m:
        return {"cipher": combo_name, "dh": "", "mode": "", "pfs": ""}
    cipher, dh, mode, pfs = m.groups()
    return {"cipher": cipher, "dh": f"dh{dh}", "mode": mode, "pfs": pfs}


def log_capture(filename, combo_name, traffic_class, notes=""):
    parsed = parse_combo(combo_name)
    file_exists = os.path.isfile(MANIFEST_PATH)
    with open(MANIFEST_PATH, mode="a", newline="") as f:
        writer = csv.writer(f)
        if not file_exists:
            writer.writerow(["filename", "combo_name", "cipher", "mode", "dh_group", "pfs", "traffic_class", "timestamp", "notes"])
        writer.writerow([filename, combo_name, parsed["cipher"], parsed["mode"], parsed["dh"], parsed["pfs"], traffic_class, datetime.now().isoformat(), notes])
    print(f"Logged: {filename} -> {traffic_class} ({combo_name})")


def ensure_tools_installed():
    print("Ensuring required tools are installed on peer-a and peer-b (one-time)...")
    for peer in ["peer-a", "peer-b"]:
        docker_exec(peer, "sh", "-c", "echo 'nameserver 8.8.8.8' > /etc/resolv.conf")
        docker_exec(peer, "sh", "-c", "apt-get update -qq", timeout=120)
        docker_exec(peer, "sh", "-c",
        "DEBIAN_FRONTEND=noninteractive NEEDRESTART_MODE=a NEEDRESTART_SUSPEND=1 "
        "apt-get install -y -qq curl wget nginx openssh-server openssh-client ffmpeg python3 sip-tester sshpass net-tools",
         timeout=600)
    # ensure ssh server + root login is ready on peer-b
    docker_exec("peer-b", "sh", "-c", f"echo 'root:{ROOT_PASSWORD}' | chpasswd")
    docker_exec("peer-b", "sh", "-c",
        "sed -i 's/#PermitRootLogin prohibit-password/PermitRootLogin yes/' /etc/ssh/sshd_config; "
        "sed -i 's/#PasswordAuthentication yes/PasswordAuthentication yes/' /etc/ssh/sshd_config")
    docker_exec("peer-b", "sh", "-c", "mkdir -p /run/sshd && (service ssh restart || /usr/sbin/sshd)")
    docker_exec("peer-b", "sh", "-c", "nginx || true")
    # generate the test video once, if missing
    check = docker_exec("peer-b", "sh", "-c", "ls /var/www/html/testvideo.mp4 2>/dev/null")
    if not check.stdout.strip():
        print("Generating test video on peer-b...")
        docker_exec("peer-b", "sh", "-c",
            "ffmpeg -y -f lavfi -i testsrc=duration=30:size=640x480:rate=30 "
            "-f lavfi -i sine=frequency=1000:duration=30 -c:v libx264 -c:a aac "
            "/var/www/html/testvideo.mp4", timeout=120)
    print("Tool setup complete.")


def switch_config(combo_name):
    src = os.path.join(GENERATED_CONFIGS_DIR, f"{combo_name}.conf")
    if not os.path.isfile(src):
        raise FileNotFoundError(f"Config not found: {src}")
    shutil.copy(src, CONFIGS_PEER_A)
    shutil.copy(src, CONFIGS_PEER_B)
    print(f"Applied config: {combo_name}")

    # Start capturing BEFORE restart, so we catch the IKE handshake
    handshake_remote_path = "/tmp/handshake_capture.pcap"
    docker_exec("peer-a", "rm", "-f", handshake_remote_path)
    handshake_proc = subprocess.Popen(
        ["docker", "exec", "peer-a", "tcpdump", "-U", "-i", "eth0", "-w", handshake_remote_path],
        stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True
    )
    time.sleep(2)  # let tcpdump attach before the restart triggers the handshake

    run(["docker", "restart", "peer-a", "peer-b"])
    time.sleep(10)  # give strongSwan time to renegotiate the tunnel

    # re-start background services that don't survive a container restart
    docker_exec("peer-b", "sh", "-c", "mkdir -p /run/sshd && /usr/sbin/sshd")
    docker_exec("peer-b", "sh", "-c", "nginx || true")

    # stop the handshake capture now that the tunnel should be up
    handshake_proc.terminate()
    try:
        handshake_proc.wait(timeout=5)
    except subprocess.TimeoutExpired:
        handshake_proc.kill()

    # copy the handshake pcap out and log it
    local_path,local_filename = copy_pcap_out("peer-a", handshake_remote_path, combo_name, "handshake")
    log_capture(local_filename, combo_name, "handshake", notes="IKE negotiation, captured during container restart")
    print(f"Handshake captured: {local_filename}")


def verify_tunnel():
    result = docker_exec("peer-a", "ipsec", "status")
    output = result.stdout
    ok = "ESTABLISHED" in output and "INSTALLED" in output
    if not ok:
        print("Tunnel NOT established:\n", output)
    return ok


def capture_start(peer, pcap_path, packet_count):
    docker_exec(peer, "rm", "-f", pcap_path)
    proc = subprocess.Popen(
        ["docker", "exec", peer, "tcpdump", "-U", "-c", str(packet_count), "-i", "eth0", "-w", pcap_path],
        stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True
    )
    time.sleep(2)  # let tcpdump attach before traffic starts
    return proc


def capture_stop(proc, timeout=20):
    try:
        proc.wait(timeout=timeout)
    except subprocess.TimeoutExpired:
        proc.terminate()
        try:
            proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            proc.kill()


def copy_pcap_out(peer, remote_path, combo_name, label):
    local_filename = f"{combo_name}__{label}.pcap"
    local_path = os.path.join(CAPTURES_DIR, local_filename)
    run(["docker", "cp", f"{peer}:{remote_path}", local_path])
    return local_path, local_filename


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
        stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True
    )
    time.sleep(2)
    docker_exec("peer-a", "sipp", "-sn", "uac", PEER_B_IP, "-m", "5", timeout=30)
    uas_proc.terminate()

GENERATORS = {
    "icmp": (gen_icmp, 20),
    "file_transfer": (gen_file_transfer, 5000),
    "web": (gen_web, 300),
    "video": (gen_video, 500),
    "voip": (gen_voip, 40),
}


def run_combo(combo_name, classes=None, repeat=1):
    classes = classes or TRAFFIC_CLASSES
    switch_config(combo_name)
    if not verify_tunnel():
        print(f"SKIPPING {combo_name} — tunnel failed to establish.")
        return
    for tclass in classes:
        gen_func, pkt_count = GENERATORS[tclass]
        for rep in range(1, repeat + 1):
            remote_pcap = f"/tmp/{tclass}_capture.pcap"
            proc = capture_start("peer-a", remote_pcap, pkt_count)
            try:
                gen_func()
            except Exception as e:
                print(f"Traffic generation error ({tclass}): {e}")
            capture_stop(proc)
            label = f"{tclass}_run{rep}"
            local_path, local_filename = copy_pcap_out("peer-a", remote_pcap, combo_name, label)
            log_capture(local_filename, combo_name, tclass, notes=f"run {rep}")
            print(f"DONE: {combo_name} / {tclass} / run {rep}\n")


if __name__ == "__main__":
    combos = sorted(f[:-5] for f in os.listdir(GENERATED_CONFIGS_DIR) if f.endswith(".conf"))
    print(f"Found {len(combos)} configs.")

    ensure_tools_installed()

    # TEST MODE: run just the first 2 combos first to confirm everything works
    for combo in combos:
        run_combo(combo)

    print(f"\nFull run complete. Processed {len(combos)} configs.")
    print("Check E:\\SIH_2026\\real_captures and manifest.csv") 