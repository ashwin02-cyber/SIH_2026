import sys
sys.path.insert(0, r"E:\SIH_2026\traffic-engineer\scripts")
from orchestrate import run_combo

failed_combos = [
    "aes128-dh19-tunnel-pfs-on",
    "aes128-dh2-transport-pfs-on",
    "aes128gcm16-dh14-transport-pfs-off",
    "aes128gcm16-dh19-transport-pfs-off",
    "aes128gcm16-dh19-tunnel-pfs-on",
    "aes256-dh2-tunnel-pfs-off",
]

for combo in failed_combos:
    run_combo(combo)