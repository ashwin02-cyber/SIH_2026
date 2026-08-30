from jinja2 import Environment, FileSystemLoader
import os

env = Environment(loader=FileSystemLoader("."))
template = env.get_template("ipsec.conf.j2")

CIPHERS = [
    {"ike_cipher": "aes128", "ike_hash": "sha256", "esp_cipher": "aes128", "esp_hash": "sha256"},
    {"ike_cipher": "aes256", "ike_hash": "sha256", "esp_cipher": "aes256", "esp_hash": "sha256"},
    {"ike_cipher": "aes128gcm16", "ike_hash": "sha256", "esp_cipher": "aes128gcm16", "esp_hash": ""},
]

DH_GROUPS = {
    "modp1024": "dh2",
    "modp2048": "dh14",
    "ecp256":   "dh19",
}

MODES = ["tunnel", "transport"]
PFS_STATES = [True, False]

PEER_A_IP = "10.10.0.10"
PEER_B_IP = "10.10.0.20"

os.makedirs("generated_configs", exist_ok=True)

count = 0
for cipher in CIPHERS:
    for dh_modp, dh_label in DH_GROUPS.items():
        for mode in MODES:
            for pfs in PFS_STATES:
                pfs_label = "pfs-on" if pfs else "pfs-off"
                conn_name = f"{cipher['ike_cipher']}-{dh_label}-{mode}-{pfs_label}"

                rendered = template.render(
                    conn_name=conn_name,
                    left_ip=PEER_A_IP,
                    right_ip=PEER_B_IP,
                    ike_cipher=cipher["ike_cipher"],
                    ike_hash=cipher["ike_hash"],
                    esp_cipher=cipher["esp_cipher"],
                    esp_hash=cipher["esp_hash"],
                    dh_group=dh_modp,
                    mode=mode,
                )

                out_path = f"generated_configs/{conn_name}.conf"
                with open(out_path, "w") as f:
                    f.write(rendered)

                count += 1

print(f"Generated {count} ipsec.conf combinations in ./generated_configs/")
