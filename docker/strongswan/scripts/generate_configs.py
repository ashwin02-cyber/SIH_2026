"""
generate_configs.py -- renders the 36 strongSwan ipsec.conf files
(3 ciphers x 3 DH groups x 2 modes x PFS on/off) from ipsec.conf.j2.

    python generate_configs.py            # writes ./generated_configs/*.conf

PFS handling (fixed): with "pfs-on" the ESP proposal now carries a DH group
(e.g. esp=aes128-sha256-modp2048!), so the child SA is rekeyed with a fresh
Diffie-Hellman exchange. With "pfs-off" it does not. Before this fix the
template ignored the PFS flag entirely, so pfs-on and pfs-off configs were
identical.
"""

import os

from jinja2 import Environment, FileSystemLoader

HERE = os.path.dirname(os.path.abspath(__file__))

CIPHERS = [
    {"ike_cipher": "aes128", "ike_hash": "sha256", "esp_cipher": "aes128", "esp_hash": "sha256"},
    {"ike_cipher": "aes256", "ike_hash": "sha256", "esp_cipher": "aes256", "esp_hash": "sha256"},
    # AEAD cipher: integrity is built in, so there is no separate ESP hash.
    {"ike_cipher": "aes128gcm16", "ike_hash": "sha256", "esp_cipher": "aes128gcm16", "esp_hash": ""},
]

# strongSwan group name -> short label used in file names
DH_GROUPS = {
    "modp1024": "dh2",
    "modp2048": "dh14",
    "ecp256": "dh19",
}

MODES = ["tunnel", "transport"]
PFS_STATES = [True, False]

PEER_A_IP = "10.10.0.10"
PEER_B_IP = "10.10.0.20"


def esp_proposal(cipher: dict, dh_group: str, pfs: bool) -> str:
    """e.g. 'aes128-sha256', 'aes128gcm16', 'aes128-sha256-modp2048', 'aes128gcm16-modp2048'."""
    parts = [cipher["esp_cipher"], cipher["esp_hash"]]
    if pfs:
        parts.append(dh_group)  # the PFS group: same group as the IKE SA
    return "-".join(p for p in parts if p)


def render_all(out_dir: str) -> list:
    """Render every combination into out_dir. Returns the list of conn names."""
    env = Environment(loader=FileSystemLoader(HERE), keep_trailing_newline=True)
    template = env.get_template("ipsec.conf.j2")
    os.makedirs(out_dir, exist_ok=True)

    names = []
    for cipher in CIPHERS:
        for dh_group, dh_label in DH_GROUPS.items():
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
                        dh_group=dh_group,
                        esp_proposal=esp_proposal(cipher, dh_group, pfs),
                        mode=mode,
                    )
                    with open(os.path.join(out_dir, f"{conn_name}.conf"), "w", newline="\n") as f:
                        f.write(rendered.replace("\r\n", "\n").replace("\r", ""))
                    names.append(conn_name)
    return names


if __name__ == "__main__":
    out = os.path.join(HERE, "generated_configs")
    n = len(render_all(out))
    print(f"Generated {n} ipsec.conf combinations in {out}")
