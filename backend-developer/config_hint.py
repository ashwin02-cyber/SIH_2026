"""
config_hint.py
Reads the VPN configuration that the TESTBED encoded in a capture's file name,
e.g.  aes128gcm16-dh19-tunnel-pfs-on__web_run1.pcap.

This is DECLARED information, not something observed in the capture. The
analyzer uses it only as a labelled fallback when the pcap itself does not
contain the cleartext IKE_SA_INIT exchange (true for every capture in the
first dataset). API responses tag each value with its source
("observed" / "declared" / "unknown") so the UI and reports never present a
declared value as a measurement.

PFS is NOT taken from the file name by default. In the first dataset the
"pfs-on" and "pfs-off" testbed configs were byte-identical, so the name says
nothing about the real behaviour. Set SIH_TRUST_DECLARED_PFS=1 once captures
have been regenerated with the fixed testbed (config_version v2).
"""

import os
import re

_PATTERN = re.compile(r"(?P<cipher>aes\d+(?:gcm\d+)?)-dh(?P<dh>\d+)-(?P<mode>tunnel|transport)-pfs-(?P<pfs>on|off)")

# testbed cipher label -> (ike_parser style cipher name, key length in bits)
_CIPHERS = {
    "aes128": ("AES-CBC", 128),
    "aes256": ("AES-CBC", 256),
    "aes128gcm16": ("AES-GCM-16", 128),
    "aes256gcm16": ("AES-GCM-16", 256),
}


def declared_config_from_filename(filename: str):
    """Returns {cipher, key_length_bits, dh_group, mode, pfs, source} or None.
    `pfs` is True/False only if SIH_TRUST_DECLARED_PFS=1, otherwise None (unknown)."""
    m = _PATTERN.search(os.path.basename(filename or ""))
    if not m or m.group("cipher") not in _CIPHERS:
        return None
    cipher, bits = _CIPHERS[m.group("cipher")]
    trust_pfs = os.environ.get("SIH_TRUST_DECLARED_PFS") == "1"
    return {
        "cipher": cipher,
        "key_length_bits": bits,
        "dh_group": int(m.group("dh")),
        "mode": m.group("mode"),
        "pfs": (m.group("pfs") == "on") if trust_pfs else None,
        "source": "declared by the testbed file name",
    }
