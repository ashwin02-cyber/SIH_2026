"""
make_fixtures.py -- regenerates the SYNTHETIC pcap fixtures in tests/fixtures/.

These files are hand-built with tests/synth_ike.py. They are NOT real
captures and must never be presented as such. Run:

    python tests/make_fixtures.py
"""

import os
import struct
import sys
import warnings

warnings.filterwarnings("ignore")
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from scapy.all import Ether, IP, UDP, Raw, wrpcap  # noqa: E402
from scapy.layers.ipsec import ESP  # noqa: E402

import synth_ike as s  # noqa: E402

OUT = os.path.join(os.path.dirname(os.path.abspath(__file__)), "fixtures")
A, B = "10.10.0.10", "10.10.0.20"


def _udp(data: bytes, src, dst, sport, dport, t):
    p = Ether() / IP(src=src, dst=dst) / UDP(sport=sport, dport=dport) / Raw(data)
    p.time = t
    return p


def build():
    os.makedirs(OUT, exist_ok=True)

    # 1. request offers two proposals, response selects AES-256-GCM / DH19
    req = s.ike_message(s.initiator_offer(s.AES256_GCM_DH19, s.AES128_CBC_DH2), response=False, dh_group=19)
    rsp = s.ike_message(s.proposal(1, s.AES256_GCM_DH19), response=True, dh_group=19)
    wrpcap(os.path.join(OUT, "SYNTHETIC_ike_sa_init_gcm256_dh19.pcap"),
           [_udp(req, A, B, 500, 500, 1.0), _udp(rsp, B, A, 500, 500, 1.001)])

    # 2. NAT-T (UDP/4500, 4-byte non-ESP marker), AES-128-CBC / DH2 (weak)
    marker = b"\x00\x00\x00\x00"
    req = s.ike_message(s.proposal(1, s.AES128_CBC_DH2), response=False, dh_group=2)
    rsp = s.ike_message(s.proposal(1, s.AES128_CBC_DH2), response=True, dh_group=2)
    wrpcap(os.path.join(OUT, "SYNTHETIC_ike_sa_init_cbc128_dh2_natt.pcap"),
           [_udp(marker + req, A, B, 4500, 4500, 1.0), _udp(marker + rsp, B, A, 4500, 4500, 1.001)])

    # 3. only the initiator request was captured (offer, not confirmed)
    req = s.ike_message(s.initiator_offer(s.AES256_CBC_DH14), response=False, dh_group=14)
    wrpcap(os.path.join(OUT, "SYNTHETIC_ike_sa_init_request_only.pcap"), [_udp(req, A, B, 500, 500, 1.0)])

    # 4. response cut short inside the SA payload (snaplen-style truncation)
    rsp = s.ike_message(s.proposal(1, s.AES256_GCM_DH19), response=True, dh_group=19)
    wrpcap(os.path.join(OUT, "SYNTHETIC_ike_sa_init_truncated_packet.pcap"),
           [_udp(rsp[:28 + 4 + 12], B, A, 500, 500, 1.0)])

    # 5. pcap FILE cut in the middle of the last record
    good = os.path.join(OUT, "SYNTHETIC_ike_sa_init_gcm256_dh19.pcap")
    with open(good, "rb") as f:
        raw = f.read()
    with open(os.path.join(OUT, "SYNTHETIC_truncated_file.pcap"), "wb") as f:
        f.write(raw[:-40])

    # 6. ESP only, no IKE at all
    esp = [Ether() / IP(src=A, dst=B, proto=50) / ESP(spi=0x1234, seq=i + 1) / Raw(b"\x99" * 64) for i in range(5)]
    for i, p in enumerate(esp):
        p.time = 1.0 + i
    wrpcap(os.path.join(OUT, "SYNTHETIC_esp_only.pcap"), esp)

    # 7. IKEv1 main-mode-looking header
    hdr = (b"\x33" * 8 + b"\x00" * 8 + struct.pack("!BBBBII", 1, 0x10, 2, 0, 0, 28 + 8) + b"\x00" * 8)
    wrpcap(os.path.join(OUT, "SYNTHETIC_ikev1_main_mode.pcap"), [_udp(hdr, A, B, 500, 500, 1.0)])

    # 8. UDP/4500 traffic that is ESP-in-UDP, not IKE (bogus-version guard)
    fake = struct.pack("!II", 0xC0FFEE01, 1) + b"\x20" * 60
    wrpcap(os.path.join(OUT, "SYNTHETIC_udp4500_esp_not_ike.pcap"), [_udp(fake, A, B, 4500, 4500, 1.0)])

    # 9. a file that is not a pcap at all
    with open(os.path.join(OUT, "SYNTHETIC_not_a_pcap.pcap"), "wb") as f:
        f.write(b"this is not a capture file\n")


if __name__ == "__main__":
    build()
    print("Wrote synthetic fixtures to", OUT)
