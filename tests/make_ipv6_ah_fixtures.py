"""
make_ipv6_ah_fixtures.py -- SYNTHETIC IPv6 / AH / NAT-T pcaps, for tests only.

Hand-built with Scapy from the protocol layouts (RFC 4303 ESP, RFC 4302 AH, RFC 8200 IPv6). They are NOT real
captures and must never be presented as such: the real testbed captures are IPv4 ESP only, so IPv6 and AH support
could not otherwise be tested. Regenerate:  python tests/make_ipv6_ah_fixtures.py
"""
import os
import sys
import warnings

warnings.filterwarnings("ignore")
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from scapy.all import Ether, IP, IPv6, Raw, UDP, wrpcap  # noqa: E402
from scapy.layers.inet6 import IPv6ExtHdrDestOpt  # noqa: E402
from scapy.layers.ipsec import AH, ESP  # noqa: E402

import synth_ike as s  # noqa: E402

OUT = os.path.join(os.path.dirname(os.path.abspath(__file__)), "fixtures")
E = lambda: Ether(src="02:00:00:00:00:01", dst="02:00:00:00:00:02")  # noqa: E731  explicit MACs: no ARP lookups
A4, B4 = "10.10.0.10", "10.10.0.20"
A6, B6 = "fd00::10", "fd00::20"
PAYLOADS = [40, 52, 64, 100, 128, 300, 576, 1000, 1200, 33, 77, 91]     # bytes of Raw payload behind the ESP header


def _stamp(p, t):
    p.time = t
    return p


def esp6(t, src, dst, spi, seq, size, ext=False):
    ip = IPv6(src=src, dst=dst)
    if ext:
        ip = ip / IPv6ExtHdrDestOpt()
    return _stamp(E() / ip / ESP(spi=spi, seq=seq) / Raw(bytes([0x99]) * size), t)


def ah(t, ipver, src, dst, spi, seq, size):
    ip = IP(src=src, dst=dst) if ipver == 4 else IPv6(src=src, dst=dst)
    return _stamp(E() / ip / AH(nh=6, payloadlen=4, spi=spi, seq=seq, icv=b"\x00" * 12) / Raw(b"PLAINTEXT-VISIBLE-" * (size // 18 + 1)), t)


def build():
    os.makedirs(OUT, exist_ok=True)

    # IPv6 ESP: two SAs, 40 packets each, monotonic sequence numbers, varied payload lengths
    pk = []
    for i in range(40):
        pk.append(esp6(1.0 + i * 0.05, A6, B6, 0x6001, i + 1, PAYLOADS[i % len(PAYLOADS)]))
        pk.append(esp6(1.02 + i * 0.05, B6, A6, 0x6002, i + 1, PAYLOADS[(i + 3) % len(PAYLOADS)]))
    wrpcap(os.path.join(OUT, "SYNTHETIC_ipv6_esp.pcap"), pk)

    # IPv6 ESP behind a destination-options extension header (esp_len must exclude the 8 extension bytes)
    wrpcap(os.path.join(OUT, "SYNTHETIC_ipv6_esp_ext_header.pcap"),
           [_stamp(E() / IPv6(src=A6, dst=B6) / IPv6ExtHdrDestOpt() / ESP(spi=0x6101, seq=i + 1) / Raw(bytes([0x99]) * 64), 1.0 + i * 0.1) for i in range(12)])

    # IPv4 and IPv6 AH (integrity only: the payload is plaintext)
    wrpcap(os.path.join(OUT, "SYNTHETIC_ipv4_ah.pcap"), [ah(1.0 + i * 0.1, 4, A4 if i % 2 == 0 else B4, B4 if i % 2 == 0 else A4, 0xA001 + (i % 2), i // 2 + 1, 60 + 7 * i) for i in range(30)])
    wrpcap(os.path.join(OUT, "SYNTHETIC_ipv6_ah.pcap"), [ah(1.0 + i * 0.1, 6, A6 if i % 2 == 0 else B6, B6 if i % 2 == 0 else A6, 0xA101 + (i % 2), i // 2 + 1, 60 + 7 * i) for i in range(30)])

    # ESP and AH together on IPv4
    mixed = [_stamp(E() / IP(src=A4, dst=B4, proto=50) / ESP(spi=0xB001, seq=i + 1) / Raw(bytes([0x99]) * (40 + 12 * i)), 1.0 + i * 0.1) for i in range(15)]
    mixed += [ah(1.05 + i * 0.1, 4, B4, A4, 0xB002, i + 1, 80) for i in range(15)]
    wrpcap(os.path.join(OUT, "SYNTHETIC_ipv4_esp_and_ah.pcap"), mixed)

    # ESP in UDP/4500 (NAT-T), IPv4, with a proper SPI (non-zero first bytes)
    wrpcap(os.path.join(OUT, "SYNTHETIC_natt_esp_udp4500.pcap"),
           [_stamp(E() / IP(src=A4, dst=B4) / UDP(sport=4500, dport=4500) / ESP(spi=0x0C001, seq=i + 1) / Raw(bytes([0x99]) * (48 + 4 * i)), 1.0 + i * 0.1) for i in range(15)])

    # IKE_SA_INIT over IPv6 (UDP/500): request + response selecting AES-256-GCM / DH 19
    req = s.ike_message(s.initiator_offer(s.AES256_GCM_DH19, s.AES128_CBC_DH2), response=False, dh_group=19)
    rsp = s.ike_message(s.proposal(1, s.AES256_GCM_DH19), response=True, dh_group=19)
    wrpcap(os.path.join(OUT, "SYNTHETIC_ipv6_ike_sa_init.pcap"),
           [_stamp(E() / IPv6(src=A6, dst=B6) / UDP(sport=500, dport=500) / Raw(req), 1.0), _stamp(E() / IPv6(src=B6, dst=A6) / UDP(sport=500, dport=500) / Raw(rsp), 1.001)])


if __name__ == "__main__":
    build()
    print("Wrote SYNTHETIC IPv6 / AH fixtures to", OUT)
