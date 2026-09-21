"""
make_esp_fixtures.py -- SYNTHETIC ESP pcaps with a KNOWN sequence-number / SPI behaviour, for tests only.

These are hand-built with Scapy. They are NOT real captures and must never be presented as such. They exist
because the real testbed captures contain no rekey, no gaps and no duplicates, so esp_sequence.py could not
otherwise be tested on those situations.  Regenerate: python tests/make_esp_fixtures.py
"""
import os
import warnings

warnings.filterwarnings("ignore")
from scapy.all import Ether, IP, IPv6, Raw, wrpcap  # noqa: E402
from scapy.layers.inet6 import IPv6 as _IPv6  # noqa: E402,F401
from scapy.layers.ipsec import AH, ESP  # noqa: E402

OUT = os.path.join(os.path.dirname(os.path.abspath(__file__)), "fixtures")
A, B = "10.10.0.10", "10.10.0.20"
A6, B6 = "fd00::10", "fd00::20"


def esp(t, src, dst, spi, seq, size=64):
    p = Ether(src="02:00:00:00:00:01", dst="02:00:00:00:00:02") / IP(src=src, dst=dst, proto=50) / ESP(spi=spi, seq=seq) / Raw(bytes([0x99]) * size)
    p.time = t
    return p


def build():
    os.makedirs(OUT, exist_ok=True)

    # 1. two clean SAs (one per direction), 30 packets each, strictly increasing, starting at 1
    pk = []
    for i in range(30):
        pk.append(esp(1.0 + i * 0.1, A, B, 0x1001, i + 1))
        pk.append(esp(1.05 + i * 0.1, B, A, 0x2001, i + 1))
    wrpcap(os.path.join(OUT, "SYNTHETIC_esp_clean_two_sas.pcap"), pk)

    # 2. anomalies on the A->B SA: gap (seq 11-14 missing), 2 duplicates, 1 out-of-order
    seqs = list(range(1, 11)) + list(range(15, 26)) + [20, 21] + [12] + list(range(26, 31))
    wrpcap(os.path.join(OUT, "SYNTHETIC_esp_anomalies.pcap"), [esp(1.0 + i * 0.1, A, B, 0x1001, s) for i, s in enumerate(seqs)])

    # 3. rekey, both directions: SA 0x1001 runs 0-25 s then 0x1002 takes over (start observed, seq 1)
    pk = []
    for i in range(50):
        pk.append(esp(0.0 + i * 0.5, A, B, 0x1001, i + 1))
        pk.append(esp(0.02 + i * 0.5, B, A, 0x2001, i + 1))
    for i in range(20):
        pk.append(esp(25.0 + i * 0.5, A, B, 0x1002, i + 1))
        pk.append(esp(25.02 + i * 0.5, B, A, 0x2002, i + 1))
    wrpcap(os.path.join(OUT, "SYNTHETIC_esp_rekey_observed.pcap"), pk)

    # 4. capture starts in the middle of an SA (seq ~5000) and then a rekey happens -> only a lower bound
    pk = [esp(0.0 + i * 0.5, A, B, 0x3001, 5000 + i) for i in range(20)] + [esp(10.0 + i * 0.5, A, B, 0x3002, i + 1) for i in range(10)]
    wrpcap(os.path.join(OUT, "SYNTHETIC_esp_rekey_start_not_observed.pcap"), pk)

    # 5. two SPIs in one direction that overlap for a long time: parallel child SAs, not a rekey
    pk = []
    for i in range(30):
        pk.append(esp(0.0 + i * 1.0, A, B, 0x4001, i + 1))
        pk.append(esp(5.0 + i * 1.0, A, B, 0x4002, i + 1))
    wrpcap(os.path.join(OUT, "SYNTHETIC_esp_parallel_sas.pcap"), pk)


if __name__ == "__main__":
    build()
    print("Wrote SYNTHETIC ESP fixtures to", OUT)
