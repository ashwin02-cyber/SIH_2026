"""List the ISAKMP/IKE packets in a pcap.

Usage: python check_handshak.py <path_to.pcap>
"""
import sys

from scapy.all import rdpcap
from scapy.layers.isakmp import ISAKMP

if len(sys.argv) != 2:
    sys.exit("Usage: python check_handshak.py <path_to.pcap>")

pkts = rdpcap(sys.argv[1])
print(f"Total packets in file: {len(pkts)}")

isakmp_count = 0
for pkt in pkts:
    if pkt.haslayer(ISAKMP):
        isakmp_count += 1
        print(pkt[ISAKMP].summary())

print(f"\nTotal ISAKMP/IKE packets found: {isakmp_count}")
