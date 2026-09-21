"""Print a one-line summary of every packet in a pcap.

Usage: python check_raw.py <path_to.pcap>
"""
import sys

from scapy.all import rdpcap

if len(sys.argv) != 2:
    sys.exit("Usage: python check_raw.py <path_to.pcap>")

pkts = rdpcap(sys.argv[1])
print(f"Total packets: {len(pkts)}")
for i, pkt in enumerate(pkts):
    print(f"\n--- Packet {i+1} ---")
    print(pkt.summary())
    print(f"Length: {len(pkt)} bytes")
