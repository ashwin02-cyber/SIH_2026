from scapy.all import rdpcap
from scapy.layers.isakmp import ISAKMP

path = r"E:\SIH_2026\real_captures\aes256-dh19-transport-pfs-off__handshake.pcap"
pkts = rdpcap(path)

print(f"Total packets in file: {len(pkts)}")

isakmp_count = 0
for pkt in pkts:
    if pkt.haslayer(ISAKMP):
        isakmp_count += 1
        print(pkt[ISAKMP].summary())

print(f"\nTotal ISAKMP/IKE packets found: {isakmp_count}")