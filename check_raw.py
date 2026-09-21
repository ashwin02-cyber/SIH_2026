from scapy.all import rdpcap

path = r"E:\SIH_2026\real_captures\aes256-dh19-transport-pfs-off__handshake.pcap"
pkts = rdpcap(path)

print(f"Total packets: {len(pkts)}")
for i, pkt in enumerate(pkts):
    print(f"\n--- Packet {i+1} ---")
    print(pkt.summary())
    print(f"Length: {len(pkt)} bytes")