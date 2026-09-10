from scapy.all import IP, TCP, Raw, wrpcap
import random

# Video sample 2 - large packets, steady stream (typical video)
print("Generating video_sample2.pcap...")
packets = []
for i in range(500):
    pkt = IP(src='192.168.1.1', dst='192.168.1.2')/TCP(sport=443, dport=random.randint(1024,65535))/Raw(load=b'x'*random.randint(800,1400))
    packets.append(pkt)
wrpcap('video_sample2.pcap', packets)
print(f"Done! Packets: {len(packets)}")

# Video sample 3
print("Generating video_sample3.pcap...")
packets = []
for i in range(400):
    pkt = IP(src='10.0.0.1', dst='10.0.0.2')/TCP(sport=443, dport=random.randint(1024,65535))/Raw(load=b'x'*random.randint(900,1500))
    packets.append(pkt)
wrpcap('video_sample3.pcap', packets)
print(f"Done! Packets: {len(packets)}")

# Video sample 4
print("Generating video_sample4.pcap...")
packets = []
for i in range(600):
    pkt = IP(src='172.16.0.1', dst='172.16.0.2')/TCP(sport=443, dport=random.randint(1024,65535))/Raw(load=b'x'*random.randint(700,1200))
    packets.append(pkt)
wrpcap('video_sample4.pcap', packets)
print(f"Done! Packets: {len(packets)}")

print("\nAll video samples generated!")