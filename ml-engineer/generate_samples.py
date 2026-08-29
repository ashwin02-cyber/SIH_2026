from scapy.all import IP, UDP, ICMP, Raw, wrpcap
import time
import random

# VoIP sample 2
print("Generating voip_sample2.pcap...")
packets = []
for i in range(150):
    pkt = IP(src='127.0.0.1', dst='127.0.0.2')/UDP(sport=5060, dport=5060)/Raw(load=b'x'*random.randint(40,80))
    packets.append(pkt)
wrpcap('voip_sample2.pcap', packets)
print(f"Done! Packets: {len(packets)}")

# VoIP sample 3
print("Generating voip_sample3.pcap...")
packets = []
for i in range(200):
    pkt = IP(src='192.168.1.1', dst='192.168.1.2')/UDP(sport=5060, dport=5060)/Raw(load=b'x'*random.randint(40,80))
    packets.append(pkt)
wrpcap('voip_sample3.pcap', packets)
print(f"Done! Packets: {len(packets)}")

# VoIP sample 4
print("Generating voip_sample4.pcap...")
packets = []
for i in range(120):
    pkt = IP(src='10.0.0.1', dst='10.0.0.2')/UDP(sport=5060, dport=5060)/Raw(load=b'x'*random.randint(40,80))
    packets.append(pkt)
wrpcap('voip_sample4.pcap', packets)
print(f"Done! Packets: {len(packets)}")

# ICMP sample 3
print("Generating icmp_sample3.pcap...")
packets = []
for i in range(50):
    pkt = IP(src='127.0.0.'+str(i%10+1), dst='127.0.0.'+str(i%5+2))/ICMP()
    packets.append(pkt)
wrpcap('icmp_sample3.pcap', packets)
print(f"Done! Packets: {len(packets)}")

print("\nAll samples generated successfully!")