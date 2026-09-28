"""
check_handshakes.py
Checks every *__handshake.pcap in real_captures/ and reports IKE version, exchanges, and DH group.
Run from the repo root:  python check_handshakes.py
"""
import sys
from pathlib import Path
from scapy.all import rdpcap, UDP

sys.stdout.reconfigure(encoding="utf-8")

CAPTURE_DIR = Path("real_captures")
EXCHANGE_NAMES = {34: "IKE_SA_INIT", 35: "IKE_AUTH", 36: "CREATE_CHILD_SA", 37: "INFORMATIONAL",
                  2: "v1-MainMode", 4: "v1-Aggressive", 32: "v1-QuickMode", 5: "v1-Info"}

def get_ike_bytes(pkt):
    if UDP not in pkt:
        return None
    udp = pkt[UDP]
    data = bytes(udp.payload)
    if 500 in (udp.sport, udp.dport):
        return data
    if 4500 in (udp.sport, udp.dport):
        if data[:4] == b"\x00\x00\x00\x00":
            return data[4:]
    return None

def find_dh_group(msg):
    next_payload = msg[16]
    offset = 28
    while next_payload != 0 and offset + 4 <= len(msg):
        if next_payload == 46:
            return None
        this_type = next_payload
        next_payload = msg[offset]
        length = int.from_bytes(msg[offset + 2:offset + 4], "big")
        if this_type == 34 and offset + 6 <= len(msg):
            return int.from_bytes(msg[offset + 4:offset + 6], "big")
        if length < 4:
            break
        offset += length
    return None

def check_file(path):
    expected_dh = int(path.name.split("-dh")[1].split("-")[0])
    ike_count, versions, exchanges, dh_found = 0, set(), [], None
    for pkt in rdpcap(str(path)):
        msg = get_ike_bytes(pkt)
        if msg is None or len(msg) < 28:
            continue
        ike_count += 1
        version = "v2" if msg[17] >> 4 == 2 else "v1"
        versions.add(version)
        exchanges.append(EXCHANGE_NAMES.get(msg[18], f"type{msg[18]}"))
        if version == "v2" and msg[18] == 34 and dh_found is None:
            dh_found = find_dh_group(msg)
    return ike_count, versions, exchanges, expected_dh, dh_found

def main():
    files = sorted(CAPTURE_DIR.glob("*__handshake.pcap"))
    print(f"Found {len(files)} handshake files\n")
    ok = 0
    for f in files:
        count, versions, exchanges, expected, found = check_file(f)
        match = "OK " if found == expected else "?? "
        if found == expected:
            ok += 1
        unique_ex = sorted(set(exchanges))
        print(f"{match} {f.name}")
        print(f"     IKE packets: {count} | version: {','.join(versions) or '-'} | exchanges: {', '.join(unique_ex) or 'NONE'}")
        print(f"     DH in filename: {expected} | DH in packet: {found}\n")
    print(f"SUMMARY: {ok}/{len(files)} files OK")

if __name__ == "__main__":
    main()