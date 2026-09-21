"""
ike_parser.py
Parses the IKEv2 handshake from a pcap file to extract security-relevant
facts: cipher, DH group, key length, integrity/PRF, PFS signal, and mode.

APPROACH
--------
Scapy is used only to read the pcap and pull out UDP payload bytes; the IKE
wire format (RFC 7296) is then walked by hand, so the result does not depend
on Scapy's dissector field names.

WHAT A PASSIVE CAPTURE CAN AND CANNOT SHOW
------------------------------------------
Only the IKE_SA_INIT exchange is sent in the clear. It negotiates the IKE SA
itself (control-channel cipher, PRF, integrity, DH group). The ESP/child-SA
parameters (its own cipher, whether a fresh DH exchange -- PFS -- was done,
tunnel-vs-transport mode) are negotiated in IKE_AUTH / CREATE_CHILD_SA, which
is encrypted under keys derived from IKE_SA_INIT. Nobody can read those bytes
from a passive capture without the keys.

Consequences, all enforced by this module:
  * A value that was not observed is reported as None / "unknown". Nothing is
    guessed or defaulted (in particular, mode is NOT assumed to be "tunnel").
  * ike_version is only reported when an IKE_SA_INIT (the exchange that
    carries the negotiation) was really seen. Encrypted IKEv2 packets on their
    own (e.g. INFORMATIONAL keep-alives) are counted, and mentioned in
    `warnings`, but do not by themselves set the version.
  * IKE headers are validated (version byte, exchange type, length field,
    SPI) before being trusted, so ESP-in-UDP data or random UDP/4500 payloads
    are not mistaken for IKE.
  * Truncated files / truncated packets never raise; whatever could be parsed
    is returned and `handshake.truncated` is set.

Malformed input that is not a pcap at all raises ValueError.
"""

import struct

from scapy.all import IP, UDP, PcapReader
from scapy.error import Scapy_Exception

IKE_PORTS = (500, 4500)
NAT_T_PORT = 4500

# --- RFC 7296 / IANA constant tables --------------------------------------

ENCR_ALGO_NAMES = {
    3: "3DES",
    12: "AES-CBC",
    13: "AES-CTR",
    14: "AES-CCM-8",
    15: "AES-CCM-12",
    16: "AES-CCM-16",
    18: "AES-GCM-8",
    19: "AES-GCM-12",
    20: "AES-GCM-16",  # AEAD variant
    28: "ChaCha20-Poly1305",
}

INTEG_ALGO_NAMES = {
    1: "HMAC-MD5-96",
    2: "HMAC-SHA1-96",
    12: "HMAC-SHA2-256-128",
    13: "HMAC-SHA2-384-192",
    14: "HMAC-SHA2-512-256",
}

PRF_ALGO_NAMES = {
    1: "PRF-HMAC-MD5",
    2: "PRF-HMAC-SHA1",
    5: "PRF-HMAC-SHA2-256",
    6: "PRF-HMAC-SHA2-384",
    7: "PRF-HMAC-SHA2-512",
}

DH_GROUP_LABELS = {
    1: "Group 1 (768-bit MODP)",
    2: "Group 2 (1024-bit MODP)",
    5: "Group 5 (1536-bit MODP)",
    14: "Group 14 (2048-bit MODP)",
    15: "Group 15 (3072-bit MODP)",
    16: "Group 16 (4096-bit MODP)",
    19: "Group 19 (256-bit random ECP)",
    20: "Group 20 (384-bit random ECP)",
    21: "Group 21 (521-bit random ECP)",
    31: "Group 31 (Curve25519)",
}

TRANSFORM_TYPE_NAMES = {1: "ENCR", 2: "PRF", 3: "INTEG", 4: "DH", 5: "ESN"}
PROTOCOL_ID_NAMES = {1: "IKE", 2: "AH", 3: "ESP"}

KEY_LENGTH_ATTR_TYPE = 14  # RFC 7296 3.3.5 -- sent as a TV attribute

PAYLOAD_SA = 33
PAYLOAD_NOTIFY = 41
NOTIFY_USE_TRANSPORT_MODE = 16391

EXCH_IKE_SA_INIT = 34
EXCH_IKE_AUTH = 35
EXCH_CREATE_CHILD_SA = 36
EXCH_INFORMATIONAL = 37
IKEV2_EXCHANGES = (34, 35, 36, 37)
# IKEv1: Identity Protection, Aggressive, Informational, Quick Mode, New Group
IKEV1_EXCHANGES = (2, 4, 5, 32, 33)

IKE_HEADER_LEN = 28
FLAG_RESPONSE = 0x20
FLAGS_VALID_MASK = 0xC7  # bits 0-2 and 6-7 are reserved and must be zero


class _Truncated(Exception):
    """Raised internally when a structure runs past the end of the buffer."""


def _u16(buf: bytes, off: int) -> int:
    if off < 0 or off + 2 > len(buf):
        raise _Truncated()
    return struct.unpack("!H", buf[off:off + 2])[0]


def _u8(buf: bytes, off: int) -> int:
    if off < 0 or off >= len(buf):
        raise _Truncated()
    return buf[off]


def _strip_nat_t_marker(data: bytes, on_nat_t_port: bool = True) -> bytes:
    """NAT-T (RFC 3948, UDP/4500) prepends a 4-byte zero "non-ESP marker"
    before the ISAKMP header so it is not confused with ESP. Only applies to
    UDP/4500; on UDP/500 the header starts at byte 0."""
    if on_nat_t_port and len(data) >= 4 and data[:4] == b"\x00\x00\x00\x00":
        return data[4:]
    return data


def classify_ike_header(payload: bytes):
    """Decide whether `payload` (the UDP payload with any NAT-T marker
    removed) starts with a plausible ISAKMP header.

    Returns a dict {version, exchange, is_response, length, truncated,
    next_payload} for IKEv2/IKEv1, or None if it does not look like IKE.
    Requires the whole 28-byte header to be present.
    """
    if len(payload) < IKE_HEADER_LEN:
        return None
    if payload[:8] == b"\x00" * 8:  # initiator SPI must be non-zero
        return None

    version_byte = payload[17]
    major, minor = version_byte >> 4, version_byte & 0x0F
    exchange = payload[18]
    flags = payload[19]
    length = struct.unpack("!I", payload[24:28])[0]

    if major == 2 and minor == 0 and exchange in IKEV2_EXCHANGES:
        if flags & FLAGS_VALID_MASK:
            return None
        version = "2.0"
    elif major == 1 and minor == 0 and exchange in IKEV1_EXCHANGES:
        version = "1.0"
    else:
        return None

    # The length field must describe this datagram. If the capture was cut
    # short (snaplen) the field is larger than what we have -- that is
    # legitimate truncation. A field smaller than the header, or smaller
    # than the data, means these bytes are not an IKE message.
    if length < IKE_HEADER_LEN or length > 65535:
        return None
    if length < len(payload):
        return None

    return {
        "version": version,
        "exchange": exchange,
        "is_response": bool(flags & FLAG_RESPONSE),
        "length": length,
        "truncated": length > len(payload),
        "next_payload": payload[16],
    }


def _parse_transform(buf: bytes, offset: int):
    """Parse one Transform substructure starting at `offset`.
    Returns (transform_dict, offset_of_next_transform)."""
    length = _u16(buf, offset + 2)
    if length < 8:
        raise _Truncated()
    ttype = _u8(buf, offset + 4)
    tid = _u16(buf, offset + 6)
    end = offset + length
    if end > len(buf):
        raise _Truncated()

    attrs = {}
    attr_off = offset + 8
    while attr_off + 4 <= end:
        attr_type_raw = _u16(buf, attr_off)
        is_tv = bool(attr_type_raw & 0x8000)
        attr_type = attr_type_raw & 0x7FFF
        if is_tv:
            attrs[attr_type] = _u16(buf, attr_off + 2)
            attr_off += 4
        else:
            alen = _u16(buf, attr_off + 2)
            if attr_off + 4 + alen > end:
                raise _Truncated()
            attrs[attr_type] = buf[attr_off + 4:attr_off + 4 + alen]
            attr_off += 4 + alen

    transform = {
        "type": TRANSFORM_TYPE_NAMES.get(ttype, ttype),
        "id": tid,
        "attrs": attrs,
    }
    return transform, end


def _parse_proposal(buf: bytes, offset: int):
    """Parse one Proposal. Returns (proposal_dict, next_offset, next_payload_flag)."""
    next_payload = _u8(buf, offset)  # 0 = last proposal, 2 = more follow
    length = _u16(buf, offset + 2)
    if length < 8:
        raise _Truncated()
    proto_id = _u8(buf, offset + 5)
    spi_size = _u8(buf, offset + 6)
    num_transforms = _u8(buf, offset + 7)

    t_off = offset + 8 + spi_size
    transforms = []
    for _ in range(num_transforms):
        transform, t_off = _parse_transform(buf, t_off)
        transforms.append(transform)

    proposal = {"protocol": PROTOCOL_ID_NAMES.get(proto_id, proto_id), "transforms": transforms}
    return proposal, offset + length, next_payload


def _parse_sa_payload(buf: bytes, body_offset: int, payload_len: int):
    """Parse an SA payload body (payload_len includes the 4-byte generic
    header). Returns (proposals, truncated_flag). Proposals fully parsed
    before a truncation are still returned."""
    end = min(body_offset + payload_len - 4, len(buf))
    proposals = []
    p_off = body_offset
    try:
        while p_off < end:
            proposal, p_off, next_payload = _parse_proposal(buf, p_off)
            proposals.append(proposal)
            if next_payload == 0:
                break
    except _Truncated:
        return proposals, True
    return proposals, False


def _walk_payloads(buf: bytes, first_payload: int, start: int, end: int):
    """Walk the generic-payload chain. Yields (payload_type, body_offset, payload_len)
    where payload_len includes the 4-byte generic header. Stops quietly on
    malformed/truncated data."""
    ptype = first_payload
    off = start
    while ptype != 0 and 0 <= off and off + 4 <= min(end, len(buf)):
        length = struct.unpack("!H", buf[off + 2:off + 4])[0]
        if length < 4 or off + length > len(buf):
            break  # malformed or truncated -- stop rather than read garbage
        yield ptype, off + 4, length
        ptype = buf[off]
        off += length


def _summarize_proposal(proposal: dict) -> dict:
    cipher = None
    key_length_bits = None
    integrity = None
    prf = None
    dh_group = None
    dh_group_label = None

    for t in proposal["transforms"]:
        if t["type"] == "ENCR":
            cipher = ENCR_ALGO_NAMES.get(t["id"], f"Unknown ENCR id {t['id']}")
            if KEY_LENGTH_ATTR_TYPE in t["attrs"]:
                key_length_bits = t["attrs"][KEY_LENGTH_ATTR_TYPE]
        elif t["type"] == "INTEG":
            integrity = INTEG_ALGO_NAMES.get(t["id"], f"Unknown INTEG id {t['id']}")
        elif t["type"] == "PRF":
            prf = PRF_ALGO_NAMES.get(t["id"], f"Unknown PRF id {t['id']}")
        elif t["type"] == "DH":
            dh_group = t["id"]
            dh_group_label = DH_GROUP_LABELS.get(t["id"], f"Group {t['id']}")

    return {
        "cipher": cipher,
        "key_length_bits": key_length_bits,
        "integrity": integrity,
        "prf": prf,
        "dh_group": dh_group,
        "dh_group_label": dh_group_label,
    }


def _read_packets(pcap_path: str):
    """Read packets from a pcap/pcapng. Returns (list_of_packets, truncated).
    A truncated file yields the packets that could be read. A file that is
    not a capture at all raises ValueError. The file handle is always closed
    (Scapy leaks it when the header is invalid, which blocks deleting the
    file on Windows)."""
    packets = []
    truncated = False
    try:
        fh = open(pcap_path, "rb")
    except OSError as e:
        raise ValueError(f"Cannot read capture file: {e}") from e

    try:
        try:
            reader = PcapReader(fh)
        except (Scapy_Exception, struct.error, EOFError, OSError) as e:
            raise ValueError(f"Not a readable pcap/pcapng file: {e}") from e

        while True:
            try:
                pkt = reader.read_packet()
            except EOFError:
                break
            except (Scapy_Exception, struct.error, ValueError, IndexError):
                truncated = True  # damaged record in the middle/end of file
                break
            if pkt is None:
                break
            packets.append(pkt)
    finally:
        fh.close()
    return packets, truncated


def parse_ike_handshake(pcap_path: str) -> dict:
    """
    Returns:
    {
      "ike_version": "2.0" | "1.0" | "unknown",
      "mode": "tunnel" | "transport" | "unknown",   # "unknown" = not observable in the clear
      "ike_sa": {cipher, key_length_bits, integrity, prf, dh_group, dh_group_label} | None,
      "esp_sa": {..., "pfs": bool} | None,           # usually None -- see module docstring
      "handshake": {
          "ike_sa_init_seen": bool,
          "sa_source": "responder-selected" | "initiator-offered" | None,
          "ike_packets": int, "encrypted_ike_packets": int, "esp_packets": int,
          "truncated": bool,
      },
      "warnings": [str, ...],
    }
    """
    packets, file_truncated = _read_packets(pcap_path)

    warnings = []
    mode = "unknown"
    ike_sa_selected = None   # from a responder message (what was actually agreed)
    ike_sa_offered = None    # from an initiator message (first proposal offered)
    esp_sa_info = None
    saw_ikev2_init = False
    saw_ikev1 = False
    ike_packets = 0
    encrypted_ike_packets = 0
    esp_packets = 0
    packet_truncated = False

    for pkt in packets:
        if IP in pkt and pkt[IP].proto == 50:
            esp_packets += 1
            continue
        if UDP not in pkt:
            continue
        sport, dport = pkt[UDP].sport, pkt[UDP].dport
        if sport not in IKE_PORTS and dport not in IKE_PORTS:
            continue

        on_nat_t = NAT_T_PORT in (sport, dport)
        raw = bytes(pkt[UDP].payload)
        payload = _strip_nat_t_marker(raw, on_nat_t)

        header = classify_ike_header(payload)
        if header is None:
            if on_nat_t and raw[:4] != b"\x00\x00\x00\x00" and len(raw) >= 8:
                esp_packets += 1  # ESP-in-UDP (NAT-T): SPI is non-zero
            continue

        ike_packets += 1
        if header["version"] == "1.0":
            saw_ikev1 = True
            continue

        if header["exchange"] != EXCH_IKE_SA_INIT:
            encrypted_ike_packets += 1  # payloads are inside an SK payload
            continue

        saw_ikev2_init = True
        if header["truncated"]:
            packet_truncated = True

        end = min(header["length"], len(payload))
        for ptype, body_off, plen in _walk_payloads(payload, header["next_payload"], IKE_HEADER_LEN, end):
            if ptype == PAYLOAD_SA:
                proposals, cut = _parse_sa_payload(payload, body_off, plen)
                packet_truncated = packet_truncated or cut
                for prop in proposals:
                    info = _summarize_proposal(prop)
                    if prop["protocol"] == "IKE":
                        if header["is_response"]:
                            if ike_sa_selected is None:
                                ike_sa_selected = info
                        elif ike_sa_offered is None:
                            ike_sa_offered = info  # first proposal offered
                    elif prop["protocol"] == "ESP" and esp_sa_info is None:
                        info["pfs"] = info["dh_group"] is not None
                        esp_sa_info = info
            elif ptype == PAYLOAD_NOTIFY:
                try:
                    if _u16(payload, body_off + 2) == NOTIFY_USE_TRANSPORT_MODE:
                        mode = "transport"
                except _Truncated:
                    packet_truncated = True

    ike_sa_info = ike_sa_selected or ike_sa_offered
    sa_source = "responder-selected" if ike_sa_selected else ("initiator-offered" if ike_sa_offered else None)

    if saw_ikev2_init:
        ike_version = "2.0"
    elif saw_ikev1:
        ike_version = "1.0"
        warnings.append(
            "IKEv1 handshake detected -- this parser decodes IKEv2 transform "
            "tables only, so no cipher/DH values are reported for it."
        )
    else:
        ike_version = "unknown"

    if file_truncated or packet_truncated:
        warnings.append(
            "The capture is truncated (cut-off file or packets shorter than "
            "their IKE length). Results are based on the parts that could be read."
        )

    if ike_sa_info is None and ike_version != "1.0":
        if encrypted_ike_packets:
            warnings.append(
                f"{encrypted_ike_packets} IKEv2 packet(s) were seen but they are encrypted "
                "IKE_AUTH/INFORMATIONAL messages; the cleartext IKE_SA_INIT exchange was "
                "not captured (start the capture before the tunnel comes up), so cipher "
                "and DH group cannot be read from this file."
            )
        else:
            warnings.append(
                "No IKE_SA_INIT exchange was found in this pcap, so cipher and DH group "
                "cannot be read from it (it may contain only ESP data)."
            )
    elif sa_source == "initiator-offered":
        warnings.append(
            "Only the initiator's IKE_SA_INIT request was captured, so the values shown "
            "are the first proposal OFFERED, not necessarily what the peer accepted."
        )

    if mode == "unknown":
        warnings.append(
            "Tunnel/transport mode is negotiated inside the encrypted IKE_AUTH exchange "
            "and is not observable in this capture; it is reported as 'unknown'."
        )

    if esp_sa_info is None:
        warnings.append(
            "The ESP SA's own cipher/DH/PFS live inside the encrypted IKE_AUTH exchange "
            "and were not observed; PFS is reported as unknown."
        )

    return {
        "ike_version": ike_version,
        "mode": mode,
        "ike_sa": ike_sa_info,
        "esp_sa": esp_sa_info,
        "handshake": {
            "ike_sa_init_seen": saw_ikev2_init,
            "sa_source": sa_source,
            "ike_packets": ike_packets,
            "encrypted_ike_packets": encrypted_ike_packets,
            "esp_packets": esp_packets,
            "truncated": bool(file_truncated or packet_truncated),
        },
        "warnings": warnings,
    }


if __name__ == "__main__":
    import json
    import sys

    if len(sys.argv) != 2:
        print("Usage: python ike_parser.py <path_to.pcap>")
        sys.exit(1)

    print(json.dumps(parse_ike_handshake(sys.argv[1]), indent=2))
