"""
ike_parser.py
Parses the IKEv2 handshake from a pcap file to extract security-relevant
facts: cipher, DH group, key length, PFS signal, and mode.

APPROACH
--------
Rather than depend on Scapy's or PyShark's exact field names (which shift
between versions), this walks the wire format directly using the fixed
byte layout from RFC 7296 (IKEv2 payloads) via Scapy only for reading the
pcap and pulling out UDP payload bytes. RFC formats don't change, so this
is the most dependency-proof way to get this right.

IMPORTANT PROTOCOL CAVEAT — READ THIS BEFORE TRUSTING THE OUTPUT
-----------------------------------------------------------------
Only the IKE_SA_INIT exchange is sent in the clear. It negotiates the
*IKE SA* itself (the control-channel cipher/DH/lifetime) — this is what
"IKE handshake, mostly plaintext" in the project brief refers to, and
it's what this parser reliably extracts.

The actual ESP/child-SA parameters (its own cipher, whether a fresh DH
exchange — PFS — was done for it, and tunnel-vs-transport mode) are
negotiated inside IKE_AUTH / CREATE_CHILD_SA, which is ENCRYPTED under
keys derived from IKE_SA_INIT's own DH exchange. That's true for every
compliant IKEv2 implementation — there's no way to see those bytes from
a passive capture without the derived keys. IKEv1 has the same shape:
Phase 1 (ISAKMP SA) is visible, Phase 2 Quick Mode (the ESP SA) is not.

Practically: if your testbed applies one shared cipher/DH/PFS/mode choice
to both `ike=` and `esp=` lines in the strongSwan config (which is what
the project's "chosen scope" table implies — one combined axis, not two
independent ones), the IKE SA values below ARE a faithful stand-in for
the whole tunnel's settings. Worth a 2-minute check with the Testbed Lead
to confirm the Jinja2 templates actually do this. Where the ESP SA's own
values genuinely aren't observable, this parser reports None rather than
guessing — scoring_engine.py handles those as "unknown", not "weak".

STATUS: written against the RFC spec, not yet run against a real pcap
(no network/Scapy available in the environment this was written in). Run
it against a real capture from `real_captures/` first and report back
anything that looks wrong — most likely trouble spots:
  - IKEv1 pcaps are detected but not parsed (this is called out clearly
    in `warnings`, not silently wrong)
  - NAT-T captures (UDP port 4500) have a 4-byte zero marker before the
    ISAKMP header — handled in `_strip_nat_t_marker`, worth double
    checking against your captures
"""

import struct

from scapy.all import rdpcap, UDP

IKE_PORTS = (500, 4500)

# --- RFC 7296 constant tables (only values in this project's chosen scope) --

ENCR_ALGO_NAMES = {
    12: "AES-CBC",
    20: "AES-GCM-16",  # AEAD variant
}

DH_GROUP_LABELS = {
    2: "Group 2 (1024-bit MODP)",
    14: "Group 14 (2048-bit MODP)",
    19: "Group 19 (256-bit random ECP)",
}

TRANSFORM_TYPE_NAMES = {1: "ENCR", 2: "PRF", 3: "INTEG", 4: "DH", 5: "ESN"}
PROTOCOL_ID_NAMES = {1: "IKE", 2: "AH", 3: "ESP"}

KEY_LENGTH_ATTR_TYPE = 14  # RFC 7296 3.3.5 — sent as a TV attribute

PAYLOAD_SA = 33
PAYLOAD_NOTIFY = 41
NOTIFY_USE_TRANSPORT_MODE = 16391


def _strip_nat_t_marker(data: bytes) -> bytes:
    """NAT-T (RFC 3948, UDP/4500) prepends a 4-byte zero marker before the
    ISAKMP header so it doesn't look like an ESP packet. Strip it if present
    so our offsets line up with the ISAKMP header."""
    if len(data) >= 4 and data[:4] == b"\x00\x00\x00\x00":
        return data[4:]
    return data


def _parse_transform(buf: bytes, offset: int):
    """Parse one Transform substructure starting at `offset`.
    Returns (transform_dict, offset_of_next_transform)."""
    length = struct.unpack("!H", buf[offset + 2:offset + 4])[0]
    ttype = buf[offset + 4]
    tid = struct.unpack("!H", buf[offset + 6:offset + 8])[0]

    attrs = {}
    attr_off = offset + 8
    attr_end = offset + length
    while attr_off < attr_end:
        attr_type_raw = struct.unpack("!H", buf[attr_off:attr_off + 2])[0]
        is_tv = bool(attr_type_raw & 0x8000)
        attr_type = attr_type_raw & 0x7FFF
        if is_tv:
            value = struct.unpack("!H", buf[attr_off + 2:attr_off + 4])[0]
            attrs[attr_type] = value
            attr_off += 4
        else:
            alen = struct.unpack("!H", buf[attr_off + 2:attr_off + 4])[0]
            value = buf[attr_off + 4:attr_off + 4 + alen]
            attrs[attr_type] = value
            attr_off += 4 + alen

    transform = {
        "type": TRANSFORM_TYPE_NAMES.get(ttype, ttype),
        "id": tid,
        "attrs": attrs,
    }
    return transform, offset + length


def _parse_proposal(buf: bytes, offset: int):
    """Parse one Proposal substructure. Returns (proposal_dict, offset_of_next_proposal, next_payload_flag)."""
    next_payload = buf[offset]  # 0 = last proposal, 2 = more follow
    length = struct.unpack("!H", buf[offset + 2:offset + 4])[0]
    proto_id = buf[offset + 5]
    spi_size = buf[offset + 6]
    num_transforms = buf[offset + 7]

    t_off = offset + 8 + spi_size
    transforms = []
    for _ in range(num_transforms):
        transform, t_off = _parse_transform(buf, t_off)
        transforms.append(transform)

    proposal = {"protocol": PROTOCOL_ID_NAMES.get(proto_id, proto_id), "transforms": transforms}
    return proposal, offset + length, next_payload


def _parse_sa_payload(buf: bytes, body_offset: int, payload_len: int):
    """Parse an SA payload body (payload_len includes the 4-byte generic header)."""
    end = body_offset + payload_len - 4
    proposals = []
    p_off = body_offset
    while p_off < end:
        proposal, p_off, next_payload = _parse_proposal(buf, p_off)
        proposals.append(proposal)
        if next_payload == 0:
            break
    return proposals


def _parse_notify_msg_type(buf: bytes, body_offset: int) -> int:
    return struct.unpack("!H", buf[body_offset + 2:body_offset + 4])[0]


def _walk_payloads(buf: bytes, first_payload: int, start: int, end: int):
    """Walk the generic-payload chain. Yields (payload_type, body_offset, payload_len)
    where payload_len includes the 4-byte generic header."""
    ptype = first_payload
    off = start
    while ptype != 0 and 0 <= off < end and off + 4 <= len(buf):
        length = struct.unpack("!H", buf[off + 2:off + 4])[0]
        if length < 4 or off + length > len(buf):
            break  # malformed — stop rather than read garbage
        yield ptype, off + 4, length
        ptype = buf[off]
        off += length


def _summarize_proposal(proposal: dict) -> dict:
    cipher = None
    key_length_bits = None
    dh_group = None
    dh_group_label = None

    for t in proposal["transforms"]:
        if t["type"] == "ENCR":
            cipher = ENCR_ALGO_NAMES.get(t["id"], f"Unknown ENCR id {t['id']}")
            if KEY_LENGTH_ATTR_TYPE in t["attrs"]:
                key_length_bits = t["attrs"][KEY_LENGTH_ATTR_TYPE]
        elif t["type"] == "DH":
            dh_group = t["id"]
            dh_group_label = DH_GROUP_LABELS.get(t["id"], f"Group {t['id']}")

    return {
        "cipher": cipher,
        "key_length_bits": key_length_bits,
        "dh_group": dh_group,
        "dh_group_label": dh_group_label,
    }


def parse_ike_handshake(pcap_path: str) -> dict:
    """
    Returns:
    {
      "ike_version": "2.0" | "1.0" | "unknown",
      "mode": "tunnel" | "transport" | None,   # None = not observable in the clear
      "ike_sa": {cipher, key_length_bits, dh_group, dh_group_label} | None,
      "esp_sa": {..., "pfs": bool} | None,     # usually None — see module docstring
      "warnings": [str, ...],
    }
    """
    packets = rdpcap(pcap_path)
    warnings = []
    mode = None  # only set if we actually observe a signal in the clear
    ike_sa_info = None
    esp_sa_info = None
    ike_version = None
    saw_ikev1 = False

    for pkt in packets:
        if UDP not in pkt:
            continue
        if pkt[UDP].sport not in IKE_PORTS and pkt[UDP].dport not in IKE_PORTS:
            continue

        payload = _strip_nat_t_marker(bytes(pkt[UDP].payload))
        if len(payload) < 28:
            continue

        version_byte = payload[17]
        major = version_byte >> 4

        if major == 1:
            saw_ikev1 = True
            continue
        if major != 2:
            continue  # not an IKE header we recognize (likely ESP data)

        ike_version = "2.0"
        first_payload = payload[16]
        header_end = 28
        total_len = struct.unpack("!I", payload[24:28])[0]
        body_end = min(total_len, len(payload))

        for ptype, body_off, plen in _walk_payloads(payload, first_payload, header_end, body_end):
            if ptype == PAYLOAD_SA:
                for prop in _parse_sa_payload(payload, body_off, plen):
                    info = _summarize_proposal(prop)
                    if prop["protocol"] == "IKE" and ike_sa_info is None:
                        ike_sa_info = info
                    elif prop["protocol"] == "ESP" and esp_sa_info is None:
                        info["pfs"] = info["dh_group"] is not None
                        esp_sa_info = info
            elif ptype == PAYLOAD_NOTIFY:
                try:
                    if _parse_notify_msg_type(payload, body_off) == NOTIFY_USE_TRANSPORT_MODE:
                        mode = "transport"
                except (struct.error, IndexError):
                    pass

    if saw_ikev1 and ike_version is None:
        ike_version = "1.0"
        warnings.append(
            "IKEv1 handshake detected — this parser currently decodes IKEv2 "
            "transform tables only. Extend it with IKEv1's attribute numbers "
            "(different from IKEv2's) if your testbed uses IKEv1."
        )

    if ike_sa_info is None and esp_sa_info is None and ike_version != "1.0":
        warnings.append(
            "No IKEv2 SA proposal found in the clear in this pcap — confirm "
            "it actually contains the IKE_SA_INIT exchange, not just ESP data."
        )

    if mode is None:
        warnings.append(
            "Mode (tunnel/transport) was not observable in cleartext — it's "
            "negotiated inside the encrypted IKE_AUTH exchange. Confirm the "
            "value against the testbed's config for this session instead."
        )
    else:
        pass

    if esp_sa_info is None:
        warnings.append(
            "ESP SA's own cipher/DH/PFS were not observable in cleartext (they "
            "live inside encrypted IKE_AUTH). Falling back to the IKE SA's "
            "values as a proxy — confirm with the Testbed Lead that ike= and "
            "esp= are configured to match in this project's templates."
        )

    return {
        "ike_version": ike_version or "unknown",
        "mode": mode or "tunnel",  # RFC 7296 default when no notify is seen
        "ike_sa": ike_sa_info,
        "esp_sa": esp_sa_info,
        "warnings": warnings,
    }


if __name__ == "__main__":
    import sys
    import json

    if len(sys.argv) != 2:
        print("Usage: python ike_parser.py <path_to.pcap>")
        sys.exit(1)

    result = parse_ike_handshake(sys.argv[1])
    print(json.dumps(result, indent=2))