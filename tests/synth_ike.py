"""
synth_ike.py -- SYNTHETIC IKE message builders, for unit tests only.

Everything produced here is hand-assembled from RFC 7296 and is NOT a real
capture. None of it came from strongSwan or any real network. It exists
because the real testbed captures in this project do not contain the
cleartext IKE_SA_INIT exchange (see FINAL_STATUS.md), so the parser needs
some other way to be tested on that exchange.
"""

import struct

# transform type ids
ENCR, PRF, INTEG, DH = 1, 2, 3, 4


def transform(ttype: int, tid: int, key_bits: int = None, last: bool = False) -> bytes:
    attrs = b""
    if key_bits is not None:
        attrs = struct.pack("!HH", 0x8000 | 14, key_bits)  # TV attribute, type 14 = key length
    length = 8 + len(attrs)
    return struct.pack("!BBHBBH", 0 if last else 3, 0, length, ttype, 0, tid) + attrs


def proposal(num: int, transforms: list, last: bool = True, proto: int = 1) -> bytes:
    """transforms: list of (type, id, key_bits|None)."""
    body = b""
    for i, (t, tid, kb) in enumerate(transforms):
        body += transform(t, tid, kb, last=(i == len(transforms) - 1))
    length = 8 + len(body)
    return struct.pack("!BBHBBBB", 0 if last else 2, 0, length, num, proto, 0, len(transforms)) + body


def payload(next_payload: int, body: bytes) -> bytes:
    return struct.pack("!BBH", next_payload, 0, 4 + len(body)) + body


def ike_message(proposals: bytes, *, response: bool, exchange: int = 34, version: int = 0x20,
                dh_group: int = 14, spi_i: bytes = b"\x11" * 8, spi_r: bytes = None,
                include_ke: bool = True) -> bytes:
    """Assemble a whole IKE_SA_INIT (SA + KE + Nonce) message."""
    spi_r = spi_r if spi_r is not None else (b"\x22" * 8 if response else b"\x00" * 8)
    sa = payload(34 if include_ke else 40, proposals)
    chain = sa
    if include_ke:
        ke = payload(40, struct.pack("!HH", dh_group, 0) + bytes(range(64)))
        chain += ke
    chain += payload(0, b"\xab" * 32)  # nonce
    flags = 0x20 if response else 0x08
    header = (spi_i + spi_r + struct.pack("!BBBBII", 33, version, exchange, flags, 0, 28 + len(chain)))
    return header + chain


def initiator_offer(*offers) -> bytes:
    """offers: list of transform lists. Builds several proposals."""
    out = b""
    for i, tr in enumerate(offers):
        out += proposal(i + 1, tr, last=(i == len(offers) - 1))
    return out


# Ready-made transform sets used by the tests
AES256_GCM_DH19 = [(ENCR, 20, 256), (PRF, 5, None), (DH, 19, None)]
AES128_CBC_DH2 = [(ENCR, 12, 128), (PRF, 5, None), (INTEG, 12, None), (DH, 2, None)]
AES256_CBC_DH14 = [(ENCR, 12, 256), (PRF, 5, None), (INTEG, 12, None), (DH, 14, None)]
