"""
scoring_engine.py
Rule-based security scoring for the IPsec VPN Analyzer.

Takes the dict returned by ike_parser.parse_ike_handshake() and produces
a per-factor weak/medium/strong verdict plus one overall security score
(0-100, higher = more secure) with human-readable reasons for the
dashboard's "why" panel.

Pure logic, no I/O — easy to unit test with hand-built fact dicts (see
the __main__ block below for an example) before wiring it into main.py.

Only scores what ike_parser can genuinely determine. Where a value is
None (not observable — see the caveat in ike_parser.py's docstring), the
factor is marked "unknown" and EXCLUDED from the weighted average rather
than silently counted as "weak" — an unknown shouldn't drag the score
down, and a fabricated "weak" would misrepresent the tunnel.
"""

CIPHER_RATING = {
    "NONE": {None: "weak"},                        # AH only: authenticates packets but does not encrypt them
    "3DES": {None: "weak"},                        # 64-bit blocks, deprecated
    "AES-CBC": {128: "medium", 256: "strong"},     # CBC needs a separate HMAC for integrity
    "AES-CTR": {128: "medium", 256: "strong"},
    "AES-GCM-16": {128: "strong", 256: "strong"},  # AEAD — confidentiality + integrity in one
    "ChaCha20-Poly1305": {256: "strong"},
}

DH_GROUP_RATING = {
    1: "weak",     # 768-bit MODP
    2: "weak",     # 1024-bit MODP — considered too small for modern threat models
    5: "weak",     # 1536-bit MODP
    14: "medium",  # 2048-bit MODP — acceptable, no long-term safety margin
    15: "medium",  # 3072-bit MODP
    16: "strong",  # 4096-bit MODP
    19: "strong",  # 256-bit ECP — modern, efficient, strong
    20: "strong",
    21: "strong",
    31: "strong",  # Curve25519
}

DH_GROUP_LABELS = {
    1: "768-bit MODP", 2: "1024-bit MODP", 5: "1536-bit MODP", 14: "2048-bit MODP",
    15: "3072-bit MODP", 16: "4096-bit MODP", 19: "256-bit ECP", 20: "384-bit ECP",
    21: "521-bit ECP", 31: "Curve25519",
}

RATING_SCORE = {"weak": 0, "medium": 60, "strong": 100}
FACTOR_WEIGHT = {"cipher": 0.4, "dh_group": 0.4, "pfs": 0.2}


def _rate_cipher(cipher_name, key_length_bits):
    if not cipher_name:
        return "unknown", "No encryption algorithm was recovered from the handshake."
    table = CIPHER_RATING.get(cipher_name)
    if table is None:
        return "unknown", f"'{cipher_name}' isn't in this project's known rating table yet."

    if key_length_bits in table:
        rating = table[key_length_bits]
    elif key_length_bits is None and None not in table:
        # Key length not stated: don't assume the strongest variant.
        rating = min(table.values(), key=lambda r: RATING_SCORE[r])
    else:
        rating = "unknown"
    label = cipher_name + (f"-{key_length_bits}" if key_length_bits else "")
    if cipher_name == "NONE":
        reason = ("No encryption: AH authenticates packets but does not encrypt them, so the payload is readable "
                  "by anyone on the path.")
    elif cipher_name == "3DES":
        reason = f"{label} is deprecated: its 64-bit blocks make it vulnerable to birthday attacks."
    elif cipher_name == "AES-CBC":
        reason = (f"{label} provides confidentiality only — it needs a separate HMAC "
                   "for integrity, and mis-set integrity checking can open padding-oracle-style issues.")
    elif cipher_name in ("AES-GCM-16", "ChaCha20-Poly1305"):
        reason = f"{label} is an AEAD cipher — confidentiality and integrity in one, no separate HMAC needed."
    else:
        reason = f"{label} is acceptable but needs a separate integrity algorithm."
    return rating, reason


def _rate_dh_group(dh_group):
    if dh_group is None:
        return "unknown", "No Diffie-Hellman group was recovered from the handshake."
    rating = DH_GROUP_RATING.get(dh_group, "unknown")
    label = DH_GROUP_LABELS.get(dh_group, f"Group {dh_group}")
    reasons = {
        "weak": f"{label} is considered too small against modern computing power.",
        "medium": f"{label} is currently acceptable but has no long-term safety margin.",
        "strong": f"{label} gives strong security.",
        "unknown": f"{label} isn't in this project's known rating table yet.",
    }
    return rating, reasons[rating]


def _rate_pfs(pfs_enabled):
    if pfs_enabled is None:
        return "unknown", "Whether Perfect Forward Secrecy is enabled could not be determined from this capture."
    if pfs_enabled:
        return "strong", "A fresh Diffie-Hellman exchange was used, so a leaked key won't expose past traffic."
    return "weak", "No fresh key exchange was found for this SA — one leaked key could expose all its traffic."


def score_ike_facts(ike_facts: dict) -> dict:
    ike_sa = ike_facts.get("ike_sa") or {}
    esp_sa = ike_facts.get("esp_sa") or {}

    # Prefer the ESP SA's own values when we actually have them; otherwise
    # fall back to the IKE SA's (see ike_parser's caveat on why ESP's own
    # values are usually unavailable from a passive capture).
    cipher_name = esp_sa.get("cipher") or ike_sa.get("cipher")
    key_length = esp_sa.get("key_length_bits") or ike_sa.get("key_length_bits")
    dh_group = esp_sa.get("dh_group") or ike_sa.get("dh_group")
    pfs_enabled = esp_sa.get("pfs")

    cipher_rating, cipher_reason = _rate_cipher(cipher_name, key_length)
    dh_rating, dh_reason = _rate_dh_group(dh_group)
    pfs_rating, pfs_reason = _rate_pfs(pfs_enabled)

    factors = {
        "cipher": {"rating": cipher_rating, "reason": cipher_reason},
        "dh_group": {"rating": dh_rating, "reason": dh_reason},
        "pfs": {"rating": pfs_rating, "reason": pfs_reason},
    }

    weighted_sum, weight_used = 0.0, 0.0
    for factor_name, weight in FACTOR_WEIGHT.items():
        rating = factors[factor_name]["rating"]
        if rating == "unknown":
            continue
        weighted_sum += RATING_SCORE[rating] * weight
        weight_used += weight

    overall_score = round(weighted_sum / weight_used) if weight_used > 0 else None

    if overall_score is None:
        risk_level = "UNKNOWN"
    elif overall_score >= 80:
        risk_level = "LOW"
    elif overall_score >= 50:
        risk_level = "MEDIUM"
    else:
        risk_level = "HIGH"

    return {
        "overall_score": overall_score,
        "risk_level": risk_level,
        "factors": factors,
        "mode": ike_facts.get("mode"),
        "ike_version": ike_facts.get("ike_version"),
        "warnings": ike_facts.get("warnings", []),
    }


if __name__ == "__main__":
    import json

    sample = {
        "ike_version": "2.0",
        "mode": "tunnel",
        "ike_sa": {"cipher": "AES-CBC", "key_length_bits": 128, "dh_group": 2, "dh_group_label": "Group 2"},
        "esp_sa": {"cipher": "AES-CBC", "key_length_bits": 128, "dh_group": None, "pfs": False},
        "warnings": [],
    }
    print(json.dumps(score_ike_facts(sample), indent=2))