"""
assessment.py
-------------
The assessment layer that sits on top of the base scoring engine (scoring_engine.py):

    * findings, each tagged  observed / inferred (with confidence) / declared / unknown
    * key lifetime and replay-protection findings (from the passive ESP sequence analysis)
    * a metadata-exposure score: what does an eavesdropper learn?
    * a compliance check against published guidance (a GUIDELINE MAPPING, not a certification)
    * assessment COMPLETENESS: how much of what matters could actually be established - and a score cap so
      that a capture about which little is known can never read "100 / LOW".

Status vocabulary
    observed  read directly from the capture (e.g. cleartext IKE_SA_INIT, ESP header fields)
    inferred  deduced from packet sizes / sequence numbers, with a confidence (never from file names)
    declared  stated by the testbed file-name convention - an unverified assertion, not a measurement
    unknown   not determinable from this capture
"""

from ike_parser import DH_GROUP_LABELS

STATUS_KNOWLEDGE = {"observed": 1.0, "declared": 0.5, "unknown": 0.0}   # inferred = its confidence

# fact id -> (label, weight in the completeness percentage; weights sum to 100)
FACTS = {
    "ike_version": ("IKE version", 5),
    "protocol": ("IPsec protocol (ESP / AH)", 5),
    "mode": ("Tunnel or transport mode", 10),
    "cipher": ("Cipher (algorithm / family)", 15),
    "key_length": ("Key length", 10),
    "integrity": ("Integrity protection", 5),
    "dh_group": ("Key exchange (DH group)", 15),
    "pfs": ("Perfect Forward Secrecy", 15),
    "auth_method": ("Authentication method", 5),
    "key_lifetime": ("SA / key lifetime", 8),
    "replay": ("Replay protection", 7),
}
assert sum(w for _, w in FACTS.values()) == 100

CAP_FLOOR, CAP_SPAN = 35, 65       # score_cap = 35 + 65 * completeness  (LOW, >= 80, needs completeness >= 69%)
LIFETIME_STRONG_SEC, LIFETIME_MEDIUM_SEC = 3600, 8 * 3600   # PROJECT HEURISTIC, not from a standard


def knowledge(status, confidence):
    if status == "inferred":
        return max(0.0, min(1.0, confidence or 0.0))
    return STATUS_KNOWLEDGE.get(status, 0.0)


def finding(fid, value, status, confidence=None, rating="unknown", evidence="", note=None):
    label, weight = FACTS.get(fid, (fid, 0))
    return {"id": fid, "title": label, "value": value, "status": status,
            "confidence": None if confidence is None else round(float(confidence), 3),
            "rating": rating, "weight": weight, "evidence": evidence, **({"note": note} if note else {})}


# --------------------------------------------------------------------------------------------- findings
def build_findings(ctx):
    """ctx keys: facts (merged), sources, conf, ike, fp (esp fingerprint), seq (esp sequence), traffic."""
    facts, src, conf, ike = ctx["facts"], ctx["sources"], ctx["conf"], ctx.get("ike") or {}
    fp, seq = ctx.get("fp") or {}, ctx.get("seq") or {}
    out = []

    # IKE version
    v = ike.get("ike_version", "unknown")
    out.append(finding("ike_version", v if v != "unknown" else "unknown", "observed" if v != "unknown" else "unknown",
                       1.0 if v != "unknown" else None, "info" if v != "unknown" else "unknown",
                       "read from an IKE_SA_INIT header in the capture" if v != "unknown" else
                       "no IKE_SA_INIT in this capture (encrypted IKE messages only, or none)"))

    # protocol
    prot = (fp or {}).get("protocols") or {}
    n_esp, n_ah = prot.get("ESP", (fp or {}).get("esp_packets", 0)), prot.get("AH", 0)
    if n_ah and not n_esp:
        out.append(finding("protocol", "AH (no encryption)", "observed", 1.0, "weak",
                           f"{n_ah} AH packets and no ESP: AH authenticates but does not encrypt, so payloads are readable"))
    elif n_ah:
        out.append(finding("protocol", "ESP + AH", "observed", 1.0, "info", f"{n_esp} ESP and {n_ah} AH packets seen"))
    else:
        out.append(finding("protocol", "ESP" if n_esp else "unknown", "observed" if n_esp else "unknown", 1.0 if n_esp else None,
                           "info" if n_esp else "unknown", f"{n_esp} ESP packets seen" if n_esp else "no ESP packets in this capture"))

    # mode
    mode_rating = {"tunnel": "strong", "transport": "medium"}.get(facts["mode"], "unknown")
    mode_ev = {"observed": "stated in the IKE exchange", "inferred": (fp.get("mode") or {}).get("evidence", ""),
               "declared": "from the testbed file name (unverified)", "unknown": "not observable in this capture"}[src["mode"]]
    out.append(finding("mode", facts["mode"], src["mode"], conf.get("mode"), mode_rating, mode_ev))

    # cipher + key length
    c = facts["ike_sa"]
    fam = fp.get("cipher_family") or {}
    if c["cipher"] == "NONE":
        out.append(finding("cipher", "none - the traffic is not encrypted", "observed", 1.0, "weak",
                           "only AH packets were seen; AH provides integrity but no confidentiality"))
        out.append(finding("key_length", "not applicable", "observed", 1.0, "info", "no encryption"))
    elif src["cipher"] in ("observed", "declared"):
        cname = f"{c['cipher']}" + (f"-{c['key_length_bits']}" if c["key_length_bits"] else "")
        cev = "read from the IKE_SA_INIT proposal" if src["cipher"] == "observed" else "from the testbed file name (unverified)"
        out.append(finding("cipher", cname, src["cipher"], conf.get("cipher"), ctx["ratings"]["cipher"], cev))
        out.append(finding("key_length", f"{c['key_length_bits']} bits" if c["key_length_bits"] else "unknown", src["cipher"],
                           conf.get("cipher"), "info" if c["key_length_bits"] else "unknown", cev))
    elif src["cipher"] == "inferred":
        out.append(finding("cipher", f"{fam.get('value')}", "inferred", conf.get("cipher"), ctx["ratings"]["cipher"], fam.get("evidence", ""),
                           note="algorithm assumed to be AES; a GCM-like stream could also be another AEAD cipher"))
        out.append(finding("key_length", "unknown", "unknown", None, "unknown",
                           "AES-128 vs AES-256 does not change packet sizes; not observable passively"))
    else:
        out.append(finding("cipher", "unknown", "unknown", None, "unknown", fam.get("evidence") or "not observable in this capture"))
        out.append(finding("key_length", "unknown", "unknown", None, "unknown", "not observable in this capture"))

    # integrity
    tag = fp.get("integrity_tag") or {}
    if fam.get("value", "").startswith("GCM"):
        out.append(finding("integrity", "AEAD (integrity built into the cipher)", "inferred", fam.get("confidence"), "strong",
                           "GCM-like stream: authentication tag is part of the cipher; tag length itself is not observable"))
    elif tag.get("candidates"):
        out.append(finding("integrity", "separate HMAC, tag length " + " or ".join(f"{x['bytes']} B" for x in tag["candidates"]),
                           "inferred", 0.5, "medium", tag.get("evidence", "")))
    else:
        out.append(finding("integrity", "unknown", "unknown", None, "unknown", tag.get("evidence") or "not observable in this capture"))

    # DH group / PFS / authentication
    dh = facts["ike_sa"]["dh_group"]
    out.append(finding("dh_group", DH_GROUP_LABELS.get(dh, f"Group {dh}") if dh is not None else "unknown", src["dh_group"],
                       conf.get("dh_group"), ctx["ratings"]["dh_group"],
                       {"observed": "read from the IKE_SA_INIT proposal", "declared": "from the testbed file name (unverified)",
                        "unknown": "only visible in the cleartext IKE_SA_INIT, which is not in this capture"}[src["dh_group"]]))
    pfs = (facts["esp_sa"] or {}).get("pfs")
    out.append(finding("pfs", "unknown" if pfs is None else ("enabled" if pfs else "disabled"), src["pfs"], conf.get("pfs"),
                       ctx["ratings"]["pfs"], "negotiated inside encrypted IKE messages; not observable passively" if src["pfs"] == "unknown"
                       else "from the testbed file name (unverified)"))
    out.append(finding("auth_method", "unknown", "unknown", None, "unknown",
                       "pre-shared key vs certificate is negotiated in the encrypted IKE_AUTH exchange; not observable passively"))

    # key lifetime
    life = seq.get("sa_lifetime") or {}
    if life.get("observable"):
        est = life["estimate_seconds"]
        rating = "strong" if est <= LIFETIME_STRONG_SEC else "medium" if est <= LIFETIME_MEDIUM_SEC else "weak"
        out.append(finding("key_lifetime", f"about {est:g} s between successive SAs", "inferred", 0.6, rating,
                           life["basis"], note=life["note"] + " (rating thresholds are a project heuristic: <= 1 h strong, <= 8 h medium)"))
    else:
        note = life.get("note", "not observable in this capture")
        out.append(finding("key_lifetime", "unknown", "unknown", None, "unknown", note))

    # replay protection
    rp = seq.get("replay_protection") or {}
    st = rp.get("status", "not_observable")
    if st in ("evidence_present", "evidence_present_reordered"):
        out.append(finding("replay", "sender uses a strictly increasing sequence counter", "inferred", 0.6, "medium", rp["evidence"],
                           note="receiver-side enforcement of the anti-replay window is not observable"))
    elif st == "anomalies_observed":
        out.append(finding("replay", "repeated sequence numbers observed", "observed", 1.0, "weak", rp["evidence"]))
    else:
        out.append(finding("replay", "unknown", "unknown", None, "unknown", rp.get("evidence", "no ESP sequence numbers in this capture")))
    return out


# --------------------------------------------------------------------------------------------- completeness + cap
def completeness(findings):
    detail, total = [], 0.0
    for f in findings:
        k = knowledge(f["status"], f["confidence"])
        total += f["weight"] * k
        detail.append({"fact": f["id"], "label": f["title"], "weight": f["weight"], "status": f["status"], "known_fraction": round(k, 2)})
    return round(total, 1), detail


def apply_cap(raw_score, completeness_pct, findings):
    """Returns (final_score, cap, adjustments). Unknown facts can never produce 100/LOW."""
    if raw_score is None:
        return None, None, []
    adjustments = []
    by = {f["id"]: f for f in findings}
    if by.get("replay", {}).get("rating") == "weak":
        adjustments.append({"reason": "repeated ESP sequence numbers observed", "points": -10})
    if by.get("key_lifetime", {}).get("rating") == "weak":
        adjustments.append({"reason": "very long observed SA lifetime", "points": -10})
    adjusted = max(0, raw_score + sum(a["points"] for a in adjustments))
    cap = round(CAP_FLOOR + CAP_SPAN * completeness_pct / 100.0)
    return min(adjusted, cap), cap, adjustments


# --------------------------------------------------------------------------------------------- metadata exposure
def metadata_exposure(ctx):
    """What an eavesdropper on the link learns WITHOUT any key. Only passive inferences count (never file names)."""
    fp, traffic, facts, src = ctx.get("fp") or {}, ctx.get("traffic"), ctx["facts"], ctx["sources"]
    items = []

    def add(what, weight, fraction, learned, why):
        items.append({"what": what, "weight": weight, "exposed_fraction": round(fraction, 2), "points": round(weight * fraction, 1),
                      "learned": learned, "why": why})
    tc = (traffic or {}).get("confidence") or 0.0
    rejected = bool(traffic and traffic.get("class") == "unrecognised")
    add("Traffic type", 30, 0.0 if (not traffic or rejected) else tc,
        f"{traffic['label']} (model confidence {tc:.0%})" if traffic and not rejected else "not identified",
        "packet sizes and timing reveal what the tunnel is used for, even though the payload is encrypted")
    mconf = (fp.get("mode") or {}).get("confidence") if (fp.get("mode") or {}).get("value") in ("tunnel", "transport") else 0.0
    add("Tunnel vs transport mode", 10, mconf or 0.0, (fp.get("mode") or {}).get("value", "undetermined"),
        "extra inner IP header changes every packet size")
    fconf = (fp.get("cipher_family") or {}).get("confidence") if str((fp.get("cipher_family") or {}).get("value", "")).startswith(("CBC", "GCM")) else 0.0
    add("Cipher family", 10, fconf or 0.0, (fp.get("cipher_family") or {}).get("value", "undetermined"),
        "padding granularity (CBC vs AEAD) shows in the packet lengths")
    add("Packet-size distribution", 15, 1.0 if fp.get("esp_packets") else 0.0, "always visible", "ESP does not hide packet lengths unless padding is added")
    add("Timing and volume", 20, 1.0 if fp.get("esp_packets") else 0.0, "always visible", "packet times and byte counts are visible on the wire")
    m = facts["mode"]
    add("Communicating endpoints", 15, {"tunnel": 0.5, "transport": 1.0}.get(m, 0.75),
        {"tunnel": "the two gateways only", "transport": "the actual hosts", "unknown": "gateways or hosts (mode unknown)"}[m if m in ("tunnel", "transport") else "unknown"],
        "outer IP addresses are always in clear; tunnel mode hides the real endpoints behind the gateways")
    if fp.get("ah_only"):
        items.append({"what": "Payload content", "weight": 0, "exposed_fraction": 1.0, "points": 0.0,
                      "learned": "the whole payload", "why": "AH does not encrypt: everything above the IP header is readable"})
        return {"score": 100, "level": "HIGH", "scale": "0 = an eavesdropper learns nothing, 100 = learns everything listed",
                "items": items, "note": "AH-only traffic is not encrypted, so nothing is hidden from an eavesdropper."}
    score = round(sum(i["points"] for i in items))
    level = "LOW" if score < 40 else "MEDIUM" if score < 70 else "HIGH"
    return {"score": score, "level": level, "scale": "0 = an eavesdropper learns nothing, 100 = learns everything listed",
            "items": items,
            "note": "IPsec cannot hide timing, volume or outer addresses; padding and dummy traffic reduce the traffic-type leak (see the defence simulation)."}


# --------------------------------------------------------------------------------------------- compliance
COMPLIANCE_LABEL = "Guideline mapping against published guidance - NOT a certification or audit result"

NOT_EVALUATED = [
    "NIST SP 800-77 Rev. 1 (Guide to IPsec VPNs): used as general background only; no individual requirement is encoded here.",
    "RFC 8247 is encoded for one item only (IKEv2 group 14); other group requirement levels are not evaluated.",
    "FIPS 140 module validation, key management, authentication strength and certificate policy are outside what a capture can show.",
]


def compliance(ctx, findings):
    by = {f["id"]: f for f in findings}
    cipher_f, dh_f = by["cipher"], by["dh_group"]
    facts = ctx["facts"]
    cname, bits, dh = facts["ike_sa"]["cipher"], facts["ike_sa"]["key_length_bits"], facts["ike_sa"]["dh_group"]
    checks = []

    def chk(cid, guideline, requirement, result, evidence, basis):
        checks.append({"id": cid, "guideline": guideline, "requirement": requirement, "result": result,
                       "evidence": evidence, "input_status": basis})

    # NIST SP 800-131A Rev. 2: two-key/three-key TDEA encryption is disallowed after 2023
    cs = cipher_f["status"]
    if cname and cs in ("observed", "declared"):
        chk("nist-131a-tdea", "NIST SP 800-131A Rev. 2", "Three-key TDEA (3DES) is not acceptable for encryption after 2023",
            "does_not_meet" if cname == "3DES" else "meets", f"cipher is {cname}", cs)
        chk("nist-aes", "NIST FIPS 197 / SP 800-38", "Use an approved block cipher (AES) and mode", "meets" if cname.startswith("AES") else "cannot_assess",
            f"cipher is {cname}", cs)
    else:
        chk("nist-131a-tdea", "NIST SP 800-131A Rev. 2", "Three-key TDEA (3DES) is not acceptable for encryption after 2023", "cannot_assess",
            "cipher algorithm not established (only a family was inferred, or nothing)", cs)
        chk("nist-aes", "NIST FIPS 197 / SP 800-38", "Use an approved block cipher (AES) and mode", "cannot_assess",
            "cipher algorithm not established", cs)
    # NIST SP 800-131A Rev. 2 / SP 800-57: key establishment needs >= 112 bits of security strength (finite-field DH >= 2048 bits)
    ds = dh_f["status"]
    if dh is None or ds not in ("observed", "declared"):
        chk("nist-112bit-kex", "NIST SP 800-131A Rev. 2 / SP 800-57", "Key establishment with at least 112 bits of security strength (finite-field DH of at least 2048 bits)",
            "cannot_assess", "DH group not established from this capture", ds)
    elif dh in (1, 2, 5):
        chk("nist-112bit-kex", "NIST SP 800-131A Rev. 2 / SP 800-57", "Key establishment with at least 112 bits of security strength (finite-field DH of at least 2048 bits)",
            "does_not_meet", f"{DH_GROUP_LABELS.get(dh)} is below 2048 bits", ds)
    elif dh in (14, 15, 16, 19, 20, 21):
        chk("nist-112bit-kex", "NIST SP 800-131A Rev. 2 / SP 800-57", "Key establishment with at least 112 bits of security strength (finite-field DH of at least 2048 bits)",
            "meets", f"{DH_GROUP_LABELS.get(dh)} provides at least 112 bits", ds)
    else:
        chk("nist-112bit-kex", "NIST SP 800-131A Rev. 2 / SP 800-57", "Key establishment with at least 112 bits of security strength", "cannot_assess",
            f"group {dh} is not mapped in this tool", ds)
    # RFC 8221: AES-CBC and AES-GCM-16 are MUST-implement ESP algorithms
    if cname and cs in ("observed", "declared"):
        ok = cname in ("AES-CBC", "AES-GCM-16")
        chk("rfc8221-esp-alg", "RFC 8221", "ESP encryption algorithm is one of the mandatory-to-implement AES-CBC or AES-GCM-16",
            "meets" if ok else "cannot_assess", f"cipher is {cname}" + ("" if ok else " (not covered by this check)"), cs)
    else:
        chk("rfc8221-esp-alg", "RFC 8221", "ESP encryption algorithm is one of the mandatory-to-implement AES-CBC or AES-GCM-16", "cannot_assess",
            "cipher algorithm not established", cs)
    # RFC 8247: 2048-bit MODP group (14) is a mandatory-to-implement IKEv2 group
    if dh == 14 and ds in ("observed", "declared"):
        chk("rfc8247-group14", "RFC 8247", "IKEv2 MODP group 14 (2048-bit) is a mandatory-to-implement group", "meets", "negotiated group is 14", ds)
    else:
        chk("rfc8247-group14", "RFC 8247", "IKEv2 MODP group 14 (2048-bit) is a mandatory-to-implement group", "cannot_assess",
            "only evaluated when group 14 is the negotiated group", ds)

    counts = {k: sum(1 for c in checks if c["result"] == k) for k in ("meets", "does_not_meet", "cannot_assess")}
    return {"label": COMPLIANCE_LABEL, "checks": checks, "summary": counts, "not_evaluated": NOT_EVALUATED}


# --------------------------------------------------------------------------------------------- entry point
def assess(ctx, raw_score):
    findings = build_findings(ctx)
    pct, detail = completeness(findings)
    final, cap, adjustments = apply_cap(raw_score, pct, findings)
    unknown = [f["title"] for f in findings if f["status"] == "unknown"]
    return {
        "completeness_pct": pct,
        "completeness_detail": detail,
        "raw_score": raw_score,
        "score_cap": cap,
        "score_capped": final is not None and raw_score is not None and final < raw_score + sum(a["points"] for a in adjustments),
        "adjustments": adjustments,
        "unknown_facts": unknown,
        "findings": findings,
        "metadata_exposure": metadata_exposure(ctx),
        "compliance": compliance(ctx, findings),
        "score_after_cap": final,
        "cap_rule": f"score <= {CAP_FLOOR} + {CAP_SPAN} x completeness (LOW needs a score of at least 80, i.e. completeness of at least 69%)",
    }
