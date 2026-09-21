"""
contract.py
Builds THE response of POST /analyze (schema_version 1.1) from the IKE parser output, the passive ESP analysis and
the ML result, and validates that any dict has that shape.

One shape, always (also when parts fail - failures go into `errors`):

{
  "schema_version": "1.1",
  "filename": str,
  "score": int 0-100 | null,        # final score = raw score capped by assessment completeness
  "raw_score": int | null,          # score from the facts that ARE known, before the completeness cap
  "risk_level": "LOW" | "MEDIUM" | "HIGH" | "UNKNOWN",
  "score_basis": "observed" | "inferred" | "declared" | "mixed" | "none",
  "cipher": str, "mode": str, "dh_group": str, "pfs": str,   # plain display strings
  "sources": {"cipher","mode","dh_group","pfs": "observed"|"inferred"|"declared"|"unknown"},
  "confidence": {"cipher": float|null, "mode": float|null, ...},   # for inferred values
  "breakdown": [ {factor, value, rating, weight, source, reason} ],
  "assessment": { completeness_pct, completeness_detail, score_cap, score_capped, adjustments, unknown_facts,
                  findings[ {id,title,value,status,confidence,rating,evidence} ], metadata_exposure, compliance, ... },
  "recommendations": { items[ {rank, priority, title, action, why, based_on, standards, config_hint} ],
                       secure_config {text, verified, note}, before_after {before, after_passive_capture, after_config_review} },
  "traffic": {"class", "label", "confidence", "probabilities": [...]} | null,
  "model_confidence": float | null,
  "explanation": [str, ...],
  "anomalies": [ {severity, name, description} ],
  "timeline": [ {window, start_sec, end_sec, class, label, confidence, packets, bytes} ],
  "capture": {...} | null,
  "details": {"ike": ..., "esp_fingerprint": ..., "esp_sequence": ..., ...},
  "warnings": [str, ...],
  "errors": [str, ...]
}
"""

from assessment import assess
from recommendations import recommend
from config_hint import declared_config_from_filename
from ike_parser import DH_GROUP_LABELS
from scoring_engine import FACTOR_WEIGHT, score_ike_facts

SCHEMA_VERSION = "1.1"
RISK_LEVELS = ("LOW", "MEDIUM", "HIGH", "UNKNOWN")
RATINGS = ("strong", "medium", "weak", "unknown", "info")
SEVERITIES = ("HIGH", "MEDIUM", "LOW")
SOURCES = ("observed", "inferred", "declared", "unknown")

TRAFFIC_LABELS = {
    "web_browsing": "Web browsing",
    "video_streaming": "Video streaming",
    "voip": "VoIP",
    "file_transfer": "File transfer",
    "icmp": "ICMP (ping)",
    "unrecognised": "Unrecognised traffic",
}

REQUIRED_KEYS = {
    "schema_version": str, "filename": str, "score": (int, type(None)), "raw_score": (int, type(None)), "risk_level": str,
    "score_basis": str, "cipher": str, "mode": str, "dh_group": str, "pfs": str, "sources": dict, "confidence": dict,
    "breakdown": list, "assessment": dict, "recommendations": dict, "traffic": (dict, type(None)), "model_confidence": (float, int, type(None)),
    "explanation": list, "anomalies": list, "timeline": list, "capture": (dict, type(None)),
    "details": dict, "warnings": list, "errors": list,
}


def risk_from_score(score):
    if score is None:
        return "UNKNOWN"
    return "LOW" if score >= 80 else "MEDIUM" if score >= 50 else "HIGH"


def traffic_label(cls):
    return TRAFFIC_LABELS.get(cls, str(cls).replace("_", " ").capitalize())


def _cipher_string(name, bits):
    if not name:
        return "unknown"
    return f"{name}-{bits}" if bits else name


def _dh_string(group):
    if group is None:
        return "unknown"
    return DH_GROUP_LABELS.get(group, f"Group {group}")


def _pfs_string(pfs):
    return "unknown" if pfs is None else ("enabled" if pfs else "disabled")


def _mode_rating(mode):
    if mode == "tunnel":
        return "strong", "Tunnel mode encrypts the whole original packet, including its IP header."
    if mode == "transport":
        return "medium", "Transport mode leaves the original IP header visible; only the payload is encrypted."
    return "unknown", "Tunnel/transport mode is negotiated inside the encrypted exchange and was not observable."


_FAMILY_TO_CIPHER = {"CBC": "AES-CBC", "GCM": "AES-GCM-16"}


def merge_facts(filename, ike_facts, esp_fp=None):
    """Choose, per property, the best available source.

        mode:            observed > inferred (packet sizes, with confidence) > declared (file name) > unknown
        cipher:          observed > declared > inferred family (key length unknown) > unknown
        DH group / PFS:  observed > declared > unknown   (not observable passively)

    File names are used ONLY for the `declared` fallback; the inferred values come from packet sizes alone.
    Returns (facts_for_scoring, sources); facts["_conf"] holds confidences for inferred values and
    facts["_consistency"] the cross-checks between declared and inferred values.
    """
    ike_facts = ike_facts or {}
    ike_sa = ike_facts.get("ike_sa") or {}
    esp_sa = ike_facts.get("esp_sa") or {}
    declared = declared_config_from_filename(filename) or {}
    fp = esp_fp or {}
    fam_fp, mode_fp = fp.get("cipher_family") or {}, fp.get("mode") or {}
    inferred_family = next((f for f in ("CBC", "GCM") if str(fam_fp.get("value", "")).startswith(f)), None)
    inferred_mode = mode_fp.get("value") if mode_fp.get("value") in ("tunnel", "transport") else None

    obs_cipher = esp_sa.get("cipher") or ike_sa.get("cipher")
    obs_bits = esp_sa.get("key_length_bits") or ike_sa.get("key_length_bits")
    obs_dh = esp_sa.get("dh_group") or ike_sa.get("dh_group")
    obs_pfs = esp_sa.get("pfs")
    obs_mode = ike_facts.get("mode", "unknown")

    sources, conf = {}, {}
    if fp.get("ah_only"):
        cipher, bits, sources["cipher"] = "NONE", None, "observed"      # only AH packets: nothing is encrypted
    elif obs_cipher:
        cipher, bits, sources["cipher"] = obs_cipher, obs_bits, "observed"
    elif declared:
        cipher, bits, sources["cipher"] = declared["cipher"], declared["key_length_bits"], "declared"
    elif inferred_family:
        cipher, bits, sources["cipher"] = _FAMILY_TO_CIPHER[inferred_family], None, "inferred"
        conf["cipher"] = fam_fp.get("confidence")
    else:
        cipher, bits, sources["cipher"] = None, None, "unknown"

    if obs_dh is not None:
        dh, sources["dh_group"] = obs_dh, "observed"
    elif declared:
        dh, sources["dh_group"] = declared["dh_group"], "declared"
    else:
        dh, sources["dh_group"] = None, "unknown"

    if obs_pfs is not None:
        pfs, sources["pfs"] = obs_pfs, "observed"
    elif declared and declared["pfs"] is not None:
        pfs, sources["pfs"] = declared["pfs"], "declared"
    else:
        pfs, sources["pfs"] = None, "unknown"

    if obs_mode in ("tunnel", "transport"):
        mode, sources["mode"] = obs_mode, "observed"
    elif inferred_mode:
        mode, sources["mode"] = inferred_mode, "inferred"
        conf["mode"] = mode_fp.get("confidence")
    elif declared:
        mode, sources["mode"] = declared["mode"], "declared"
    else:
        mode, sources["mode"] = "unknown", "unknown"

    # cross-check declared (file name) values against what the packet sizes say
    consistency = []
    if declared and inferred_family:
        declared_family = "GCM" if declared["cipher"] == "AES-GCM-16" else "CBC"
        consistency.append({"item": "cipher family", "declared": declared_family, "inferred": inferred_family,
                            "agree": declared_family == inferred_family})
    if declared and inferred_mode:
        consistency.append({"item": "mode", "declared": declared["mode"], "inferred": inferred_mode,
                            "agree": declared["mode"] == inferred_mode})

    facts = {
        "ike_version": ike_facts.get("ike_version", "unknown"),
        "mode": mode,
        "ike_sa": {"cipher": cipher, "key_length_bits": bits, "dh_group": dh},
        "esp_sa": {"pfs": pfs} if pfs is not None else None,
        "warnings": [],
        "_conf": conf,
        "_consistency": consistency,
    }
    return facts, sources


def _score_basis(breakdown):
    used = {b["source"] for b in breakdown if b["weight"] > 0 and b["rating"] != "unknown"}
    if not used:
        return "none"
    return next(iter(used)) if len(used) == 1 else "mixed"


def build_explanation(score, raw, risk, basis, breakdown, traffic, ml_explanation, assessment, consistency):
    lines = []
    if score is None:
        lines.append("A security score could not be calculated because the capture does not reveal the cipher or Diffie-Hellman group.")
    else:
        lines.append(f"Overall security score {score}/100 - {risk.lower()} risk.")
        lines.append(f"Only {assessment['completeness_pct']:.0f}% of the security facts that matter could be established from this capture"
                     + (f", so the score is capped at {assessment['score_cap']} (the facts that are known alone would give {raw})."
                        if assessment["score_capped"] else "."))
        if basis == "declared":
            lines.append("The rating uses the VPN configuration named in the capture's file name (declared by the testbed), because the capture "
                         "itself does not contain the readable IKE negotiation.")
        elif basis == "inferred":
            lines.append("The rating uses values inferred from packet sizes (see the confidence figures).")
        elif basis == "mixed":
            lines.append("Rated values come from more than one source (observed, inferred from packet sizes, or declared by the testbed file name).")
    for b in breakdown:
        if b["weight"] > 0 and b["rating"] in ("weak", "medium"):
            lines.append(f"{b['factor']} - {b['value']} - is rated {b['rating']}. {b['reason']}")
    unknown = [b["factor"] for b in breakdown if b["rating"] == "unknown" and b["weight"] > 0]
    if unknown:
        lines.append(f"Not determinable from this capture: {', '.join(unknown)}. "
                     "They are left out of the raw score instead of being counted as weak, but they lower the completeness.")
    for c in consistency:
        if not c["agree"]:
            lines.append(f"Warning: the file name declares {c['item']} = {c['declared']}, but the packet sizes suggest {c['inferred']}. "
                         "The declared value may be wrong, or the inference may be.")
    if traffic:
        if traffic["class"] == "unrecognised":
            lines.append(f"The traffic pattern does not match any of the trained traffic types well enough (closest: "
                         f"{str(traffic.get('nearest_label', 'n/a')).lower()}, confidence {traffic['confidence']:.0%}), so it is reported as unrecognised.")
        else:
            lines.append(f"The encrypted traffic looks like {traffic['label'].lower()} (model confidence {traffic['confidence']:.0%}).")
    for item in ml_explanation or []:
        if isinstance(item, dict) and item.get("text"):
            lines.append(item["text"])
    return lines


def build_response(filename, ike_facts, ml_result, errors=None, warnings=None, esp=None, extras=None):
    """Assemble the contract response. Never raises; problems become `errors` / `warnings`.
    `extras` (dict) is merged into `details` (e.g. the defence simulation)."""
    errors = list(errors or [])
    warnings = list(warnings or [])
    esp = esp or {}

    facts, sources = merge_facts(filename, ike_facts, esp.get("fingerprint"))
    conf, consistency = facts["_conf"], facts["_consistency"]
    risk = score_ike_facts(facts)
    factors = risk["factors"]

    mode_rating, mode_reason = _mode_rating(facts["mode"])
    cipher_value = _cipher_string(facts["ike_sa"]["cipher"], facts["ike_sa"]["key_length_bits"])
    if sources["cipher"] == "inferred":
        cipher_value = f"{cipher_value} family (key length unknown)"
    breakdown = [
        {"factor": "Cipher", "value": cipher_value, "rating": factors["cipher"]["rating"], "weight": FACTOR_WEIGHT["cipher"],
         "source": sources["cipher"], "reason": factors["cipher"]["reason"]},
        {"factor": "DH group", "value": _dh_string(facts["ike_sa"]["dh_group"]), "rating": factors["dh_group"]["rating"],
         "weight": FACTOR_WEIGHT["dh_group"], "source": sources["dh_group"], "reason": factors["dh_group"]["reason"]},
        {"factor": "PFS", "value": _pfs_string((facts["esp_sa"] or {}).get("pfs")), "rating": factors["pfs"]["rating"],
         "weight": FACTOR_WEIGHT["pfs"], "source": sources["pfs"], "reason": factors["pfs"]["reason"]},
        {"factor": "Mode", "value": facts["mode"], "rating": mode_rating, "weight": 0.0, "source": sources["mode"], "reason": mode_reason},
    ]

    traffic = timeline = anomalies = capture = None
    ml_explanation = []
    model_confidence = None
    if ml_result and "error" not in ml_result:
        cls = ml_result["class"]
        traffic = {
            "class": cls, "label": traffic_label(cls), "confidence": ml_result["confidence"],
            "probabilities": sorted(
                ({"name": traffic_label(k), "value": v} for k, v in ml_result["class_probabilities"].items()),
                key=lambda d: d["value"], reverse=True),
        }
        if cls == "unrecognised":
            traffic["nearest_class"] = ml_result.get("nearest_class")
            traffic["nearest_label"] = traffic_label(ml_result.get("nearest_class"))
            traffic["rejection_reason"] = ml_result.get("rejection_reason")
        model_confidence = ml_result["confidence"]
        ml_explanation = ml_result.get("explanation", [])
        anomalies = ml_result.get("anomalies", [])
        timeline = [{**seg, "label": traffic_label(seg["class"])} for seg in ml_result.get("timeline", [])]
        capture = {**ml_result["capture"], "windows": ml_result["windows_analyzed"],
                   "window_sec": ml_result["window_sec"], "esp_only": ml_result["esp_only"]}
        warnings += ml_result.get("warnings", [])
    elif ml_result and "error" in ml_result:
        errors.append(f"Traffic classification: {ml_result['error']}")

    warnings += (ike_facts or {}).get("warnings", [])

    ctx = {"facts": facts, "sources": sources, "conf": conf, "ike": ike_facts, "fp": esp.get("fingerprint"),
           "seq": esp.get("sequence"), "traffic": traffic,
           "ratings": {"cipher": factors["cipher"]["rating"], "dh_group": factors["dh_group"]["rating"], "pfs": factors["pfs"]["rating"]}}
    assessment = assess(ctx, risk["overall_score"])
    assessment["consistency_checks"] = consistency

    # informational rows in the threat matrix (weight 0: shown, not scored)
    by_id = {f["id"]: f for f in assessment["findings"]}
    for fid, factor in (("integrity", "Integrity"), ("key_lifetime", "Key lifetime"), ("replay", "Replay protection")):
        f = by_id[fid]
        breakdown.append({"factor": factor, "value": f["value"], "rating": f["rating"], "weight": 0.0,
                          "source": f["status"], "reason": f["evidence"]})

    score = assessment["score_after_cap"]
    recs = recommend(ctx, assessment, score, risk["overall_score"])
    basis = _score_basis(breakdown)
    for c in consistency:
        if not c["agree"]:
            warnings.append(f"Declared {c['item']} ({c['declared']}) disagrees with the packet-size inference ({c['inferred']}).")

    return {
        "schema_version": SCHEMA_VERSION,
        "filename": filename,
        "score": score,
        "raw_score": risk["overall_score"],
        "risk_level": risk_from_score(score),
        "score_basis": basis,
        "cipher": breakdown[0]["value"],
        "mode": facts["mode"],
        "dh_group": breakdown[1]["value"],
        "pfs": breakdown[2]["value"],
        "sources": sources,
        "confidence": {k: (round(v, 3) if v is not None else None) for k, v in conf.items()},
        "breakdown": breakdown,
        "assessment": assessment,
        "recommendations": recs,
        "traffic": traffic,
        "model_confidence": model_confidence,
        "explanation": build_explanation(score, risk["overall_score"], risk_from_score(score), basis, breakdown, traffic, ml_explanation,
                                         assessment, consistency),
        "anomalies": anomalies or [],
        "timeline": timeline or [],
        "capture": capture,
        "details": {"ike": ike_facts, "esp_fingerprint": esp.get("fingerprint"), "esp_sequence": esp.get("sequence"), **(extras or {})},
        "warnings": list(dict.fromkeys(warnings)),
        "errors": errors,
    }


def validate_response(resp):
    """Returns a list of problems (empty list = valid). Used by tests for the real response AND for the
    bundled frontend mocks, so they cannot drift apart."""
    problems = []
    if not isinstance(resp, dict):
        return ["response is not an object"]
    for key, typ in REQUIRED_KEYS.items():
        if key not in resp:
            problems.append(f"missing key: {key}")
        elif not isinstance(resp[key], typ):
            problems.append(f"{key} has wrong type {type(resp[key]).__name__}")
    if problems:
        return problems

    if resp["schema_version"] != SCHEMA_VERSION:
        problems.append("unknown schema_version")
    if resp["risk_level"] not in RISK_LEVELS:
        problems.append("bad risk_level")
    if resp["score"] is not None and not 0 <= resp["score"] <= 100:
        problems.append("score out of range")
    if (resp["score"] is None) != (resp["risk_level"] == "UNKNOWN"):
        problems.append("score/risk_level inconsistent")
    if resp["score"] is not None and resp["raw_score"] is not None and resp["score"] > resp["raw_score"]:
        problems.append("score exceeds raw_score (the completeness cap can only lower it)")
    a = resp["assessment"]
    for k in ("completeness_pct", "score_cap", "findings", "metadata_exposure", "compliance", "unknown_facts"):
        if k not in a:
            problems.append(f"assessment missing {k}")
    if "completeness_pct" in a and resp["score"] is not None and a.get("score_cap") is not None and resp["score"] > a["score_cap"]:
        problems.append("score exceeds the completeness cap")
    if resp["risk_level"] == "LOW" and a.get("completeness_pct", 0) < 69:
        problems.append("LOW risk with assessment completeness below 69%")
    r = resp["recommendations"]
    for k in ("items", "secure_config", "before_after"):
        if k not in r:
            problems.append(f"recommendations missing {k}")
    for it in r.get("items", []):
        if not {"rank", "priority", "title", "action", "why", "based_on"} <= set(it) or it["priority"] not in ("Critical", "High", "Medium", "Low"):
            problems.append("bad recommendation item")
    if r.get("secure_config", {}).get("verified") is not False:
        problems.append("secure_config.verified must be false (the snippet was not run against a live strongSwan)")
    for f in a.get("findings", []):
        if not {"id", "title", "value", "status", "confidence", "rating", "evidence"} <= set(f) or f["status"] not in SOURCES:
            problems.append("bad finding")
    for k in ("cipher", "mode", "dh_group", "pfs"):
        if not resp[k]:
            problems.append(f"{k} is empty (use 'unknown')")
        if resp["sources"].get(k) not in SOURCES:
            problems.append(f"bad source for {k}")
    for b in resp["breakdown"]:
        if not {"factor", "value", "rating", "weight", "source", "reason"} <= set(b):
            problems.append("breakdown item missing keys")
        elif b["rating"] not in RATINGS:
            problems.append("bad rating")
        elif b["source"] not in SOURCES:
            problems.append("bad breakdown source")
    if not all(isinstance(s, str) for s in resp["explanation"] + resp["warnings"] + resp["errors"]):
        problems.append("explanation/warnings/errors must be plain strings")
    for a_ in resp["anomalies"]:
        if not {"severity", "name", "description"} <= set(a_) or a_["severity"] not in SEVERITIES:
            problems.append("bad anomaly item")
    for seg in resp["timeline"]:
        if not {"window", "start_sec", "end_sec", "class", "label", "confidence"} <= set(seg):
            problems.append("timeline item missing keys")
    if resp["traffic"] is not None and not {"class", "label", "confidence", "probabilities"} <= set(resp["traffic"]):
        problems.append("traffic missing keys")
    return problems
