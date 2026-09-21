"""
contract.py
Builds THE response of POST /analyze (schema_version 1.0) from the IKE parser
output and the ML result, and validates that any dict has that shape.

One shape, always (also when parts fail - failures go into `errors`):

{
  "schema_version": "1.0",
  "filename": str,
  "score": int 0-100 | null,               # security score, higher = safer
  "risk_level": "LOW" | "MEDIUM" | "HIGH" | "UNKNOWN",
  "score_basis": "observed" | "declared" | "mixed" | "none",
  "cipher": str, "mode": str, "dh_group": str, "pfs": str,   # plain display strings
  "sources": {"cipher","mode","dh_group","pfs": "observed"|"declared"|"unknown"},
  "breakdown": [ {factor, value, rating, weight, source, reason} ],   # what makes up the score
  "traffic": {"class": str, "label": str, "confidence": float|null,
              "probabilities": [ {name, value} ]},
  "model_confidence": float | null,
  "explanation": [str, ...],               # plain sentences for a non-expert
  "anomalies": [ {severity, name, description} ],
  "timeline": [ {window, start_sec, end_sec, class, label, confidence, packets, bytes} ],
  "capture": {packets, bytes, span_sec, windows, window_sec, esp_only, truncated} | null,
  "details": {"ike": <raw ike_parser output> | null, "esp_fingerprint": <passive ESP fingerprint> | null,
                                                "esp_sequence": <SPI/sequence analysis> | null},
  "warnings": [str, ...],
  "errors": [str, ...]
}
"""

from config_hint import declared_config_from_filename
from ike_parser import DH_GROUP_LABELS
from scoring_engine import FACTOR_WEIGHT, score_ike_facts

SCHEMA_VERSION = "1.0"
RISK_LEVELS = ("LOW", "MEDIUM", "HIGH", "UNKNOWN")
RATINGS = ("strong", "medium", "weak", "unknown")
SEVERITIES = ("HIGH", "MEDIUM", "LOW")

TRAFFIC_LABELS = {
    "web_browsing": "Web browsing",
    "video_streaming": "Video streaming",
    "voip": "VoIP",
    "file_transfer": "File transfer",
    "icmp": "ICMP (ping)",
}

REQUIRED_KEYS = {
    "schema_version": str, "filename": str, "score": (int, type(None)), "risk_level": str,
    "score_basis": str, "cipher": str, "mode": str, "dh_group": str, "pfs": str, "sources": dict,
    "breakdown": list, "traffic": (dict, type(None)), "model_confidence": (float, int, type(None)),
    "explanation": list, "anomalies": list, "timeline": list, "capture": (dict, type(None)),
    "details": dict, "warnings": list, "errors": list,
}


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


def merge_facts(filename, ike_facts):
    """Choose, per property, the observed value if there is one, else the value declared
    by the testbed file name, else unknown. Returns (facts_for_scoring, sources)."""
    ike_facts = ike_facts or {}
    ike_sa = ike_facts.get("ike_sa") or {}
    esp_sa = ike_facts.get("esp_sa") or {}
    declared = declared_config_from_filename(filename) or {}

    obs_cipher = esp_sa.get("cipher") or ike_sa.get("cipher")
    obs_bits = esp_sa.get("key_length_bits") or ike_sa.get("key_length_bits")
    obs_dh = esp_sa.get("dh_group") or ike_sa.get("dh_group")
    obs_pfs = esp_sa.get("pfs")
    obs_mode = ike_facts.get("mode", "unknown")

    sources = {}
    if obs_cipher:
        cipher, bits, sources["cipher"] = obs_cipher, obs_bits, "observed"
    elif declared:
        cipher, bits, sources["cipher"] = declared["cipher"], declared["key_length_bits"], "declared"
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
    elif declared:
        mode, sources["mode"] = declared["mode"], "declared"
    else:
        mode, sources["mode"] = "unknown", "unknown"

    facts = {
        "ike_version": ike_facts.get("ike_version", "unknown"),
        "mode": mode,
        "ike_sa": {"cipher": cipher, "key_length_bits": bits, "dh_group": dh},
        "esp_sa": {"pfs": pfs} if pfs is not None else None,
        "warnings": [],
    }
    return facts, sources


def _score_basis(sources, breakdown):
    used = {b["source"] for b in breakdown if b["weight"] > 0 and b["rating"] != "unknown"}
    if not used:
        return "none"
    if used == {"observed"}:
        return "observed"
    if used == {"declared"}:
        return "declared"
    return "mixed"


def build_explanation(score, risk, basis, breakdown, traffic, ml_explanation, sources):
    lines = []
    if score is None:
        lines.append("A security score could not be calculated because the capture does not reveal "
                     "the cipher or Diffie-Hellman group.")
    else:
        lines.append(f"Overall security score {score}/100 - {risk.lower()} risk.")
        if basis == "declared":
            lines.append("This rating uses the VPN configuration named in the capture's file name "
                         "(declared by the testbed), because the capture itself does not contain the "
                         "readable IKE negotiation.")
        elif basis == "mixed":
            lines.append("Some rated values were observed in the capture and others come from the "
                         "testbed file name.")
    for b in breakdown:
        if b["rating"] in ("weak", "medium"):
            lines.append(f"{b['factor']} - {b['value']} - is rated {b['rating']}. {b['reason']}")
    unknown = [b["factor"] for b in breakdown if b["rating"] == "unknown" and b["weight"] > 0]
    if unknown:
        lines.append(f"Not determinable from this capture: {', '.join(unknown)}. "
                     "These are left out of the score instead of being counted as weak.")
    if traffic:
        lines.append(f"The encrypted traffic looks like {traffic['label'].lower()} "
                     f"(model confidence {traffic['confidence']:.0%}).")
    for item in ml_explanation or []:
        if isinstance(item, dict) and item.get("text"):
            lines.append(item["text"])
    return lines


def build_response(filename, ike_facts, ml_result, errors=None, warnings=None, esp=None):
    """Assemble the contract response. Never raises; problems become `errors` / `warnings`."""
    errors = list(errors or [])
    warnings = list(warnings or [])

    facts, sources = merge_facts(filename, ike_facts)
    risk = score_ike_facts(facts)
    factors = risk["factors"]

    mode_rating, mode_reason = _mode_rating(facts["mode"])
    breakdown = [
        {"factor": "Cipher", "value": _cipher_string(facts["ike_sa"]["cipher"], facts["ike_sa"]["key_length_bits"]),
         "rating": factors["cipher"]["rating"], "weight": FACTOR_WEIGHT["cipher"],
         "source": sources["cipher"], "reason": factors["cipher"]["reason"]},
        {"factor": "DH group", "value": _dh_string(facts["ike_sa"]["dh_group"]),
         "rating": factors["dh_group"]["rating"], "weight": FACTOR_WEIGHT["dh_group"],
         "source": sources["dh_group"], "reason": factors["dh_group"]["reason"]},
        {"factor": "PFS", "value": _pfs_string((facts["esp_sa"] or {}).get("pfs")),
         "rating": factors["pfs"]["rating"], "weight": FACTOR_WEIGHT["pfs"],
         "source": sources["pfs"], "reason": factors["pfs"]["reason"]},
        {"factor": "Mode", "value": facts["mode"], "rating": mode_rating, "weight": 0.0,
         "source": sources["mode"], "reason": mode_reason},
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
    basis = _score_basis(sources, breakdown)

    return {
        "schema_version": SCHEMA_VERSION,
        "filename": filename,
        "score": risk["overall_score"],
        "risk_level": risk["risk_level"],
        "score_basis": basis,
        "cipher": breakdown[0]["value"],
        "mode": facts["mode"],
        "dh_group": breakdown[1]["value"],
        "pfs": breakdown[2]["value"],
        "sources": sources,
        "breakdown": breakdown,
        "traffic": traffic,
        "model_confidence": model_confidence,
        "explanation": build_explanation(risk["overall_score"], risk["risk_level"], basis, breakdown,
                                         traffic, ml_explanation, sources),
        "anomalies": anomalies or [],
        "timeline": timeline or [],
        "capture": capture,
        "details": {"ike": ike_facts, "esp_fingerprint": (esp or {}).get("fingerprint"),
                    "esp_sequence": (esp or {}).get("sequence")},
        "warnings": list(dict.fromkeys(warnings)),  # de-duplicate, keep order
        "errors": errors,
    }


def validate_response(resp):
    """Returns a list of problems (empty list = valid). Used by tests for the real
    response AND for the bundled frontend mocks, so they cannot drift apart."""
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
    for k in ("cipher", "mode", "dh_group", "pfs"):
        if not resp[k]:
            problems.append(f"{k} is empty (use 'unknown')")
    for k in ("cipher", "mode", "dh_group", "pfs"):
        if resp["sources"].get(k) not in ("observed", "declared", "unknown"):
            problems.append(f"bad source for {k}")
    for b in resp["breakdown"]:
        if not {"factor", "value", "rating", "weight", "source", "reason"} <= set(b):
            problems.append("breakdown item missing keys")
        elif b["rating"] not in RATINGS:
            problems.append("bad rating")
    if not all(isinstance(s, str) for s in resp["explanation"] + resp["warnings"] + resp["errors"]):
        problems.append("explanation/warnings/errors must be plain strings")
    for a in resp["anomalies"]:
        if not {"severity", "name", "description"} <= set(a) or a["severity"] not in SEVERITIES:
            problems.append("bad anomaly item")
    for seg in resp["timeline"]:
        if not {"window", "start_sec", "end_sec", "class", "label", "confidence"} <= set(seg):
            problems.append("timeline item missing keys")
    if resp["traffic"] is not None and not {"class", "label", "confidence", "probabilities"} <= set(resp["traffic"]):
        problems.append("traffic missing keys")
    return problems
