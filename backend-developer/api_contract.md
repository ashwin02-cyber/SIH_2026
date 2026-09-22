# API contract — schema version 1.1

One response shape for `POST /analyze` (and `POST /analyze/sample/{name}`). It is built in
[`contract.py`](contract.py) and checked by `validate_response()`; the tests validate the real
API output **and** the sample responses bundled in the frontend, so they cannot drift apart.

Version 1.1 only **adds** keys to 1.0 (`raw_score`, `confidence`, `assessment`, `recommendations`, `details.esp_fingerprint`,
`details.esp_sequence`, `details.defence_simulation`, and a few fields on `traffic`); nothing was removed or renamed.

## Endpoints

| Method & path | Purpose |
|---|---|
| `GET /health` | `{status, schema_version, ml_model_loaded, ml_import_error, max_upload_mb}` |
| `POST /analyze` | multipart form field `file` (.pcap/.pcapng, default limit 50 MB) → contract response |
| `POST /replay?pace=0.15` | same upload, answered as a **replay** stream (see below) |
| `GET /samples` | `{samples: [file names]}` bundled in `data/samples/` |
| `POST /analyze/sample/{name}` | analyze a bundled sample (used by the "Try a sample" button) |
| `POST /replay/sample/{name}?pace=0.15` | replay a bundled sample |
| `POST /report/{executive\|technical}.{html\|pdf}` | body = an analysis response → the rendered report file |

Errors: `400` not a .pcap/.pcapng or not a readable capture, `413` too large, `500` unexpected.
If only *part* of the analysis fails (e.g. no IP traffic) the answer is still `200` with the
problem listed in `errors` — the shape never changes.

### Replay stream (`application/x-ndjson`, one JSON object per line)

This is a **replay of a capture file in time order, not live sniffing**; the `start` event says so in `label`.
`pace` is the pause in seconds between windows (0–2; 0 = as fast as possible, used by the tests).

| Event `type` | Fields |
|---|---|
| `start` | `filename`, `label`, `total_windows`, `span_sec`, `window_sec`, `packets_total`, `esp_only`, `truncated` |
| `window` | `index`, `start_sec`, `end_sec`, `packets`, `bytes`, `window` (`{class, confidence}` of this second, or `null` if it had < 2 packets), and `so_far`: `packets`, `bytes`, `verdict` (running class / "unrecognised"), `cipher_family`, `mode`, `replay_protection` (`status`, `evidence`), `sas_seen`, `rekeys_seen` — all computed **only from the packets seen so far** |
| `end` | `windows_replayed`, `truncated` |
| `final` | `analysis`: the complete response (same shape as `POST /analyze`) |

At most 300 windows are replayed for one capture.

## Response

```jsonc
{
  "schema_version": "1.1",
  "filename": "aes128gcm16-dh19-tunnel-pfs-on__web_run1.pcap",

  "score": 64,                  // 0-100, higher = safer; null when nothing could be rated. NEVER above score_cap
  "raw_score": 100,             // the base scoring engine's number before the completeness cap
  "risk_level": "MEDIUM",       // LOW | MEDIUM | HIGH | UNKNOWN (UNKNOWN <=> score is null)
  "score_basis": "declared",    // observed | declared | mixed | none  (see "Honesty rules")

  "cipher": "AES-GCM-16-128",   // plain display strings, "unknown" when not determinable; "NONE" = AH only, not encrypted
  "mode": "tunnel",             // tunnel | transport | unknown
  "dh_group": "Group 19 (256-bit random ECP)",
  "pfs": "unknown",             // enabled | disabled | unknown
  "sources": { "cipher": "declared", "mode": "inferred", "dh_group": "declared", "pfs": "unknown" },
  "confidence": { "mode": 0.997 },   // only for values whose source is "inferred"

  "breakdown": [                // what the base score is made of (the "threat matrix")
    { "factor": "Cipher", "value": "AES-GCM-16-128", "rating": "strong", "weight": 0.4,
      "source": "declared", "reason": "AES-GCM-16-128 is an AEAD cipher ..." }
    // DH group (0.4), PFS (0.2), Mode (weight 0: shown, not scored)
  ],

  "assessment": {               // Stage 3
    "completeness_pct": 44.0,   // how much of what matters was established (observed = 1, inferred = its confidence, declared = 0.5, unknown = 0)
    "completeness_detail": [ { "fact": "dh_group", "label": "...", "weight": 15, "status": "declared", "known_fraction": 0.5 } ],
    "raw_score": 100, "score_cap": 64, "score_capped": true,          // cap = 35 + 65 x completeness; LOW needs >= 69 % completeness
    "cap_rule": "score <= 35 + 65 x completeness (LOW needs ...)",
    "unknown_facts": [ "IKE version" ],
    "findings": [ { "id": "cipher", "title": "...", "value": "...", "status": "observed|inferred|declared|unknown",
                    "confidence": null, "rating": "strong|medium|weak|info|unknown", "weight": 15, "evidence": "..." } ],
    "metadata_exposure": { "score": 92, "level": "HIGH", "scale": "...", "items": [ { "what": "...", "exposed_fraction": 1.0, "points": 12.0, "learned": "...", "why": "..." } ], "note": "..." },
    "compliance": { "label": "Guideline mapping against published guidance - NOT a certification",
                    "checks": [ { "id": "...", "guideline": "NIST SP 800-131A Rev. 2", "requirement": "...", "result": "meets|does_not_meet|cannot_assess", "evidence": "...", "input_status": "..." } ],
                    "summary": { "meets": 3, "does_not_meet": 0, "cannot_assess": 2 },
                    "not_evaluated": [ "NIST SP 800-77 Rev. 1 (Guide to IPsec VPNs)" ] },
    "score_after_cap": 64,
    "consistency_checks": [ { "item": "...", "declared": "...", "inferred": "...", "agree": true } ]
  },

  "recommendations": {          // Stage 4
    "items": [ { "id": "pfs", "priority": "Critical|High|Medium|Low", "rank": 1, "title": "...", "action": "...", "why": "...",
                 "based_on": { "status": "unknown", "confidence": null }, "standards": [], "config_hint": "esp=aes256gcm16-ecp384!" } ],
    "secure_config": { "format": "strongSwan ipsec.conf", "text": "...", "verified": false, "note": "NOT verified against a live strongSwan" },
    "before_after": { "label": "Projection ...", "before": { "score": 64, "risk_level": "MEDIUM", "completeness_pct": 44.0 },
                      "after_passive_capture": { "score": 80, "risk_level": "LOW", "completeness_pct": 69.0, "assumption": "..." },
                      "after_config_review":   { "score": 100, "risk_level": "LOW", "completeness_pct": 100.0, "assumption": "..." } }
  },

  "traffic": {                  // null if the traffic model could not run
    "class": "web_browsing",    // one of the 5 classes, or "unrecognised" (open-set rejection, Stage 5)
    "label": "Web browsing", "confidence": 0.98,     // calibrated (temperature scaling, softening only)
    "probabilities": [ { "name": "Web browsing", "value": 0.98 } /* ... 5 classes */ ],
    "nearest_class": "video", "nearest_label": "Video", "rejection_reason": "..."   // only when class == "unrecognised"
  },
  "model_confidence": 0.98,     // same number as traffic.confidence, null if no traffic result

  "explanation": [ "..." ],     // plain strings only
  "anomalies": [ { "severity": "LOW", "name": "...", "description": "..." } ],
  "timeline": [ { "window": 1, "start_sec": 0.0, "end_sec": 1.0, "class": "web_browsing", "label": "Web browsing", "confidence": 0.99,
                  "packets": 22, "bytes": 5300, "packets_per_sec": 22.0, "bytes_per_sec": 5300.0 } ],
  "capture": { "packets": 300, "bytes": 73047, "span_sec": 13.4, "windows": 14, "window_sec": 1.0, "esp_only": true,
               "truncated": false, "windows_dropped": 0 },

  "details": {
    "ike": { /* raw ike_parser output (adds handshake.ah_packets in 1.1) */ },
    "esp_fingerprint": {        // Stage 1: from packet sizes only, never from file names
      "esp_packets": 215, "distinct_sizes": 4, "residues_mod16": { "8": 100 },
      "cipher_family": { "value": "CBC-like|GCM-like|undetermined", "confidence": 0.99, "evidence": "..." },
      "integrity_tag": { "value": null, "candidates": [ { "bytes": 16 } ], "evidence": "..." },
      "mode": { "value": "tunnel|transport|undetermined", "confidence": 0.99, "evidence": "..." },
      "not_observable": [ "AES-128 vs AES-256 ...", "..." ],
      "protocols": { "ESP": 215, "AH": 0, "IPv6": 0 }, "ah_only": false        // Stage 8
    },
    "esp_sequence": {           // Stage 2
      "sas": [ { "spi": "0x...", "protocol": "ESP|AH", "direction": "a -> b", "packets": 100, "first_seq": 1, "last_seq": 100,
                 "monotonic": true, "duplicates": 0, "out_of_order": 0, "gap_events": 0, "rollovers": 0 } ],
      "replay_protection": { "status": "evidence_present|evidence_present_reordered|anomalies_observed|not_observable", "evidence": "...", "limits": [] },
      "rekey_events": [], "sa_lifetime": { "observable": false, "estimate_seconds": null, "lower_bound_seconds": null, "note": "not observable in this capture" }
    },
    "defence_simulation": { "available": true, "label": "SIMULATION - ...", "baseline": { }, "defences": [ ] }   // Stage 6
  },
  "warnings": [ "..." ],        // things the reader should know (unobservable fields, truncation, ...)
  "errors":   [ "..." ]         // parts that failed; empty when everything ran
}
```

## Honesty rules the contract enforces

1. **`sources` says where every value came from.**
   * `observed` — read directly from the capture (cleartext IKE_SA_INIT, ESP/AH headers);
   * `inferred` — deduced from packet sizes / sequence numbers, with a confidence in `confidence` (never from file names);
   * `declared` — taken from the testbed's file-name convention (`<cipher>-dh<N>-<mode>-pfs-<on|off>__...`): an unverified assertion;
   * `unknown` — not determinable.
2. **The real testbed captures contain no cleartext IKE_SA_INIT** (only encrypted keep-alives and ESP),
   so for them cipher/DH are `declared` (mode and cipher family are `inferred` from sizes where possible), and the UI/report must say so.
3. **PFS is `unknown` for declared configs.** In the first dataset the `pfs-on` and `pfs-off` testbed
   configs were byte-identical, so the file name says nothing about PFS. (`SIH_TRUST_DECLARED_PFS=1`
   turns file-name PFS on once captures are regenerated with the fixed testbed.)
4. **Unknown factors are excluded from the base score**, never counted as weak — but they lower `assessment.completeness_pct`.
5. **The score can never read better than what is known:** `score <= raw_score`, `score <= assessment.score_cap`, and `LOW` requires completeness ≥ 69 %.
   `validate_response()` fails the response otherwise.
6. **Mode is never defaulted to "tunnel"** — it is negotiated inside encrypted IKE_AUTH; it is `inferred` (with a confidence) only when the size pattern supports it.
7. `secure_config.verified` is always `false` (the snippet was not run against a live strongSwan), the compliance block is a
   *guideline mapping* and not a certification, and the defence simulation and replay are labelled as such.
