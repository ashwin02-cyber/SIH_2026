# API contract — schema version 1.0

One response shape for `POST /analyze` (and `POST /analyze/sample/{name}`). It is built in
[`contract.py`](contract.py) and checked by `validate_response()`; the tests validate the real
API output **and** the sample responses bundled in the frontend, so they cannot drift apart.

## Endpoints

| Method & path | Purpose |
|---|---|
| `GET /health` | `{status, schema_version, ml_model_loaded, ml_import_error, max_upload_mb}` |
| `POST /analyze` | multipart form field `file` (.pcap/.pcapng, default limit 50 MB) → contract response |
| `GET /samples` | `{samples: [file names]}` bundled in `data/samples/` |
| `POST /analyze/sample/{name}` | analyze a bundled sample (used by the "Try a sample" button) |
| `POST /report/{executive\|technical}.{html\|pdf}` | body = an analysis response → the rendered report file |

Errors: `400` not a .pcap/.pcapng or not a readable capture, `413` too large, `500` unexpected.
If only *part* of the analysis fails (e.g. no IP traffic) the answer is still `200` with the
problem listed in `errors` — the shape never changes.

## Response

```jsonc
{
  "schema_version": "1.0",
  "filename": "aes128gcm16-dh19-tunnel-pfs-on__web_run1.pcap",

  "score": 100,                 // 0-100, higher = safer; null when nothing could be rated
  "risk_level": "LOW",          // LOW | MEDIUM | HIGH | UNKNOWN (UNKNOWN <=> score is null)
  "score_basis": "declared",    // observed | declared | mixed | none  (see "Honesty rules")

  "cipher": "AES-GCM-16-128",   // plain display strings, "unknown" when not determinable
  "mode": "tunnel",             // tunnel | transport | unknown
  "dh_group": "Group 19 (256-bit random ECP)",
  "pfs": "unknown",             // enabled | disabled | unknown
  "sources": { "cipher": "declared", "mode": "declared", "dh_group": "declared", "pfs": "unknown" },

  "breakdown": [                // what the score is made of (the "threat matrix")
    { "factor": "Cipher", "value": "AES-GCM-16-128", "rating": "strong", "weight": 0.4,
      "source": "declared", "reason": "AES-GCM-16-128 is an AEAD cipher ..." }
    // DH group (0.4), PFS (0.2), Mode (weight 0: shown, not scored)
  ],

  "traffic": {                  // null if the traffic model could not run
    "class": "web_browsing", "label": "Web browsing", "confidence": 0.98,
    "probabilities": [ { "name": "Web browsing", "value": 0.98 } /* ... 5 classes */ ]
  },
  "model_confidence": 0.98,     // same number as traffic.confidence, null if no traffic result

  "explanation": [ "Overall security score 100/100 - low risk.", "..." ],   // plain strings only
  "anomalies": [ { "severity": "LOW", "name": "...", "description": "..." } ],
  "timeline": [                 // one entry per fixed 1-second window
    { "window": 1, "start_sec": 0.0, "end_sec": 1.0, "class": "web_browsing",
      "label": "Web browsing", "confidence": 0.99, "packets": 22, "bytes": 5300,
      "packets_per_sec": 22.0, "bytes_per_sec": 5300.0 }
  ],
  "capture": { "packets": 300, "bytes": 73047, "span_sec": 13.4, "windows": 14,
               "window_sec": 1.0, "esp_only": true, "truncated": false, "windows_dropped": 0 },
  "details": { "ike": { /* raw ike_parser output, for the technical report */ } },
  "warnings": [ "..." ],        // things the reader should know (unobservable fields, truncation, ...)
  "errors":   [ "..." ]         // parts that failed; empty when everything ran
}
```

## Honesty rules the contract enforces

1. **`sources` says where every value came from.** `observed` = read from the capture's cleartext
   IKE_SA_INIT; `declared` = taken from the testbed's file-name convention
   (`<cipher>-dh<N>-<mode>-pfs-<on|off>__...`); `unknown` = not determinable.
2. **The real testbed captures contain no cleartext IKE_SA_INIT** (only encrypted keep-alives and ESP),
   so for them cipher/DH/mode are `declared`, and the UI/report must say so.
3. **PFS is `unknown` for declared configs.** In the first dataset the `pfs-on` and `pfs-off` testbed
   configs were byte-identical, so the file name says nothing about PFS. (`SIH_TRUST_DECLARED_PFS=1`
   turns file-name PFS on once captures are regenerated with the fixed testbed.)
4. **Unknown factors are excluded from the score**, never counted as weak.
5. **Mode is never defaulted to "tunnel"** — it is negotiated inside encrypted IKE_AUTH.
6. `score_basis` is `declared` whenever a rated value came from the file name, so a number is never
   presented as a measurement when it is not.
