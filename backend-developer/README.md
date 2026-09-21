# Backend Developer — IPsec VPN Analyzer

## Files
- `ike_parser.py` — extracts cipher, DH group, key length, PFS signal, and
  mode from a pcap's IKEv2 handshake. **Read the module docstring first** —
  there's an important note on what is and isn't visible from a passive
  capture (see "One thing to confirm" below).
- `scoring_engine.py` — turns those facts into a weak/medium/strong rubric
  per factor plus one overall 0–100 score. Pure logic, no I/O — run
  `python scoring_engine.py` for a self-contained sanity check.
- `main.py` — FastAPI app: `POST /analyze` (upload a pcap, get the combined
  IKE + ML + risk-score JSON) and `GET /health`.

## Setup
```
pip install -r requirements.txt
uvicorn main:app --reload --port 8000
```
Open `http://127.0.0.1:8000/docs` and use the Swagger UI to upload a pcap
from `real_captures/` before wiring up the frontend.

## One thing to confirm with the Testbed Lead
A real IPsec handshake only exposes the *IKE SA's own* cipher/DH group in
the clear — the ESP (data-channel) SA's own parameters and the
tunnel/transport mode choice are negotiated inside an encrypted exchange
(true for every RFC-compliant implementation, not a bug in this parser).

`ike_parser.py` reports the IKE SA's values as a stand-in for the whole
tunnel whenever the ESP-specific value isn't observable, and flags this in
its `warnings` list. This is a fair proxy **only if** the strongSwan
config templates apply the same cipher/DH/PFS/mode choice to both the
`ike=` and `esp=` lines — worth a quick check with Testbed Lead. If they
do differ, `test_ike_parser.py`-style testing against real captures will
make that obvious quickly (the two won't line up with `manifest.csv`).

## Testing against real data
Run the parser directly against a real capture first:
```
python ike_parser.py ../real_captures/<some_file>.pcap
```
Compare the output against that file's row in `data/manifest.csv`. If
something's off, send me the JSON output and I'll help debug — the parser
was written against the RFC spec but hasn't been run against a real
capture yet (no network access in the environment it was built in).

## Handoff to Frontend Developer
`POST /analyze` response shape:
```json
{
  "filename": "...",
  "ike_facts": { "ike_version": "...", "mode": "...", "ike_sa": {...}, "esp_sa": {...}, "warnings": [...] },
  "risk_assessment": { "overall_score": 0-100, "risk_level": "LOW|MEDIUM|HIGH|UNKNOWN", "factors": {...} },
  "traffic_classification": { "class": "...", "confidence": ..., "explanation": [...], "anomalies": [...], "timeline": [...] }
}
```