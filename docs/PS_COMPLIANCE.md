# Problem-statement compliance (SIH 2026, PS 26160)

Every item of the problem statement, with an honest status and the evidence for it (a file, a test, or a metric you can re-run).

**Status words**

| Status | Meaning |
|---|---|
| **Done** | Implemented and tested. Where the only test data is synthetic, that is stated in the "Limits" column. |
| **Partial** | Implemented, but only part of the item is achievable from a passive capture, or it was only verified on synthetic / lab data. The limit is stated. |
| **Not possible without Docker** | Needs the two-peer strongSwan testbed to run (Docker was not running), so it could not be produced or checked. |

"Passive" means: only the packets of one capture file, nothing decrypted, no access to either gateway. Some facts are simply *not visible* to such an observer;
for those the tool answers **unknown** (it never guesses) and the assessment-completeness percentage and score cap reflect it.

**Metrics quoted here** come from `ml-engineer/*.json` and are all lab results (180 scripted captures, 36 VPN configurations x 5 traffic types, cross-validation grouped by configuration).
They are audited in [ACCURACY_REPORT.md](../ACCURACY_REPORT.md) and [ACCURACY_ADDENDUM.md](../ACCURACY_ADDENDUM.md). They are **not** evidence about real-world traffic.

## A. What the analyzer must identify

| # | Problem-statement item | Status | Evidence | Limits |
|---|---|---|---|---|
| A1 | IPsec protocol (ESP / AH / IKE) | **Done** | `ml-engineer/traffic_features.py` (`read_packets`), `backend-developer/ike_parser.py`; `tests/test_ipv6_ah.py`, `tests/test_ike_parser.py`, `tests/test_traffic_features.py` | Real captures are IPv4 ESP; IPv6, AH and ESP-in-UDP/4500 are verified on **synthetic** fixtures only. |
| A2 | IKE version | **Partial** | `ike_parser.py`; `tests/test_ike_parser.py` (synthetic `IKE_SA_INIT`, also over IPv6) | None of the 216 real captures holds a cleartext `IKE_SA_INIT`, so for real files it is reported `unknown`. IKEv1 is recognised as "not IKEv2", not decoded. |
| A3 | Tunnel vs transport mode | **Partial** | Passive inference `ml-engineer/esp_fingerprint.py`; `esp_fingerprint_metrics.json`: 96.7 % grouped-CV accuracy, 100 % when it commits (89 % coverage), shuffled-label control 45 %; `tests/test_esp_fingerprint.py` | Not readable from any packet (negotiated in encrypted IKE_AUTH); it is an **inference** with a confidence. Weak on ICMP (83 %, 50 % coverage). |
| A4 | Encryption algorithm / cipher | **Partial** | Family from sizes: 144 / 180 captures answered, 144 / 144 correct, abstains on all 36 ICMP captures (`esp_fingerprint_metrics.json`); exact algorithm read from `IKE_SA_INIT` when present (`tests/test_ike_parser.py`) | Sizes give CBC-like vs GCM-like only, never the exact algorithm. For real captures the exact cipher is **declared** (from the file name) and labelled so. |
| A5 | Key length | **Partial** | Read from the `IKE_SA_INIT` proposal (`ike_parser.py`); `esp_fingerprint.py` `not_observable` list | AES-128 vs AES-256 does not change packet sizes: **not observable passively**. `unknown` when no `IKE_SA_INIT`. |
| A6 | Integrity / authentication tag | **Partial** | `infer_integrity_tag`: true 16-byte tag among the candidates in 96 / 96 CBC answers; `tests/test_esp_fingerprint.py` | Reported as **candidates**, not one value; GCM tag length is not observable. |
| A7 | Authentication method (PSK / certificates) | **Partial** | Field exists in the assessment (`backend-developer/assessment.py`), recommendation to confirm it (`recommendations.py`) | It is exchanged inside encrypted `IKE_AUTH`: **not visible to a passive observer**; always `unknown` from a capture. |
| A8 | Key exchange (DH group) | **Partial** | `ike_parser.py` (group, label), `scoring_engine.py`; `tests/test_scoring.py`, `tests/test_ike_parser.py` | Visible only in `IKE_SA_INIT`. Real captures: declared from the file name. Verification on a real `IKE_SA_INIT` needs the testbed (see D1). |
| A9 | SA characteristics (SPIs, sequence numbers, direction, rekeys) | **Done** | `ml-engineer/esp_sequence.py`; `tests/test_esp_sequence.py` (synthetic: clean, gaps, duplicates, out-of-order, rekey, parallel SAs; plus real captures) | Per-SA statistics for ESP and AH; IPv6 and AH on synthetic data only. |
| A10 | Traffic type inside the ESP tunnel (web, video, VoIP, file transfer, ICMP) | **Done** (lab) | `ml-engineer/predict.py`, `metrics.json`: 100 % per window (1,027) and per capture (180) on unseen configurations; `tests/test_predict.py` | Lab data with five very different scripted traffic types. **Not** a claim about real traffic; excerpts of a file transfer can be misjudged (now answered "unrecognised"). |

## B. What the analyzer must assess

| # | Item | Status | Evidence | Limits |
|---|---|---|---|---|
| B1 | Cryptographic strength rating | **Done** | `backend-developer/scoring_engine.py` (cipher, DH group, PFS weights 0.4 / 0.4 / 0.2); `tests/test_scoring.py` | Weights are a project design choice, documented in `docs/TECHNICAL_DOCUMENTATION.md` section 4. |
| B2 | Key lifetime | **Partial** | `esp_sequence.py` `sa_lifetime`; `assessment.py`; `tests/test_esp_sequence.py` (synthetic rekey) | Reported **only when a rekey is observed** (an estimate or a lower bound); otherwise "not observable in this capture". The real captures contain no rekey; the testbed fix that forces one (`keylife=25s`) is not run (D2). |
| B3 | Replay protection | **Partial** | `esp_sequence.py` `replay_protection` (evidence_present / reordered / anomalies / not_observable); `tests/test_esp_sequence.py` | Monotonic sequence numbers are *evidence that the sender uses them*; whether the receiver actually enforces the anti-replay window is **not observable** (stated in the output). |
| B4 | Perfect Forward Secrecy | **Partial** | `contract.py`, `assessment.py`; the file-name PFS is deliberately not trusted (`tests/test_contract.py`) | A fresh DH exchange for the child SA happens inside encrypted `CREATE_CHILD_SA` / `IKE_AUTH`: **not passively observable**. Real PFS labels need a regenerated dataset (D1). |
| B5 | Compliance with guidance | **Done** (as a mapping) | `assessment.py` `compliance`: NIST SP 800-131A Rev. 2, FIPS 197, RFC 8221, RFC 8247; `tests/test_assessment.py` | A *guideline mapping, not a certification*. NIST SP 800-77 is listed as "not evaluated" because we cannot check it from a capture. Only requirements the authors are certain of are included. |
| B6 | Metadata exposure | **Done** | `assessment.py` `metadata_exposure` (what an eavesdropper still learns without any key: traffic type, mode, cipher family, packet sizes, timing and volume, endpoints); `tests/test_assessment.py` | A project-defined 0-100 scale, explained in the output. Only passive inferences count, never file names. |
| B7 | Unencrypted traffic (AH only) | **Done** | `contract.py`, `assessment.py`, `recommendations.py`; `tests/test_ipv6_ah.py` | Synthetic AH fixtures only. |

## C. What the analyzer must output

| # | Item | Status | Evidence | Limits |
|---|---|---|---|---|
| C1 | Overall security score and risk level | **Done** | `contract.py` (`score`, `raw_score`, `risk_level`); the score is capped by assessment completeness and can never be `LOW` when key facts are unknown (`validate_response`); `tests/test_contract.py` | Real testbed files cap at 64 / MEDIUM (44 % completeness): deliberately not 100 / LOW. |
| C2 | Threat matrix / breakdown | **Done** | `breakdown` in the response, threat matrix panel in `frontend-developer/src/`; `tests/test_contract.py` | Rows are the scored factors plus mode (shown, weight 0). |
| C3 | AI confidence | **Done** | Calibrated probabilities and open-set rejection ("unrecognised traffic"): `ml-engineer/open_set.py`, `open_set_metrics.json` (holding out each class entirely: 100 % of unknown captures rejected, 94.7 % of known accepted); `tests/test_open_set.py` | Lab classes are far apart, so real unknowns will be harder. Temperature is floored at 1.0 (softening only). |
| C4 | Every finding tagged observed / inferred / declared / unknown | **Done** | `assessment.py`, `contract.py` (`sources`, `confidence`); enforced by `validate_response`; `tests/test_assessment.py` | - |
| C5 | Assessment completeness | **Done** | `assessment.py` `completeness`, `apply_cap`; `tests/test_assessment.py` | Weights are a project design choice. |
| C6 | Actionable recommendations, prioritised | **Done** | `backend-developer/recommendations.py` (Critical / High / Medium / Low, each tied to a finding and its status); `tests/test_recommendations.py` | Rule-based text, no free-text generation. |
| C7 | Generated secure configuration | **Partial** | strongSwan `ipsec.conf` snippet from `secure_ipsec_conf`; the "after" score is computed by parsing that snippet back (`tests/test_recommendations.py`) | Labelled `verified: false`: **not run against a live strongSwan** (D3). |
| C8 | Before / after score | **Done** | `recommendations.py` `before_after`, projections for a passive re-capture and a config review; `tests/test_recommendations.py` | A projection of what the tool would report, not a measurement of a real fixed VPN. |
| C9 | Reports for executives and engineers | **Done** | `reports/report_builder.py`, `reports/templates/executive.html.j2`, `technical.html.j2`; `tests/test_reports.py` (real PDFs, text checked), `docs/sample_reports/` | - |
| C10 | Dashboard | **Done** | `frontend-developer/src/`; `npm run lint`, `npm run build`, `tools/e2e_check.py` (real browser) | - |

## D. Things the testbed must do, and extras

| # | Item | Status | Evidence | Limits |
|---|---|---|---|---|
| D1 | Regenerate the dataset with a readable `IKE_SA_INIT`, real PFS labels, forced rekeys | **Not possible without Docker** | Fixed orchestration: `traffic-engineer/scripts/orchestrate.py`, `tests/test_orchestrate.py` (fake Docker) | The fix is unit-tested with a fake Docker only. Steps for you: `FINAL_STATUS.md` section 5.1. |
| D2 | Observe a real rekey (key lifetime from a real capture) | **Not possible without Docker** | `keylife=25s` in the generated configs (`tests/test_testbed_configs.py`) | Not observed on real data; sequence/rekey logic is tested on synthetic captures. |
| D3 | Run the generated strongSwan snippet | **Not possible without Docker** | Snippet in the response and in the reports | Standard syntax, never executed. Test in a lab before use. |
| D4 | Defence what-if simulator (padding, dummy traffic, delay, shaping) | **Done** (simulation) | `ml-engineer/defence_sim.py`, `defence_metrics.json`; `tests/test_defence_sim.py`; dashboard panel and report section | A *simulation* on scripted lab traffic. Fools a naive attacker (e.g. full-size padding: 42.8 % accuracy) but an adaptive attacker is back to 100 % here, at +72 % to +223 % bandwidth. |
| D5 | Live analysis | **Partial** | Replay mode: `ml-engineer/replay_stream.py`, `POST /replay`, dashboard replay panel; `tests/test_replay.py` | It **replays a capture file** in time order with a running verdict. **Not live sniffing**; the UI and the stream say so. |
| D6 | IPv6, AH, NAT-T | **Done** (synthetic-tested) | `traffic_features.py`, `esp_analysis.py`, `ike_parser.py`; `tests/test_ipv6_ah.py`; `tests/fixtures/README.md` | Synthetic fixtures only (named `SYNTHETIC_*`). |
| D7 | Decrypting the payload | **Out of scope by design** | - | Passive analysis without keys; the tool never claims to see inside the encryption. |
| D8 | Deployment (Vercel / Render, etc.) | **Not done** | `DEPLOY.md`, `render.yaml`, `vercel.json`, `netlify.toml` (syntax-checked only) | Needs your accounts. Docker images were not built (Docker not running). |
| D9 | Demo video and slides | **Partial** | `docs/VIDEO_SCRIPT.md` (timed shot list), `docs/IPsec_VPN_Analyzer_Deck.pptx`; `tests/test_docs.py` | The video itself must be recorded by you; add team names on slide 1. |

## Summary

* **Done:** 18 items (A1, A9, A10, B1, B5, B6, B7, C1-C6, C8-C10, D4, D6) - several with the "lab / synthetic only" limit noted.
* **Partial:** 13 items (A2-A8, B2-B4, C7, D5, D9) - mainly because the fact is not visible to a passive observer, or was only verified on synthetic data.
* **Not possible without Docker:** D1, D2, D3 (plus building and running the container images).
* **Not done / by design:** D7 (by design), D8 (needs your accounts).
* 36 items in total: 18 + 13 + 3 + 2.
