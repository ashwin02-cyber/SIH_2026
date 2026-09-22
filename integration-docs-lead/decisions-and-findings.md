# Decisions, findings and assumptions

Each entry: what was found or decided, the evidence, and what was done. IDs are referenced from `FINAL_STATUS.md`.

## Findings (things that were wrong or surprising)

| ID | Finding | Evidence | Action |
|---|---|---|---|
| F1 | **No real capture contains `IKE_SA_INIT`.** The 36 "handshake" pcaps hold 2–4 packets on UDP/4500 that are encrypted `INFORMATIONAL` messages (exchange type 37, next payload 46). | raw header dump of `*__handshake.pcap`; old parser returned `ike_sa: null` for all 216 files | Parser returns `unknown`; declared-config fallback with labels (D2); testbed fixed (F2) |
| F2 | The capture-before-tunnel logic was most likely broken (inferred from the code and the data): `tcpdump` ran inside `peer-a` and `docker restart` would kill it together with the container. | `traffic-engineer/scripts/orchestrate.py` (old `switch_config`) | Containers no longer restarted; `tcpdump` starts first, then `ipsec down` + `ipsec reload`. **Not run on real Docker.** |
| F3 | **`pfs-on` and `pfs-off` configs were byte-identical** (template ignored the PFS flag). The `pfs` column in `manifest.csv` is meaningless for the 216 files. | `diff` of the generated configs (only the `conn` name differs) | Template fixed (DH group in `esp=`, `keylife=25s`); old rows marked `v1-pfs-identical`; PFS reported `unknown` (D3) |
| F4 | **The old 100 % accuracy was a capture-length shortcut.** Packet count alone predicts the class. | `ml-engineer/shortcut_check.json`: 100 % from `packet_count` under grouped CV (ICMP 18–20, web 300, video 500, VoIP 30–40, file 4998–5000) | Capture-length features dropped; 1 s windows (D4) |
| F5 | Tunnel-mode captures include **decrypted inner packets** (85 of 300 packets in a web capture were plaintext TCP). | packet composition analysis | ESP-only features (D5) |
| F6 | SHAP output shape `(1, 12, 5)` was flattened and zipped with 12 feature names → wrong names/values. `predict_from_features` had no `return`. | reproduced; `tests/test_predict.py` | Fixed and tested |
| F7 | Old parser reported `mode: "tunnel"` for every file and IKE version `2.0` for ICMP captures (from 2 encrypted keep-alives). | scan of all 216 files before/after | Mode `unknown`; version only when `IKE_SA_INIT` seen |
| F8 | On Windows, Scapy leaks the file handle when a file has an invalid header, so the upload temp file could not be deleted. | `PermissionError` in `tests/test_api.py` | Files opened and closed explicitly in both readers |
| F9 | The model is sensitive to **which part** of a capture it sees: the first 300 packets of a file transfer (ssh negotiation) classify as *video* (64 %). | manual test on the real file | Sample uses a bulk-phase excerpt, labelled; limitation documented |
| F10 | file_transfer, VoIP and video captures last < 2 s (stopped by packet count) → 1–2 windows each; class balance in windows is 611 web / 266 ICMP / 78 video / 36 VoIP / 36 file transfer. | `metrics.json` | Class-weighted training; balanced accuracy and macro-F1 reported; time-based capture in the fixed testbed |
| F11 | Some facts cannot be seen by a passive observer at all: AES-128 vs AES-256, authentication method, PFS, DH group after `IKE_SA_INIT`, SA lifetime unless a rekey is seen. | reasoning from RFC 7296 / RFC 4303; `esp_fingerprint.py` `NOT_OBSERVABLE` | Reported `unknown`; they lower completeness and the score cap |
| F12 | The real captures contain no rekey, no duplicates and no gaps; real video / file captures show *reordered* packets with zero duplicates. | `esp_sequence.py` on the 180 captures | Duplicates and reordering are separate findings; rekey / lifetime logic is tested on SYNTHETIC captures |
| F13 | The first 300 packets of a file transfer are now answered "unrecognised" (nearest class: video) instead of a wrong 64 % "video". | `predict.py`, `open_set_metrics.json` | Closes F9 |

## Decisions

| ID | Decision | Why |
|---|---|---|
| D1 | One venv, pinned versions matching the models (scikit-learn 1.9.1 etc.), UTF-8 `requirements.txt`; lean `requirements-backend.txt` for deployment | the old file was UTF-16 and included Jupyter; models warned about version mismatch |
| D2 | Values not observable in the capture may be filled from the testbed **file name**, but only as `declared`, and `score_basis` says so | otherwise every real capture would show `UNKNOWN`, which makes the demo useless — but a guess must never look like a measurement |
| D3 | PFS is never taken from the file name (unless `SIH_TRUST_DECLARED_PFS=1` after re-capture) | F3 |
| D4 | 1-second fixed windows, min 2 packets, rates over the nominal window | removes the capture-length shortcut; keeps a timeline |
| D5 | Classify ESP packets only | F5 |
| D6 | Cross-validation grouped by VPN config, RF vs XGBoost chosen by window macro-F1 | tests generalisation to unseen configs |
| D7 | PDF via xhtml2pdf | pure Python → installs with pip on Windows and on Render/Railway |
| D8 | Render/Railway via Docker (one Dockerfile), Vercel/Netlify for the site | same image locally and in the cloud |
| D9 | Removed superseded artefacts: `feature_extraction.py`, `features.csv`, `features_real.csv`, `generate_samples.py`, `generate_video_samples.py`, old `test_predict.py`, duplicate `docker/strongswan/generated_configs/`, html2canvas PNG export | replaced by the new pipeline; recoverable from git history |
| D10 | Frontend bundled samples come from real API output, not hand-written numbers | Rule 6 in the integration guide |
| D11 | The comparison card's weak example is a fixed reference configuration (`weak_reference.json`, generated by `make_sample_responses.py`) with PFS off and a score computed by the scoring engine with PFS counted (24), not the capture-based weak sample (30, PFS unknown and excluded) | a reference example is a defined configuration, so PFS can be off; showing "off" next to a score that ignored PFS would have been inconsistent |
| D12 | The final score is capped at 35 + 65 x assessment completeness, and every finding is tagged observed / inferred / declared / unknown | a capture about which little is known must never read 100 / LOW; a real testbed file now reads 64 / MEDIUM (44 % complete) |
| D13 | Cipher family, integrity-tag candidates and tunnel vs transport are *inferred* from ESP sizes (never from file names), committed only above a confidence threshold, otherwise "undetermined" | 144 / 144 correct when committed, but ICMP (constant size) cannot be answered; abstaining is more honest than guessing |
| D14 | Calibration temperature is floored at 1.0 | the unconstrained fit hit its search bound and made every confidence 100 %; softening only is the safe direction |
| D15 | Defence simulation reports a naive and an adaptive attacker | a defence that only fools an attacker who does not adapt would otherwise look far better than it is |
| D16 | Replay mode streams a file; live sniffing is not implemented | needs privileged capture on a network interface; the UI and stream say "replay, not live sniffing" |
| D17 | IPv6 / AH / NAT-T are tested on SYNTHETIC fixtures only | the real testbed is IPv4 ESP |
| D18 | The strongSwan snippet is labelled `verified: false`; the guideline mapping is labelled "not a certification" | Docker was unavailable; only requirements the authors are certain of are cited |

## Assumptions
1. Peer-a's eth0 sees the same ESP packets a passive observer between the peers would see.
2. The scripted traffic types are a fair proxy for the five classes (limitation acknowledged in the docs).
3. Anomaly thresholds (5 MB, 1 MB/s, 1400 B, 95 % one-way, 1 h) are reasonable defaults; they are rules, not learned.
4. The 4-byte zero *non-ESP marker* on UDP/4500 is the only NAT-T framing that needs handling.
5. `strongSwan` accepts `esp=aes128-sha256-modp2048!`, `esp=aes128gcm16!` and `keylife=25s` (standard syntax; **unverified without Docker**).
