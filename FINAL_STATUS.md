# FINAL STATUS — `innovations` branch

Branched from `finish-project` (commit `5f9604c`). One local commit per stage, **nothing pushed**. Everything below was verified by running it, except the items in section 5 that are marked *not verified* or *not possible without Docker*.

## 1. What is done

| Stage | Result | Evidence |
|---|---|---|
| 1 Passive ESP fingerprint | Cipher family (CBC vs GCM) from the ESP-length residue mod 16, integrity-tag candidates, tunnel vs transport — all from packet sizes only, never from file names; abstains (`undetermined`) below a confidence threshold or on constant-size streams (e.g. ICMP). | `tests/test_esp_fingerprint.py`, `ml-engineer/esp_fingerprint.py`, `ACCURACY_ADDENDUM.md` |
| 2 ESP/SPI sequence analysis | Per-SA (SPI × direction × protocol) sequence tracking: gaps, duplicates vs reordering, rollovers, replay evidence; rekey detection by SPI change; SA lifetime reported only when a rekey is actually observed. | `tests/test_esp_sequence.py`, `ml-engineer/esp_sequence.py` |
| 3 Assessment engine | 11 weighted facts (cipher, DH, PFS, mode, key length, lifetime, replay, IKE version, protocol, integrity, auth method); every finding tagged `observed`/`inferred`/`declared`/`unknown`; completeness %, guideline mapping (NIST/FIPS/RFC, labelled "not a certification"), metadata-exposure score; **score capped at 35 + 65 × completeness** so an under-observed capture can never read 100/LOW. | `tests/test_assessment.py`, `backend-developer/assessment.py` |
| 4 Recommendations | Prioritised Critical/High/Medium/Low fixes tied to findings; generated strongSwan `ipsec.conf` snippet (labelled `verified: false`); before/after score computed by re-scoring the parsed-back snippet. | `tests/test_recommendations.py`, `backend-developer/recommendations.py` |
| 5 Calibrated confidence + open set | Temperature scaling (floored at 1.0, softening only) + kNN novelty check; "unrecognised" verdict when a capture doesn't match any trained class; evaluated by holding out each traffic class entirely. | `tests/test_open_set.py`, `ml-engineer/open_set.py`, `ACCURACY_ADDENDUM.md` |
| 6 Defence what-if simulator | Simulated padding/dummy-traffic/delay/shaping defences, each with bandwidth/delay cost, scored against a naive and an adaptive attacker; always labelled a simulation. | `tests/test_defence_sim.py`, `ml-engineer/defence_sim.py`, `evaluate_defences.py` |
| 7 Replay mode | `POST /replay` streams a capture file window-by-window as NDJSON with a running verdict; UI and stream both say "replay, not live sniffing". | `tests/test_replay.py`, `ml-engineer/replay_stream.py` |
| 8 IPv6 / AH support | IPv4 + IPv6 parsing (extension headers excluded from ESP length), AH, ESP-in-UDP/4500; tested on hand-built SYNTHETIC fixtures only (the real dataset is IPv4 ESP); IPv4 results reproduce byte-for-byte after the change. | `tests/test_ipv6_ah.py`, `tests/fixtures/SYNTHETIC_*`, `tests/make_ipv6_ah_fixtures.py` |
| 9 Wrap-up | API contract → schema 1.1; README, technical docs, video script, deck (`.pptx`, checked in real PowerPoint), architecture diagram, sample reports and screenshots regenerated; `docs/PS_COMPLIANCE.md` (36-item gap analysis) and `ACCURACY_ADDENDUM.md` (new-model numbers, reproducibility check) added; integration-docs-lead updated with new findings/decisions and the `innovations` push command. | `tests/test_docs.py`, this file |

**Automated tests: 243 passed, 0 failed** (`pytest tests`, confirmed via `tools/make_test_report.py`). Also passing: `npm run lint`, `npm run build`, `tools/e2e_check.py` (real Edge browser, real PDF download).

## 2. Real numbers (see `ACCURACY_ADDENDUM.md` for the full breakdown)

* **ESP fingerprint (cipher family / mode):** committed on 144 of 180 captures, **144/144 correct** when committed (abstains on all 36 constant-size ICMP captures, correctly, since size alone carries no information there); the true 16-byte ICV was among the returned candidates in 96/96 CBC captures.
* **Tunnel vs transport mode:** 96.7 % accuracy overall; **100 %** on the 89.4 % of captures where the model commits; shuffled-label control 45.4 % (rules out a leak); ICMP alone 83.3 % (its constant size makes this the hardest class).
* **Open-set rejection:** with each traffic class held out entirely, **100 %** of the unknown class is rejected and **94.7 %** of known captures are still accepted; temperature floored at 1.0 so confidence is only ever softened, never inflated.
* **Defence simulation:** padding to full MTU drops a naive attacker to 42.8 % accuracy (+223 % bandwidth); dummy traffic to 60 % (+72 % bandwidth); combined defences also 60 % (+119 %). An **adaptive** attacker (retrained on defended traffic) stays near 100 % against every defence — the honest headline is that these defences only work against an attacker who doesn't adapt.
* **Reproducibility:** the three training/evaluation scripts were re-run from the 180 raw pcaps during this stage and produced byte-identical model and metrics files to the ones committed.
* **Assessment score cap in practice:** a real testbed capture (`aes128gcm16-dh19-tunnel-pfs-on`, web traffic) scores raw 100 but only 44 % complete, so the final score is capped to **64/MEDIUM**, not 100/LOW. A declared-weak sample scores **30/HIGH**.
* Old Stage-3 classifier numbers (100 % window/capture accuracy on the original 5-class task, grouped CV by VPN config) are unchanged and still lab-only — see `finish-project`'s `FINAL_STATUS.md` history for that discussion.

## 3. Problem-statement gap analysis

`docs/PS_COMPLIANCE.md` maps 36 problem-statement items to status: **18 Done**, **13 Partial** (works, but with a stated limitation — e.g. lab-only accuracy, synthetic-only IPv6/AH), **3 Not possible without Docker** (regenerate the dataset from the testbed, observe a real IKE rekey, run the generated strongSwan snippet against a live strongSwan), and **2 other** (decrypting traffic is out of scope by design for a passive analyser; a live deployment needs cloud accounts the author doesn't have). Read that file for the item-by-item evidence.

## 4. Assumptions I made (and kept going)

| # | Assumption |
|---|---|
| A1–A11 | Carried over unchanged from `finish-project`'s `FINAL_STATUS.md` (declared-vs-observed fallback, PFS trust flag, 1 s windows, ESP-only classification, model choice, PDF engine, deploy targets, file cleanup, strongSwan syntax not verified, the weak-comparison card, outer-folder read-only). |
| D12 | The final score is capped at 35 + 65 × assessment completeness, and every finding is tagged observed/inferred/declared/unknown, so a capture about which little is known can never read 100/LOW; a real testbed file now reads 64/MEDIUM (44 % complete). |
| D13 | Cipher family, integrity-tag candidates and tunnel-vs-transport are *inferred* from ESP sizes only (never from file names), committed only above a confidence threshold, otherwise "undetermined" — abstaining is more honest than guessing on a constant-size stream. |
| D14 | Calibration temperature is floored at 1.0: the unconstrained fit hit its search bound and would have made every confidence 100 %, so only softening is applied. |
| D15 | Defence simulation reports both a naive and an adaptive attacker, since a defence that only fools a non-adapting attacker would otherwise look far better than it is. |
| D16 | Replay mode streams a file; live sniffing (capturing from a network interface) is not implemented — the UI and the NDJSON stream both say "replay, not live sniffing". |
| D17 | IPv6/AH/NAT-T are tested on SYNTHETIC fixtures only; the real testbed and its 180 captures are IPv4 ESP. |
| D18 | The strongSwan snippet is labelled `verified: false` and the guideline mapping is labelled "not a certification", because Docker was unavailable to actually run either one — only requirements the author is certain of are cited. |

## 5. What still needs you

### 5.1 Run Docker (three items PS_COMPLIANCE.md marks "not possible without Docker")
1. Start **Docker Desktop** and wait for "Engine running".
2. Regenerate the dataset (see `finish-project`'s FINAL_STATUS.md section 5.1 for the exact commands) if you want a larger/fresher testbed.
3. Force a rekey during a capture (e.g. a short `ikelifetime`) so `esp_sequence.py`'s rekey/SA-lifetime logic can be checked against a real rekey instead of only the SYNTHETIC fixtures in `tests/make_esp_fixtures.py`.
4. Apply the generated strongSwan snippet (`backend-developer/recommendations.py`'s output) to a real strongSwan `ipsec.conf` and bring the tunnel up, to confirm the syntax is actually correct — right now it is only parsed back into the scoring engine, never executed.

### 5.2 Deployment logins (I cannot do these)
Vercel (or Netlify) and Render (or Railway) accounts → follow `DEPLOY.md`. Nothing has been deployed.

### 5.3 Record the video
`docs/VIDEO_SCRIPT.md` has the updated timed shot list, including the new gauge/completeness and inferred-badge/recommendation rows.

### 5.4 Check before you submit
* Open `docs/IPsec_VPN_Analyzer_Deck.pptx` and add your team names on slide 1.
* Not covered by any test: real Docker containers, a real observed IKE rekey, a real strongSwan run of the generated snippet, and real cloud deployment.
* No authentication or rate limiting on the API (documented as future work).

## 6. Push (only you do this)

```powershell
cd E:\SIH\SIH_2026\SIH_2026_full
git status                          # should be clean
git log --oneline -14               # one commit per stage, innovations on top of finish-project
git push -u origin innovations      # uploads the branch to https://github.com/ashwin02-cyber/SIH_2026
```
Optional afterwards, on GitHub: **Compare & pull request → Create pull request → Merge** to bring it into `main` (or into `finish-project`, whichever the team prefers as the base).
