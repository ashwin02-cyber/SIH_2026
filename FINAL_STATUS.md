# FINAL STATUS

Branch `finish-project`, one local commit per stage, **nothing pushed**. Everything below was verified by running it, except the items in section 5 that are marked *not verified*.

## 1. What is done

| Stage | Result | Evidence |
|---|---|---|
| 1 Environment | One venv, UTF-8 pinned `requirements.txt` (matches the trained models: scikit-learn 1.9.1, xgboost 3.4.1, shap 0.52 …) + fastapi, uvicorn, python-multipart, shap, jinja2. `/health` and `/analyze` work on real pcaps. All hard-coded `E:\SIH_2026` paths removed. | `tests/test_api.py` |
| 2 Bugs | SHAP `(1,12,5)` axis mismatch fixed; `predict_from_features` returns; parser reports mode `unknown` (not `tunnel`) and no bogus IKE version; truncated files/packets handled; file handles closed (Windows bug found by a test). | `tests/test_ike_parser.py`, `test_predict.py` |
| 3 Honest ML | Fixed 1-second windows of **ESP-only** packets, no `packet_count`/`total_bytes`/`duration`, CV grouped by VPN config, retrained, `metrics.json` + confusion matrix saved. Timeline uses time windows. | `ml-engineer/metrics.json` |
| 4 Testbed | PFS now puts a DH group in `esp=`; tcpdump starts **before** teardown/renegotiation; captures stop by time (30 s; handshake 20 s); manifest upserts. Synthetic IKE fixtures labelled SYNTHETIC. | `tests/test_testbed_configs.py`, `test_orchestrate.py` (fake Docker) |
| 5 API contract | One response shape (`backend-developer/api_contract.md`); mocks are real API output. | `tests/test_contract.py`, `test_frontend_samples.py` |
| 6 Frontend | Real upload → results, risk gauge, threat matrix, timeline chart, `api.js`, `.env`; PNG export replaced by real report download. `npm run lint` and `npm run build` pass. | `tools/e2e_check.py` (real Edge browser) |
| 7 Reports | Jinja2 → HTML → PDF with xhtml2pdf (pure Python, Windows-safe); executive + technical; `/report` endpoint. | `tests/test_reports.py` |
| 8 Packaging | Dockerfiles, root `docker-compose.yml`, `render.yaml`, `railway.json`, `vercel.json`, `netlify.toml`, `DEPLOY.md`, `data/samples` (10 real pcaps) + manifest. | fresh-venv API run from a Docker-like layout (see A7, `DEPLOY.md`) |
| 9 Docs | Root README, technical documentation + architecture diagram, `integration-docs-lead/`, `.pptx` (12 slides, rendered in real PowerPoint and checked), video script, sample assessment from a real pcap. | `tests/test_docs.py` |

**Automated tests: 95 passed, 0 failed** (`pytest tests`). Also passing: `npm run lint`, `npm run build`, `tools/e2e_check.py`.

## 2. Real ML metrics (from `ml-engineer/metrics.json`)

* Random Forest, cross-validation grouped by VPN config (every test fold = configs never seen in training): **100 % accuracy per 1-second window (1,027 windows) and 100 % per capture (180 captures)**, macro-F1 1.00. XGBoost: 99.9 % / 100 %. Confusion matrix is perfectly diagonal — no class pair is confused.
* Controls: majority-class baseline 59.5 %; shuffled labels 46.3 % (cannot beat the baseline ⇒ no pipeline leak); without rate features still 100 %.
* **The old "100 %" was meaningless:** `packet_count` alone predicts the class with 100 % (`ml-engineer/shortcut_check.json`), because captures were stopped by `tcpdump -c N`.
* **What the 100 % does and does not mean:** the five scripted traffic types have very different packet-size signatures. It shows the approach works on this lab data with unseen VPN configs. It does **not** show the accuracy on real user traffic. Do not present it as such.
* Known weakness: the first 300 packets of a file transfer (ssh negotiation) are classified as *video* (64 %). The classifier expects reasonably complete captures.

## 3. Findings you should know about (details: `integration-docs-lead/decisions-and-findings.md`)

1. **None of the 216 captures contains a readable `IKE_SA_INIT`.** "Handshake" files hold 2–4 encrypted keep-alive packets, most likely because the old script started tcpdump inside a container and then ran `docker restart`, which would kill it (an inference from the script and the data; I could not re-run it without Docker). So cipher/DH cannot be read from them.
2. **`pfs-on` and `pfs-off` configs were byte-identical** — the `pfs` column of the old dataset is meaningless.
3. Tunnel-mode captures contain decrypted duplicates of packets (85 of 300 in one web capture) — a real observer would never see them.
4. Because of (1) the app shows cipher/DH/mode from the **file name** and labels them *declared* (not *observed*); PFS is shown as *unknown*; the score says `score_basis: declared`. This is my assumption A1 below — if you prefer `UNKNOWN` for every existing capture, set `declared_config_from_filename` to return `None`.

## 4. Assumptions I made (and kept going)

| # | Assumption |
|---|---|
| A1 | Show testbed-declared cipher/DH/mode as a **labelled fallback** so the demo is useful; never present it as observed. |
| A2 | PFS from file names is not trusted for the old dataset (env `SIH_TRUST_DECLARED_PFS=1` re-enables it after re-capture). |
| A3 | 1-second windows, ≥ 2 packets per window, rates over the nominal window length. |
| A4 | Classify ESP packets only. |
| A5 | Model selection by window-level macro-F1 between Random Forest and XGBoost (RF won). |
| A6 | PDF engine = xhtml2pdf (needs no GTK/Chrome). |
| A7 | Deploy the API as a Docker image (Render/Railway), the site on Vercel/Netlify; upload limit 50 MB locally, 20 MB on Render (512 MB RAM; measured ~320 MB in use after one analysis + PDF on Windows). |
| A8 | Removed superseded files (old feature scripts/CSVs, duplicate `docker/strongswan/generated_configs/`, html2canvas PNG export); all recoverable from git history. |
| A9 | strongSwan accepts `esp=aes128-sha256-modp2048!`, `esp=aes128gcm16!`, `keylife=25s` — standard syntax, **not verified without Docker**. |
| A11 | The "Compare against a weak setup" card compares the analysed capture with a **fixed reference configuration** (AES-CBC-128, DH 2, transport, PFS **off**, score 24 / HIGH from the real scoring engine), labelled as not a capture. "This capture" keeps showing PFS `unknown` for real captures. |
| A10 | Not touched: anything in `E:\SIH\SIH_2026` outside `SIH_2026_full` (read-only; only copied 10 small pcaps into `data/samples/`). No zip, no bulk pcap committed. |

## 5. What still needs you

### 5.1 Run Docker (dataset regeneration — skipped, Docker was not running)
1. Start **Docker Desktop** and wait for "Engine running".
2. ```powershell
   cd E:\SIH\SIH_2026\SIH_2026_full\docker\strongswan
   docker compose up -d --build
   cd ..\..
   python traffic-engineer\scripts\orchestrate.py --list
   python traffic-engineer\scripts\orchestrate.py --combo aes128-dh14-tunnel-pfs-on      # try ONE first
   docker exec peer-a ipsec statusall        # for pfs-on the child SA should show the DH group
   ```
3. Check the new `real_captures\aes128-dh14-tunnel-pfs-on__handshake.pcap`: `python backend-developer\ike_parser.py <that file>` should now show `ike_sa_init_seen: true` with a real cipher/DH. If not, send me the output — the fixed orchestration is *not verified*.
4. Then `python traffic-engineer\scripts\orchestrate.py --all` (about 90 minutes: 30 s × 5 classes × 36 configs), and retrain: `cd ml-engineer; python batch_extract.py; python train_model.py`. Re-run `backend-developer\make_sample_responses.py` and the tests afterwards; numbers in docs/slides update from `metrics.json` (re-run `tools\make_deck.py`).

### 5.2 Deployment logins (I cannot do these)
Vercel (or Netlify) and Render (or Railway) accounts → follow **`DEPLOY.md`** click by click. Nothing has been deployed; configs are syntax-checked only.

### 5.3 Record the video
`docs/VIDEO_SCRIPT.md` has the timed shot list (exactly 3:00, ~300 words) and a 10-minute pre-recording checklist.

### 5.4 Check before you submit
* Open `docs/IPsec_VPN_Analyzer_Deck.pptx` and add your team names on slide 1 (I did not invent any).
* Not covered by any test: real Docker containers, real cloud deployment, and the IKE parser on a *real* `IKE_SA_INIT` (only synthetic fixtures exist until 5.1 is done).
* No authentication or rate limiting on the API (documented as future work).

## 6. Push (only you do this)

```powershell
cd E:\SIH\SIH_2026\SIH_2026_full
git status                          # should be clean
git log --oneline -12               # one commit per stage
git push -u origin finish-project   # uploads the branch to https://github.com/ashwin02-cyber/SIH_2026
```
Optional afterwards, on GitHub: **Compare & pull request → Create pull request → Merge** to bring it into `main`.
