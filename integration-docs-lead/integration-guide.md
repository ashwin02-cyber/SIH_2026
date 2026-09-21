# Integration guide

## 1. Hand-offs between workstreams

```
Traffic/Testbed ──pcaps + manifest.csv──► ML ──models + metrics.json──► Backend ──JSON contract──► Frontend
                                                                           └──────HTML→PDF────────► Reports
```

| From → To | Artifact | Interface (exact) | Owner check |
|---|---|---|---|
| Testbed → ML | `real_captures/<config>__<class>_run<N>.pcap`, `manifest.csv` | file-name convention `<cipher>-dh<N>-<mode>-pfs-<on|off>__<class>_run<N>.pcap` | `ml-engineer/batch_extract.py::parse_name` |
| ML → Backend | `ml-engineer/models/{traffic_classifier,label_encoder}.pkl` | `predict.predict_from_pcap(path) -> dict` (see `ml-engineer/predict.py`), raises `ValueError` for non-captures | `tests/test_predict.py` |
| ML training ↔ inference | `traffic_features.py` | **the same module** is used to train and to predict; `predict.py` refuses to load a model whose `feature_names_in_` differ from `FEATURE_COLS` | import-time check in `predict.py` |
| Backend parser → contract | `ike_parser.parse_ike_handshake(path) -> dict` | never guesses: missing values are `None`/`"unknown"` | `tests/test_ike_parser.py` |
| Backend → Frontend | `POST /analyze` → `contract.build_response(...)` | schema 1.0, validated by `contract.validate_response` | `tests/test_api.py`, `tests/test_frontend_samples.py` |
| Backend → Reports | `report_builder.render_report(analysis, kind, fmt)` | takes the *same* contract dict; `/report/{kind}.{fmt}` re-validates it | `tests/test_reports.py` |
| Frontend → Backend | `frontend-developer/src/api.js` | base URL = `VITE_API_URL` | `tools/e2e_check.py` |

## 2. Runtime layout

| Service | Local address | Start | Env vars |
|---|---|---|---|
| FastAPI | http://127.0.0.1:8000 (`/docs`, `/health`) | `cd backend-developer && uvicorn main:app --port 8000` | `ALLOWED_ORIGINS` (default `*`), `MAX_UPLOAD_MB` (50), `SIH_SAMPLES_DIR`, `SIH_TRUST_DECLARED_PFS` |
| React (dev) | http://localhost:5173 | `cd frontend-developer && npm run dev` | `VITE_API_URL` (`.env`) |
| React (docker) | http://localhost:8080 | `docker compose up --build` | build arg `VITE_API_URL` |
| Testbed | Docker network 10.10.0.0/24 (peer-a .10, peer-b .20) | see `traffic-engineer/readme.MD` | `SIH_PROJECT_ROOT`, `SIH_CAPTURES_DIR`, `TESTBED_ROOT_PASSWORD` |

Start order: API first (the website checks `/health` on load and disables uploads if it cannot reach it), then the website.
The backend finds the ML code via `sys.path` (`../ml-engineer`) — keep the folder layout, or use the provided Docker image which preserves it.

## 3. Shared rules every workstream must keep

1. **Never present a guess as a measurement.** Values in API responses carry `sources.*` (`observed`/`declared`/`unknown`); the UI and reports print that in words.
2. **Unknown ≠ weak.** Unknown factors are excluded from the score.
3. **No capture-length features** in the model (`packet_count`, `total_bytes`, `duration`) — enforced by an assertion in `train_model.py` and a test.
4. **ESP-only for the classifier**, because a wire observer never sees decrypted packets.
5. **Fixtures must say SYNTHETIC** (file names `SYNTHETIC_*`, `tests/fixtures/README.md`). They are never used as evidence of real behaviour.
6. **Bundled frontend samples are regenerated from real API output** (`backend-developer/make_sample_responses.py`); a test fails if they are edited by hand.

## 4. Data provenance

| Data | Where | In git? | Notes |
|---|---|---|---|
| Full dataset (216 pcaps, ~500 MB, plus a 200 MB zip) | outside the repo | no | `batch_extract.py --pcap-dir` / `SIH_PCAP_DIR` |
| `manifest.csv` | repo root | yes | `config_version=v1-pfs-identical`, `capture_stop=packet-count` for existing rows |
| `data/samples/` (10 small real captures) + `data/manifest.csv` | repo | yes | one file is an excerpt (marked in the manifest) |
| `ml-engineer/features_windowed.csv` | repo | yes | 1,027 windows, regenerable |
| `tests/fixtures/SYNTHETIC_*.pcap` | repo | yes | hand-built IKE messages, regenerable with `tests/make_fixtures.py` |
