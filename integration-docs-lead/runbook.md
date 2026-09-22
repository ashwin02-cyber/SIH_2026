# Run book (Windows PowerShell)

```powershell
cd E:\SIH\SIH_2026\SIH_2026_full
.\venv\Scripts\Activate.ps1          # created with: python -m venv venv ; pip install -r requirements.txt
```

## Run the app
```powershell
cd backend-developer;  uvicorn main:app --port 8000          # API   http://127.0.0.1:8000/docs
cd frontend-developer; npm install; npm run dev              # site  http://localhost:5173
docker compose up --build                                    # both, in Docker   http://localhost:8080
```

## Test
```powershell
python -m pytest tests -q                                    # all Python tests
cd frontend-developer; npm run lint; npm run build
pip install -r requirements-dev.txt                          # once, for the browser check
cd frontend-developer; npm run build; cd ..
python tools\e2e_check.py                                    # real Edge browser, full flow, saves docs/screenshots
python tools\make_test_report.py                             # regenerates integration-docs-lead/test-report.md
```

## Retrain the model (needs the folder with the 216 pcaps)
```powershell
cd ml-engineer
python batch_extract.py --pcap-dir "D:\path\to\pcaps"        # -> features_windowed.csv
python train_model.py                                        # -> models/, metrics.json, confusion_matrix.png
python shortcut_check.py --pcap-dir "D:\path\to\pcaps"       # -> shortcut_check.json
cd ..\backend-developer; python make_sample_responses.py     # refresh the frontend's bundled samples
```

## Regenerate the testbed dataset (needs Docker Desktop RUNNING)
```powershell
cd docker\strongswan; docker compose up -d --build; cd ..\..
python docker\strongswan\scripts\generate_configs.py         # only if the template changed
python traffic-engineer\scripts\orchestrate.py --combo aes128-dh14-tunnel-pfs-on    # test ONE config first
docker exec peer-a ipsec statusall                           # child SA should list the DH group for pfs-on
python traffic-engineer\scripts\orchestrate.py --all         # ~40 min per 15 configs
```

## Regenerate documents and assets
```powershell
python tools\make_diagram.py            # docs/architecture.png
python tools\make_sample_reports.py     # docs/sample_reports/ from a real capture
python tools\make_deck.py               # docs/IPsec_VPN_Analyzer_Deck.pptx
python tests\make_fixtures.py           # SYNTHETIC IKE fixtures
python tools\make_data_samples.py --pcap-dir "D:\path\to\pcaps"
```

## Regenerate the newer models and their numbers (needs the raw pcaps; no Docker)
```powershell
cd ml-engineer
python train_esp_fingerprint.py      # -> models/esp_mode_classifier.pkl, esp_fingerprint_metrics.json
python train_open_set.py             # -> models/open_set.pkl, open_set_metrics.json
python evaluate_defences.py          # -> defence_metrics.json
cd ..; python tools\accuracy_addendum.py    # -> ACCURACY_ADDENDUM.md (formats the JSON files)
python tests\make_esp_fixtures.py; python tests\make_ipv6_ah_fixtures.py   # SYNTHETIC fixtures
python tools\make_test_report.py     # integration-docs-lead/test-report.md from a real pytest run
```

## Push (only you do this)
```powershell
git push -u origin innovations
```
