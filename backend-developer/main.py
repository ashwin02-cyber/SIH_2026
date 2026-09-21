"""
main.py
FastAPI app for the IPsec VPN Analyzer backend.

    POST /analyze  - upload a .pcap/.pcapng, get back combined IKE facts +
                     risk score + ML traffic classification
    GET  /health   - liveness check for Docker Compose / the frontend

Run locally:
    uvicorn main:app --reload --port 8000
Then open http://127.0.0.1:8000/docs for the interactive Swagger UI to
test uploads (drag in a pcap from real_captures/) before wiring up the
frontend.
"""

import os
import sys
import tempfile
import traceback

from fastapi import FastAPI, UploadFile, File, HTTPException
from fastapi.middleware.cors import CORSMiddleware

from ike_parser import parse_ike_handshake
from scoring_engine import score_ike_facts

# --- wire up the ML Engineer's predict_from_pcap() --------------------------
# Adjust ML_ENGINEER_DIR if the final repo layout differs. This assumes:
#   SIH_2026/
#     ml-engineer/predict.py, models/
#     backend-developer/main.py   <- this file
ML_ENGINEER_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "ml-engineer")
sys.path.insert(0, ML_ENGINEER_DIR)

try:
    from predict import predict_from_pcap
    ML_MODEL_LOADED = True
    _ml_import_error = None
except Exception as e:
    # A missing model file shouldn't crash the whole API at import time —
    # /analyze reports a clear error per-request instead, and /health
    # still works so Docker Compose / the frontend can tell what's wrong.
    ML_MODEL_LOADED = False
    _ml_import_error = str(e)


app = FastAPI(title="IPsec VPN Analyzer API", version="0.1.0")

# Lets the frontend (different port in dev, a Vercel/Netlify origin once
# deployed) call this API. Tighten allow_origins once you know the
# deployed frontend's exact URL.
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.get("/health")
def health():
    return {"status": "ok", "ml_model_loaded": ML_MODEL_LOADED,"ml_import_error": _ml_import_error,}


@app.post("/analyze")
async def analyze(file: UploadFile = File(...)):
    if not file.filename.lower().endswith((".pcap", ".pcapng")):
        raise HTTPException(status_code=400, detail="Please upload a .pcap or .pcapng file")

    # Both the IKE parser and the ML predictor expect a real file path, not
    # an in-memory stream, so save the upload to a temp file first.
    suffix = os.path.splitext(file.filename)[1]
    with tempfile.NamedTemporaryFile(delete=False, suffix=suffix) as tmp:
        tmp.write(await file.read())
        tmp_path = tmp.name

    try:
        result = {"filename": file.filename}

        # --- IKE side: deterministic parsing + rule-based scoring ---
        try:
            ike_facts = parse_ike_handshake(tmp_path)
            result["ike_facts"] = ike_facts
            result["risk_assessment"] = score_ike_facts(ike_facts)
        except Exception as e:
            result["ike_facts"] = None
            result["risk_assessment"] = None
            result["ike_error"] = f"IKE parsing failed: {e}"

        # --- ESP side: ML traffic classification ---
        if ML_MODEL_LOADED:
            try:
                result["traffic_classification"] = predict_from_pcap(tmp_path)
            except Exception as e:
                result["traffic_classification"] = None
                result["ml_error"] = f"Traffic classification failed: {e}"
        else:
            result["traffic_classification"] = None
            result["ml_error"] = f"ML model not loaded: {_ml_import_error}"

        return result

    except Exception:
        # Catch-all so a malformed pcap returns a clean 500 with a
        # traceback in the server logs, not a silent crash.
        traceback.print_exc()
        raise HTTPException(status_code=500, detail="Analysis failed — check server logs for details")

    finally:
        os.remove(tmp_path)