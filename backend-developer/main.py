"""
main.py
FastAPI app for the IPsec VPN Analyzer backend.

    POST /analyze                 upload a .pcap/.pcapng -> the contract response (see contract.py)
    GET  /samples                 list the bundled sample captures
    POST /analyze/sample/{name}   analyze one of the bundled samples (handy for demos)
    POST /replay                  upload a pcap -> a progressive REPLAY stream (NDJSON), one event per second of capture time
    POST /replay/sample/{name}    the same for a bundled sample
    POST /report/{kind}.{fmt}     render a report from an analysis (see reports/) - kind: executive|technical,
                                  fmt: html|pdf
    GET  /health                  liveness + model status

Run locally (from backend-developer/):
    uvicorn main:app --reload --port 8000
then open http://127.0.0.1:8000/docs for the interactive Swagger UI.

Environment variables (all optional):
    ALLOWED_ORIGINS   comma-separated CORS origins, default "*"  (set to your Vercel/Netlify URL when deployed)
    ALLOWED_ORIGIN_REGEX  regex for origins not known in advance (VS Code port forwarding: https://.*[.]devtunnels[.]ms)
    MAX_UPLOAD_MB     upload size limit, default 50
    SIH_SAMPLES_DIR   folder with sample pcaps, default <repo>/data/samples
"""

import json
import os
import sys
import tempfile
import traceback

from fastapi import Body, FastAPI, File, HTTPException, UploadFile
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import Response, StreamingResponse

HERE = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.abspath(os.path.join(HERE, ".."))
for sub in ("ml-engineer", "reports"):
    sys.path.insert(0, os.path.join(REPO, sub))
sys.path.insert(0, HERE)

from contract import SCHEMA_VERSION, build_response  # noqa: E402
from ike_parser import parse_ike_handshake  # noqa: E402

# --- the ML Engineer's predict_from_pcap() ----------------------------------
try:
    import traffic_features as tf
    from defence_capture import simulate_packets
    from esp_analysis import analyze_packets
    from replay_stream import REPLAY_LABEL, replay_events
    from predict import predict_from_pcap
    ML_MODEL_LOADED = True
    _ml_import_error = None
except Exception as e:  # a missing model file must not stop the API from starting
    ML_MODEL_LOADED = False
    _ml_import_error = str(e)

SAMPLES_DIR = os.environ.get("SIH_SAMPLES_DIR") or os.path.join(REPO, "data", "samples")
MAX_UPLOAD_BYTES = int(float(os.environ.get("MAX_UPLOAD_MB", "50")) * 1024 * 1024)
ALLOWED_EXT = (".pcap", ".pcapng")

app = FastAPI(title="IPsec VPN Analyzer API", version="1.0.0")


def cors_settings(environ):
    """CORS options from the environment.
    ALLOWED_ORIGINS       comma-separated exact origins (default "*" = any)
    ALLOWED_ORIGIN_REGEX  optional regular expression for origins whose name is not known in advance, e.g.
                          VS Code port forwarding:  https://.*[.]devtunnels[.]ms
    """
    origins = [o.strip() for o in environ.get("ALLOWED_ORIGINS", "*").split(",") if o.strip()]
    return {"allow_origins": origins, "allow_origin_regex": environ.get("ALLOWED_ORIGIN_REGEX") or None,
            "allow_methods": ["*"], "allow_headers": ["*"]}


app.add_middleware(CORSMiddleware, **cors_settings(os.environ))


@app.get("/health")
def health():
    return {"status": "ok", "schema_version": SCHEMA_VERSION, "ml_model_loaded": ML_MODEL_LOADED,
            "ml_import_error": _ml_import_error, "max_upload_mb": MAX_UPLOAD_BYTES // (1024 * 1024)}


def analyze_path(path: str, display_name: str) -> dict:
    """Run both analyzers on a file on disk and build the contract response.
    Raises ValueError only if the file is not a readable capture at all."""
    errors, not_a_capture = [], 0

    ike_facts = None
    try:
        ike_facts = parse_ike_handshake(path)
    except ValueError as e:
        not_a_capture += 1
        errors.append(f"IKE parsing: {e}")
    except Exception as e:
        traceback.print_exc()
        errors.append(f"IKE parsing failed: {e}")

    ml_result = None
    if ML_MODEL_LOADED:
        try:
            ml_result = predict_from_pcap(path)
        except ValueError as e:
            not_a_capture += 1
            errors.append(f"Traffic classification: {e}")
        except Exception as e:
            traceback.print_exc()
            errors.append(f"Traffic classification failed: {e}")
    else:
        errors.append(f"ML model not loaded: {_ml_import_error}")

    # Passive ESP fingerprint + SPI/sequence analysis: from packet headers and sizes only - the file name is never used.
    esp_fp, extras = None, {}
    if ML_MODEL_LOADED:
        try:
            packets, esp_only, _ = tf.read_packets(path)          # the capture is read once for both analyses below
            esp_fp = analyze_packets(packets, esp_only)
            if esp_only:
                extras["defence_simulation"] = simulate_packets(packets)   # SIMULATION: what-if padding / dummy traffic / delay
        except ValueError:
            pass  # not a capture: already reported above
        except Exception as e:
            traceback.print_exc()
            errors.append(f"ESP analysis failed: {e}")

    if not_a_capture >= (2 if ML_MODEL_LOADED else 1):
        raise ValueError(errors[0])
    return build_response(display_name, ike_facts, ml_result, errors=errors, esp=esp_fp, extras=extras)


async def _store_upload(file: UploadFile):
    """Stream an upload to a temp file (with a size cap). Returns (display_name, temp_path)."""
    name = os.path.basename(file.filename or "")
    if not name.lower().endswith(ALLOWED_EXT):
        raise HTTPException(status_code=400, detail="Please upload a .pcap or .pcapng file")

    # The analyzers need a real file path, so stream the upload to a temp file (with a size cap).
    suffix = os.path.splitext(name)[1]
    size = 0
    with tempfile.NamedTemporaryFile(delete=False, suffix=suffix) as tmp:
        tmp_path = tmp.name
        while chunk := await file.read(1024 * 1024):
            size += len(chunk)
            if size > MAX_UPLOAD_BYTES:
                tmp.close()
                os.remove(tmp_path)
                raise HTTPException(status_code=413,
                                    detail=f"File too large (limit {MAX_UPLOAD_BYTES // (1024 * 1024)} MB)")
            tmp.write(chunk)
    if size == 0:
        os.remove(tmp_path)
        raise HTTPException(status_code=400, detail="The uploaded file is empty")
    return name, tmp_path


@app.post("/analyze")
async def analyze(file: UploadFile = File(...)):
    name, tmp_path = await _store_upload(file)
    try:
        return analyze_path(tmp_path, name)
    except ValueError as e:
        raise HTTPException(status_code=400, detail=f"Not a valid capture file: {e}")
    except Exception:
        traceback.print_exc()
        raise HTTPException(status_code=500, detail="Analysis failed - check server logs for details")
    finally:
        if os.path.exists(tmp_path):
            os.remove(tmp_path)


def _replay_response(path, name, pace, cleanup):
    """NDJSON stream: 'start', one 'window' per second of capture time, 'end', then 'final' with the full analysis."""
    if not ML_MODEL_LOADED:
        cleanup()
        raise HTTPException(status_code=503, detail=f"Replay needs the ML model: {_ml_import_error}")
    try:
        packets, esp_only, _ = tf.read_packets(path)          # raises ValueError for a file that is not a capture
    except ValueError as e:
        cleanup()
        raise HTTPException(status_code=400, detail=f"Not a valid capture file: {e}")

    def lines():
        try:
            for ev in replay_events(packets, esp_only, name, pace):
                yield json.dumps(ev) + "\n"
            yield json.dumps({"type": "final", "analysis": analyze_path(path, name)}) + "\n"
        except Exception as e:  # the stream has started, so report the failure as an event
            traceback.print_exc()
            yield json.dumps({"type": "error", "detail": f"Replay failed: {e}"}) + "\n"
        finally:
            cleanup()

    return StreamingResponse(lines(), media_type="application/x-ndjson",
                             headers={"Cache-Control": "no-store", "X-Accel-Buffering": "no"})


@app.post("/replay")
async def replay(file: UploadFile = File(...), pace: float = 0.15):
    """REPLAY (not live sniffing): stream the analysis of an uploaded capture progressively. `pace` = seconds between windows (0-2)."""
    name, tmp_path = await _store_upload(file)
    return _replay_response(tmp_path, name, pace, lambda: os.path.exists(tmp_path) and os.remove(tmp_path))


def _sample_names():
    if not os.path.isdir(SAMPLES_DIR):
        return []
    return sorted(f for f in os.listdir(SAMPLES_DIR) if f.lower().endswith(ALLOWED_EXT))


@app.get("/samples")
def samples():
    return {"samples": _sample_names()}


@app.post("/analyze/sample/{name}")
def analyze_sample(name: str):
    if name not in _sample_names():  # whitelist: no path traversal
        raise HTTPException(status_code=404, detail="Unknown sample")
    try:
        return analyze_path(os.path.join(SAMPLES_DIR, name), name)
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))


@app.post("/replay/sample/{name}")
def replay_sample(name: str, pace: float = 0.15):
    if name not in _sample_names():  # whitelist: no path traversal
        raise HTTPException(status_code=404, detail="Unknown sample")
    return _replay_response(os.path.join(SAMPLES_DIR, name), name, pace, lambda: None)


@app.post("/report/{kind}.{fmt}")
def report(kind: str, fmt: str, analysis: dict = Body(...)):
    """Render an executive or technical report from an analysis response (as returned by /analyze)."""
    if kind not in ("executive", "technical") or fmt not in ("html", "pdf"):
        raise HTTPException(status_code=404, detail="Use /report/{executive|technical}.{html|pdf}")
    from contract import validate_response
    problems = validate_response(analysis)
    if problems:
        raise HTTPException(status_code=422, detail=f"Not a valid analysis: {problems[:3]}")
    try:
        from report_builder import render_report
        data, media = render_report(analysis, kind, fmt)
    except Exception:
        traceback.print_exc()
        raise HTTPException(status_code=500, detail="Report generation failed - check server logs")
    base = os.path.splitext(analysis["filename"])[0] or "analysis"
    return Response(content=data, media_type=media,
                    headers={"Content-Disposition": f'attachment; filename="{base}-{kind}.{fmt}"'})
