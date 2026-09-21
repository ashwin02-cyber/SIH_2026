# API image. Build from the REPO ROOT (the API needs ml-engineer/, reports/ and data/ too):
#   docker build -f backend-developer/Dockerfile -t ipsec-analyzer-api .
FROM python:3.12-slim

ENV PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    MPLBACKEND=Agg \
    MPLCONFIGDIR=/tmp/matplotlib

WORKDIR /app

COPY requirements-backend.txt .
RUN pip install -r requirements-backend.txt

COPY backend-developer/*.py backend-developer/
COPY ml-engineer/traffic_features.py ml-engineer/predict.py ml-engineer/metrics.json ml-engineer/
COPY ml-engineer/models ml-engineer/models
COPY reports reports
COPY data/samples data/samples

RUN useradd --create-home appuser
USER appuser

WORKDIR /app/backend-developer
EXPOSE 8000

# Render/Railway inject $PORT; locally it defaults to 8000.
CMD ["sh", "-c", "uvicorn main:app --host 0.0.0.0 --port ${PORT:-8000}"]
