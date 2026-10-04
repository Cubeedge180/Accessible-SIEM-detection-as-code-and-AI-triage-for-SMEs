"""Ingestion API. Placeholder: only exposes a health check for now."""

from fastapi import FastAPI

app = FastAPI(title="SIEM ingest", version="0.0.1")


@app.get("/health")
def health() -> dict[str, str]:
    return {"status": "ok"}
