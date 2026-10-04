FROM python:3.12-slim

WORKDIR /app
COPY ingest/requirements.txt ingest/requirements.txt
RUN pip install --no-cache-dir -r ingest/requirements.txt
COPY ingest/ ingest/

RUN useradd --create-home --uid 10001 siem
USER siem

EXPOSE 8000
CMD ["uvicorn", "ingest.app:app", "--host", "0.0.0.0", "--port", "8000"]
