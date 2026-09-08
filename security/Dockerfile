# Evidence Assistant CLI image — NOT a network service.
#
# This image used to run `uvicorn evidence_ui.app:app`, a FastAPI application
# with no authentication on any of its routes (SOC 2 finding AUTH-02). That
# service has been retired:
#
#   * the standalone app is no longer constructed at import time and is built
#     only by `security.evidence_ui.app:create_app()`, which refuses to run
#     unless AUTOAUDIT_EVIDENCE_UI_DEV_SERVER is set on a non-production host;
#   * evidence scanning in a deployed environment is served by the
#     authenticated backend router at /v1/evidence (see backend-api/);
#   * the old CMD could not have worked anyway — the build context is
#     `security/`, so the `security.*` package imports in evidence_ui/app.py
#     were unresolvable inside this image.
#
# What remains is a reproducible OCR toolchain for the offline CLI. It listens
# on no port and must not be given one. Build and run it as an interactive tool:
#
#   docker build -t autoaudit-evidence-cli security/
#   docker run --rm -it -v "$PWD/security/evidence:/app/evidence" \
#       autoaudit-evidence-cli

FROM python:3.11-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

WORKDIR /app

# System packages needed for OCR (Tesseract). Keep the image small by avoiding
# optional PDF converters (LibreOffice) — the CLI falls back gracefully.
RUN apt-get update && \
    DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
      tesseract-ocr \
      libtesseract-dev && \
    rm -rf /var/lib/apt/lists/*

# Create non-root user early, before any COPYs
RUN adduser --disabled-password --gecos "" --uid 1000 appuser
RUN chown appuser:appuser /app

# Python dependencies
COPY --chown=appuser:appuser requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Application code
COPY --chown=appuser:appuser . .

USER appuser

# Deliberately no EXPOSE and no server process: this image runs the offline CLI.
CMD ["python", "evidenceassistant.py"]
