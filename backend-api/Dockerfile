# Backend API Dockerfile

# uv comes from a digest-pinned image rather than `pip install uv`, which
# resolved a different installer on every build. engine/Dockerfile already did
# this; this one still did not.
FROM ghcr.io/astral-sh/uv:0.8.22@sha256:9874eb7afe5ca16c363fe80b294fe700e460df29a55532bbfea234a0f12eddb1 AS uv

# Digest-pinned: `python:3.11-slim` is a moving tag, so two builds of the same
# commit produced two different base layers and the SBOM described whichever one
# happened to be current.
FROM python:3.11-slim@sha256:9534e5a8e315485d4061ed659af0fd78a284c015f9b73661b41d6bab25604534

WORKDIR /app

# Install system dependencies (incl. Tesseract for evidence OCR)
RUN apt-get update && apt-get install -y --no-install-recommends \
    curl \
    tesseract-ocr \
    libtesseract-dev \
    && rm -rf /var/lib/apt/lists/*

# Create non-root user early, before any COPYs
RUN adduser --disabled-password --gecos "" --uid 1000 appuser
RUN chown appuser:appuser /app

# Install uv from the digest-pinned image copied in above.
COPY --chown=appuser:appuser --from=uv /uv /usr/local/bin/uv

# Copy dependency files and install dependencies
COPY --chown=appuser:appuser backend-api/pyproject.toml backend-api/uv.lock ./
RUN uv sync --frozen --no-dev --extra evidence \
    && chown -R appuser:appuser /app/.venv

# Copy application code
COPY --chown=appuser:appuser backend-api/app ./app
COPY --chown=appuser:appuser backend-api/alembic ./alembic
COPY --chown=appuser:appuser backend-api/alembic.ini backend-api/entrypoint.sh ./

# Copy evidence scanner assets/logic
COPY --chown=appuser:appuser security ./security

# Evidence object store. Created in the image and owned by the runtime user so a
# fresh named volume mounted here inherits that ownership; without this the mount
# lands root-owned and every upload fails as the non-root user.
RUN install -d -o appuser -g appuser -m 0700 /app/evidence-store

# Make entrypoint executable
RUN chmod +x entrypoint.sh

# Expose port
EXPOSE 8000

USER appuser

# Run migrations and start the application
ENTRYPOINT ["./entrypoint.sh"]
