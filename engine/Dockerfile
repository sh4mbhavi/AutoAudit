FROM openpolicyagent/opa:1.20.2@sha256:7b15f9d96345dfa639322ad97f65a0b38260f95efcdd7f5c24e284228708f06c AS opa

# Pinned by digest for the same reason as OPA: an unpinned `pip install uv`
# resolves a different installer on every build.
FROM ghcr.io/astral-sh/uv:0.8.22@sha256:9874eb7afe5ca16c363fe80b294fe700e460df29a55532bbfea234a0f12eddb1 AS uv

FROM python:3.11-slim

COPY --from=opa /opa /usr/local/bin/opa

ARG ENGINE_GIT_SHA
ENV ENGINE_GIT_SHA=${ENGINE_GIT_SHA}
RUN python -c 'import os,re; assert re.fullmatch("[0-9a-f]{40}", os.environ.get("ENGINE_GIT_SHA", "")), "Build requires --build-arg ENGINE_GIT_SHA=<full source commit>"'

WORKDIR /app

# Install system dependencies (for gevent and psycopg2)
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    libpq-dev \
    && rm -rf /var/lib/apt/lists/*

# Create non-root user early, before any COPYs
RUN adduser --disabled-password --gecos "" --uid 1000 appuser
RUN chown appuser:appuser /app

# uv comes from a digest-pinned image. `pip install uv` -- what backend-api
# still does -- resolves a different installer on every build, which is the same
# class of problem this block exists to fix one layer down.
COPY --chown=appuser:appuser --from=uv /uv /usr/local/bin/uv

# Install Python dependencies FROM THE LOCKFILE.
#
# This previously read `COPY pyproject.toml .` followed by `pip install .`, with
# no uv.lock in sight. engine/pyproject.toml declares only floating lower bounds
# (celery>=5.6.3, httpx>=0.26.0, cryptography>=48.0.0 ...), so every worker image
# resolved whatever was newest on PyPI that day -- while CI ran
# `uv sync --frozen` and Grype scanned the lockfile. The tests and the scan
# described one dependency set and the shipped image contained another, and an
# SBOM generated from the lockfile would have described neither.
#
# backend-api/Dockerfile already did this correctly; the engine did not.
COPY --chown=appuser:appuser pyproject.toml uv.lock ./
RUN uv sync --frozen --no-dev --no-install-project \
    && chown -R appuser:appuser /app/.venv
ENV PATH="/app/.venv/bin:$PATH"

# Copy application code
COPY --chown=appuser:appuser worker/ ./worker/
COPY --chown=appuser:appuser collectors/ ./collectors/
COPY --chown=appuser:appuser powershell/service/ ./powershell/service/
COPY --chown=appuser:appuser powershell/__init__.py ./powershell/__init__.py
COPY --chown=appuser:appuser policies/ ./policies/
# Versioned SOC 2 crosswalk mappings. Shipped so the worker computes the same
# mapping digest the API pinned, rather than trusting a value passed to it.
COPY --chown=appuser:appuser mappings/ ./mappings/
COPY --chown=appuser:appuser opa_client.py ./

# Set Python path to include /app
ENV PYTHONPATH=/app

# Copy entrypoint script and fix line endings
COPY --chown=appuser:appuser worker_entrypoint.sh .
RUN sed -i 's/\r$//' worker_entrypoint.sh && chmod +x worker_entrypoint.sh

USER appuser

CMD ["./worker_entrypoint.sh"]
