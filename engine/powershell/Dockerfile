ARG TARGETPLATFORM

# uv from a digest-pinned image. This previously piped a remote shell script
# from astral.sh into sh at build time: an unpinned installer, fetched over the
# network, executed as root, in the one image that runs against a customer
# tenant.
FROM ghcr.io/astral-sh/uv:0.8.22@sha256:9874eb7afe5ca16c363fe80b294fe700e460df29a55532bbfea234a0f12eddb1 AS uv

# Digest-pinned like every other base in this repository. This image is the one
# that authenticates to Exchange and Teams, so "whatever the tag pointed at that
# day" is the least acceptable answer here of anywhere.
FROM --platform=$TARGETPLATFORM mcr.microsoft.com/powershell:7.5-mariner-2.0@sha256:37b70c835b3ad0242e8b3602a770fc0de5fa347b7473c9bc5a6f5da600154c68

# Mariner's python3 is 3.9. tools/tests/test_powershell_service_python_floor.py
# holds the service's source to that floor; if this base changes, re-derive the
# floor from the new image rather than editing the constant.
# curl is for the healthcheck, which probes the service over TLS by hostname.
RUN tdnf install -y python3 curl && tdnf clean all

COPY --from=uv /uv /usr/local/bin/uv

# Install PowerShell modules at reviewed versions.
#
# ExchangeOnlineManagement and MicrosoftTeams were installed unpinned, so the
# image that authenticates to a customer tenant picked up whatever the gallery
# published that morning -- no review, no lockfile, no SBOM entry that meant
# anything twice. The versions below are the ones the six-service overlay smoke
# was verified against. Raise them deliberately.
RUN pwsh -NoProfile -Command " \
    Set-PSRepository PSGallery -InstallationPolicy Trusted; \
    Install-Module -Name ExchangeOnlineManagement -RequiredVersion 3.10.1 -Scope AllUsers -Force; \
    Install-Module -Name MicrosoftTeams -RequiredVersion 7.9.0 -Scope AllUsers -Force; \
    Install-Module -Name PnP.PowerShell -RequiredVersion 3.4.0 -Scope AllUsers -Force \
    "

ENV PNPPOWERSHELL_UPDATECHECK=Off

# Create non-root user early, before any COPYs
RUN tdnf install -y shadow-utils && tdnf clean all \
    && useradd --uid 1000 --create-home appuser

# Copy service code and install Python dependencies
COPY --chown=appuser:appuser service/ /app/
WORKDIR /app
RUN uv pip install --system -r pyproject.toml \
    && chown -R appuser:appuser /app

# Expose port
EXPOSE 8001

USER appuser

# Run FastAPI service
CMD ["python3", "-m", "uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8001"]
