from fastapi import APIRouter
from app.api.v1 import (
    auth,
    benchmarks,
    contact,
    drift,
    evidence,
    m365_connections,
    manual_evidence,
    manual_verification,
    platforms,
    scans,
    settings,
    soc2,
    test,
)

api_router = APIRouter()

# Authentication routes
api_router.include_router(auth.router)

# Test routes
api_router.include_router(test.router)

# Platform routes (list available platforms)
api_router.include_router(platforms.router)

# Cloud connection routes
api_router.include_router(m365_connections.router)

# Scan routes
api_router.include_router(scans.router)

# SOC 2 report projection (renders from each scan's pinned mapping)
api_router.include_router(soc2.router)

# Configuration drift (Phase 8). Reports only; no rating, result or score is affected.
api_router.include_router(drift.router)

# Benchmark discovery routes
api_router.include_router(benchmarks.router)

# Evidence routes
api_router.include_router(evidence.router)

# Contact routes
api_router.include_router(contact.router)

# User settings routes
api_router.include_router(settings.router)

# Manual verification routes
api_router.include_router(manual_verification.router)

# Manual / inherited evidence approval workflow (Phase 7)
api_router.include_router(manual_evidence.router)
