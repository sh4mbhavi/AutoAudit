"""Prometheus metrics for the API.

Every alert rule in ``infrastructure/monitoring/alerts/`` referenced a metric
that nothing in this repository produced. This module is the API's half of
closing that: the request-level series an HTTP service can honestly report.

**Naming.** Every series is prefixed ``autoaudit_``. The pre-Phase-10 rules
named bare metrics (``api_errors_total``) that could collide with anything else
in a shared Prometheus; the rules were rewritten onto these names rather than
these names bent to match the rules.

**Cardinality.** The path label is the *route template*
(``/v1/scans/{scan_id}``), never the requested path. A label taken from a URL a
caller controls is an unbounded label, and an unbounded label is how a metrics
endpoint becomes a denial-of-service surface. A request that matches no route
is reported once, as ``__unmatched__``.

**What is deliberately not here.** Nothing about scan outcomes, control
statuses or evidence lives in this module. Those are derived from the database
by the dispatcher exporter (``engine/worker/metrics.py``), so the numbers an
operator alerts on and the numbers an auditor reads come from the same rows. An
in-process counter would drift from the audit record on every restart.
"""

from __future__ import annotations

from prometheus_client import CollectorRegistry, Counter, Histogram, multiprocess

# A registry of this module's own, rather than the global default: the default
# registry also carries process and GC collectors that the default
# ``prometheus_client`` import installs, and a test that asserts on exposition
# output should not have to filter those out.
REGISTRY = CollectorRegistry()

UNMATCHED_ROUTE = "__unmatched__"
# CSRF rejects before the router runs, so no route template exists for these.
# A dedicated bucket rather than __unmatched__: a 403 storm is a specific,
# actionable signal (a broken client build, or a stale FRONTEND_URL) and
# folding it in with genuine 404s would hide it.
CSRF_REJECTED_ROUTE = "__csrf_rejected__"

api_requests_total = Counter(
    "autoaudit_api_requests_total",
    "HTTP requests handled by the API.",
    ["method", "route", "status"],
    registry=REGISTRY,
)

api_errors_total = Counter(
    "autoaudit_api_errors_total",
    "HTTP requests that returned an error status.",
    # `class` distinguishes a caller's mistake (4xx) from ours (5xx). Alerting
    # on the two together is what makes an error-rate alert unactionable.
    ["method", "route", "status", "class"],
    registry=REGISTRY,
)

api_request_duration_seconds = Histogram(
    "autoaudit_api_request_duration_seconds",
    "Wall time spent handling a request, in seconds.",
    ["method", "route"],
    # Tuned for this API: the conditional scan poll answers 304 in single-digit
    # milliseconds, while an evidence upload is bounded at
    # EVIDENCE_PROCESSING_TIMEOUT_SECONDS (default 120).
    buckets=(
        0.005,
        0.01,
        0.025,
        0.05,
        0.1,
        0.25,
        0.5,
        1.0,
        2.5,
        5.0,
        10.0,
        30.0,
        120.0,
    ),
    registry=REGISTRY,
)

# Deliberately absent: an authentication-failure counter and a
# privilege-escalation counter.
#
# Failed authentication is already fully described by
# ``autoaudit_api_errors_total{route="/v1/auth/...", status="400"}`` -- a
# separate counter would be a second, driftable name for the same requests, and
# would mean new code in the path Phase 5 hardened.
#
# Privilege escalation has no honest application signal at all: no API route
# writes ``user.role``. Roles are set by the (production-prohibited) development
# seed or out of band against the database, so the application cannot observe a
# change it never performs. The pre-Phase-10 ``SuspiciousPrivilegeEscalation``
# rule is retired for that reason rather than fed an invented series.

decryption_failures_total = Counter(
    "autoaudit_decryption_failures_total",
    "Stored ciphertext no key in the ring could read.",
    # The column, never the row, the tenant or any key material.
    ["column"],
    registry=REGISTRY,
)

# Every column that can produce this failure, initialised to zero at import.
#
# A labelled counter has no series until its first .inc(), and `increase()` over
# a window in which a series first appears cannot see the rise from nothing --
# so StoredCredentialUnreadable, which is the alert for a botched key rotation,
# could not fire on the *first* failure. That is precisely the one that matters:
# the first unreadable credential is the signal that a retired key was dropped
# too early. Found by the review pass.
DECRYPTABLE_COLUMNS = ("m365_connection.encrypted_client_secret",)
for _column in DECRYPTABLE_COLUMNS:
    decryption_failures_total.labels(column=_column)


def route_label(request) -> str:
    """The matched route template, or a single bucket for unmatched requests.

    Starlette records the matched ``APIRoute`` on the scope, so this is the
    template the router chose, not anything the caller supplied.
    """
    route = request.scope.get("route")
    path = getattr(route, "path_format", None) or getattr(route, "path", None)
    return path if isinstance(path, str) and path else UNMATCHED_ROUTE


def observe_request(*, method: str, route: str, status: int, duration: float) -> None:
    """Record one completed request."""
    status_label = str(status)
    api_requests_total.labels(method=method, route=route, status=status_label).inc()
    api_request_duration_seconds.labels(method=method, route=route).observe(duration)
    if status >= 400:
        api_errors_total.labels(
            method=method,
            route=route,
            status=status_label,
            **{"class": f"{status // 100}xx"},
        ).inc()


def exposition() -> tuple[bytes, str]:
    """Render the current metrics, as (body, content type).

    Under ``PROMETHEUS_MULTIPROC_DIR`` the per-process files are collected
    instead, so a multi-worker deployment reports the whole container rather
    than whichever worker happened to answer the scrape.
    """
    # Imported here so the module has no import-time dependency on the env var.
    import os

    from prometheus_client import CONTENT_TYPE_LATEST, generate_latest

    if os.environ.get("PROMETHEUS_MULTIPROC_DIR"):
        registry = CollectorRegistry()
        multiprocess.MultiProcessCollector(registry)
    else:
        registry = REGISTRY
    return generate_latest(registry), CONTENT_TYPE_LATEST
