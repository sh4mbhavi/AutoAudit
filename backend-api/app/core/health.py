"""Readiness checks: whether this replica can serve, not whether it is running.

Before Phase 10 the only health surface was ``/liveness``, which returns a
hardcoded ``{"status": "healthy"}`` and touches nothing. A container whose
database was unreachable reported healthy and kept receiving traffic; scans
accepted in that state sat in the outbox with no operator signal at all.

The split matters and is deliberate:

``/liveness``
    "the process is running". Must never check a dependency -- a liveness probe
    that fails on a database blip restarts a healthy container and turns an
    outage into a crash loop.

``/readiness``
    "this replica can serve". Checks the dependencies a request actually needs.
    A failure removes the replica from rotation without killing it.

Each check is bounded by its own timeout, so a hung dependency makes readiness
report *not ready* rather than making the probe itself hang -- a probe that never
answers is indistinguishable from a probe that never ran.
"""

from __future__ import annotations

import asyncio
import logging

from sqlalchemy import text

from app.core.config import get_settings
from app.db.base import engine

logger = logging.getLogger("api")

# Deliberately short. A readiness probe runs on the orchestrator's interval; a
# check slower than the interval queues probes behind each other.
CHECK_TIMEOUT_SECONDS = 3.0


async def _database() -> tuple[bool, str]:
    async with engine.connect() as connection:
        await connection.execute(text("SELECT 1"))
    return True, "ok"


async def _broker() -> tuple[bool, str]:
    """Reachability of the Celery broker.

    The API does not publish to the broker directly -- Phase 6 made the outbox
    the only authorisation to publish -- but a scan accepted while Redis is down
    cannot be dispatched, so an API that cannot see the broker is not ready to
    accept one.
    """
    settings = get_settings()
    # Imported lazily: kombu is a celery transitive dependency and this keeps
    # the module importable in environments that do not install it.
    from kombu import Connection

    def _probe() -> None:
        with Connection(
            settings.REDIS_URL, connect_timeout=CHECK_TIMEOUT_SECONDS
        ) as connection:
            connection.ensure_connection(max_retries=0, timeout=CHECK_TIMEOUT_SECONDS)

    await asyncio.to_thread(_probe)
    return True, "ok"


CHECKS = {"database": _database, "broker": _broker}


async def readiness_report() -> tuple[dict[str, dict], bool]:
    """Run every check concurrently and report each one's outcome.

    Returns (checks, healthy). A check's failure message is the exception type,
    never its text: a connection error's message routinely carries the DSN, and
    ``/readiness`` is unauthenticated.
    """

    async def _run(name, check):
        try:
            async with asyncio.timeout(CHECK_TIMEOUT_SECONDS):
                ok, detail = await check()
            return name, {"ok": ok, "detail": detail}
        except TimeoutError:
            return name, {"ok": False, "detail": "timeout"}
        except Exception as exc:  # pylint: disable=broad-exception-caught
            logger.warning({"readiness_check": name, "error": type(exc).__name__})
            return name, {"ok": False, "detail": type(exc).__name__}

    results = await asyncio.gather(
        *(_run(name, check) for name, check in CHECKS.items())
    )
    checks = dict(results)
    return checks, all(entry["ok"] for entry in checks.values())
