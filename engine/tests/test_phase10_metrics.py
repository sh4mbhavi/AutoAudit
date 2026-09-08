"""The database-derived exporter, against a real PostgreSQL database.

These gauges exist to be alerted on, so the thing worth testing is not that a
Gauge object can be set -- it is that the numbers match the rows, and that the
timestamp arithmetic survives a server that is not on UTC.

That last one is the point of this module. ``scan.last_progress_at``,
``scan.deadline_at`` and ``scan_dispatch.available_at`` are timezone-naive
columns holding UTC. Phase 7 documented what happens when such a column is
compared against a bare ``now()`` on a non-UTC server: every scan is judged past
its deadline immediately. A staleness gauge built the same careless way would
report every live scan as stale from the moment it started and page an operator
continuously. Phase 6 hit exactly this on the dispatcher's deadline SQL; the fix
there was ``(now() AT TIME ZONE 'UTC')`` and it is the fix here. So the
arithmetic is asserted under explicitly shifted session timezones, where a naive
comparison is off by the whole UTC offset.

This runs in the engine environment on purpose: the dispatcher reads the
database synchronously through psycopg2, and a metrics path exercised through a
different driver than the one it runs on is not the path being tested.
"""

from __future__ import annotations

import os
import subprocess  # nosec B404 # controlled Alembic subprocess against a disposable database
from pathlib import Path
from uuid import uuid4

import pytest
from cryptography.fernet import Fernet
from sqlalchemy import create_engine, text
from sqlalchemy.orm import Session

from worker import metrics

BACKEND = Path(__file__).resolve().parents[2] / "backend-api"


@pytest.fixture
def database_url():
    """A disposable database migrated to head by the backend's own Alembic."""
    admin_url = os.environ.get("MIGRATION_TEST_ADMIN_URL")
    if not admin_url:
        pytest.skip("Set MIGRATION_TEST_ADMIN_URL for disposable PostgreSQL tests")
    if "@127.0.0.1:" not in admin_url:
        pytest.fail("Only loopback test databases are allowed")
    admin = create_engine(admin_url, isolation_level="AUTOCOMMIT")
    name = "autoaudit_metrics_test_" + uuid4().hex
    with admin.connect() as connection:
        connection.execute(text(f'CREATE DATABASE "{name}"'))
    url = admin_url.rsplit("/", 1)[0] + "/" + name
    try:
        _alembic(url)
        yield url
    finally:
        with admin.connect() as connection:
            connection.execute(text(f'DROP DATABASE "{name}" WITH (FORCE)'))
        admin.dispose()


def _alembic(url: str) -> None:
    environment = {
        **os.environ,
        "APP_ENV": "dev",
        "DATABASE_URL": url.replace("postgresql://", "postgresql+asyncpg://", 1),
        "SECRET_KEY": uuid4().hex + uuid4().hex,
        "ENCRYPTION_KEY": Fernet.generate_key().decode(),
    }
    result = subprocess.run(  # nosec B603 # fixed uv/Alembic arguments
        ["uv", "run", "--project", str(BACKEND), "alembic", "upgrade", "head"],
        cwd=BACKEND,
        env=environment,
        text=True,
        capture_output=True,
        timeout=300,
        check=False,
    )
    assert result.returncode == 0, result.stdout + result.stderr


def _seed(url: str) -> None:
    """A user, a connection, and three scans in known states."""
    sql = f"""
        INSERT INTO "user" (id, role, email, hashed_password, is_active, is_superuser, is_verified)
        VALUES (700, 'user', 'metrics@example.invalid', 'synthetic-not-a-password', true, false, true);
        INSERT INTO m365_connection (id, user_id, name, tenant_id, client_id, encrypted_client_secret)
        VALUES (700, 700, 'metrics fixture', 'synthetic-tenant', 'synthetic-client', '');

        -- A running scan that last advanced 600 seconds ago.
        INSERT INTO scan (id, user_id, m365_connection_id, framework, benchmark, version,
                          status, last_progress_at, deadline_at)
        VALUES (701, 700, 700, 'CIS', 'M365', '6.0.0', 'running',
                (now() AT TIME ZONE 'UTC') - interval '600 seconds',
                (now() AT TIME ZONE 'UTC') + interval '3000 seconds');

        -- A pending scan that advanced 60 seconds ago and is already overdue.
        INSERT INTO scan (id, user_id, m365_connection_id, framework, benchmark, version,
                          status, last_progress_at, deadline_at)
        VALUES (702, 700, 700, 'CIS', 'M365', '6.0.0', 'pending',
                (now() AT TIME ZONE 'UTC') - interval '60 seconds',
                (now() AT TIME ZONE 'UTC') - interval '5 seconds');

        -- A finished scan: terminal, so it must not appear in the live gauges.
        INSERT INTO scan (id, user_id, m365_connection_id, framework, benchmark, version,
                          status, last_progress_at, finished_at)
        VALUES (703, 700, 700, 'CIS', 'M365', '6.0.0', 'completed',
                (now() AT TIME ZONE 'UTC') - interval '99999 seconds',
                (now() AT TIME ZONE 'UTC') - interval '30 seconds');

        INSERT INTO scan_result (id, scan_id, control_id, status, selected)
        VALUES (711, 703, '1.1.1', 'passed', true),
               (712, 703, '1.1.3', 'passed', true),
               (713, 703, '1.2.1', 'failed', true),
               (714, 703, '1.3.1', 'error', true),
               (715, 703, '2.1.1', 'passed', false);

        INSERT INTO scan_dispatch (id, scan_id, task_name, available_at, attempts)
        VALUES ('{uuid4()}', 701, 'worker.tasks.run_scan',
                (now() AT TIME ZONE 'UTC') - interval '120 seconds', 2),
               ('{uuid4()}', 701, 'worker.tasks.evaluate_collection',
                (now() AT TIME ZONE 'UTC') - interval '30 seconds', 0),
               ('{uuid4()}', 702, 'worker.tasks.evaluate_collection',
                (now() AT TIME ZONE 'UTC') + interval '300 seconds', 1);
    """
    engine = create_engine(url)
    try:
        with engine.begin() as connection:
            connection.execute(text(sql))
    finally:
        engine.dispose()


def _value(metric, **labels) -> float:
    return metric.labels(**labels)._value.get() if labels else metric._value.get()


def _collect(metrics_module, url: str, *, timezone: str = "UTC") -> None:
    engine = create_engine(url)
    try:
        with Session(engine) as session:
            session.execute(text(f"SET TIME ZONE '{timezone}'"))
            metrics_module.collect(session)
    finally:
        engine.dispose()


@pytest.fixture
def metrics_module():
    return metrics


def test_live_scan_states_count_only_non_terminal_scans(metrics_module, database_url):
    _seed(database_url)
    _collect(metrics_module, database_url)

    assert _value(metrics_module.scans_in_state, state="running") == 1
    assert _value(metrics_module.scans_in_state, state="pending") == 1
    # The completed scan is terminal; counting it would make the gauge grow with
    # history instead of describing the present.
    assert metrics_module.collector_exporter_up._value.get() == 1


def test_control_results_match_the_rows_and_exclude_unselected(
    metrics_module, database_url
):
    _seed(database_url)
    _collect(metrics_module, database_url)

    assert _value(metrics_module.control_results, status="passed") == 2
    assert _value(metrics_module.control_results, status="failed") == 1
    assert _value(metrics_module.control_results, status="error") == 1
    # Result 715 is selected=false: an unselected control is outside the assessed
    # population, exactly as Phase 3's scoring contract requires.


def test_dispatch_backlog_separates_due_from_deferred(metrics_module, database_url):
    _seed(database_url)
    _collect(metrics_module, database_url)

    assert _value(metrics_module.dispatch_backlog, state="due") == 2
    assert _value(metrics_module.dispatch_backlog, state="deferred") == 1
    assert _value(metrics_module.dispatch_attempts, attempts="0") == 1
    assert _value(metrics_module.dispatch_attempts, attempts="1") == 1
    assert _value(metrics_module.dispatch_attempts, attempts="2") == 1


def test_overdue_scans_are_counted(metrics_module, database_url):
    _seed(database_url)
    _collect(metrics_module, database_url)
    assert _value(metrics_module.scans_past_deadline) == 1


def test_oldest_progress_age_reads_the_stalest_live_scan(metrics_module, database_url):
    _seed(database_url)
    _collect(metrics_module, database_url)

    age = _value(metrics_module.scan_oldest_progress_age_seconds)
    # 600s from the running scan, not 99999s from the completed one.
    assert 595 <= age <= 660, age


@pytest.mark.parametrize("timezone", ["UTC", "Australia/Melbourne", "America/New_York"])
def test_staleness_is_computed_in_utc_whatever_the_server_timezone(
    metrics_module, database_url, timezone
):
    """The defect this test exists to prevent.

    ``last_progress_at`` is timezone-naive UTC. Compared against a bare ``now()``
    on an Australia/Melbourne server the age is wrong by ten or eleven hours, and
    the staleness gauge would report every live scan as stale from the moment it
    started. Phase 6 hit exactly this on the dispatcher's deadline SQL; the fix
    there was ``(now() AT TIME ZONE 'UTC')`` and it is the fix here.
    """
    _seed(database_url)
    _collect(metrics_module, database_url, timezone=timezone)

    age = _value(metrics_module.scan_oldest_progress_age_seconds)
    assert 595 <= age <= 660, (timezone, age)
    assert _value(metrics_module.scans_past_deadline) == 1
    assert _value(metrics_module.dispatch_backlog, state="due") == 2
    assert _value(metrics_module.dispatch_backlog, state="deferred") == 1


def test_a_failed_read_lowers_the_up_gauge_without_zeroing_the_others(
    metrics_module, database_url
):
    """A failed collection must not look like a drained queue.

    Zeroing every gauge on error is indistinguishable from "the backlog cleared
    and every scan finished", which is the opposite of what a failed read means.
    """
    _seed(database_url)
    _collect(metrics_module, database_url)
    before = _value(metrics_module.dispatch_backlog, state="due")

    class _Broken:
        def execute(self, *args, **kwargs):
            # A synthetic DSN-shaped message: the point of the test is that a
            # credential-bearing exception text is never logged or exposed.
            raise RuntimeError(
                "postgresql://user:secret@host/db is unreachable"  # pragma: allowlist secret
            )

    metrics_module.collect(_Broken())

    assert metrics_module.collector_exporter_up._value.get() == 0
    assert _value(metrics_module.dispatch_backlog, state="due") == before


def test_exposition_renders_the_series_and_no_credentials(metrics_module, database_url):
    _seed(database_url)
    _collect(metrics_module, database_url)
    body, content_type = metrics_module.exposition()
    text_body = body.decode()

    assert "text/plain" in content_type
    for name in (
        "autoaudit_scans_in_state",
        "autoaudit_control_results",
        "autoaudit_dispatch_backlog",
        "autoaudit_scan_oldest_progress_age_seconds",
        "autoaudit_collector_exporter_up",
    ):
        assert name in text_body, name
    # Exposition is unauthenticated by design; nothing tenant-identifying or
    # credential-shaped may appear in it.
    for forbidden in (
        "synthetic-tenant",
        "synthetic-client",
        "password",
        "postgresql://",
    ):
        assert forbidden not in text_body, forbidden


def test_last_completion_timestamp_is_reported_per_status(metrics_module, database_url):
    """An alert can ask 'has a scan finished recently' with this.

    The pre-Phase-10 rule used ``absent_over_time(compliance_scan_success[1h])``,
    which fires whenever nobody happened to scan in the last hour -- permanently,
    in any deployment where scans are user-initiated. A timestamp is answerable.
    """
    _seed(database_url)
    _collect(metrics_module, database_url)
    completed = _value(
        metrics_module.scan_last_completion_timestamp_seconds, status="completed"
    )
    assert completed > 0


# ---------------------------------------------------------------------------
# Defects found by the independent review pass, and their regressions.
# ---------------------------------------------------------------------------


def test_every_result_status_is_emitted_even_at_zero(metrics_module, database_url):
    """A status-labelled series must never blink out of existence.

    `GROUP BY status` returns no row for a status with no results, so a naive
    exporter drops the series when the count reaches zero. `delta()` over a
    series that has only just reappeared EXTRAPOLATES across the whole range
    window -- four errors three minutes into a thirty-minute window would be read
    as forty, and ControlErrorRateHigh would fire on a fifth of its threshold.
    """
    _seed(database_url)
    _collect(metrics_module, database_url)

    # Asserted against the EXPOSITION, not against .labels(): calling .labels()
    # creates the child, so `_value(...) >= 0` would be trivially true and would
    # pass even if _apply never emitted the status at all. What matters is what
    # a scrape sees.
    body = metrics_module.exposition()[0].decode()
    for status in metrics_module.RESULT_STATES:
        assert f'autoaudit_control_results{{status="{status}"}}' in body, status
    # The fixture has no indeterminate results; the series must be present AND
    # read zero rather than be absent.
    assert 'autoaudit_control_results{status="indeterminate"} 0.0' in body


def test_a_scan_with_a_null_deadline_still_counts_as_overdue(
    metrics_module, database_url
):
    """The metric must mirror the reconciler's own expiry rule, COALESCE included.

    The reconciler expires a scan on
    `COALESCE(deadline_at, last_progress_at + SCAN_DEADLINE_SECONDS)`. An earlier
    version of this gauge filtered on `deadline_at IS NOT NULL`, so a scan that
    the reconciler itself considers overdue reported zero -- a metric quieter
    than the behaviour it describes.
    """
    _seed(database_url)
    engine = create_engine(database_url)
    try:
        with engine.begin() as connection:
            connection.execute(
                text(
                    "INSERT INTO scan (id, user_id, m365_connection_id, framework,"
                    " benchmark, version, status, last_progress_at, deadline_at)"
                    " VALUES (704, 700, 700, 'CIS', 'M365', '6.0.0', 'running',"
                    " (now() AT TIME ZONE 'UTC') - interval '7200 seconds', NULL)"
                )
            )
    finally:
        engine.dispose()

    # SCAN_DEADLINE_SECONDS defaults to 3600, and this scan last advanced 7200
    # seconds ago, so the reconciler would fail it.
    _collect(metrics_module, database_url)
    assert _value(metrics_module.scans_past_deadline) == 2


def test_a_partial_collection_leaves_every_gauge_at_its_previous_value(
    metrics_module, database_url
):
    """Read-then-apply: a failure part way through must change nothing.

    The gauges are mutated in one pass after every value has been read. An
    earlier version wrote them as it went, so a failure on the fifth query left
    some gauges fresh, one cleared to nothing, and the rest stale -- while
    reporting up=0, which this module's contract says means "previous values".
    """
    _seed(database_url)
    _collect(metrics_module, database_url)
    before = {
        "due": _value(metrics_module.dispatch_backlog, state="due"),
        "passed": _value(metrics_module.control_results, status="passed"),
        "running": _value(metrics_module.scans_in_state, state="running"),
    }

    calls = {"n": 0}

    class _FailsPartWay:
        """Answers the first query, then fails -- the dangerous shape."""

        def execute(self, *args, **kwargs):
            calls["n"] += 1
            if calls["n"] > 1:
                raise RuntimeError(
                    "postgresql://user:secret@host/db went away"  # pragma: allowlist secret
                )

            class _Result:
                def mappings(self_inner):
                    return self_inner

                def all(self_inner):
                    return [{"status": "running", "count": 999}]

            return _Result()

    metrics_module.collect(_FailsPartWay(), deadline_seconds=3600)

    assert metrics_module.collector_exporter_up._value.get() == 0
    # Not 999: the first query's result must not have been applied either.
    assert _value(metrics_module.scans_in_state, state="running") == before["running"]
    assert _value(metrics_module.dispatch_backlog, state="due") == before["due"]
    assert _value(metrics_module.control_results, status="passed") == before["passed"]
