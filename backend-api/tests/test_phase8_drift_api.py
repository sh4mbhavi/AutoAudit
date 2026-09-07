"""Phase 8 configuration drift API (plan item 16.2).

Two halves, matching the Phase 7 precedent:

* source-level and routing checks that need no database — the router-level
  authentication dependency, the fixed no-events sentence, the transition table,
  and a structural proof that neither drift service ever writes ``scan`` or
  ``scan_result``;
* integration checks against a disposable PostgreSQL 16 migrated to head, which
  drive the real routes through ASGI with a real session so the CHECK
  constraints, the partial unique index and the append-only triggers all
  participate.

The load-bearing assertions are ``test_run_request_enqueues_and_never_writes_a_run``
(the backend never computes drift and never writes a run) and
``test_verify_refuses_without_a_later_clean_run`` (remediation is evidence-backed,
not a checkbox).
"""

import ast
import asyncio
import itertools
import json
import os
import subprocess  # nosec B404 # controlled Alembic subprocess in disposable database tests
import sys
from datetime import datetime, timezone
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch
from urllib.parse import urlsplit, urlunsplit
from uuid import uuid4

import asyncpg
import pytest
from cryptography.fernet import Fernet
from fastapi import FastAPI
from httpx import ASGITransport, AsyncClient
from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine

from app.api.v1 import drift as routes
from app.core.auth import get_current_user
from app.schemas import drift as schemas
from app.services import drift as service
from app.services import drift_notifications as notifications

BACKEND = Path(__file__).resolve().parents[1]

OWNER = SimpleNamespace(id=901, role="auditor")
STRANGER = SimpleNamespace(id=903, role="auditor")

OWNER_CONNECTION = 921
STRANGER_CONNECTION = 923

# The pinned identity every owner scan shares, so they all resolve to the same
# configuration_key and a second baseline supersedes the first.
METADATA_DIGEST = "1" * 64
POLICY_CORPUS_DIGEST = "2" * 64
CONNECTION_SNAPSHOT = {
    "tenant_id": "synthetic-tenant-owner",
    "client_id": "synthetic-client",
    "sharepoint_admin_url": None,
    "sharepoint_tenant_id": None,
    "sharepoint_certificate_alias": None,
}

# The sentence, written out here rather than imported, so this test fails if the
# constant is ever reworded. It is the single most misreadable thing this API
# returns and the wording is the assertion.
NO_EVENTS_SENTENCE = (
    "Zero events means the compared observations were identical for every "
    "comparable control. It never means the tenant was not changed between "
    "scans, and it never means a control passed."
)

_scan_ids = itertools.count(9401)
_result_ids = itertools.count(94001)
_thread_keys = itertools.count(1)


def _thread_key() -> str:
    return f"{next(_thread_keys):064x}"


# ---------------------------------------------------------------------------
# Routing and source-level checks. No database.
# ---------------------------------------------------------------------------


def _dependency_calls(dependant):
    calls = []
    for sub in dependant.dependencies:
        calls.append(sub.call)
        calls.extend(_dependency_calls(sub))
    return calls


def test_every_route_declares_the_authentication_dependency():
    """Authentication is on the router, so a later route cannot skip it."""
    assert [dependency.dependency for dependency in routes.router.dependencies] == [
        get_current_user
    ]
    assert routes.router.routes, "the drift router registered no routes"
    for route in routes.router.routes:
        calls = _dependency_calls(route.dependant)
        assert get_current_user in calls, route.path


def test_the_router_registers_exactly_the_fourteen_specified_routes():
    registered = {
        (method, route.path)
        for route in routes.router.routes
        for method in sorted(route.methods)
    }
    assert registered == {
        ("POST", "/drift/baselines"),
        ("GET", "/drift/baselines"),
        ("GET", "/drift/baselines/{baseline_id}"),
        ("POST", "/drift/baselines/{baseline_id}/revoke"),
        ("POST", "/drift/runs"),
        ("GET", "/drift/runs"),
        ("GET", "/drift/runs/{run_id}"),
        ("GET", "/drift/runs/{run_id}/events"),
        ("GET", "/drift/scans/{scan_id}"),
        ("GET", "/drift/notifications"),
        ("GET", "/drift/notifications/{thread_key}"),
        ("POST", "/drift/notifications/{thread_key}/acknowledge"),
        ("POST", "/drift/notifications/{thread_key}/remediation"),
        ("POST", "/drift/notifications/{thread_key}/verify"),
    }


def test_the_drift_router_is_registered_under_the_versioned_api():
    from app.api.v1.router import api_router

    paths = {route.path for route in api_router.routes}
    assert "/drift/baselines" in paths


def test_no_events_sentence_is_the_fixed_string_byte_for_byte():
    assert schemas.NO_EVENTS_SENTENCE == NO_EVENTS_SENTENCE


def test_transition_table_is_exactly_the_documented_state_machine():
    assert notifications.TRANSITIONS == {
        "open": frozenset({"acknowledged", "accepted_risk"}),
        "acknowledged": frozenset(
            {"remediation_planned", "accepted_risk", "remediation_verified"}
        ),
        "remediation_planned": frozenset({"remediation_verified", "accepted_risk"}),
        "remediation_verified": frozenset(),
        "accepted_risk": frozenset(),
        "superseded": frozenset(),
    }


# Fields that belong to a scan's outcome. Drift may read a scan's identity; it
# may never write a result, a counter or a score.
FORBIDDEN_WRITES = {
    "compliance_score",
    "coverage_score",
    "total_controls",
    "selected_count",
    "passed_count",
    "failed_count",
    "skipped_count",
    "error_count",
    "indeterminate_count",
    "not_assessable_count",
    "reason_code",
    "evidence",
    "provenance",
}

DRIFT_MODULES = (service, notifications, routes)


@pytest.mark.parametrize("module", DRIFT_MODULES)
def test_no_drift_route_writes_scan_or_scan_result(module):
    """The Scan and ScanResult models appear only in read positions."""
    source = Path(module.__file__).read_text(encoding="utf-8")
    tree = ast.parse(source)

    constructed = {
        node.func.id
        for node in ast.walk(tree)
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Name)
    }
    assert "Scan" not in constructed
    assert "ScanResult" not in constructed
    assert "ScanResultFactprint" not in constructed
    # No drift row that the worker owns is constructed here either.
    assert "DriftRun" not in constructed
    assert "DriftEvent" not in constructed

    # No statement-level mutation of any table through the Core.
    assert not {"insert", "update", "delete"} & constructed

    assigned = {
        node.attr
        for node in ast.walk(tree)
        if isinstance(node, ast.Attribute) and isinstance(node.ctx, ast.Store)
    }
    assert not assigned & FORBIDDEN_WRITES, sorted(assigned & FORBIDDEN_WRITES)


@pytest.mark.parametrize("module", DRIFT_MODULES)
def test_no_rating_is_created_promoted_or_altered(module):
    source = Path(module.__file__).read_text(encoding="utf-8").lower()
    for forbidden in ("configuration_rating", "rating_counts", "soc2_rating"):
        assert forbidden not in source


def test_the_backend_ships_no_second_comparison_implementation():
    """The drift algorithm lives once, in the worker. Not here."""
    source = Path(service.__file__).read_text(encoding="utf-8")
    tree = ast.parse(source)
    defined = {
        node.name
        for node in ast.walk(tree)
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
    }
    assert "compare" not in defined
    assert "evaluate_scan_drift" not in defined


def test_comparability_key_omits_the_policy_corpus_digest_on_the_configuration_axis():
    """A Rego edit cannot change tenant configuration, so it cannot break it."""
    scan = {
        "user_id": 1,
        "m365_connection_id": 2,
        "framework": "cis",
        "benchmark": "microsoft-365-foundations",
        "version": "v6.0.0",
        "metadata_digest": METADATA_DIGEST,
        "semantics_version": "phase3-v1",
        "policy_corpus_digest": POLICY_CORPUS_DIGEST,
        "connection_snapshot": CONNECTION_SNAPSHOT,
    }
    other = {**scan, "policy_corpus_digest": "3" * 64}
    assert service.comparability_key(
        "configuration", scan
    ) == service.comparability_key("configuration", other)
    assert service.comparability_key("evaluation", scan) != service.comparability_key(
        "evaluation", other
    )


def test_utc_now_is_aware():
    """Every Phase 8 column is timestamptz; a naive value here is the old bug."""
    assert service.utc_now().tzinfo is not None


# ---------------------------------------------------------------------------
# Integration: disposable PostgreSQL migrated to head.
# ---------------------------------------------------------------------------


async def _sql(url, statement, *parameters, fetch=True):
    connection = await asyncpg.connect(url)
    try:
        if fetch:
            return [dict(row) for row in await connection.fetch(statement, *parameters)]
        return await connection.execute(statement, *parameters)
    finally:
        await connection.close()


def _alembic(url, *arguments):
    environment = {
        **os.environ,
        "APP_ENV": "dev",
        "DATABASE_URL": url.replace("postgresql://", "postgresql+asyncpg://", 1),
        "SECRET_KEY": uuid4().hex + uuid4().hex,
        "ENCRYPTION_KEY": Fernet.generate_key().decode(),
    }
    result = subprocess.run(  # nosec B603 # fixed interpreter and Alembic arguments from this test
        [sys.executable, "-m", "alembic", *arguments],
        cwd=BACKEND,
        env=environment,
        text=True,
        capture_output=True,
        timeout=180,
        check=False,
    )
    assert result.returncode == 0, result.stdout + result.stderr
    return result.stdout


SEED = """
INSERT INTO "user" (id, role, email, hashed_password, is_active, is_superuser, is_verified)
VALUES (901, 'auditor', 'phase8-owner@example.invalid', 'synthetic-not-a-password', true, false, true),
       (903, 'auditor', 'phase8-stranger@example.invalid', 'synthetic-not-a-password', true, false, true);
INSERT INTO m365_connection (id, user_id, name, tenant_id, client_id, encrypted_client_secret)
VALUES (921, 901, 'Owner tenant', 'synthetic-tenant-owner', 'synthetic-client', 'synthetic-ciphertext'),
       (923, 903, 'Stranger tenant', 'synthetic-tenant-stranger', 'synthetic-client', 'synthetic-ciphertext');
"""


@pytest.fixture(scope="module")
def database_url():
    """A fresh migrated database; never migrate the configured admin database."""
    admin_url = os.environ.get("MIGRATION_TEST_ADMIN_URL")
    if not admin_url:
        pytest.skip(
            "Set MIGRATION_TEST_ADMIN_URL to a disposable local PostgreSQL server"
        )
    parsed = urlsplit(admin_url)
    if parsed.scheme != "postgresql" or parsed.hostname not in {"127.0.0.1", "::1"}:
        pytest.fail("MIGRATION_TEST_ADMIN_URL must be a loopback postgresql:// URL")
    name = "autoaudit_phase8_drift_api_" + uuid4().hex
    asyncio.run(_sql(admin_url, f'CREATE DATABASE "{name}"', fetch=False))
    url = urlunsplit(parsed._replace(path="/" + name))
    try:
        _alembic(url, "upgrade", "head")
        asyncio.run(_sql(url, SEED, fetch=False))
        yield url
    finally:
        asyncio.run(
            _sql(admin_url, f'DROP DATABASE "{name}" WITH (FORCE)', fetch=False)
        )


async def _new_scan(
    url,
    *,
    user_id=OWNER.id,
    connection_id=OWNER_CONNECTION,
    status="completed",
    semantics_version="phase3-v1",
    metadata_digest=METADATA_DIGEST,
    policy_corpus_digest=POLICY_CORPUS_DIGEST,
    snapshot=None,
    results=("passed", "failed"),
    facts=1,
):
    """One synthetic scan, plus its results and declared facts."""
    scan_id = next(_scan_ids)
    await _sql(
        url,
        "INSERT INTO scan (id, user_id, m365_connection_id, framework, benchmark,"
        " version, status, total_controls, selected_count, semantics_version,"
        " metadata_digest, policy_corpus_digest, connection_snapshot,"
        " lifecycle_version, evidence_version)"
        " VALUES ($1, $2, $3, 'cis', 'microsoft-365-foundations', 'v6.0.0', $4, 2, 2,"
        " $5, $6, $7, $8::jsonb, 'phase6-v1', 'phase7-v1')",
        scan_id,
        user_id,
        connection_id,
        status,
        semantics_version,
        metadata_digest,
        policy_corpus_digest,
        json.dumps(CONNECTION_SNAPSHOT if snapshot is None else snapshot),
        fetch=False,
    )
    for index, result_status in enumerate(results):
        await _sql(
            url,
            "INSERT INTO scan_result (id, scan_id, control_id, status, selected,"
            " reason_code) VALUES ($1, $2, $3, $4, true, 'synthetic')",
            next(_result_ids),
            scan_id,
            f"1.{index + 1}",
            result_status,
            fetch=False,
        )
    for index in range(facts):
        await _sql(
            url,
            "INSERT INTO scan_result_factprint (scan_id, control_id, collector_id,"
            " projection_id, field_name, field_kind, value_digest, observed_value,"
            " factprint_schema, key_id, retention_policy_version, recorded_at)"
            " VALUES ($1, $2, 'graph.synthetic', 'graph.synthetic.v1', $3, 'bool',"
            " $4, 'true'::jsonb, 'phase8-factprint-v1', $5, 'phase8-draft-1', $6)",
            scan_id,
            f"1.{index + 1}",
            f"synthetic_field_{index}",
            f"{index:064x}",
            "0" * 16,
            datetime.now(timezone.utc),
            fetch=False,
        )
    return scan_id


async def _new_run(
    url,
    *,
    baseline_id,
    current_scan_id,
    baseline_scan_id,
    user_id=OWNER.id,
    status="completed",
    event_count=0,
    configuration_comparable=None,
    evaluation_comparable=None,
    controls_skipped="{}",
):
    """One drift_run row, written the way the worker writes it.

    The two axis flags are settable independently because the worker sets status
    'completed' whenever EITHER axis compared. Binding them to one value hides
    the completed-but-half-comparable run entirely, which is exactly the shape
    that let a run prove a remediation it never looked at.
    """
    moment = datetime.now(timezone.utc)
    comparable = status == "completed" or status == "event_limit_exceeded"
    if configuration_comparable is None:
        configuration_comparable = comparable
    if evaluation_comparable is None:
        evaluation_comparable = comparable
    rows = await _sql(
        url,
        "INSERT INTO drift_run (baseline_id, baseline_scan_id, current_scan_id,"
        " user_id, framework, benchmark, version, status, trigger,"
        " configuration_comparable, evaluation_comparable, axis_reasons,"
        " baseline_configuration_key, current_configuration_key,"
        " baseline_evaluation_key, current_evaluation_key, controls_compared,"
        " controls_skipped, event_count, event_counts, event_set_digest,"
        " drift_version, retention_policy_version, started_at, completed_at)"
        " VALUES ($1, $2, $3, $4, 'cis', 'microsoft-365-foundations', 'v6.0.0', $5,"
        " 'api_request', $6, $12, '{}'::jsonb, $7, $7, $8, $8, 2, $13::jsonb, $9,"
        " '{}'::jsonb, $10, 'phase8-drift-v1', 'phase8-draft-1', $11, $11)"
        " RETURNING id",
        baseline_id,
        baseline_scan_id,
        current_scan_id,
        user_id,
        status,
        configuration_comparable,
        "a" * 64,
        "b" * 64,
        event_count,
        "c" * 64,
        moment,
        evaluation_comparable,
        controls_skipped,
        fetch=True,
    )
    return rows[0]["id"]


async def _new_event(
    url,
    *,
    run_id,
    baseline_id,
    event_key,
    user_id=OWNER.id,
    severity="high",
    control_id="1.1",
):
    rows = await _sql(
        url,
        "INSERT INTO drift_event (drift_run_id, baseline_id, user_id, control_id,"
        " collector_id, event_class, change_type, fact_name, previous_value,"
        " current_value, severity, severity_basis, event_key, detail, drift_version,"
        " retention_policy_version, occurred_at)"
        " VALUES ($1, $2, $3, $4, 'graph.synthetic', 'configuration', 'changed',"
        " 'synthetic_field_0', 'false'::jsonb, 'true'::jsonb, $5,"
        " 'benchmark_severity', $6, '{}'::jsonb, 'phase8-drift-v1',"
        " 'phase8-draft-1', $7) RETURNING id",
        run_id,
        baseline_id,
        user_id,
        control_id,
        severity,
        event_key,
        datetime.now(timezone.utc),
        fetch=True,
    )
    return rows[0]["id"]


async def _new_thread(
    url,
    *,
    thread_key,
    baseline_id,
    run_id,
    event_id,
    user_id=OWNER.id,
    severity="high",
):
    """Revision 1 of a notification thread, as the worker raises it."""
    await _sql(
        url,
        "INSERT INTO drift_notification (baseline_id, drift_run_id, drift_event_id,"
        " user_id, thread_key, scope, channel, routing_rule, revision_number, action,"
        " state_after, severity, summary_code, summary_counts, drift_version,"
        " retention_policy_version, occurred_at)"
        " VALUES ($1, $2, $3, $4, $5, 'event', 'inapp', 'owner_high_or_above', 1,"
        " 'raised', 'open', $6, 'configuration_changed_high', $7::jsonb,"
        " 'phase8-drift-v1', 'phase8-draft-1', $8)",
        baseline_id,
        run_id,
        event_id,
        user_id,
        thread_key,
        severity,
        json.dumps({"configuration": {severity: 1}, "evaluation": {}}),
        datetime.now(timezone.utc),
        fetch=False,
    )


async def _new_run_thread(url, *, thread_key, baseline_id, run_id, user_id=OWNER.id):
    """Revision 1 of a run-scope thread, as the worker raises one."""
    await _sql(
        url,
        "INSERT INTO drift_notification (baseline_id, drift_run_id, user_id,"
        " thread_key, scope, channel, routing_rule, revision_number, action,"
        " state_after, severity, summary_code, summary_counts, drift_version,"
        " retention_policy_version, occurred_at)"
        " VALUES ($1, $2, $3, $4, 'run', 'inapp', 'owner_not_comparable', 1,"
        " 'raised', 'open', 'informational', 'run_not_comparable', '{}'::jsonb,"
        " 'phase8-drift-v1', 'phase8-draft-1', $5)",
        baseline_id,
        run_id,
        user_id,
        thread_key,
        datetime.now(timezone.utc),
        fetch=False,
    )


def _run(url, scenario):
    """Drive the real routes with a real session inside one event loop."""

    async def main():
        engine = create_async_engine(
            url.replace("postgresql://", "postgresql+asyncpg://", 1)
        )
        maker = async_sessionmaker(engine, expire_on_commit=False)
        try:
            async with maker() as session:
                actor = {"user": OWNER}
                app = FastAPI()
                app.include_router(routes.router)
                app.dependency_overrides[get_current_user] = lambda: actor["user"]
                app.dependency_overrides[routes.get_async_session] = lambda: session
                transport = ASGITransport(app=app)
                async with AsyncClient(
                    transport=transport, base_url="http://api.invalid"
                ) as client:
                    context = SimpleNamespace(
                        session=session,
                        client=client,
                        url=url,
                        act_as=lambda user: actor.__setitem__("user", user),
                    )
                    return await scenario(context)
        finally:
            await engine.dispose()

    return asyncio.run(main())


async def _establish(context, scan_id):
    response = await context.client.post(
        "/drift/baselines", json={"scan_id": scan_id, "note": "synthetic baseline"}
    )
    assert response.status_code == 201, response.text
    return response.json()


# ---------------------------------------------------------------------------
# Ownership. Another account's row is 404, never 403.
# ---------------------------------------------------------------------------


def test_another_users_baseline_run_event_and_scan_are_404_not_403(database_url):
    async def scenario(context):
        scan_id = await _new_scan(context.url)
        baseline = await _establish(context, scan_id)
        current = await _new_scan(context.url)
        run_id = await _new_run(
            context.url,
            baseline_id=baseline["id"],
            current_scan_id=current,
            baseline_scan_id=scan_id,
        )
        thread_key = _thread_key()
        event_id = await _new_event(
            context.url,
            run_id=run_id,
            baseline_id=baseline["id"],
            event_key=thread_key,
        )
        await _new_thread(
            context.url,
            thread_key=thread_key,
            baseline_id=baseline["id"],
            run_id=run_id,
            event_id=event_id,
        )

        context.act_as(STRANGER)
        answers = {
            "baseline": await context.client.get(f"/drift/baselines/{baseline['id']}"),
            "run": await context.client.get(f"/drift/runs/{run_id}"),
            "events": await context.client.get(f"/drift/runs/{run_id}/events"),
            "scan": await context.client.get(f"/drift/scans/{scan_id}"),
            "notification": await context.client.get(
                f"/drift/notifications/{thread_key}"
            ),
        }
        for name, response in answers.items():
            assert response.status_code == 404, (name, response.text)
            assert isinstance(response.json()["detail"], dict), name
        # The stranger's own lists are empty rather than forbidden.
        for path in ("/drift/baselines", "/drift/runs", "/drift/notifications"):
            listing = await context.client.get(path)
            assert listing.status_code == 200, path
            assert listing.json()["items"] == [], path
        return True

    assert _run(database_url, scenario)


# ---------------------------------------------------------------------------
# Establishment.
# ---------------------------------------------------------------------------


def test_baseline_requires_a_completed_pinned_scan_with_facts(database_url):
    async def scenario(context):
        running = await _new_scan(context.url, status="running")
        unpinned = await _new_scan(context.url, semantics_version=None)
        no_metadata = await _new_scan(context.url, metadata_digest=None)
        no_corpus = await _new_scan(context.url, policy_corpus_digest=None)
        no_facts = await _new_scan(context.url, facts=0)
        stranger_scan = await _new_scan(
            context.url,
            user_id=STRANGER.id,
            connection_id=STRANGER_CONNECTION,
        )

        cases = {
            running: (422, "drift_scan_not_completed"),
            unpinned: (422, "drift_scan_not_pinned"),
            no_metadata: (422, "drift_scan_not_pinned"),
            no_corpus: (422, "drift_scan_not_pinned"),
            no_facts: (422, "drift_facts_unavailable"),
            stranger_scan: (404, "drift_scan_not_found"),
            10_000_000: (404, "drift_scan_not_found"),
        }
        for scan_id, (expected_status, expected_code) in cases.items():
            response = await context.client.post(
                "/drift/baselines", json={"scan_id": scan_id}
            )
            assert response.status_code == expected_status, (scan_id, response.text)
            assert response.json()["detail"]["code"] == expected_code, scan_id

        rows = await _sql(context.url, "SELECT count(*) AS n FROM drift_baseline")
        return rows[0]["n"]

    before = _run(database_url, lambda context: _count(context, "drift_baseline"))
    after = _run(database_url, scenario)
    assert after == before


async def _count(context, table):
    rows = await _sql(context.url, f"SELECT count(*) AS n FROM {table}")  # nosec B608
    return rows[0]["n"]


def test_baseline_supersedes_the_previous_active_row_in_one_transaction(database_url):
    async def scenario(context):
        first_scan = await _new_scan(context.url)
        second_scan = await _new_scan(context.url)
        first = await _establish(context, first_scan)
        assert first["status"] == "active"
        second = await _establish(context, second_scan)
        assert second["status"] == "active"
        assert second["configuration_key"] == first["configuration_key"]

        rows = await _sql(
            context.url,
            "SELECT id, status, superseded_by_id, superseded_at FROM drift_baseline"
            " WHERE id = $1",
            first["id"],
        )
        assert len(rows) == 1, "the superseded baseline must never be deleted"
        assert rows[0]["status"] == "superseded"
        assert rows[0]["superseded_by_id"] == second["id"]
        assert rows[0]["superseded_at"] is not None

        active = await _sql(
            context.url,
            "SELECT count(*) AS n FROM drift_baseline WHERE configuration_key = $1"
            " AND status = 'active'",
            first["configuration_key"],
        )
        assert active[0]["n"] == 1

        # A second baseline for the same scan is a conflict, not a supersede.
        repeat = await context.client.post(
            "/drift/baselines", json={"scan_id": second_scan}
        )
        assert repeat.status_code == 409, repeat.text
        assert repeat.json()["detail"]["code"] == "drift_baseline_exists"
        return True

    assert _run(database_url, scenario)


def test_revoking_a_baseline_is_not_a_delete_and_cannot_repeat(database_url):
    async def scenario(context):
        scan_id = await _new_scan(context.url)
        baseline = await _establish(context, scan_id)
        response = await context.client.post(
            f"/drift/baselines/{baseline['id']}/revoke"
        )
        assert response.status_code == 200, response.text
        assert response.json()["status"] == "revoked"

        again = await context.client.post(f"/drift/baselines/{baseline['id']}/revoke")
        assert again.status_code == 409, again.text
        assert again.json()["detail"]["code"] == "drift_baseline_not_active"

        rows = await _sql(
            context.url,
            "SELECT status FROM drift_baseline WHERE id = $1",
            baseline["id"],
        )
        assert rows[0]["status"] == "revoked"
        return True

    assert _run(database_url, scenario)


# ---------------------------------------------------------------------------
# Enqueue. The API never computes drift and never writes a run.
# ---------------------------------------------------------------------------


def test_run_request_enqueues_and_never_writes_a_run(database_url):
    async def scenario(context):
        baseline_scan = await _new_scan(context.url)
        baseline = await _establish(context, baseline_scan)
        current = await _new_scan(context.url)
        before = await _count(context, "drift_run")

        sent = []

        class _Broker:
            def send_task(self, name, **kwargs):
                sent.append((name, kwargs))
                return SimpleNamespace(id="synthetic-task-id")

        with patch.object(service, "celery_app", _Broker()):
            response = await context.client.post(
                "/drift/runs",
                json={"baseline_id": baseline["id"], "scan_id": current},
            )
        assert response.status_code == 202, response.text
        assert response.json() == {
            "code": "drift_evaluation_queued",
            "baseline_id": baseline["id"],
            "scan_id": current,
        }
        assert sent == [
            (
                "worker.tasks.evaluate_drift",
                {
                    "kwargs": {"baseline_id": baseline["id"], "scan_id": current},
                    "queue": "autoaudit",
                },
            )
        ]
        assert await _count(context, "drift_run") == before

        class _DeadBroker:
            def send_task(self, name, **kwargs):
                raise OSError("synthetic broker unavailable")

        with patch.object(service, "celery_app", _DeadBroker()):
            failure = await context.client.post(
                "/drift/runs",
                json={"baseline_id": baseline["id"], "scan_id": current},
            )
        assert failure.status_code == 503, failure.text
        assert failure.json()["detail"]["code"] == "drift_queue_unavailable"
        assert await _count(context, "drift_run") == before

        # An existing run for the pair is a conflict, and still writes nothing.
        run_id = await _new_run(
            context.url,
            baseline_id=baseline["id"],
            current_scan_id=current,
            baseline_scan_id=baseline_scan,
        )
        with patch.object(service, "celery_app", _Broker()):
            duplicate = await context.client.post(
                "/drift/runs",
                json={"baseline_id": baseline["id"], "scan_id": current},
            )
        assert duplicate.status_code == 409, duplicate.text
        assert duplicate.json()["detail"]["code"] == "drift_run_exists"
        assert len(sent) == 1, "a conflicting request must not reach the broker"

        # Someone else's baseline or scan is 404 from this route too.
        context.act_as(STRANGER)
        with patch.object(service, "celery_app", _Broker()):
            forbidden = await context.client.post(
                "/drift/runs",
                json={"baseline_id": baseline["id"], "scan_id": current},
            )
        assert forbidden.status_code == 404, forbidden.text
        assert forbidden.json()["detail"]["code"] == "drift_baseline_not_found"
        context.act_as(OWNER)
        return run_id

    assert _run(database_url, scenario)


# ---------------------------------------------------------------------------
# The fixed sentence.
# ---------------------------------------------------------------------------


def test_zero_events_response_carries_the_fixed_sentence_byte_for_byte(database_url):
    async def scenario(context):
        baseline_scan = await _new_scan(context.url)
        baseline = await _establish(context, baseline_scan)
        current = await _new_scan(context.url)
        run_id = await _new_run(
            context.url,
            baseline_id=baseline["id"],
            current_scan_id=current,
            baseline_scan_id=baseline_scan,
        )

        run = await context.client.get(f"/drift/runs/{run_id}")
        assert run.status_code == 200, run.text
        assert run.json()["no_events_means"] == NO_EVENTS_SENTENCE
        assert run.json()["event_count"] == 0
        assert run.json()["is_real_time"] is False
        assert run.json()["changes_ratings"] is False
        assert run.json()["counted_in_automated_coverage"] is False

        events = await context.client.get(f"/drift/runs/{run_id}/events")
        assert events.status_code == 200, events.text
        assert events.json()["items"] == []
        assert events.json()["run_status"] == "completed"
        assert events.json()["no_events_means"] == NO_EVENTS_SENTENCE

        scan_status = await context.client.get(f"/drift/scans/{current}")
        assert scan_status.status_code == 200, scan_status.text
        assert scan_status.json()["no_events_means"] == NO_EVENTS_SENTENCE
        assert scan_status.json()["status"] == "completed"
        return True

    assert _run(database_url, scenario)


def test_scan_without_a_baseline_or_facts_answers_explicitly(database_url):
    async def scenario(context):
        # A scan whose configuration has no active baseline at all.
        lonely = await _new_scan(
            context.url,
            metadata_digest="9" * 64,
            facts=0,
        )
        answer = await context.client.get(f"/drift/scans/{lonely}")
        assert answer.status_code == 200, answer.text
        assert answer.json()["status"] == "no_baseline"
        assert answer.json()["drift_available"] is False
        assert answer.json()["message"]

        # A scan covered by a baseline but carrying no facts of its own.
        baseline_scan = await _new_scan(context.url, metadata_digest="8" * 64)
        await _establish(context, baseline_scan)
        factless = await _new_scan(context.url, metadata_digest="8" * 64, facts=0)
        answer = await context.client.get(f"/drift/scans/{factless}")
        assert answer.json()["status"] == "facts_unavailable"

        covered = await _new_scan(context.url, metadata_digest="8" * 64)
        answer = await context.client.get(f"/drift/scans/{covered}")
        assert answer.json()["status"] == "not_run"
        assert answer.json()["drift_available"] is False
        return True

    assert _run(database_url, scenario)


# ---------------------------------------------------------------------------
# Notification threads.
# ---------------------------------------------------------------------------


async def _thread_fixture(context, *, severity="high"):
    baseline_scan = await _new_scan(context.url)
    baseline = await _establish(context, baseline_scan)
    current = await _new_scan(context.url)
    run_id = await _new_run(
        context.url,
        baseline_id=baseline["id"],
        current_scan_id=current,
        baseline_scan_id=baseline_scan,
        event_count=1,
    )
    thread_key = _thread_key()
    event_id = await _new_event(
        context.url,
        run_id=run_id,
        baseline_id=baseline["id"],
        event_key=thread_key,
        severity=severity,
    )
    await _new_thread(
        context.url,
        thread_key=thread_key,
        baseline_id=baseline["id"],
        run_id=run_id,
        event_id=event_id,
        severity=severity,
    )
    return SimpleNamespace(
        baseline_id=baseline["id"],
        baseline_scan_id=baseline_scan,
        run_id=run_id,
        event_id=event_id,
        thread_key=thread_key,
    )


def test_notification_state_is_derived_from_the_max_revision(database_url):
    async def scenario(context):
        thread = await _thread_fixture(context)

        listed = await context.client.get("/drift/notifications")
        assert listed.status_code == 200, listed.text
        opened = [
            item
            for item in listed.json()["items"]
            if item["thread_key"] == thread.thread_key
        ]
        assert len(opened) == 1
        assert opened[0]["state"] == "open"
        assert opened[0]["current_revision_number"] == 1
        assert opened[0]["remediation_evidenced"] is False

        acknowledged = await context.client.post(
            f"/drift/notifications/{thread.thread_key}/acknowledge",
            json={"note": "Seen, investigating."},
        )
        assert acknowledged.status_code == 200, acknowledged.text
        assert acknowledged.json()["state"] == "acknowledged"

        planned = await context.client.post(
            f"/drift/notifications/{thread.thread_key}/remediation",
            json={"state": "remediation_planned", "note": "Change scheduled."},
        )
        assert planned.status_code == 200, planned.text
        body = planned.json()
        assert body["state"] == "remediation_planned"
        assert body["current_revision_number"] == 3
        assert body["remediation_evidenced"] is False

        history = await context.client.get(f"/drift/notifications/{thread.thread_key}")
        assert history.status_code == 200, history.text
        revisions = history.json()["revisions"]
        assert [revision["revision_number"] for revision in revisions] == [1, 2, 3]
        assert [revision["action"] for revision in revisions] == [
            "raised",
            "acknowledged",
            "remediation_planned",
        ]
        assert history.json()["state"] == "remediation_planned"
        assert history.json()["raised_at"] <= history.json()["updated_at"]

        # Exactly one thread, three revisions: nothing was rewritten.
        rows = await _sql(
            context.url,
            "SELECT count(*) AS n FROM drift_notification WHERE thread_key = $1",
            thread.thread_key,
        )
        assert rows[0]["n"] == 3

        # A filter on the derived state selects by the newest revision only.
        still_open = await context.client.get("/drift/notifications?state=open")
        assert thread.thread_key not in {
            item["thread_key"] for item in still_open.json()["items"]
        }
        return True

    assert _run(database_url, scenario)


def test_illegal_transition_is_409_and_writes_no_revision(database_url):
    async def scenario(context):
        thread = await _thread_fixture(context)

        illegal = await context.client.post(
            f"/drift/notifications/{thread.thread_key}/remediation",
            json={"state": "remediation_planned", "note": "Skipping acknowledgement."},
        )
        assert illegal.status_code == 409, illegal.text
        assert (
            illegal.json()["detail"]["code"] == "drift_notification_transition_invalid"
        )

        rows = await _sql(
            context.url,
            "SELECT count(*) AS n FROM drift_notification WHERE thread_key = $1",
            thread.thread_key,
        )
        assert rows[0]["n"] == 1

        # A terminal state is terminal: accepted_risk accepts nothing further.
        accepted = await context.client.post(
            f"/drift/notifications/{thread.thread_key}/remediation",
            json={"state": "accepted_risk", "note": "Compensating control in place."},
        )
        assert accepted.status_code == 200, accepted.text
        assert accepted.json()["state"] == "accepted_risk"

        after = await context.client.post(
            f"/drift/notifications/{thread.thread_key}/acknowledge",
            json={"note": "Too late."},
        )
        assert after.status_code == 409, after.text
        rows = await _sql(
            context.url,
            "SELECT count(*) AS n FROM drift_notification WHERE thread_key = $1",
            thread.thread_key,
        )
        assert rows[0]["n"] == 2
        return True

    assert _run(database_url, scenario)


def test_verify_refuses_without_a_later_clean_run(database_url):
    async def scenario(context):
        thread = await _thread_fixture(context)
        acknowledged = await context.client.post(
            f"/drift/notifications/{thread.thread_key}/acknowledge", json={}
        )
        assert acknowledged.status_code == 200, acknowledged.text

        # A later completed run in which the same finding recurs proves nothing.
        recurring_scan = await _new_scan(context.url)
        recurring_run = await _new_run(
            context.url,
            baseline_id=thread.baseline_id,
            current_scan_id=recurring_scan,
            baseline_scan_id=thread.baseline_scan_id,
            event_count=1,
        )
        await _new_event(
            context.url,
            run_id=recurring_run,
            baseline_id=thread.baseline_id,
            event_key=thread.thread_key,
        )
        refusal = await context.client.post(
            f"/drift/notifications/{thread.thread_key}/verify",
            json={"scan_id": recurring_scan},
        )
        assert refusal.status_code == 422, refusal.text
        assert refusal.json()["detail"]["code"] == "drift_remediation_not_evidenced"

        # A run that could not compare proves nothing either.
        incomparable_scan = await _new_scan(context.url)
        await _new_run(
            context.url,
            baseline_id=thread.baseline_id,
            current_scan_id=incomparable_scan,
            baseline_scan_id=thread.baseline_scan_id,
            status="not_comparable",
        )
        refusal = await context.client.post(
            f"/drift/notifications/{thread.thread_key}/verify",
            json={"scan_id": incomparable_scan},
        )
        assert refusal.status_code == 422, refusal.text

        # A scan with no run at all proves nothing.
        unrun_scan = await _new_scan(context.url)
        refusal = await context.client.post(
            f"/drift/notifications/{thread.thread_key}/verify",
            json={"scan_id": unrun_scan},
        )
        assert refusal.status_code == 422, refusal.text

        rows = await _sql(
            context.url,
            "SELECT count(*) AS n FROM drift_notification WHERE thread_key = $1",
            thread.thread_key,
        )
        assert rows[0]["n"] == 2
        return True

    assert _run(database_url, scenario)


def test_verify_accepts_a_later_run_with_no_matching_event_key(database_url):
    async def scenario(context):
        thread = await _thread_fixture(context)
        acknowledged = await context.client.post(
            f"/drift/notifications/{thread.thread_key}/acknowledge", json={}
        )
        assert acknowledged.status_code == 200, acknowledged.text

        clean_scan = await _new_scan(context.url)
        clean_run = await _new_run(
            context.url,
            baseline_id=thread.baseline_id,
            current_scan_id=clean_scan,
            baseline_scan_id=thread.baseline_scan_id,
            event_count=1,
        )
        # The run is not empty; it simply does not carry THIS finding.
        await _new_event(
            context.url,
            run_id=clean_run,
            baseline_id=thread.baseline_id,
            event_key=_thread_key(),
        )

        verified = await context.client.post(
            f"/drift/notifications/{thread.thread_key}/verify",
            json={"scan_id": clean_scan},
        )
        assert verified.status_code == 200, verified.text
        assert verified.json()["state"] == "remediation_verified"
        assert verified.json()["remediation_evidenced"] is True

        rows = await _sql(
            context.url,
            "SELECT revision_number, action, verified_run_id FROM drift_notification"
            " WHERE thread_key = $1 ORDER BY revision_number",
            thread.thread_key,
        )
        assert [row["action"] for row in rows] == [
            "raised",
            "acknowledged",
            "remediation_verified",
        ]
        assert rows[-1]["verified_run_id"] == clean_run
        assert rows[0]["verified_run_id"] is None
        return True

    assert _run(database_url, scenario)


def test_a_run_scope_thread_refusal_is_a_typed_409_and_never_a_500(database_url):
    """Pins the boundary behaviour of a defect in code this item does not own.

    ``ck_drift_notification_event_scope`` reads
    ``(scope = 'event') = (drift_event_id IS NOT NULL OR revision_number > 1)``.
    On a ``scope = 'run'`` thread the right side becomes true at revision 2
    while the left side stays false, so the database refuses every revision
    after the first: a ``run_not_comparable`` or
    ``run_fingerprints_unavailable`` notification can never be acknowledged or
    accepted. That constraint belongs to the migration and the model, not to
    this work item, and is reported rather than changed here.

    What IS this item's responsibility is that the refusal reaches the caller as
    a typed 409 with a stable code and a clean session, never a 500, and that no
    revision is written.
    """

    async def scenario(context):
        baseline_scan = await _new_scan(context.url)
        baseline = await _establish(context, baseline_scan)
        current = await _new_scan(context.url)
        run_id = await _new_run(
            context.url,
            baseline_id=baseline["id"],
            current_scan_id=current,
            baseline_scan_id=baseline_scan,
            status="not_comparable",
        )
        thread_key = _thread_key()
        await _new_run_thread(
            context.url,
            thread_key=thread_key,
            baseline_id=baseline["id"],
            run_id=run_id,
        )

        thread = await context.client.get(f"/drift/notifications/{thread_key}")
        assert thread.status_code == 200, thread.text
        assert thread.json()["scope"] == "run"
        assert thread.json()["state"] == "open"

        refusal = await context.client.post(
            f"/drift/notifications/{thread_key}/acknowledge", json={}
        )
        assert refusal.status_code == 409, refusal.text
        detail = refusal.json()["detail"]
        assert isinstance(detail, dict)
        assert detail["code"] == "drift_conflict"

        rows = await _sql(
            context.url,
            "SELECT count(*) AS n FROM drift_notification WHERE thread_key = $1",
            thread_key,
        )
        assert rows[0]["n"] == 1

        # The session is still usable afterwards.
        listing = await context.client.get("/drift/notifications")
        assert listing.status_code == 200, listing.text
        return True

    assert _run(database_url, scenario)


# ---------------------------------------------------------------------------
# Error bodies.
# ---------------------------------------------------------------------------


def test_error_bodies_are_dicts_with_a_code(database_url):
    async def scenario(context):
        missing_thread = "f" * 64
        responses = [
            await context.client.get("/drift/baselines/999999"),
            await context.client.get("/drift/runs/999999"),
            await context.client.get("/drift/runs/999999/events"),
            await context.client.get("/drift/scans/999999"),
            await context.client.get(f"/drift/notifications/{missing_thread}"),
            await context.client.post(
                f"/drift/notifications/{missing_thread}/acknowledge", json={}
            ),
            await context.client.post(
                f"/drift/notifications/{missing_thread}/verify", json={"scan_id": 1}
            ),
            await context.client.post("/drift/baselines", json={"scan_id": 999999}),
        ]
        for response in responses:
            assert response.status_code in (404, 409, 422), response.text
            detail = response.json()["detail"]
            assert isinstance(detail, dict), response.text
            assert detail["code"].startswith("drift_"), detail
            assert detail["message"], detail
        return True

    assert _run(database_url, scenario)


def test_list_endpoints_return_the_house_envelope_without_a_total(database_url):
    async def scenario(context):
        scan_id = await _new_scan(context.url)
        await _establish(context, scan_id)
        for path in ("/drift/baselines", "/drift/runs", "/drift/notifications"):
            response = await context.client.get(f"{path}?limit=1&offset=0")
            assert response.status_code == 200, path
            body = response.json()
            assert set(body) >= {"items", "limit", "offset", "returned"}, path
            assert "total" not in body, path
            assert body["returned"] == len(body["items"]), path
            assert body["limit"] == 1 and body["offset"] == 0, path
        over = await context.client.get("/drift/baselines?limit=101")
        assert over.status_code == 422, over.text
        return True

    assert _run(database_url, scenario)


def test_soc2_summary_reads_a_run_and_never_a_rating(database_url):
    """B7 consumes this. It returns counts, and None when no run exists."""

    async def scenario(context):
        baseline_scan = await _new_scan(context.url)
        baseline = await _establish(context, baseline_scan)
        current = await _new_scan(context.url)
        assert (
            await service.soc2_drift_summary(context.session, current, OWNER.id)
        ) is None

        run_id = await _new_run(
            context.url,
            baseline_id=baseline["id"],
            current_scan_id=current,
            baseline_scan_id=baseline_scan,
            event_count=1,
        )
        thread_key = _thread_key()
        event_id = await _new_event(
            context.url,
            run_id=run_id,
            baseline_id=baseline["id"],
            event_key=thread_key,
        )
        await _new_thread(
            context.url,
            thread_key=thread_key,
            baseline_id=baseline["id"],
            run_id=run_id,
            event_id=event_id,
        )
        summary = await service.soc2_drift_summary(context.session, current, OWNER.id)
        assert summary["run_id"] == run_id
        assert summary["baseline_id"] == baseline["id"]
        assert summary["run_status"] == "completed"
        assert summary["event_count"] == 1
        assert summary["open_notification_count"] == 1
        assert "rating" not in json.dumps(summary)

        acknowledged = await context.client.post(
            f"/drift/notifications/{thread_key}/acknowledge", json={}
        )
        assert acknowledged.status_code == 200, acknowledged.text
        summary = await service.soc2_drift_summary(context.session, current, OWNER.id)
        assert summary["open_notification_count"] == 0

        # Another account reads nothing from this scan.
        assert (
            await service.soc2_drift_summary(context.session, current, STRANGER.id)
        ) is None
        return True

    assert _run(database_url, scenario)


# ---------------------------------------------------------------------------
# Remediation evidence must prove the run actually LOOKED. A run is 'completed'
# whenever EITHER axis compared, so absence of the finding in a run that never
# compared this axis -- or never compared this control -- proves nothing.
# Accepting it would turn "we could not look" into "it is remediated".
# ---------------------------------------------------------------------------


def test_verify_refuses_a_run_whose_configuration_axis_never_compared(database_url):
    async def scenario(context):
        thread = await _thread_fixture(context)
        await context.client.post(
            f"/drift/notifications/{thread.thread_key}/acknowledge", json={}
        )
        blind_scan = await _new_scan(context.url)
        # Completed, but the configuration axis could not compare: exactly what a
        # rotated or absent fingerprint key produces.
        await _new_run(
            context.url,
            baseline_id=thread.baseline_id,
            current_scan_id=blind_scan,
            baseline_scan_id=thread.baseline_scan_id,
            configuration_comparable=False,
            evaluation_comparable=True,
        )
        refused = await context.client.post(
            f"/drift/notifications/{thread.thread_key}/verify",
            json={"scan_id": blind_scan},
        )
        assert refused.status_code == 422, refused.text
        assert refused.json()["detail"]["code"] == "drift_remediation_not_evidenced"
        return True

    assert _run(database_url, scenario)


def test_verify_refuses_a_run_that_skipped_the_findings_control(database_url):
    async def scenario(context):
        thread = await _thread_fixture(context)
        await context.client.post(
            f"/drift/notifications/{thread.thread_key}/acknowledge", json={}
        )
        skipped_scan = await _new_scan(context.url)
        # Both axes comparable, but THIS control was not compared -- the shape a
        # collector error or a narrowed scan scope produces.
        await _new_run(
            context.url,
            baseline_id=thread.baseline_id,
            current_scan_id=skipped_scan,
            baseline_scan_id=thread.baseline_scan_id,
            controls_skipped='{"control_absent_current": ["1.1"]}',
        )
        refused = await context.client.post(
            f"/drift/notifications/{thread.thread_key}/verify",
            json={"scan_id": skipped_scan},
        )
        assert refused.status_code == 422, refused.text
        assert refused.json()["detail"]["code"] == "drift_remediation_not_evidenced"
        return True

    assert _run(database_url, scenario)
