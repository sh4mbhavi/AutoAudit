"""Worker integration: fact capture on success only, drift only on finalisation.

Every value here is synthetic. The HMAC key is generated inside the test process
from a literal byte range and never leaves it; no tenant identifier, credential

or real evidence appears in this module.

The properties this file exists to hold:

  * a projection rides back from the async helper and is popped BEFORE strict
    validation, because ``OPAResult`` forbids extra keys;
  * a failed, unverified or unusable collection produces no fact row at all;
  * the fact write is gated on the same first-write-wins flag as the result
    write, so a redelivered Celery message cannot add a second observation;
  * drift runs exactly once, on finalisation, after the result write has been
    committed, and a drift failure can never change a scan or a result.
"""

import base64
import json
import os
import subprocess
from contextlib import contextmanager
import re
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock
from uuid import uuid4

import pytest
from cryptography.fernet import Fernet
from pydantic import ValidationError
from sqlalchemy import create_engine, text
from sqlalchemy.orm import Session

from worker import drift as drift_module
from worker import factprint, tasks
from worker.factprint import project_facts
from worker.provenance import canonical_digest
from worker.result_contract import OPAResult

# Every factprint digest is scoped to a tenant; see TENANT_KEY_DOMAIN.
TENANT_ID = "00000000-0000-0000-0000-0000000000aa"
REPO_ROOT = Path(__file__).resolve().parents[2]

# Deterministic synthetic key material: 32 bytes generated in-process.
KEY = base64.urlsafe_b64encode(bytes(range(32))).decode()

# entra.groups.groups declares exactly one int field in FACT_PROJECTIONS v1.
COLLECTOR = "entra.groups.groups"
COLLECTED = {"public_groups_count": 3}
FIELD = "public_groups_count"

CONNECTION_ID = 1
SCAN_ID = 1

# Literal placeholders; nothing here is a credential and nothing leaves the process.
SYNTHETIC = {
    "tenant_id": "synthetic",
    "client_id": "synthetic",
    "client_secret": "synthetic",  # pragma: allowlist secret - synthetic fixture
}

METADATA = {
    "controls": [
        {
            "control_id": "1.1.1",
            "automation_status": "ready",
            "data_collector_id": COLLECTOR,
            "policy_file": "1.1.1_admin_cloud_only.rego",
        },
        {
            "control_id": "1.2.1",
            "automation_status": "ready",
            "data_collector_id": COLLECTOR,
            "policy_file": "1.1.1_admin_cloud_only.rego",
        },
    ]
}

# The same two controls with nothing to dispatch, so run_scan finalises inline.
BLOCKED_METADATA = {
    "controls": [
        {"control_id": control["control_id"], "automation_status": "blocked"}
        for control in METADATA["controls"]
    ]
}

SUCCESS = {
    "compliant": True,
    "message": "Synthetic result",
    "affected_resources": [],
    "details": {},
}


def payload(facts):
    """What _evaluate_control_async returns on its success path."""
    return {
        **SUCCESS,
        "provenance": {"provenance_status": "captured"},
        "factprint": facts,
    }


def scan_context(status: str = "running") -> dict:
    return {
        "m365_connection_id": CONNECTION_ID,
        "status": status,
        "metadata_snapshot": METADATA,
        "metadata_digest": canonical_digest(METADATA),
        "semantics_version": "phase3-v1",
        "framework": "cis",
        "benchmark": "microsoft-365-foundations",
        "version": "v6.0.0",
        "correlation_id": "synthetic",
    }


# ---------------------------------------------------------------------------
# The pop, which needs no database.
# ---------------------------------------------------------------------------


def test_factprint_is_popped_before_strict_validation(monkeypatch):
    """OPAResult forbids extra keys, so the projection must never reach it."""
    monkeypatch.setattr(factprint.settings, "DRIFT_FACT_HMAC_KEY", KEY)
    facts = project_facts(COLLECTOR, COLLECTED, TENANT_ID)
    assert facts and facts[0]["field_name"] == FIELD

    # The regression this guards: the payload is invalid to the contract as-is.
    with pytest.raises(ValidationError):
        OPAResult.model_validate({**SUCCESS, "factprint": facts})

    session = MagicMock()

    @contextmanager
    def database():
        yield session

    monkeypatch.setattr(tasks, "get_db_session", database)
    monkeypatch.setattr(
        tasks,
        "_evaluate_control_async",
        AsyncMock(side_effect=lambda **_: payload(facts)),
    )
    monkeypatch.setattr(tasks, "get_scan", lambda *_: scan_context())
    monkeypatch.setattr(
        tasks,
        "get_execution_result",
        lambda *_: {"control_id": "1.1.1", "status": "pending", "selected": True},
    )
    monkeypatch.setattr(tasks, "get_execution_credentials", lambda *_: {})
    saved = MagicMock(return_value=True)
    monkeypatch.setattr(tasks, "update_scan_result", saved)
    monkeypatch.setattr(
        tasks, "finalize_scan_if_complete", MagicMock(return_value=False)
    )
    written = MagicMock(return_value=1)
    monkeypatch.setattr(tasks, "persist_factprint", written)

    outcome = tasks.evaluate_control.run(SCAN_ID, 2, CONNECTION_ID)

    assert outcome == {"control_id": "1.1.1", "compliant": True, "status": "passed"}
    assert written.call_args.kwargs["fields"] == facts
    assert written.call_args.kwargs["collector_id"] == COLLECTOR
    assert written.call_args.kwargs["control_id"] == "1.1.1"
    # The evidence column keeps exactly its Phase 3 shape; no fact leaks into it.
    assert saved.call_args.kwargs["evidence"] == {"affected_resource_count": 0}


# ---------------------------------------------------------------------------
# A real migrated PostgreSQL, because the remaining assertions are about rows.
# ---------------------------------------------------------------------------


def _alembic(database):
    backend = Path(__file__).resolve().parents[2] / "backend-api"
    environment = {
        **os.environ,
        "APP_ENV": "dev",
        "DATABASE_URL": str(database.url).replace(
            "postgresql://", "postgresql+asyncpg://"
        ),
        "ENCRYPTION_KEY": Fernet.generate_key().decode(),
        "SECRET_KEY": uuid4().hex + uuid4().hex,
    }
    # nosec B603 B607 # fixed interpreter and Alembic arguments, disposable database
    migration = subprocess.run(  # nosec
        [
            "uv",
            "run",
            "--project",
            str(backend),
            "python",
            "-m",
            "alembic",
            "upgrade",
            "head",
        ],
        cwd=backend,
        env=environment,
        capture_output=True,
        text=True,
        timeout=180,
    )
    assert migration.returncode == 0, migration.stdout + migration.stderr


@pytest.fixture(scope="module")
def migrated():
    url = os.environ.get("MIGRATION_TEST_ADMIN_URL")
    if not url:
        pytest.skip("Set MIGRATION_TEST_ADMIN_URL for disposable PostgreSQL tests")
    if "@127.0.0.1:" not in url:
        pytest.fail("Only loopback test databases are allowed")
    admin = create_engine(url, isolation_level="AUTOCOMMIT")
    name = "autoaudit_hook_test_" + uuid4().hex
    with admin.connect() as connection:
        connection.execute(text(f'CREATE DATABASE "{name}"'))
    engine = create_engine(url.rsplit("/", 1)[0] + "/" + name)
    try:
        _alembic(engine)
        yield engine
    finally:
        engine.dispose()
        with admin.connect() as connection:
            connection.execute(text(f'DROP DATABASE "{name}" WITH (FORCE)'))
        admin.dispose()


INSERT_SCAN = text("""
    INSERT INTO scan (id,user_id,m365_connection_id,framework,benchmark,version,
        status,selected_count,total_controls,semantics_version,metadata_snapshot,
        metadata_digest,correlation_id)
    VALUES (:id,1,:connection_id,'cis','microsoft-365-foundations','v6.0.0',:status,
        :selected,:selected,'phase3-v1',CAST(:metadata AS jsonb),:digest,:correlation)
""")

INSERT_RESULT = text("""
    INSERT INTO scan_result (scan_id,control_id,status,selected)
    VALUES (:scan_id,:control_id,'pending',true) RETURNING id
""")


def seed(engine, *, controls=("1.1.1", "1.2.1"), metadata=None, digest=None):
    """One running scan owned by a synthetic user, with pending selected results."""
    snapshot = metadata or METADATA
    with engine.begin() as connection:
        connection.execute(
            text(
                "TRUNCATE drift_notification, drift_event, drift_run, drift_baseline,"
                ' scan_result_factprint, scan_result, scan, m365_connection, "user"'
                " RESTART IDENTITY CASCADE"
            )
        )
        connection.execute(
            text("""INSERT INTO "user" (id,role,email,hashed_password,is_active,
            is_superuser,is_verified)
            VALUES (1,'user','synthetic@example.invalid','synthetic',true,false,true)""")
        )
        connection.execute(
            text("""INSERT INTO m365_connection
            (id,user_id,name,tenant_id,client_id,encrypted_client_secret,is_active)
            VALUES (:id,1,'synthetic','synthetic-tenant','synthetic-client',
            'synthetic-ciphertext',true)"""),
            {"id": CONNECTION_ID},
        )
        connection.execute(
            INSERT_SCAN,
            {
                "id": SCAN_ID,
                "connection_id": CONNECTION_ID,
                "status": "running",
                "selected": len(controls),
                "metadata": json.dumps(snapshot),
                "digest": digest or canonical_digest(snapshot),
                "correlation": str(uuid4()),
            },
        )
        return [
            connection.execute(
                INSERT_RESULT, {"scan_id": SCAN_ID, "control_id": control}
            ).scalar_one()
            for control in controls
        ]


@pytest.fixture
def worker(migrated, monkeypatch):
    """tasks.py bound to the migrated database, with a usable fingerprint key."""

    @contextmanager
    def database():
        session = Session(migrated)
        try:
            yield session
            session.commit()
        except Exception:
            session.rollback()
            raise
        finally:
            session.close()

    monkeypatch.setattr(tasks, "get_db_session", database)
    # A fresh dict per call: evaluate_control clears what it is handed in its
    # finally block, which would otherwise empty the module constant.
    monkeypatch.setattr(tasks, "get_execution_credentials", lambda *_: dict(SYNTHETIC))
    monkeypatch.setattr(factprint.settings, "DRIFT_FACT_HMAC_KEY", KEY)
    return migrated


def count(engine, table: str) -> int:
    with engine.connect() as connection:
        return connection.execute(text(f"SELECT count(*) FROM {table}")).scalar_one()


def rows(engine, statement: str):
    with engine.connect() as connection:
        return connection.execute(text(statement)).mappings().all()


def scan_status(engine) -> str:
    return rows(engine, "SELECT status FROM scan")[0]["status"]


def pending_results(engine) -> int:
    with engine.connect() as connection:
        return connection.execute(
            text("SELECT count(*) FROM scan_result WHERE status='pending'")
        ).scalar_one()


def spy_on_drift(monkeypatch, *, side_effect=None):
    calls = MagicMock(side_effect=side_effect, return_value={"status": "no_baseline"})
    monkeypatch.setattr(drift_module, "evaluate_scan_drift", calls)
    return calls


def succeed(monkeypatch, facts):
    # A fresh dict per call: evaluate_control pops from what it is handed, so a
    # shared return_value would silently strip the projection off the redelivery.
    monkeypatch.setattr(
        tasks,
        "_evaluate_control_async",
        AsyncMock(side_effect=lambda **_: payload(facts)),
    )


# ---------------------------------------------------------------------------
# Nothing but a clean success writes a fact row.
# ---------------------------------------------------------------------------


def test_failed_collection_writes_no_factprint(worker, monkeypatch):
    """An EvaluationFailure and a collection_only return both write nothing.

    Both run through the real _evaluate_control_async, so what is asserted is
    that neither return SHAPE carries a projection, not merely that tasks.py
    declined to persist one.
    """
    from collectors import graph_client, registry

    spy_on_drift(monkeypatch)
    monkeypatch.setattr(graph_client, "GraphClient", lambda **_: object())
    first, second = seed(worker)

    # 1. The collector reports an execution failure, so the helper raises
    #    EvaluationFailure and the retry-exhausted branch records the error.
    monkeypatch.setattr(
        registry,
        "get_collector",
        lambda _: type(
            "Collector",
            (),
            {"collect": AsyncMock(return_value={"error": "synthetic failure"})},
        )(),
    )
    tasks.evaluate_control.push_request(retries=3)
    try:
        outcome = tasks.evaluate_control.run(SCAN_ID, first, CONNECTION_ID)
    finally:
        tasks.evaluate_control.pop_request()
    assert outcome["status"] == "error"
    assert count(worker, "scan_result_factprint") == 0

    # 2. A non-object payload cannot fulfil any collector contract; the helper
    #    returns collection_only and carries no projection at all.
    monkeypatch.setattr(
        registry,
        "get_collector",
        lambda _: type("Collector", (), {"collect": AsyncMock(return_value=[1, 2])})(),
    )
    outcome = tasks.evaluate_control.run(SCAN_ID, second, CONNECTION_ID)
    assert outcome["status"] == "indeterminate"
    assert count(worker, "scan_result_factprint") == 0
    assert {
        row["control_id"]: row["status"]
        for row in rows(worker, "SELECT control_id,status FROM scan_result")
    } == {"1.1.1": "error", "1.2.1": "indeterminate"}


def test_first_write_wins_gates_the_factprint(worker, monkeypatch):
    """A redelivered evaluate_control writes no second fact row."""
    spy_on_drift(monkeypatch)
    facts = project_facts(COLLECTOR, COLLECTED, TENANT_ID)
    succeed(monkeypatch, facts)
    first, _ = seed(worker)

    assert (
        tasks.evaluate_control.run(SCAN_ID, first, CONNECTION_ID)["status"] == "passed"
    )
    assert count(worker, "scan_result_factprint") == 1

    # An ordinary redelivery is refused by the pending guard.
    assert tasks.evaluate_control.run(SCAN_ID, first, CONNECTION_ID) == {
        "scan_id": SCAN_ID,
        "result_id": first,
        "status": "ignored",
    }
    assert count(worker, "scan_result_factprint") == 1

    # The race the guard cannot catch: two workers both read the row while it is
    # still pending. update_scan_result refuses the second write, and because the
    # fact write is gated on that same flag it is refused with it.
    monkeypatch.setattr(
        tasks,
        "get_execution_result",
        lambda *_: {
            "id": first,
            "control_id": "1.1.1",
            "status": "pending",
            "selected": True,
        },
    )
    raced = tasks.evaluate_control.run(SCAN_ID, first, CONNECTION_ID)
    assert raced["status"] == "ignored"
    assert count(worker, "scan_result_factprint") == 1

    row = rows(worker, "SELECT * FROM scan_result_factprint")[0]
    assert row["scan_id"] == SCAN_ID
    assert row["control_id"] == "1.1.1"
    assert row["collector_id"] == COLLECTOR
    assert row["field_name"] == FIELD
    assert row["observed_value"] == 3
    assert row["factprint_schema"] == factprint.FACTPRINT_SCHEMA
    assert row["retention_policy_version"] == factprint.RETENTION_POLICY_VERSION


def test_no_key_configured_writes_no_factprint(worker, monkeypatch):
    """The key is the gate: without one a clean success still writes no row."""
    spy_on_drift(monkeypatch)
    monkeypatch.setattr(factprint.settings, "DRIFT_FACT_HMAC_KEY", "")
    succeed(monkeypatch, project_facts(COLLECTOR, COLLECTED, TENANT_ID))
    first, _ = seed(worker)

    assert (
        tasks.evaluate_control.run(SCAN_ID, first, CONNECTION_ID)["status"] == "passed"
    )
    assert count(worker, "scan_result_factprint") == 0


# ---------------------------------------------------------------------------
# Drift fires on finalisation, once, and never harms a scan.
# ---------------------------------------------------------------------------


def test_drift_runs_only_when_the_scan_finalises(worker, monkeypatch):
    observed = {}

    def record(session, scan_id, *, trigger):
        # A connection of its own: what it can see is what has been committed.
        observed["scan_status"] = scan_status(worker)
        observed["pending"] = pending_results(worker)
        return {"status": "no_baseline", "scan_id": scan_id, "trigger": trigger}

    calls = spy_on_drift(monkeypatch, side_effect=record)
    succeed(monkeypatch, project_facts(COLLECTOR, COLLECTED, TENANT_ID))
    first, second = seed(worker)

    tasks.evaluate_control.run(SCAN_ID, first, CONNECTION_ID)
    assert calls.call_count == 0
    assert scan_status(worker) == "running"

    tasks.evaluate_control.run(SCAN_ID, second, CONNECTION_ID)
    assert calls.call_count == 1
    assert calls.call_args.args[1] == SCAN_ID
    assert calls.call_args.kwargs == {"trigger": "scan_finalised"}
    # The hook runs after the enclosing session block has committed, so drift
    # reads a finalised scan rather than the writer's uncommitted transaction.
    assert observed == {"scan_status": "completed", "pending": 0}


def test_drift_failure_never_fails_the_scan(worker, monkeypatch, caplog):
    calls = spy_on_drift(
        monkeypatch, side_effect=RuntimeError("SENSITIVE_SYNTHETIC_DIAGNOSTIC")
    )
    succeed(monkeypatch, project_facts(COLLECTOR, COLLECTED, TENANT_ID))
    first, second = seed(worker)

    tasks.evaluate_control.run(SCAN_ID, first, CONNECTION_ID)
    with caplog.at_level("ERROR"):
        outcome = tasks.evaluate_control.run(SCAN_ID, second, CONNECTION_ID)

    assert outcome == {"control_id": "1.2.1", "compliant": True, "status": "passed"}
    assert calls.call_count == 1
    assert scan_status(worker) == "completed"
    assert {
        row["status"] for row in rows(worker, "SELECT status FROM scan_result")
    } == {"passed"}
    assert count(worker, "scan_result_factprint") == 2
    assert "drift_cycle_failed scan_id=1" in caplog.text
    assert "SENSITIVE_SYNTHETIC_DIAGNOSTIC" not in caplog.text


def test_drift_is_not_run_on_a_failed_scan(worker, monkeypatch):
    """A scan that never reaches 'completed' produces no drift run."""
    calls = spy_on_drift(monkeypatch)

    # run_scan refuses a scan whose frozen metadata no longer verifies and fails
    # it through lifecycle.fail_scan; the hook is never reached.
    seed(worker, digest="f" * 64)
    assert tasks.run_scan.run(SCAN_ID) == {"scan_id": SCAN_ID, "status": "failed"}
    assert scan_status(worker) == "failed"
    assert calls.call_count == 0


def test_a_scan_finalised_through_the_error_branch_still_gets_drift(
    worker, monkeypatch
):
    """Drift must not depend on which control happens to finish last.

    The retry-exhausted branch writes a terminal result and finalises the scan
    exactly as the success path does. If only the success path fired drift, a
    scan whose LAST control exhausted its retries would be completed and never
    compared -- and a control that stopped being assessable is precisely the
    coverage_lost the evaluation axis exists to report.
    """
    calls = spy_on_drift(monkeypatch)
    (first,) = seed(worker, controls=("1.1.1",))
    monkeypatch.setattr(
        tasks,
        "_evaluate_control_async",
        AsyncMock(side_effect=RuntimeError("synthetic execution failure")),
    )
    tasks.evaluate_control.push_request(retries=3)
    try:
        outcome = tasks.evaluate_control.run(SCAN_ID, first, CONNECTION_ID)
    finally:
        tasks.evaluate_control.pop_request()
    assert outcome["status"] == "error"
    assert scan_status(worker) == "completed"
    assert calls.call_count == 1
    # A failed execution still writes no fact: an error is never an observation.
    assert count(worker, "scan_result_factprint") == 0


def test_run_scan_finalisation_triggers_drift(worker, monkeypatch):
    """A scan with nothing to dispatch finalises inside run_scan and drifts once."""
    calls = spy_on_drift(monkeypatch)
    seed(worker, metadata=BLOCKED_METADATA)

    outcome = tasks.run_scan.run(SCAN_ID)

    assert outcome["status"] == "completed"
    assert outcome["dispatched"] == 0 and outcome["not_assessable"] == 2
    assert calls.call_count == 1
    assert calls.call_args.args[1] == SCAN_ID
    assert calls.call_args.kwargs == {"trigger": "scan_finalised"}


# ---------------------------------------------------------------------------
# The backend enqueues a task by NAME. A test that asserts only the string the
# backend sends is self-referential and passes while the endpoint is a no-op,
# which is exactly how worker.tasks.evaluate_drift shipped unregistered. This
# asserts the two sides against each other.
# ---------------------------------------------------------------------------


def _name_sent_by_backend() -> str:
    """The literal task name backend-api/app/services/drift.py sends."""
    source = (REPO_ROOT / "backend-api" / "app" / "services" / "drift.py").read_text(
        encoding="utf-8"
    )
    match = re.search(r'send_task\(\s*"([^"]+)"', source)
    assert match, "queue_drift_run no longer sends a literal task name"
    return match.group(1)


def test_the_task_name_the_backend_sends_is_registered_in_the_worker():
    from worker.celery_app import celery_app
    import worker.tasks  # noqa: F401  (registers the tasks)

    sent = _name_sent_by_backend()
    assert sent in celery_app.tasks, (
        f"backend-api enqueues {sent!r} but the worker registers "
        f"{sorted(n for n in celery_app.tasks if n.startswith('worker.tasks'))}. "
        "The endpoint would answer 202 and the task would be discarded."
    )


def test_evaluate_drift_rejects_invalid_identifiers():
    from worker.tasks import evaluate_drift

    for baseline_id, scan_id in ((0, 1), (-1, 1), (1, 0), (1, -1)):
        with pytest.raises(ValueError):
            evaluate_drift(baseline_id, scan_id)
