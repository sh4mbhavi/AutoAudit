"""Durable lifecycle regressions using disposable PostgreSQL and a fake broker."""

import json
from contextlib import contextmanager
from unittest.mock import MagicMock

import pytest
from sqlalchemy import text
from sqlalchemy.orm import Session

from tests.test_phase3_persistence import database as _database, seed

from worker import db, tasks
from worker.provenance import canonical_digest

database = _database


@pytest.mark.parametrize("terminal", ["completed", "failed", "cancelled"])
def test_terminal_scan_rejects_late_result(database, terminal):
    seed(database, ["pending"], 1)
    with Session(database) as s:
        s.execute(text("UPDATE scan SET status=:status"), {"status": terminal})
        assert not db.update_scan_result(s, 1, "passed")
        assert not db.finalize_scan_if_complete(s, 1)
        assert (
            s.execute(text("SELECT status FROM scan_result")).scalar_one() == "pending"
        )


def test_terminal_scan_cannot_reopen(database):
    seed(database, ["passed"], 1)
    with Session(database) as s:
        db.finalize_scan_if_complete(s, 1)
        db.update_scan_status(s, 1, "running")
        assert s.execute(text("SELECT status FROM scan")).scalar_one() == "completed"


@pytest.fixture
def lifecycle(database, monkeypatch):
    with database.begin() as c:
        c.execute(
            text("""ALTER TABLE scan ADD COLUMN user_id int, ADD COLUMN m365_connection_id int,
        ADD COLUMN azure_connection_id int, ADD COLUMN gcp_connection_id int, ADD COLUMN aws_connection_id int,
        ADD COLUMN framework text DEFAULT 'cis', ADD COLUMN benchmark text DEFAULT 'synthetic',
        ADD COLUMN version text DEFAULT 'v1', ADD COLUMN started_at timestamp,
        ADD COLUMN notes text, ADD COLUMN semantics_version text DEFAULT 'phase3-v1',
        ADD COLUMN connection_snapshot jsonb, ADD COLUMN metadata_snapshot jsonb, ADD COLUMN metadata_digest text, ADD COLUMN correlation_id text,
        ADD COLUMN dispatch_id varchar(36) UNIQUE, ADD COLUMN dispatch_count int DEFAULT 0,
        ADD COLUMN deadline_at timestamp, ADD COLUMN lifecycle_version text DEFAULT 'phase6-v1' """)
        )
        c.execute(
            text("""CREATE TABLE scan_dispatch (id varchar(36) PRIMARY KEY,
        scan_id int REFERENCES scan(id) ON DELETE CASCADE,
        result_id int REFERENCES scan_result(id) ON DELETE CASCADE, task_name varchar(100) NOT NULL,
        attempts int NOT NULL DEFAULT 0,
        available_at timestamp NOT NULL DEFAULT (now() AT TIME ZONE 'UTC'),
        dispatched_at timestamp, last_error varchar(100),
        created_at timestamp NOT NULL DEFAULT (now() AT TIME ZONE 'UTC'))""")
        )
    seed(database, ["pending", "pending"], 2)
    metadata = {
        "controls": [
            {
                "control_id": str(i),
                "data_collector_id": "entra.synthetic",
                "automation_status": "ready",
            }
            for i in (1, 2)
        ]
    }
    with database.begin() as c:
        c.execute(
            text("""UPDATE scan SET status='pending', metadata_snapshot=CAST(:metadata AS jsonb),
        metadata_digest=:digest, m365_connection_id=3, correlation_id='synthetic',
        deadline_at=(now() AT TIME ZONE 'UTC')+interval '1 hour' """),
            {"metadata": json.dumps(metadata), "digest": canonical_digest(metadata)},
        )

    @contextmanager
    def session():
        with Session(database) as s:
            with s.begin():
                yield s

    monkeypatch.setattr(tasks, "get_db_session", session)
    return database, session


def test_duplicate_orchestration_builds_atomic_outbox(lifecycle, monkeypatch):
    database, _ = lifecycle
    send = MagicMock(side_effect=AssertionError("broker must not be called"))
    monkeypatch.setattr(tasks.evaluate_control, "delay", send)
    tasks.run_scan.run(1)
    tasks.run_scan.run(1)
    with database.connect() as c:
        rows = c.execute(text("SELECT * FROM scan_dispatch")).mappings().all()
        assert len(rows) == 2
        assert {r["result_id"] for r in rows} == {1, 2}
        assert all(r["task_name"] == "worker.tasks.evaluate_control" for r in rows)
        assert c.execute(text("SELECT status FROM scan")).scalar_one() == "running"


def test_dispatcher_recovers_broker_outage_and_sends_identifiers(
    lifecycle, monkeypatch
):
    from worker import dispatcher

    database, session = lifecycle
    monkeypatch.setattr(dispatcher, "get_db_session", session)
    tasks.run_scan.run(1)
    send = MagicMock(side_effect=RuntimeError("SENSITIVE_BROKER_CANARY"))
    monkeypatch.setattr(dispatcher.celery_app, "send_task", send)
    dispatcher.tick()
    with database.begin() as c:
        rows = c.execute(text("SELECT * FROM scan_dispatch")).mappings().all()
        assert all(r["last_error"] == "broker_unavailable" for r in rows)
        assert all(r["dispatched_at"] is None for r in rows)
        c.execute(
            text("UPDATE scan_dispatch SET available_at=(now() AT TIME ZONE 'UTC')")
        )
    send.side_effect = None
    dispatcher.tick()
    assert send.call_args.kwargs["kwargs"] in [
        dict(scan_id=1, result_id=i, connection_id=3) for i in (1, 2)
    ]
    assert send.call_args.kwargs["headers"]["correlation_id"] == "synthetic"
    with database.connect() as c:
        assert (
            c.execute(
                text(
                    "SELECT count(*) FROM scan_dispatch WHERE dispatched_at IS NOT NULL"
                )
            ).scalar_one()
            == 2
        )


def test_deadline_fails_scan_and_terminalizes_pending(lifecycle, monkeypatch):
    from worker import dispatcher

    database, session = lifecycle
    monkeypatch.setattr(dispatcher, "get_db_session", session)
    with database.begin() as c:
        c.execute(
            text(
                "UPDATE scan SET deadline_at=(now() AT TIME ZONE 'UTC')-interval '1 second'"
            )
        )
    dispatcher.tick()
    with database.connect() as c:
        row = c.execute(text("SELECT * FROM scan")).mappings().one()
        assert row["status"] == "failed"
        assert row["error_count"] == 2
        assert row["finished_at"] is not None
        assert (
            c.execute(text("SELECT DISTINCT reason_code FROM scan_result")).scalar_one()
            == "scan_deadline_exceeded"
        )
        provenance = c.execute(
            text("SELECT provenance FROM scan_result WHERE id=1")
        ).scalar_one()
        assert provenance["schema_version"] == 1
        assert provenance["control_id"] == "1"
        assert provenance["metadata_digest"]
        assert provenance["correlation_id"] == "synthetic"
        assert provenance["provenance_status"] == "not_executed"


def test_reconciliation_recreates_missing_child_dispatch(lifecycle, monkeypatch):
    from worker import dispatcher

    database, session = lifecycle
    monkeypatch.setattr(dispatcher, "get_db_session", session)
    monkeypatch.setattr(dispatcher.celery_app, "send_task", MagicMock())
    tasks.run_scan.run(1)
    with database.begin() as c:
        c.execute(text("DELETE FROM scan_dispatch WHERE result_id=2"))
    dispatcher.tick()
    with database.connect() as c:
        assert (
            c.execute(
                text("SELECT count(*) FROM scan_dispatch WHERE result_id IS NOT NULL")
            ).scalar_one()
            == 2
        )


def test_stalled_delivery_exhaustion_fails_scan(lifecycle, monkeypatch):
    from worker import dispatcher

    database, session = lifecycle
    monkeypatch.setattr(dispatcher, "get_db_session", session)
    tasks.run_scan.run(1)
    with database.begin() as c:
        c.execute(
            text(
                "UPDATE scan_dispatch SET attempts=100, dispatched_at=(now() AT TIME ZONE 'UTC')-interval '1 day', available_at=(now() AT TIME ZONE 'UTC')-interval '1 day'"
            )
        )
    dispatcher.tick()
    with database.connect() as c:
        assert c.execute(text("SELECT status FROM scan")).scalar_one() == "failed"
        assert (
            c.execute(
                text("SELECT count(*) FROM scan_result WHERE status='pending'")
            ).scalar_one()
            == 0
        )


def test_orchestrator_rollback_leaves_pending_without_partial_children(
    lifecycle, monkeypatch
):
    database, _ = lifecycle
    original = tasks.enqueue

    def crash_after_first(session, scan_id, result_id):
        original(session, scan_id, result_id)
        raise RuntimeError("synthetic crash before commit")

    monkeypatch.setattr(tasks, "enqueue", crash_after_first)
    with pytest.raises(RuntimeError):
        tasks.run_scan.run(1)
    with database.connect() as c:
        assert c.execute(text("SELECT status FROM scan")).scalar_one() == "pending"
        assert c.execute(text("SELECT count(*) FROM scan_dispatch")).scalar_one() == 0


def test_orphan_initial_and_stale_child_delivery_are_recovered(lifecycle, monkeypatch):
    from worker import dispatcher

    database, session = lifecycle
    monkeypatch.setattr(dispatcher, "get_db_session", session)
    send = MagicMock()
    monkeypatch.setattr(dispatcher.celery_app, "send_task", send)
    dispatcher.tick()
    assert send.call_args.args == ("worker.tasks.run_scan",)
    assert send.call_args.kwargs["kwargs"] == {"scan_id": 1}
    tasks.run_scan.run(1)
    dispatcher.tick()
    with database.begin() as c:
        before = dict(c.execute(text("SELECT id, attempts FROM scan_dispatch")).all())
        assert len(before) == 2
        c.execute(
            text(
                "UPDATE scan_dispatch SET available_at=(now() AT TIME ZONE 'UTC')-interval '1 second'"
            )
        )
    send.reset_mock()
    dispatcher.tick()
    assert send.call_count == 2
    with database.connect() as c:
        after = dict(c.execute(text("SELECT id, attempts FROM scan_dispatch")).all())
        assert after == {key: value + 1 for key, value in before.items()}


@pytest.mark.parametrize("action", ["cancel", "delete"])
def test_parent_lock_serializes_cancellation_deletion_before_late_write(
    lifecycle, action
):
    from concurrent.futures import ThreadPoolExecutor
    from threading import Event

    database, _ = lifecycle
    acquired = Event()
    attempted = Event()

    def lifecycle_change():
        with Session(database) as s:
            db.lock_scan(s, 1)
            acquired.set()
            assert attempted.wait(5)
            if action == "cancel":
                s.execute(
                    text(
                        "UPDATE scan_result SET status='indeterminate', reason_code='scan_cancelled' WHERE scan_id=1 AND status='pending'"
                    )
                )
                db.finalize_scan_if_complete(s, 1, final_status="cancelled")
            else:
                s.execute(text("DELETE FROM scan_result WHERE scan_id=1"))
                s.execute(text("DELETE FROM scan WHERE id=1"))
            s.commit()

    def late_write():
        assert acquired.wait(5)
        with Session(database) as s:
            attempted.set()
            changed = db.update_scan_result(s, 1, "passed")
            db.finalize_scan_if_complete(s, 1)
            s.commit()
            return changed

    with ThreadPoolExecutor(max_workers=2) as pool:
        lifecycle_future = pool.submit(lifecycle_change)
        worker_future = pool.submit(late_write)
        lifecycle_future.result(10)
        assert worker_future.result(10) is False
    with database.connect() as c:
        scan = c.execute(text("SELECT * FROM scan")).mappings().first()
        if action == "cancel":
            assert scan["status"] == "cancelled"
            assert scan["indeterminate_count"] == 2
            assert scan["passed_count"] == 0
        else:
            assert scan is None


def test_terminal_outbox_rows_are_cleaned(lifecycle, monkeypatch):
    from worker import dispatcher

    database, session = lifecycle
    monkeypatch.setattr(dispatcher, "get_db_session", session)
    tasks.run_scan.run(1)
    with Session(database) as s:
        db.update_scan_result(s, 1, "passed")
        db.update_scan_result(s, 2, "passed")
        db.finalize_scan_if_complete(s, 1)
        s.commit()
    dispatcher.tick()
    with database.connect() as c:
        assert c.execute(text("SELECT count(*) FROM scan_dispatch")).scalar_one() == 0


def test_corrupt_metadata_still_terminalizes_on_deadline(lifecycle, monkeypatch):
    from worker import dispatcher

    database, session = lifecycle
    monkeypatch.setattr(dispatcher, "get_db_session", session)
    with database.begin() as c:
        c.execute(
            text(
                "UPDATE scan SET metadata_snapshot='[1]'::jsonb, deadline_at=(now() AT TIME ZONE 'UTC')-interval '1 second'"
            )
        )
    dispatcher.tick()
    with database.connect() as c:
        assert c.execute(text("SELECT status FROM scan")).scalar_one() == "failed"


@pytest.mark.parametrize(
    "changed_field",
    [
        "tenant_id",
        "client_id",
        "sharepoint_admin_url",
        "sharepoint_tenant_id",
        "sharepoint_certificate_alias",
        "is_active",
    ],
)
def test_credential_drift_fails_before_decryption(monkeypatch, changed_field):
    identity = {
        "tenant_id": "tenant-a",
        "client_id": "client-a",
        "sharepoint_admin_url": "https://synthetic-admin.sharepoint.com",
        "sharepoint_tenant_id": "tenant-a",
        "sharepoint_certificate_alias": "synthetic",
    }
    row = {
        **identity,
        "connection_snapshot": identity.copy(),
        "is_active": True,
        "encrypted_client_secret": "synthetic-ciphertext",  # pragma: allowlist secret - synthetic fixture or migration revision
    }
    row[changed_field] = False if changed_field == "is_active" else "drifted"
    session = MagicMock()
    session.execute.return_value.mappings.return_value.first.return_value = row
    decrypt = MagicMock()
    monkeypatch.setattr(db, "decrypt", decrypt)
    with pytest.raises(ValueError):
        db.get_execution_credentials(session, 1, 3)
    decrypt.assert_not_called()


@pytest.fixture
def migrated_legacy(database, monkeypatch):
    import os
    import subprocess
    from pathlib import Path
    from uuid import uuid4
    from cryptography.fernet import Fernet

    backend = Path(__file__).resolve().parents[2] / "backend-api"
    with database.begin() as c:
        c.execute(text("DROP TABLE scan_result"))
        c.execute(text("DROP TABLE scan"))
    env = {
        **os.environ,
        "APP_ENV": "dev",
        "DATABASE_URL": str(database.url).replace(
            "postgresql://", "postgresql+asyncpg://"
        ),
        "ENCRYPTION_KEY": Fernet.generate_key().decode(),
        "SECRET_KEY": uuid4().hex + uuid4().hex,
    }

    def migrate(revision):
        result = subprocess.run(
            [
                "uv",
                "run",
                "--frozen",
                "--project",
                str(backend),
                "python",
                "-m",
                "alembic",
                "upgrade",
                revision,
            ],
            cwd=backend,
            env=env,
            capture_output=True,
            text=True,
            timeout=60,
        )
        assert result.returncode == 0, result.stdout + result.stderr

    migrate(
        "2899a0e678b6"  # pragma: allowlist secret
    )  # pragma: allowlist secret - synthetic fixture or migration revision
    with database.begin() as c:
        c.execute(
            text("""INSERT INTO "user" (id,role,email,hashed_password,is_active,is_superuser,is_verified)
            VALUES (1,'user','synthetic@example.invalid','synthetic',true,false,true)""")
        )
        c.execute(
            text("""INSERT INTO scan(id,user_id,framework,benchmark,version,status,total_controls,compliance_score)
            VALUES(1,1,'cis','synthetic','v1','running',3,100)""")
        )
        c.execute(
            text("""INSERT INTO scan_result(id,scan_id,control_id,status,evidence)
            VALUES(1,1,'1','pending',NULL),(2,1,'2','pending',NULL),(3,1,'3','passed','{"legacy":"unchanged"}'::jsonb)""")
        )
    migrate("head")

    @contextmanager
    def sessions():
        with Session(database) as s:
            with s.begin():
                yield s

    return database, sessions


@pytest.mark.parametrize(
    "failure", ["reconcile", "scan_deadline_exceeded", "dispatch_retry_exhausted"]
)
def test_migrated_legacy_pending_rows_finish_without_invented_attribution(
    migrated_legacy, monkeypatch, failure
):
    from worker import dispatcher
    from worker.lifecycle import enqueue, fail_scan

    database, sessions = migrated_legacy
    with sessions() as s:
        enqueue(s, 1)
        row = s.execute(text("SELECT * FROM scan")).mappings().one()
        assert row["semantics_version"] is None
        assert row["selected_count"] is None
        assert (
            s.execute(
                text("SELECT count(*) FROM scan_result WHERE selected IS NULL")
            ).scalar_one()
            == 3
        )
    if failure in {"reconcile", "scan_deadline_exceeded"}:
        if failure == "scan_deadline_exceeded":
            with sessions() as s:
                s.execute(
                    text(
                        "UPDATE scan SET deadline_at=(now() AT TIME ZONE 'UTC')-interval '1 second'"
                    )
                )
        monkeypatch.setattr(dispatcher, "get_db_session", sessions)
        dispatcher.tick()
    else:
        with sessions() as s:
            assert fail_scan(s, 1, failure)
    with database.connect() as c:
        scan = c.execute(text("SELECT * FROM scan")).mappings().one()
        rows = c.execute(text("SELECT * FROM scan_result ORDER BY id")).mappings().all()
        assert scan["status"] == "failed"
        assert scan["finished_at"] is not None
        assert scan["selected_count"] is None
        assert scan["semantics_version"] is None
        assert scan["compliance_score"] is None
        assert scan["coverage_score"] is None
        assert scan["error_count"] == 2 and scan["passed_count"] == 1
        assert all(row["selected"] is None for row in rows)
        assert [row["status"] for row in rows] == ["error", "error", "passed"]
        for row in rows[:2]:
            assert row["reason_code"] == "legacy_scan_context"
            assert row["provenance"]["provenance_status"] == "legacy_unknown"
            assert row["provenance"]["metadata_digest"] is None
            assert row["provenance"]["policy_digest"] is None
            assert row["provenance"]["collector_id"] is None
        assert rows[2]["evidence"] == {"legacy": "unchanged"}
        assert rows[2]["provenance"] is None
        assert c.execute(text("SELECT count(*) FROM scan_dispatch")).scalar_one() == 0
    with sessions() as s:
        assert fail_scan(s, 1, "dispatch_retry_exhausted") is False


def test_failure_cannot_report_completion_or_drop_outbox_without_finalization(
    lifecycle, monkeypatch
):
    from worker import lifecycle as state

    database, sessions = lifecycle
    with sessions() as s:
        state.enqueue(s, 1)
        monkeypatch.setattr(
            state, "finalize_scan_if_complete", lambda *args, **kwargs: False
        )
        assert state.fail_scan(s, 1, "scan_deadline_exceeded") is False
        assert s.execute(text("SELECT count(*) FROM scan_dispatch")).scalar_one() == 1


def test_failure_preserves_existing_versioned_terminal_evidence(lifecycle):
    from worker.lifecycle import fail_scan

    database, sessions = lifecycle
    with sessions() as s:
        assert db.update_scan_result(
            s,
            1,
            "passed",
            evidence={"synthetic": "immutable"},
            provenance={"synthetic": "original"},
        )
        assert fail_scan(s, 1, "scan_deadline_exceeded")
        row = s.execute(text("SELECT * FROM scan_result WHERE id=1")).mappings().one()
        assert row["selected"] is True
        assert row["status"] == "passed"
        assert row["evidence"] == {"synthetic": "immutable"}
        assert row["provenance"] == {"synthetic": "original"}
        scan = s.execute(text("SELECT * FROM scan")).mappings().one()
        assert scan["passed_count"] == 1 and scan["error_count"] == 1
        assert scan["compliance_score"] == 100 and scan["coverage_score"] == 50
