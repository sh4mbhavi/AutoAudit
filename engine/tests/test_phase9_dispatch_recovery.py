"""Recovery of a collection-keyed outbox, against a real PostgreSQL.

Phase 6 made the outbox the sole authorisation to publish and gave every row a
deterministic identity so duplicate orchestration and reconciler recovery
converge. Phase 9 changes what a row identifies. These are the recovery
properties that had to survive that, plus two defects the phase's own
adversarial review found.
"""

import json
from contextlib import contextmanager
from unittest.mock import MagicMock

import pytest
from sqlalchemy import text
from sqlalchemy.orm import Session

from tests.test_phase3_persistence import database as _database, seed
from worker import dispatcher, tasks
from worker.execution_plan import collection_dispatch_id, control_dispatch_id
from worker.provenance import canonical_digest

database = _database

# Two controls that SHARE one collector, so a group is genuinely a group.
METADATA = {
    "controls": [
        {
            "control_id": str(index),
            "data_collector_id": "entra.shared",
            "automation_status": "ready",
            "policy_file": f"{index}.rego",
        }
        for index in (1, 2)
    ]
}


@pytest.fixture
def scan(database, monkeypatch):
    with database.begin() as connection:
        connection.execute(
            text("""ALTER TABLE scan ADD COLUMN user_id int, ADD COLUMN m365_connection_id int,
        ADD COLUMN azure_connection_id int, ADD COLUMN gcp_connection_id int,
        ADD COLUMN aws_connection_id int,
        ADD COLUMN framework text DEFAULT 'cis', ADD COLUMN benchmark text DEFAULT 'synthetic',
        ADD COLUMN version text DEFAULT 'v1', ADD COLUMN started_at timestamp,
        ADD COLUMN notes text, ADD COLUMN semantics_version text DEFAULT 'phase3-v1',
        ADD COLUMN connection_snapshot jsonb, ADD COLUMN metadata_snapshot jsonb,
        ADD COLUMN metadata_digest text, ADD COLUMN correlation_id text,
        ADD COLUMN dispatch_id varchar(36) UNIQUE, ADD COLUMN dispatch_count int DEFAULT 0,
        ADD COLUMN deadline_at timestamp, ADD COLUMN lifecycle_version text DEFAULT 'phase6-v1' """)
        )
        connection.execute(
            text("""CREATE TABLE scan_dispatch (id varchar(36) PRIMARY KEY,
        scan_id int REFERENCES scan(id) ON DELETE CASCADE,
        result_id int REFERENCES scan_result(id) ON DELETE CASCADE,
        collector_id varchar(200),
        CONSTRAINT ck_scan_dispatch_single_key CHECK (result_id IS NULL OR collector_id IS NULL),
        task_name varchar(100) NOT NULL,
        attempts int NOT NULL DEFAULT 0,
        available_at timestamp NOT NULL DEFAULT (now() AT TIME ZONE 'UTC'),
        dispatched_at timestamp, last_error varchar(100),
        created_at timestamp NOT NULL DEFAULT (now() AT TIME ZONE 'UTC'))""")
        )
    seed(database, ["pending", "pending"], 2)
    with database.begin() as connection:
        connection.execute(
            text("""UPDATE scan SET status='running', metadata_snapshot=CAST(:metadata AS jsonb),
        metadata_digest=:digest, m365_connection_id=3, correlation_id='synthetic',
        deadline_at=(now() AT TIME ZONE 'UTC')+interval '1 hour' """),
            {"metadata": json.dumps(METADATA), "digest": canonical_digest(METADATA)},
        )

    @contextmanager
    def session():
        with Session(database) as opened:
            with opened.begin():
                yield opened

    monkeypatch.setattr(dispatcher, "get_db_session", session)
    monkeypatch.setattr(tasks, "get_db_session", session)
    monkeypatch.setattr(dispatcher.celery_app, "send_task", MagicMock())
    return database


def _rows(database):
    with database.connect() as connection:
        return (
            connection.execute(text("SELECT * FROM scan_dispatch ORDER BY id"))
            .mappings()
            .all()
        )


def test_two_controls_that_share_a_collector_get_one_outbox_row(scan):
    dispatcher.reconcile()
    rows = _rows(scan)
    assert len(rows) == 1
    assert rows[0]["collector_id"] == "entra.shared"
    assert rows[0]["result_id"] is None
    assert rows[0]["id"] == collection_dispatch_id(1, "entra.shared")


def test_the_group_row_survives_until_every_member_is_written(scan):
    """A group is not finished because one of its controls is.

    The result-keyed DELETE cannot see a collection row at all, so without
    _retire_settled_collections the row would only be dropped when the scan
    finalised -- and it must not be dropped before then either, or the second
    control would be stranded pending until the deadline failed the scan.
    """
    dispatcher.reconcile()
    with scan.begin() as connection:
        connection.execute(text("UPDATE scan_result SET status='passed' WHERE id=1"))
    dispatcher.reconcile()
    rows = _rows(scan)
    assert len(rows) == 1 and rows[0]["collector_id"] == "entra.shared"


def test_the_group_row_is_retired_once_every_member_is_written(scan):
    dispatcher.reconcile()
    with scan.begin() as connection:
        connection.execute(text("UPDATE scan_result SET status='passed'"))
    dispatcher.reconcile()
    # Finalisation clears the outbox; either way the row must not survive to be
    # republished against a scan with nothing left to do.
    assert _rows(scan) == []


def test_recovery_recreates_a_deleted_group_row_with_the_same_identity(scan):
    dispatcher.reconcile()
    identity = _rows(scan)[0]["id"]
    with scan.begin() as connection:
        connection.execute(text("DELETE FROM scan_dispatch"))
    dispatcher.reconcile()
    rows = _rows(scan)
    assert len(rows) == 1 and rows[0]["id"] == identity


def test_reconciliation_is_idempotent(scan):
    dispatcher.reconcile()
    dispatcher.reconcile()
    dispatcher.reconcile()
    assert len(_rows(scan)) == 1


def test_a_control_already_claimed_by_a_legacy_row_is_not_also_grouped(scan):
    """Found in review: a rolling deploy could execute a control twice.

    A scan orchestrated by a pre-Phase-9 build carries one per-result row per
    control. Reconciled by this build, it would ALSO get a collection row for
    the same controls, and publish_due would send both -- two collections, two
    remote sessions, against the same tenant for the same evidence. The result
    write is still first-write-wins, so only one assessment could land; the
    second collection is pure waste.
    """
    with Session(scan) as session, session.begin():
        session.execute(
            text("""INSERT INTO scan_dispatch (id, scan_id, result_id, task_name)
            VALUES (:id, 1, 1, 'worker.tasks.evaluate_control')"""),
            {"id": control_dispatch_id(1, 1)},
        )
    dispatcher.reconcile()
    rows = _rows(scan)
    assert len(rows) == 2
    assert [row["result_id"] for row in rows if row["result_id"]] == [1]
    assert [row["collector_id"] for row in rows if row["collector_id"]] == [
        "entra.shared"
    ]
    # Control 1 is served by its legacy row; the group covers ONLY control 2.
    # That is observable: writing control 2 retires the group row while the
    # legacy row survives, because the group has no pending member of its own
    # left. If the group also covered control 1 it would stay live and keep
    # being published, collecting the same evidence a second time.
    with scan.begin() as connection:
        connection.execute(text("UPDATE scan_result SET status='passed' WHERE id=2"))
    dispatcher.reconcile()
    remaining = _rows(scan)
    assert len(remaining) == 1
    assert remaining[0]["result_id"] == 1
    assert remaining[0]["collector_id"] is None


def test_a_pending_non_ready_control_never_becomes_a_collection_row(scan):
    """Found in review: an unpublishable group failed the whole scan.

    evaluate_collection resolves only READY controls. A group built from a
    non-ready one resolves to nothing, raises, writes no result -- so the row
    stayed live and was republished every cycle until reconcile() failed the
    scan with dispatch_retry_exhausted.
    """
    metadata = {
        "controls": [
            dict(METADATA["controls"][0]),
            dict(
                METADATA["controls"][1], automation_status="blocked", policy_file=None
            ),
        ]
    }
    with scan.begin() as connection:
        connection.execute(
            text(
                "UPDATE scan SET metadata_snapshot=CAST(:m AS jsonb), metadata_digest=:d"
            ),
            {"m": json.dumps(metadata), "d": canonical_digest(metadata)},
        )
    dispatcher.reconcile()
    rows = _rows(scan)
    assert len(rows) == 2
    assert {row["collector_id"] for row in rows} == {"entra.shared", None}
    # The non-ready control falls back to the Phase 6 per-result row, which is
    # exactly what would have been written before Phase 9.
    fallback = [row for row in rows if row["collector_id"] is None][0]
    assert fallback["result_id"] == 2
    assert fallback["task_name"] == "worker.tasks.evaluate_control"


def test_a_group_row_is_not_published_once_its_controls_are_written(scan):
    dispatcher.reconcile()
    with scan.begin() as connection:
        connection.execute(text("UPDATE scan_result SET status='passed'"))
        connection.execute(
            text("UPDATE scan_dispatch SET available_at=(now() AT TIME ZONE 'UTC')")
        )
    published = []
    dispatcher.celery_app.send_task.side_effect = (
        lambda name, **kwargs: published.append(name)
    )
    dispatcher.publish_due()
    assert published == []
    assert _rows(scan) == []
