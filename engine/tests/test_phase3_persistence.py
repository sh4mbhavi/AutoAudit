"""Real PostgreSQL worker persistence and scoring tests; no tenant data."""

import os
from uuid import uuid4

import pytest
from sqlalchemy import create_engine, text
from sqlalchemy.orm import Session

from worker.db import update_scan_result, finalize_scan_if_complete


@pytest.fixture
def database():
    url = os.environ.get("MIGRATION_TEST_ADMIN_URL")
    if not url:
        pytest.skip("Set MIGRATION_TEST_ADMIN_URL for disposable PostgreSQL tests")
    if "@127.0.0.1:" not in url:
        pytest.fail("Only loopback test databases are allowed")
    admin = create_engine(url, isolation_level="AUTOCOMMIT")
    name = "autoaudit_worker_test_" + uuid4().hex
    with admin.connect() as connection:
        connection.execute(text(f'CREATE DATABASE "{name}"'))
    engine = create_engine(url.rsplit("/", 1)[0] + "/" + name)
    try:
        with engine.begin() as connection:
            connection.execute(
                text("""CREATE TABLE scan (id int PRIMARY KEY, status text, selected_count int,
                total_controls int, passed_count int DEFAULT 0, failed_count int DEFAULT 0,
                indeterminate_count int DEFAULT 0, error_count int DEFAULT 0,
                skipped_count int DEFAULT 0, not_assessable_count int DEFAULT 0,
                compliance_score numeric, coverage_score numeric, finished_at timestamp, last_progress_at timestamp DEFAULT now())""")
            )
            connection.execute(
                text("""CREATE TABLE scan_result (id int PRIMARY KEY, scan_id int REFERENCES scan(id),
                control_id text, selected boolean, status text, message text, evidence jsonb,
                reason_code text, provenance jsonb, updated_at timestamp)""")
            )
        yield engine
    finally:
        engine.dispose()
        with admin.connect() as connection:
            connection.execute(text(f'DROP DATABASE "{name}" WITH (FORCE)'))
        admin.dispose()


def seed(engine, outcomes, selected):
    with engine.begin() as c:
        c.execute(
            text(
                "INSERT INTO scan(id,status,selected_count,total_controls) VALUES (1,'running',:selected,:total)"
            ),
            {"selected": selected, "total": len(outcomes)},
        )
        for i, status in enumerate(outcomes, 1):
            c.execute(
                text(
                    "INSERT INTO scan_result(id,scan_id,control_id,selected,status) VALUES (:id,1,:control,:selected,:status)"
                ),
                {
                    "id": i,
                    "control": str(i),
                    "selected": status != "skipped",
                    "status": status,
                },
            )


def test_finalization_counts_all_states_and_separates_scores(database):
    seed(
        database,
        ["passed"] * 8
        + ["failed"] * 2
        + ["indeterminate"] * 3
        + ["error"] * 2
        + ["not_assessable"] * 5
        + ["skipped"] * 120,
        20,
    )
    with Session(database) as s:
        assert finalize_scan_if_complete(s, 1)
        row = s.execute(text("SELECT * FROM scan WHERE id=1")).mappings().one()
        assert row["compliance_score"] == 80
        assert row["coverage_score"] == 50
        assert row["indeterminate_count"] == 3
        assert row["not_assessable_count"] == 5


@pytest.mark.parametrize(
    "outcomes,selected,coverage",
    [
        (["error"] * 3, 3, 0),
        (["not_assessable"], 1, 0),
        (["skipped"], 0, None),
        ([], 0, None),
    ],
)
def test_no_assessment_has_null_compliance(database, outcomes, selected, coverage):
    seed(database, outcomes, selected)
    with Session(database) as s:
        assert finalize_scan_if_complete(s, 1)
        row = s.execute(text("SELECT * FROM scan WHERE id=1")).mappings().one()
        assert row["compliance_score"] is None
        assert row["coverage_score"] == coverage


def test_redelivery_cannot_rewrite_first_terminal_result(database):
    seed(database, ["pending"], 1)
    with Session(database) as s:
        assert update_scan_result(
            s,
            1,
            "indeterminate",
            message="Original",
            reason_code="insufficient_evidence",
            provenance={"input_digest": "synthetic-digest"},
        )
        assert not update_scan_result(
            s,
            1,
            "passed",
            message="Overwrite",
            provenance={"input_digest": "different"},
        )
        finalize_scan_if_complete(s, 1)
        row = s.execute(text("SELECT * FROM scan_result WHERE id=1")).mappings().one()
        assert row["status"] == "indeterminate"
        assert row["message"] == "Original"
        assert row["provenance"] == {"input_digest": "synthetic-digest"}


def test_progress_counts_are_derived_while_pending(database):
    seed(database, ["passed", "indeterminate", "pending", "not_assessable"], 4)
    with Session(database) as s:
        assert not finalize_scan_if_complete(s, 1)
        row = s.execute(text("SELECT * FROM scan WHERE id=1")).mappings().one()
        assert row["passed_count"] == 1
        assert row["indeterminate_count"] == 1
        assert row["not_assessable_count"] == 1
        assert row["status"] == "running"


def test_concurrent_last_controls_finalize_once(database):
    from concurrent.futures import ThreadPoolExecutor
    from threading import Barrier

    seed(database, ["pending", "pending"], 2)
    barrier = Barrier(2)

    def finish(result_id):
        with Session(database) as session:
            barrier.wait(timeout=5)
            update_scan_result(
                session, result_id, "passed", provenance={"fixture": "synthetic"}
            )
            finalized = finalize_scan_if_complete(session, 1)
            session.commit()
            return finalized

    with ThreadPoolExecutor(max_workers=2) as pool:
        results = list(pool.map(finish, [1, 2]))
    assert sorted(results) == [False, True]
    with database.connect() as c:
        row = c.execute(text("SELECT * FROM scan WHERE id=1")).mappings().one()
        assert row["status"] == "completed"
        assert row["passed_count"] == 2
        assert row["compliance_score"] == row["coverage_score"] == 100


def test_concurrent_duplicate_delivery_counts_once(database):
    from concurrent.futures import ThreadPoolExecutor

    seed(database, ["pending"], 1)

    def finish(_):
        with Session(database) as session:
            changed = update_scan_result(
                session, 1, "passed", provenance={"fixture": "synthetic"}
            )
            finalize_scan_if_complete(session, 1)
            session.commit()
            return changed

    with ThreadPoolExecutor(max_workers=2) as pool:
        results = list(pool.map(finish, [1, 2]))
    assert sorted(results) == [False, True]
    with database.connect() as c:
        assert (
            c.execute(text("SELECT passed_count FROM scan WHERE id=1")).scalar_one()
            == 1
        )
