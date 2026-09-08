"""A non-UTC PostgreSQL server must not fail scans or misstamp naive columns.

Phase 6 wrote every scan / scan_result / scan_dispatch timestamp as TIMESTAMP
WITHOUT TIME ZONE holding naive UTC, but compared and assigned them with bare
``now()``, which is timestamptz and is cast to the SERVER's local wall clock.
On any non-UTC server that made every fresh scan look past its deadline. These
tests pin the repaired behaviour in both directions: the non-UTC session proves
the defect is gone, the UTC session proves the repair is a no-op on CI.
"""

import re
import tokenize
from contextlib import contextmanager
from datetime import datetime, timedelta, timezone
from pathlib import Path
from unittest.mock import MagicMock

import pytest
from sqlalchemy import text
from sqlalchemy.orm import Session

from tests.test_phase3_persistence import database as _database, seed
from tests.test_phase6_lifecycle import lifecycle as _lifecycle

from worker import db, dispatcher
from worker import lifecycle as worker_lifecycle

database = _database
lifecycle = _lifecycle

# East of UTC, so a wall-clock cast lands in the future and the defect is loud.
NON_UTC = "Australia/Melbourne"
DISPATCH_ID = "3f0a5f36-1b5f-4d6c-9a0f-2f5f2f7c8d10"
SOURCES = (
    Path(dispatcher.__file__),
    Path(db.__file__),
    Path(worker_lifecycle.__file__),
)


def _utc_now() -> datetime:
    """The naive-UTC clock the API writes into these columns."""
    return datetime.now(timezone.utc).replace(tzinfo=None)


def _is_recent_utc(stamp) -> bool:
    return stamp is not None and abs((stamp - _utc_now()).total_seconds()) < 60


def _sessions(engine, zone):
    """Session factory whose connection reports the given server timezone."""

    @contextmanager
    def session():
        with Session(engine) as opened:
            with opened.begin():
                opened.execute(
                    text("SELECT set_config('TimeZone', :zone, false)"), {"zone": zone}
                )
                yield opened

    return session


def _dispatch_under(fixture, monkeypatch, zone):
    """Seed one pending scan with naive-UTC stamps and run a dispatcher tick."""
    engine, _ = fixture
    monkeypatch.setattr(dispatcher, "get_db_session", _sessions(engine, zone))
    send = MagicMock()
    monkeypatch.setattr(dispatcher.celery_app, "send_task", send)
    stamped = _utc_now()
    with engine.begin() as connection:
        # Reuse the scan's own dispatch identity so reconcile's ON CONFLICT
        # enqueue is a no-op and exactly one row can ever be published.
        connection.execute(
            text("""UPDATE scan SET status='pending', last_progress_at=:stamped,
            deadline_at=:deadline, dispatch_id=:dispatch WHERE id=1"""),
            {
                "stamped": stamped,
                "deadline": stamped + timedelta(hours=1),
                "dispatch": DISPATCH_ID,
            },
        )
        connection.execute(
            text("""INSERT INTO scan_dispatch (id, scan_id, task_name, available_at)
            VALUES (:id, 1, 'worker.tasks.run_scan', :available)"""),
            {"id": DISPATCH_ID, "available": stamped},
        )
    published = dispatcher.tick()
    with engine.connect() as connection:
        scan = (
            connection.execute(text("SELECT * FROM scan WHERE id=1")).mappings().one()
        )
        reasons = (
            connection.execute(text("SELECT DISTINCT reason_code FROM scan_result"))
            .scalars()
            .all()
        )
        dispatched_at = connection.execute(
            text("SELECT dispatched_at FROM scan_dispatch WHERE id=:id"),
            {"id": DISPATCH_ID},
        ).scalar_one()
    assert scan["status"] == "pending"
    assert reasons == [None]
    assert published == 1
    assert send.call_args.args == ("worker.tasks.run_scan",)
    assert send.call_args.kwargs["kwargs"] == {"scan_id": 1}
    assert _is_recent_utc(dispatched_at)


def test_dispatcher_publishes_under_a_non_utc_session(lifecycle, monkeypatch):
    _dispatch_under(lifecycle, monkeypatch, NON_UTC)


def test_dispatcher_publishes_under_utc(lifecycle, monkeypatch):
    _dispatch_under(lifecycle, monkeypatch, "UTC")


def test_result_write_stamps_utc_under_a_non_utc_session(database):
    seed(database, ["pending"], 1)
    with _sessions(database, NON_UTC)() as session:
        assert db.update_scan_result(session, 1, "passed", message="synthetic")
    with database.connect() as connection:
        updated_at = connection.execute(
            text("SELECT updated_at FROM scan_result WHERE id=1")
        ).scalar_one()
        progressed = connection.execute(
            text("SELECT last_progress_at FROM scan WHERE id=1")
        ).scalar_one()
    assert _is_recent_utc(updated_at)
    assert _is_recent_utc(progressed)


def test_scan_progress_and_finish_stamp_utc_under_a_non_utc_session(database):
    seed(database, ["passed"], 1)
    sessions = _sessions(database, NON_UTC)
    with database.begin() as connection:
        connection.execute(
            text("UPDATE scan SET status='pending', last_progress_at=NULL WHERE id=1")
        )
    with sessions() as session:
        db.update_scan_status(session, 1, "running")
    with sessions() as session:
        assert db.finalize_scan_if_complete(session, 1)
    with database.connect() as connection:
        row = (
            connection.execute(
                text("SELECT last_progress_at, finished_at FROM scan WHERE id=1")
            )
            .mappings()
            .one()
        )
    assert _is_recent_utc(row["last_progress_at"])
    assert _is_recent_utc(row["finished_at"])


def test_recovery_write_stamps_utc_under_a_non_utc_session(lifecycle):
    engine, _ = lifecycle
    with _sessions(engine, NON_UTC)() as session:
        assert worker_lifecycle.fail_scan(session, 1, "scan_deadline_exceeded")
    with engine.connect() as connection:
        stamps = (
            connection.execute(text("SELECT updated_at FROM scan_result"))
            .scalars()
            .all()
        )
    assert len(stamps) == 2
    assert all(_is_recent_utc(stamp) for stamp in stamps)


def _sql_without_comments(path: Path) -> str:
    """Token text with comments dropped; SQL strings survive intact."""
    with path.open(encoding="utf-8") as handle:
        return "\n".join(
            token.string
            for token in tokenize.generate_tokens(handle.readline)
            if token.type != tokenize.COMMENT
        )


@pytest.mark.parametrize("path", SOURCES, ids=lambda path: path.name)
def test_no_bare_now_remains(path):
    pinned = "now() AT TIME ZONE 'UTC'"
    source = _sql_without_comments(path)
    matches = list(re.finditer(r"(?<!ZONE ')\bnow\(\)", source))
    assert matches, f"{path.name} should still stamp time in SQL"
    for match in matches:
        assert (
            source[match.start() : match.start() + len(pinned)] == pinned
        ), f"{path.name} regained a bare now() against a naive column"
