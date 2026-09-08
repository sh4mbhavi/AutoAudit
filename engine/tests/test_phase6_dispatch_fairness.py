"""Locked scans must not starve unrelated due dispatches."""

from unittest.mock import MagicMock
from sqlalchemy import text
from sqlalchemy.orm import Session
from tests import test_phase6_lifecycle as lifecycle_helpers

from worker import dispatcher
from worker.lifecycle import enqueue

lifecycle = lifecycle_helpers.lifecycle
database = lifecycle_helpers.database


def test_locked_oldest_scan_does_not_starve_next_scan(lifecycle, monkeypatch):
    database, sessions = lifecycle
    monkeypatch.setattr(dispatcher, "get_db_session", sessions)
    monkeypatch.setattr(dispatcher.settings, "DISPATCH_BATCH_SIZE", 1)
    send = MagicMock()
    monkeypatch.setattr(dispatcher.celery_app, "send_task", send)
    with sessions() as s:
        enqueue(s, 1)
        s.execute(text("UPDATE scan_dispatch SET available_at=now()-interval '1 hour'"))
        s.execute(
            text(
                "INSERT INTO scan(id,status,selected_count,total_controls,correlation_id) VALUES(2,'pending',1,1,'second')"
            )
        )
        enqueue(s, 2)
    with Session(database) as locked:
        locked.execute(text("SELECT id FROM scan WHERE id=1 FOR UPDATE"))
        assert dispatcher.publish_due() == 1
    assert send.call_args.kwargs["kwargs"] == {"scan_id": 2}
