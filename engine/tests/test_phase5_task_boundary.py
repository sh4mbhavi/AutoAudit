"""Identifier-only messages and just-in-time credential regression tests."""

import asyncio
import inspect
from contextlib import contextmanager
from unittest.mock import AsyncMock, MagicMock

import pytest
from worker import tasks
from worker.provenance import canonical_digest
from collectors.graph_client import GraphClient


def test_task_signature_has_identifiers_only():
    assert list(inspect.signature(tasks.evaluate_control.run).parameters) == [
        "scan_id",
        "result_id",
        "connection_id",
    ]


def test_orchestration_serializes_only_identifiers(monkeypatch):
    metadata = {
        "controls": [
            {
                "control_id": "1.1.1",
                "automation_status": "ready",
                "data_collector_id": "entra.roles.cloud_only_admins",
            }
        ]
    }
    scan = dict(
        status="pending",
        semantics_version="phase3-v1",
        metadata_snapshot=metadata,
        metadata_digest=canonical_digest(metadata),
        correlation_id="synthetic",
        m365_connection_id=3,
    )
    session = MagicMock()

    @contextmanager
    def database():
        yield session

    monkeypatch.setattr(tasks, "get_db_session", database)
    monkeypatch.setattr(tasks, "get_scan", lambda *_: scan)
    monkeypatch.setattr(tasks, "lock_scan", lambda *_: scan)
    monkeypatch.setattr(tasks, "update_scan_status", MagicMock())
    monkeypatch.setattr(
        tasks, "get_pending_scan_results", lambda *_: [{"id": 2, "control_id": "1.1.1"}]
    )
    send = MagicMock()
    monkeypatch.setattr(tasks, "enqueue", send)
    monkeypatch.setattr(tasks, "finalize_scan_if_complete", MagicMock())
    tasks.run_scan.run(1)
    assert send.call_args.args == (session, 1, 2)


@pytest.mark.parametrize("method", ["POST", "PATCH", "PUT", "DELETE", "HEAD", "get"])
def test_graph_rejects_non_get_before_token_acquisition(method):
    client = GraphClient.__new__(GraphClient)
    client._get_access_token = AsyncMock()
    with pytest.raises(ValueError, match="GET"):
        asyncio.run(client._request(method, "/users"))
    client._get_access_token.assert_not_called()


def execution_setup(monkeypatch):
    metadata = {
        "controls": [{"control_id": "1.1.1", "data_collector_id": "entra.synthetic"}]
    }
    scan = dict(
        status="running",
        semantics_version="phase3-v1",
        metadata_snapshot=metadata,
        metadata_digest=canonical_digest(metadata),
        correlation_id="synthetic",
        m365_connection_id=3,
        framework="cis",
        benchmark="microsoft-365-foundations",
        version="v6.0.0",
    )
    row = dict(status="pending", selected=True, control_id="1.1.1")

    @contextmanager
    def database():
        yield MagicMock()

    monkeypatch.setattr(tasks, "get_db_session", database)
    monkeypatch.setattr(tasks, "get_scan", lambda *_: scan)
    monkeypatch.setattr(tasks, "lock_scan", lambda *_: scan)
    monkeypatch.setattr(tasks, "get_execution_result", lambda *_: row)
    monkeypatch.setattr(tasks, "finalize_scan_if_complete", MagicMock())
    return scan, row


@pytest.mark.parametrize(
    "change", ["connection", "missing_result", "digest", "terminal", "unselected"]
)
def test_invalid_context_never_decrypts(monkeypatch, change):
    scan, row = execution_setup(monkeypatch)
    if change == "connection":
        scan["m365_connection_id"] = 4
    if change == "missing_result":
        monkeypatch.setattr(tasks, "get_execution_result", lambda *_: None)
    if change == "digest":
        scan["metadata_digest"] = "invalid"
    if change == "terminal":
        row["status"] = "passed"
    if change == "unselected":
        row["selected"] = False
    decrypt = MagicMock()
    monkeypatch.setattr(tasks, "get_execution_credentials", decrypt)
    if change in {"terminal", "unselected", "missing_result"}:
        assert tasks.evaluate_control.run(1, 2, 3)["status"] == "ignored"
    else:
        with pytest.raises(ValueError):
            tasks.evaluate_control.run(1, 2, 3)
    decrypt.assert_not_called()


def test_execution_clears_credentials_and_redacts_failures(monkeypatch):
    execution_setup(monkeypatch)
    credentials = {
        "client_secret": "SYNTHETIC_SENSITIVE_CANARY"  # pragma: allowlist secret
    }  # pragma: allowlist secret
    monkeypatch.setattr(tasks, "get_execution_credentials", lambda *_: credentials)
    monkeypatch.setattr(
        tasks,
        "_evaluate_control_async",
        AsyncMock(side_effect=RuntimeError(credentials["client_secret"])),
    )
    saved = MagicMock()
    monkeypatch.setattr(tasks, "update_scan_result", saved)
    tasks.evaluate_control.push_request(retries=3)
    try:
        outcome = tasks.evaluate_control.run(1, 2, 3)
    finally:
        tasks.evaluate_control.pop_request()
    assert credentials == {}
    assert "SYNTHETIC_SENSITIVE_CANARY" not in repr((outcome, saved.call_args))
    assert outcome["status"] == "error"


def test_retry_uses_identifier_only_envelope_and_redacted_exception(monkeypatch):
    execution_setup(monkeypatch)
    credentials = {
        "client_secret": "SYNTHETIC_RETRY_CANARY"  # pragma: allowlist secret
    }  # pragma: allowlist secret
    monkeypatch.setattr(tasks, "get_execution_credentials", lambda *_: credentials)
    monkeypatch.setattr(
        tasks,
        "_evaluate_control_async",
        AsyncMock(side_effect=RuntimeError(credentials["client_secret"])),
    )
    retry = MagicMock(side_effect=RuntimeError("retry-scheduled"))
    monkeypatch.setattr(tasks.evaluate_control, "retry", retry)
    with pytest.raises(RuntimeError, match="retry-scheduled"):
        tasks.evaluate_control.run(1, 2, 3)
    assert credentials == {}
    assert str(retry.call_args.kwargs["exc"]) == "Control execution failed"
    assert set(retry.call_args.kwargs) == {"exc"}


def test_database_context_loading_does_not_select_credentials():
    from worker import db

    session = MagicMock()
    session.execute.return_value.fetchone.return_value = None
    assert db.get_scan(session, 1) is None
    query = str(session.execute.call_args.args[0])
    assert "encrypted_client_secret" not in query
    assert "m365_connection c" not in query


def test_credential_lookup_binds_scan_connection_and_owner(monkeypatch):
    from worker import db

    session = MagicMock()
    session.execute.return_value.mappings.return_value.first.return_value = None
    decrypt = MagicMock()
    monkeypatch.setattr(db, "decrypt", decrypt)
    with pytest.raises(ValueError, match="unavailable"):
        db.get_execution_credentials(session, 1, 3)
    query, values = session.execute.call_args.args
    assert "c.user_id=s.user_id" in str(query)
    assert values == {"scan_id": 1, "connection_id": 3}
    decrypt.assert_not_called()


def test_transient_context_lookup_failure_retries_without_decryption(monkeypatch):
    execution_setup(monkeypatch)
    monkeypatch.setattr(
        tasks, "get_scan", MagicMock(side_effect=RuntimeError("SYNTHETIC_DB_CANARY"))
    )
    decrypt = MagicMock()
    monkeypatch.setattr(tasks, "get_execution_credentials", decrypt)
    retry = MagicMock(side_effect=RuntimeError("retry-scheduled"))
    monkeypatch.setattr(tasks.evaluate_control, "retry", retry)
    with pytest.raises(RuntimeError, match="retry-scheduled"):
        tasks.evaluate_control.run(1, 2, 3)
    decrypt.assert_not_called()
    assert str(retry.call_args.kwargs["exc"]) == "Execution context unavailable"
    assert set(retry.call_args.kwargs) == {"exc"}
