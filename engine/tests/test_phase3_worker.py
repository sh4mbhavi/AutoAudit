"""Worker regression tests without tenant credentials or external services."""

from contextlib import contextmanager
from unittest.mock import AsyncMock, MagicMock

import pytest

from worker import tasks


@pytest.fixture(autouse=True)
def execution_context(monkeypatch):
    metadata = {"controls": [{"control_id": "1.1.1"}]}
    monkeypatch.setattr(
        tasks,
        "get_scan",
        lambda *_: {
            "m365_connection_id": 3,
            "status": "running",
            "metadata_snapshot": metadata,
            "metadata_digest": tasks.canonical_digest(metadata),
            "semantics_version": "phase3-v1",
            "framework": "cis",
            "benchmark": "microsoft-365-foundations",
            "version": "v6.0.0",
            "correlation_id": "synthetic",
        },
    )
    monkeypatch.setattr(
        tasks,
        "get_execution_result",
        lambda *_: {
            "control_id": "1.1.1",
            "status": "pending",
            "selected": True,
        },
    )
    monkeypatch.setattr(tasks, "get_execution_credentials", lambda *_: {})


@pytest.mark.parametrize(
    "compliant,expected", [(True, "passed"), (False, "failed"), (None, "indeterminate")]
)
def test_worker_preserves_opa_uncertainty(monkeypatch, compliant, expected):
    session = MagicMock()

    @contextmanager
    def database():
        yield session

    monkeypatch.setattr(tasks, "get_db_session", database)
    monkeypatch.setattr(
        tasks,
        "_evaluate_control_async",
        AsyncMock(
            return_value={
                "compliant": compliant,
                "message": "Synthetic result",
                "details": {},
                "affected_resources": [],
            }
        ),
    )
    saved = MagicMock(return_value=True)
    monkeypatch.setattr(tasks, "update_scan_result", saved)
    monkeypatch.setattr(tasks, "finalize_scan_if_complete", MagicMock())
    tasks.evaluate_control.run(
        scan_id=1,
        result_id=2,
        connection_id=3,
    )
    assert saved.call_args.kwargs["status"] == expected


@pytest.mark.parametrize(
    "data",
    [
        {"error": "synthetic upstream failure"},
        {"success": False},
        {"collection_error": "synthetic failure"},
    ],
)
def test_collector_error_envelopes_never_reach_opa(monkeypatch, data):
    from collectors import registry, graph_client
    from opa_client import opa_client

    monkeypatch.setattr(
        registry,
        "get_collector",
        lambda _: type("Collector", (), {"collect": AsyncMock(return_value=data)})(),
    )
    monkeypatch.setattr(graph_client, "GraphClient", lambda **_: object())
    evaluate = AsyncMock()
    monkeypatch.setattr(opa_client, "evaluate_snapshot", evaluate, raising=False)
    with pytest.raises(Exception):
        import asyncio

        asyncio.run(
            tasks._evaluate_control_async(
                "1.1.1",
                "entra.synthetic",
                "1.1.1_admin_cloud_only.rego",
                {
                    "tenant_id": "synthetic",
                    "client_id": "synthetic",
                    "client_secret": "synthetic",  # pragma: allowlist secret - synthetic fixture
                },
                "cis",
                "microsoft-365-foundations",
                "v6.0.0",
            )
        )
    evaluate.assert_not_called()


def test_terminal_exception_is_error_and_redacted(monkeypatch):
    session = MagicMock()

    @contextmanager
    def database():
        yield session

    monkeypatch.setattr(tasks, "get_db_session", database)
    monkeypatch.setattr(
        tasks,
        "_evaluate_control_async",
        AsyncMock(side_effect=RuntimeError("SENSITIVE_SYNTHETIC_DIAGNOSTIC")),
    )
    saved = MagicMock(return_value=True)
    monkeypatch.setattr(tasks, "update_scan_result", saved)
    monkeypatch.setattr(tasks, "finalize_scan_if_complete", MagicMock())
    tasks.evaluate_control.push_request(retries=3)
    try:
        result = tasks.evaluate_control.run(
            1,
            2,
            3,
        )
    finally:
        tasks.evaluate_control.pop_request()
    assert saved.call_args.kwargs["status"] == "error"
    assert saved.call_args.kwargs["reason_code"] == "evaluation_error"
    assert "SENSITIVE_SYNTHETIC_DIAGNOSTIC" not in str(saved.call_args)
    assert "SENSITIVE_SYNTHETIC_DIAGNOSTIC" not in str(result)


@pytest.mark.parametrize(
    "data",
    [
        {},
        {"admin_accounts": []},
        {
            "admin_accounts": [
                {
                    "userPrincipalName": "synthetic@example.invalid",
                    "on_premises_sync_enabled": None,
                }
            ]
        },
    ],
)
def test_real_phase2_policy_uncertainty_has_complete_provenance(monkeypatch, data):
    import asyncio
    import os
    import hashlib

    if not os.environ.get("OPA_BINARY"):
        pytest.skip("OPA_BINARY required")
    from collectors import registry, graph_client

    monkeypatch.setattr(
        registry,
        "get_collector",
        lambda _: type("Collector", (), {"collect": AsyncMock(return_value=data)})(),
    )
    monkeypatch.setattr(graph_client, "GraphClient", lambda **_: object())
    result = asyncio.run(
        tasks._evaluate_control_async(
            "1.1.1",
            "entra.synthetic",
            "1.1.1_admin_cloud_only.rego",
            {
                "tenant_id": "synthetic",
                "client_id": "synthetic",
                "client_secret": "synthetic",  # pragma: allowlist secret - synthetic fixture
            },
            "cis",
            "microsoft-365-foundations",
            "v6.0.0",
            {
                "metadata_digest": "synthetic-digest",
                "correlation_id": "synthetic-correlation",
            },
        )
    )
    assert result["compliant"] is None
    provenance = result["provenance"]
    assert (
        provenance["policy_digest"]
        == hashlib.sha256(provenance["policy_source"].encode()).hexdigest()
    )
    assert provenance["input_digest"] == tasks.canonical_digest(data)
    for field in [
        "framework",
        "benchmark",
        "benchmark_version",
        "collector_id",
        "engine_git_sha",
        "engine_source_digest",
        "opa_version",
        "correlation_id",
        "metadata_digest",
        "collection_started_at",
        "collection_completed_at",
        "evaluation_started_at",
        "evaluated_at",
    ]:
        assert provenance[field]
    assert "synthetic-ciphertext" not in str(provenance)


@pytest.mark.parametrize(
    "automation_status", ["manual", "blocked", "deferred", "not_started"]
)
def test_selected_nonautomated_controls_are_not_skipped(monkeypatch, automation_status):
    from worker.provenance import canonical_digest

    session = MagicMock()

    @contextmanager
    def database():
        yield session

    metadata = {
        "controls": [{"control_id": "1.1.1", "automation_status": automation_status}]
    }
    scan = {
        "status": "pending",
        "semantics_version": "phase3-v1",
        "metadata_snapshot": metadata,
        "metadata_digest": canonical_digest(metadata),
        "correlation_id": "synthetic",
        "framework": "cis",
        "benchmark": "microsoft-365-foundations",
        "version": "v6.0.0",
        "tenant_id": "synthetic",
        "client_id": "synthetic",
        "client_secret": "synthetic",  # pragma: allowlist secret - synthetic fixture
    }
    monkeypatch.setattr(tasks, "get_db_session", database)
    monkeypatch.setattr(tasks, "get_scan", lambda *_: scan)
    monkeypatch.setattr(tasks, "lock_scan", lambda *_: scan)
    monkeypatch.setattr(
        tasks, "get_pending_scan_results", lambda *_: [{"id": 2, "control_id": "1.1.1"}]
    )
    saved = MagicMock(return_value=True)
    monkeypatch.setattr(tasks, "update_scan_result", saved)
    monkeypatch.setattr(tasks, "update_scan_status", MagicMock())
    monkeypatch.setattr(tasks, "finalize_scan_if_complete", MagicMock())
    dispatched = MagicMock()
    monkeypatch.setattr(tasks.evaluate_control, "delay", dispatched)
    tasks.run_scan.run(1)
    assert saved.call_args.kwargs["status"] == "not_assessable"
    assert saved.call_args.kwargs["reason_code"] == "not_automated"
    assert (
        saved.call_args.kwargs["provenance"]["metadata_digest"]
        == scan["metadata_digest"]
    )
    dispatched.assert_not_called()


@pytest.mark.parametrize("data", [None, [], "synthetic", 42])
def test_nonobject_input_retains_digest_without_false_assessment(monkeypatch, data):
    import asyncio
    from collectors import registry, graph_client

    monkeypatch.setattr(
        registry,
        "get_collector",
        lambda _: type("Collector", (), {"collect": AsyncMock(return_value=data)})(),
    )
    monkeypatch.setattr(graph_client, "GraphClient", lambda **_: object())
    result = asyncio.run(
        tasks._evaluate_control_async(
            "1.1.1",
            "entra.synthetic",
            "1.1.1_admin_cloud_only.rego",
            {
                "tenant_id": "synthetic",
                "client_id": "synthetic",
                "client_secret": "synthetic",  # pragma: allowlist secret - synthetic fixture
            },
            "cis",
            "microsoft-365-foundations",
            "v6.0.0",
        )
    )
    assert result["compliant"] is None
    assert result["provenance"]["input_digest"] == tasks.canonical_digest(data)
    assert result["provenance"]["opa_version"] is None
    assert result["provenance"]["provenance_status"] == "collection_only"


def test_policy_error_retains_opa_version_and_completion_time(monkeypatch):
    import asyncio
    import os

    if not os.environ.get("OPA_BINARY"):
        pytest.skip("OPA_BINARY required")
    from collectors import registry, graph_client

    monkeypatch.setattr(
        registry,
        "get_collector",
        lambda _: type("Collector", (), {"collect": AsyncMock(return_value={})})(),
    )
    monkeypatch.setattr(graph_client, "GraphClient", lambda **_: object())
    monkeypatch.setattr(tasks, "capture_policy", lambda *_: "invalid synthetic rego")
    with pytest.raises(tasks.EvaluationFailure) as failure:
        asyncio.run(
            tasks._evaluate_control_async(
                "1.1.1",
                "entra.synthetic",
                "policy.rego",
                {
                    "tenant_id": "synthetic",
                    "client_id": "synthetic",
                    "client_secret": "synthetic",  # pragma: allowlist secret - synthetic fixture
                },
                "cis",
                "microsoft-365-foundations",
                "v6.0.0",
            )
        )
    provenance = failure.value.provenance
    assert failure.value.reason_code == "evaluation_error"
    assert provenance["opa_version"]
    assert provenance["evaluated_at"] >= provenance["evaluation_started_at"]
    assert provenance["provenance_status"] == "incomplete"


def test_unverified_tenant_reason_survives_result_persistence(monkeypatch):
    @contextmanager
    def database():
        yield MagicMock()

    monkeypatch.setattr(tasks, "get_db_session", database)
    monkeypatch.setattr(
        tasks,
        "_evaluate_control_async",
        AsyncMock(
            return_value={
                "compliant": None,
                "message": "Unverified tenant",
                "details": {},
                "affected_resources": [],
                "provenance": {"reason_code": "sharepoint_tenant_unverified"},
            }
        ),
    )
    saved = MagicMock()
    monkeypatch.setattr(tasks, "update_scan_result", saved)
    monkeypatch.setattr(tasks, "finalize_scan_if_complete", MagicMock())
    tasks.evaluate_control.run(1, 2, 3)
    assert saved.call_args.kwargs["reason_code"] == "sharepoint_tenant_unverified"


def test_late_completion_reports_ignored_when_write_rejected(monkeypatch):
    session = MagicMock()

    @contextmanager
    def database():
        yield session

    monkeypatch.setattr(tasks, "get_db_session", database)
    monkeypatch.setattr(
        tasks,
        "_evaluate_control_async",
        AsyncMock(
            return_value={
                "compliant": True,
                "message": "synthetic",
                "details": {},
                "affected_resources": [],
            }
        ),
    )
    monkeypatch.setattr(tasks, "update_scan_result", MagicMock(return_value=False))
    monkeypatch.setattr(tasks, "finalize_scan_if_complete", MagicMock())
    assert tasks.evaluate_control.run(1, 2, 3)["status"] == "ignored"


def test_late_exhausted_error_reports_ignored_when_write_rejected(monkeypatch):
    session = MagicMock()

    @contextmanager
    def database():
        yield session

    monkeypatch.setattr(tasks, "get_db_session", database)
    monkeypatch.setattr(
        tasks,
        "_evaluate_control_async",
        AsyncMock(side_effect=RuntimeError("synthetic failure")),
    )
    monkeypatch.setattr(tasks, "update_scan_result", MagicMock(return_value=False))
    monkeypatch.setattr(tasks, "finalize_scan_if_complete", MagicMock())
    tasks.evaluate_control.push_request(retries=3)
    try:
        assert tasks.evaluate_control.run(1, 2, 3)["status"] == "ignored"
    finally:
        tasks.evaluate_control.pop_request()
