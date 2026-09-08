"""Durable creation, cancellation and migration regression coverage."""

import asyncio
from unittest.mock import MagicMock

from tests import test_phase3_scans as selection_helpers
from tests import test_migrations as migration_helpers
from tests.test_migrations import _alembic, _query

api = selection_helpers.api
create = selection_helpers.create
database_url = migration_helpers.database_url


def test_creation_commits_dispatch_without_contacting_broker(api):
    api[3].side_effect = RuntimeError("synthetic broker unavailable")
    response = create(api, ["1.1"])
    assert response.status_code == 201
    api[3].assert_not_called()
    records = [call.args[0] for call in api[1].add.call_args_list]
    outbox = [r for r in records if r.__tablename__ == "scan_dispatch"]
    assert len(outbox) == 1
    assert outbox[0].scan_id == 9
    assert outbox[0].task_name == "worker.tasks.run_scan"
    scan = next(r for r in records if r.__tablename__ == "scan")
    assert outbox[0].id == scan.dispatch_id
    assert scan.deadline_at > scan.last_progress_at
    api[1].commit.assert_awaited_once()


def test_request_correlation_is_preserved(api):
    from app.core.middleware import RequestLoggingMiddleware

    api[0].app.add_middleware(RequestLoggingMiddleware)
    response = api[0].post(
        "/scans/",
        headers={"X-Request-ID": "synthetic-request-42"},
        json={
            "m365_connection_id": 1,
            "framework": "cis",
            "benchmark": "m365",
            "version": "v1",
            "control_ids": ["1.1"],
        },
    )
    assert response.status_code == 201
    scan = next(
        c.args[0]
        for c in api[1].add.call_args_list
        if c.args[0].__tablename__ == "scan"
    )
    assert (
        scan.correlation_id
        == response.headers["X-Request-ID"]
        == "synthetic-request-42"
    )


def test_cancel_unknown_or_other_owner_is_404(api):
    result = MagicMock()
    result.scalar_one_or_none.return_value = None
    api[1].execute.return_value = result
    assert api[0].post("/scans/1/cancel").status_code == 404
    api[1].commit.assert_not_awaited()


def test_migration_adds_durable_queue_and_connection_binding(database_url):
    _alembic(database_url, "upgrade", "head")
    rows = asyncio.run(
        _query(
            database_url,
            "SELECT table_name,column_name FROM information_schema.columns WHERE table_name IN ('scan','scan_dispatch','m365_connection')",
        )
    )
    columns = {(r["table_name"], r["column_name"]) for r in rows}
    assert {
        ("scan", "dispatch_id"),
        ("scan", "deadline_at"),
        ("scan_dispatch", "available_at"),
        ("scan_dispatch", "attempts"),
        ("m365_connection", "sharepoint_admin_url"),
        ("m365_connection", "sharepoint_tenant_id"),
        ("m365_connection", "sharepoint_certificate_alias"),
    } <= columns


def test_sharepoint_configuration_rejects_cross_tenant_and_unsafe_urls():
    import pytest
    from pydantic import ValidationError
    from app.schemas.m365_connection import M365ConnectionCreate

    data = dict(  # nosec B106 # synthetic schema validation fixture
        name="Synthetic",
        tenant_id="00000000-0000-4000-8000-000000000001",
        client_id="00000000-0000-4000-8000-000000000002",
        client_secret="synthetic",  # pragma: allowlist secret - synthetic fixture or migration revision
        sharepoint_tenant_id="00000000-0000-4000-8000-000000000001",
        sharepoint_admin_url="https://contoso-admin.sharepoint.com",
        sharepoint_certificate_alias="contoso",
    )
    model = M365ConnectionCreate(**data)
    assert getattr(model, "sharepoint_admin_url", None) == data["sharepoint_admin_url"]
    for key, value in [
        ("sharepoint_tenant_id", data["client_id"]),
        ("sharepoint_admin_url", "http://contoso-admin.sharepoint.com"),
        ("sharepoint_admin_url", "https://contoso-admin.sharepoint.com.evil.invalid"),
        ("sharepoint_certificate_alias", "../../cert"),
        ("sharepoint_certificate_alias", "_contoso"),
        ("sharepoint_certificate_alias", "a" * 65),
        ("sharepoint_admin_url", None),
    ]:
        with pytest.raises(ValidationError):
            M365ConnectionCreate(**{**data, key: value})


def test_upgrade_populated_phase5_preserves_existing_evidence(database_url):
    from tests.test_migrations import _snapshot, _assert_preserved

    _alembic(
        database_url,
        "upgrade",
        "d5f02b84c731",  # pragma: allowlist secret
    )  # pragma: allowlist secret - migration revision
    asyncio.run(
        _query(
            database_url,
            """INSERT INTO "user" (id,role,email,hashed_password,is_active,is_superuser,is_verified)
    VALUES(1,'user','fixture@example.invalid','synthetic',true,false,true);
    INSERT INTO m365_connection(id,user_id,name,tenant_id,client_id,encrypted_client_secret)
    VALUES(1,1,'Synthetic','synthetic','synthetic','synthetic-ciphertext');
    INSERT INTO scan(id,user_id,m365_connection_id,framework,benchmark,version,status,selected_count,semantics_version,metadata_snapshot,metadata_digest,correlation_id)
    VALUES(1,1,1,'cis','m365','v6.0.0','completed',1,'phase3-v1','{"controls":[]}','synthetic','old-request');
    INSERT INTO scan_result(id,scan_id,control_id,status,selected,provenance,evidence)
    VALUES(1,1,'1.1.1','passed',true,'{"fixture":true}','{"preserved":true}');""",
            execute=True,
        )
    )
    before = asyncio.run(_snapshot(database_url))
    _alembic(database_url, "upgrade", "head")
    after = asyncio.run(_snapshot(database_url))
    _assert_preserved(before, after)
    assert after["scan"][0]["connection_snapshot"] is None
    assert after["m365_connection"][0]["sharepoint_admin_url"] is None
    assert after["scan_dispatch"] == []
    _alembic(database_url, "upgrade", "head")
    assert asyncio.run(_snapshot(database_url)) == after


def test_real_api_cancel_delete_and_ownership(database_url, monkeypatch):
    from types import SimpleNamespace
    from fastapi import FastAPI
    from fastapi.testclient import TestClient
    from sqlalchemy.ext.asyncio import create_async_engine, async_sessionmaker
    from sqlalchemy.pool import NullPool
    from app.api.v1 import scans
    from app.core.middleware import RequestLoggingMiddleware

    _alembic(database_url, "upgrade", "head")
    asyncio.run(
        _query(
            database_url,
            """INSERT INTO "user" (id,role,email,hashed_password,is_active,is_superuser,is_verified)
    VALUES(1,'user','one@example.invalid','synthetic',true,false,true),(2,'user','two@example.invalid','synthetic',true,false,true);
    INSERT INTO m365_connection(id,user_id,name,tenant_id,client_id,encrypted_client_secret)
    VALUES(1,1,'Synthetic','synthetic','synthetic','synthetic-ciphertext');""",
            execute=True,
        )
    )
    engine = create_async_engine(
        database_url.replace("postgresql://", "postgresql+asyncpg://"),
        poolclass=NullPool,
    )
    sessions = async_sessionmaker(engine, expire_on_commit=False)

    async def db():
        async with sessions() as session:
            yield session

    user = SimpleNamespace(id=1)
    app = FastAPI()
    app.include_router(scans.router)
    app.add_middleware(RequestLoggingMiddleware)
    app.dependency_overrides[scans.get_async_session] = db
    app.dependency_overrides[scans.get_current_user] = lambda: user
    reader = MagicMock()
    reader.get_benchmark_metadata.return_value = {
        "platform": "m365",
        "controls": [
            {
                "control_id": "1.1.1",
                "data_collector_id": "entra.synthetic",
                "policy_file": "synthetic.rego",
            },
            {"control_id": "1.1.2"},
        ],
    }
    monkeypatch.setattr(scans, "get_file_reader", lambda: reader)
    with TestClient(app) as client:
        response = client.post(
            "/scans/",
            json={
                "m365_connection_id": 1,
                "framework": "cis",
                "benchmark": "m365",
                "version": "v6.0.0",
                "control_ids": ["1.1.1"],
            },
            headers={"X-Request-ID": "cancel-fixture"},
        )
        assert response.status_code == 201, response.text
        scan_id = response.json()["id"]
        user.id = 2
        assert client.post(f"/scans/{scan_id}/cancel").status_code == 404
        assert client.delete(f"/scans/{scan_id}").status_code == 404
        user.id = 1
        assert client.post(f"/scans/{scan_id}/cancel").json()["status"] == "cancelled"
        summary = client.get(f"/scans/{scan_id}/summary").json()
        assert summary["pending_count"] == 0
        assert summary["indeterminate_count"] == 1
        assert summary["skipped_count"] == 1
        assert summary["compliance_score"] is None
        assert float(summary["coverage_score"]) == 0
        rows = client.get(f"/scans/{scan_id}/results").json()
        result = next(row for row in rows if row["selected"])
        assert result["reason_code"] == "scan_cancelled"
        assert result["provenance"]["control_id"] == "1.1.1"
        assert result["provenance"]["correlation_id"] == "cancel-fixture"
        assert result["provenance"]["recorded_at"]
        assert asyncio.run(_query(database_url, "SELECT * FROM scan_dispatch")) == []
        # Repeated cancellation preserves terminal evidence and timestamp.
        assert client.post(f"/scans/{scan_id}/cancel").json()["status"] == "cancelled"
        assert client.get(f"/scans/{scan_id}/results").json() == rows
        assert client.get(f"/scans/{scan_id}/summary").json() == summary
        assert client.delete(f"/scans/{scan_id}").status_code == 204
        assert client.get(f"/scans/{scan_id}").status_code == 404
        assert asyncio.run(_query(database_url, "SELECT * FROM scan_result")) == []
    asyncio.run(engine.dispose())


def test_sharepoint_readiness_includes_runtime_identity_permission():
    from app.services.scan_readiness import (
        extract_required_permissions,
        PERMISSION_PROBES,
    )

    assert "Sites.Read.All" in extract_required_permissions(
        [
            {
                "automation_status": "ready",
                "data_collector_id": "sharepoint.pnp.tenant",
                "requires_permissions": [],
            }
        ]
    )
    assert (
        PERMISSION_PROBES["Sites.Read.All"]
        == "/v1.0/sites/root?$select=webUrl,sharepointIds"
    )
