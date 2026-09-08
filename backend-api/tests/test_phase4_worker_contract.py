"""HTTP scan creation -> serialized task -> real worker/OPA -> HTTP result."""

import asyncio
import json
import os
import subprocess  # nosec B404 # controlled worker subprocess for the synthetic API contract
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import MagicMock

import pytest
from cryptography.fernet import Fernet
from fastapi import FastAPI
from fastapi.testclient import TestClient
from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine
from sqlalchemy.pool import NullPool

from app.api.v1 import scans
from app.services import celery_client
from tests import test_migrations as migration_helpers
from tests.test_migrations import _alembic, _query

ROOT = Path(__file__).resolve().parents[2]
database_url = migration_helpers.database_url


@pytest.mark.skipif(not os.environ.get("OPA_BINARY"), reason="OPA_BINARY required")
def test_api_task_worker_result_contract(database_url, monkeypatch):
    _alembic(database_url, "upgrade", "head")
    encryption_key = Fernet.generate_key()
    monkeypatch.setenv("ENCRYPTION_KEY", encryption_key.decode())
    asyncio.run(
        _query(
            database_url,
            """
        INSERT INTO "user" (id,role,email,hashed_password,is_active,is_superuser,is_verified)
        VALUES (1,'user','contract@example.invalid','synthetic',true,false,true);
        INSERT INTO m365_connection (id,user_id,name,tenant_id,client_id,encrypted_client_secret)
        VALUES (1,1,'Synthetic','synthetic','synthetic','');
    """,
            execute=True,
        )
    )
    engine = create_async_engine(
        database_url.replace("postgresql://", "postgresql+asyncpg://"),
        poolclass=NullPool,
    )
    sessions = async_sessionmaker(engine, expire_on_commit=False)

    async def session():
        async with sessions() as db:
            yield db

    app = FastAPI()
    app.include_router(scans.router)
    app.dependency_overrides[scans.get_current_user] = lambda: SimpleNamespace(id=1)
    app.dependency_overrides[scans.get_async_session] = session
    metadata = {
        "platform": "m365",
        "controls": [
            {
                "control_id": "1.1.1",
                "automation_status": "ready",
                "data_collector_id": "entra.roles.cloud_only_admins",
                "policy_file": "1.1.1_admin_cloud_only.rego",
            },
            {"control_id": "1.1.2", "automation_status": "manual"},
        ],
    }
    reader = MagicMock()
    reader.get_benchmark_metadata.return_value = metadata
    monkeypatch.setattr(scans, "get_file_reader", lambda: reader)
    send = MagicMock(return_value=SimpleNamespace(id="synthetic-task"))
    monkeypatch.setattr(celery_client.celery_app, "send_task", send)
    with TestClient(app) as client:
        response = client.post(
            "/scans/",
            json={
                "m365_connection_id": 1,
                "framework": "cis",
                "benchmark": "microsoft-365-foundations",
                "version": "v6.0.0",
                "control_ids": ["1.1.1", "1.1.2"],
            },
        )
        assert response.status_code == 201, response.text
        scan_id = response.json()["id"]
        send.assert_not_called()
        outbox = asyncio.run(
            _query(
                database_url,
                "SELECT * FROM scan_dispatch WHERE scan_id=$1",
                parameters=(scan_id,),
            )
        )
        assert len(outbox) == 1
        assert outbox[0]["task_name"] == "worker.tasks.run_scan"
        envelope = json.dumps({"task": outbox[0]["task_name"], "args": [scan_id]})
        script = """
import json, sys
from unittest.mock import AsyncMock, patch
from worker import tasks, db, dispatcher
from sqlalchemy import text
from cryptography.fernet import Fernet
import os
with db.get_db_session() as session:
    session.execute(text("UPDATE m365_connection SET encrypted_client_secret=:secret WHERE id=1"), {"secret": Fernet(os.environ["ENCRYPTION_KEY"].encode()).encrypt(b"synthetic-fixture").decode()})
from collectors import registry, graph_client
from kombu.serialization import dumps, loads
message = json.loads(sys.argv[1])
def execute_serialized(**kwargs):
    assert set(kwargs) == {"scan_id", "result_id", "connection_id"}
    assert all(type(value) is int for value in kwargs.values())
    content_type, encoding, body = dumps(kwargs, serializer="json")
    assert "synthetic-fixture" not in body
    tasks.evaluate_control.run(**loads(body, content_type, encoding))
assert message["task"] == tasks.run_scan.name
collector = type("SyntheticCollector", (), {"collect": AsyncMock(return_value={})})()
messages = []
def capture(task_name, **options):
    assert options["headers"]["correlation_id"]
    messages.append((task_name, options["kwargs"]))
with patch.object(registry, "get_collector", return_value=collector), patch.object(graph_client, "GraphClient", return_value=object()), patch.object(dispatcher.celery_app, "send_task", side_effect=capture):
    dispatcher.tick()
    name, kwargs = messages.pop(0)
    assert name == tasks.run_scan.name
    tasks.run_scan.run(**kwargs)
    dispatcher.tick()
    for name, kwargs in messages:
        assert name == tasks.evaluate_control.name
        execute_serialized(**kwargs)
"""
        result = subprocess.run(
            [
                "uv",
                "run",
                "--frozen",
                "--project",
                str(ROOT / "engine"),
                "--extra",
                "dev",
                "python",
                "-c",
                script,
                envelope,
            ],
            cwd=ROOT / "engine",
            env={**os.environ, "DATABASE_URL": database_url},
            capture_output=True,
            text=True,
            timeout=90,
        )  # nosec B603, B607 # fixed uv/Python script and JSON-encoded synthetic task
        assert result.returncode == 0, result.stdout + result.stderr
        summary = client.get(f"/scans/{scan_id}/summary")
        assert summary.status_code == 200, summary.text
        body = summary.json()
        assert body["status"] == "completed"
        assert body["compliance_score"] is None
        assert float(body["coverage_score"]) == 0
        assert body["indeterminate_count"] == 1
        assert body["not_assessable_count"] == 1
        response = client.get(f"/scans/{scan_id}/results")
        assert response.status_code == 200, response.text
        results = response.json()
        executed = next(row for row in results if row["control_id"] == "1.1.1")
        assert executed["status"] == "indeterminate"
        assert executed["provenance"]["metadata_digest"] == body["metadata_digest"]
        assert executed["provenance"]["opa_version"] == "1.20.2"
    asyncio.run(engine.dispose())
