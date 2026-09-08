"""Production migration + worker + real OPA integration using synthetic evidence."""

import json
import os
import subprocess
from contextlib import contextmanager
from pathlib import Path
from unittest.mock import AsyncMock
from uuid import uuid4

import pytest
from cryptography.fernet import Fernet
from sqlalchemy import text
from sqlalchemy.orm import Session

from tests import test_phase3_persistence as persistence_helpers
from worker import tasks, db
from worker.provenance import canonical_digest


database = persistence_helpers.database


@pytest.mark.skipif(not os.environ.get("OPA_BINARY"), reason="OPA_BINARY required")
@pytest.mark.parametrize(
    "data,expected,compliance,coverage",
    [
        ({}, "indeterminate", None, 0),
        (
            {
                "admin_accounts": [
                    {
                        "userPrincipalName": "synthetic@example.invalid",
                        "on_premises_sync_enabled": False,
                    }
                ]
            },
            "passed",
            100,
            50,
        ),
        (
            {
                "admin_accounts": [
                    {
                        "userPrincipalName": "synthetic@example.invalid",
                        "on_premises_sync_enabled": True,
                    }
                ]
            },
            "failed",
            0,
            50,
        ),
    ],
)
def test_migrated_scan_evaluates_and_freezes_provenance(
    database, monkeypatch, data, expected, compliance, coverage
):
    from collectors import registry, graph_client

    backend = Path(__file__).resolve().parents[2] / "backend-api"
    with database.begin() as connection:
        connection.execute(text("DROP TABLE scan_result"))
        connection.execute(text("DROP TABLE scan"))
    env = {
        **os.environ,
        "APP_ENV": "dev",
        "DATABASE_URL": str(database.url).replace(
            "postgresql://", "postgresql+asyncpg://"
        ),
        "ENCRYPTION_KEY": Fernet.generate_key().decode(),
        "SECRET_KEY": uuid4().hex + uuid4().hex,
    }
    migration = subprocess.run(
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
        env=env,
        capture_output=True,
        text=True,
        timeout=60,
    )
    assert migration.returncode == 0, migration.stdout + migration.stderr
    metadata = {
        "controls": [
            {
                "control_id": "1.1.1",
                "automation_status": "ready",
                "data_collector_id": "entra.synthetic",
                "policy_file": "1.1.1_admin_cloud_only.rego",
            },
            {"control_id": "1.1.2", "automation_status": "manual"},
        ]
    }
    with database.begin() as c:
        c.execute(
            text("""INSERT INTO "user" (id,role,email,hashed_password,is_active,is_superuser,is_verified)
            VALUES (1,'user','synthetic@example.invalid','synthetic',true,false,true)""")
        )
        c.execute(
            text("""INSERT INTO m365_connection (id,user_id,name,tenant_id,client_id,encrypted_client_secret)
            VALUES (1,1,'Synthetic','synthetic','synthetic','')""")
        )
        c.execute(
            text("""INSERT INTO scan (id,user_id,m365_connection_id,framework,benchmark,version,status,selected_count,total_controls,semantics_version,metadata_snapshot,metadata_digest,correlation_id)
            VALUES (1,1,1,'cis','microsoft-365-foundations','v6.0.0','pending',2,2,'phase3-v1',CAST(:metadata AS jsonb),:digest,:correlation)"""),
            {
                "metadata": json.dumps(metadata),
                "digest": canonical_digest(metadata),
                "correlation": str(uuid4()),
            },
        )
        c.execute(
            text(
                "INSERT INTO scan_result(id,scan_id,control_id,selected,status) VALUES (1,1,'1.1.1',true,'pending'),(2,1,'1.1.2',true,'pending')"
            )
        )

    @contextmanager
    def sessions():
        with Session(database) as session:
            yield session
            session.commit()

    monkeypatch.setattr(tasks, "get_db_session", sessions)
    cipher = Fernet(Fernet.generate_key())
    monkeypatch.setattr(db, "_fernet", cipher)
    with database.begin() as connection:
        connection.execute(
            text(
                "UPDATE m365_connection SET encrypted_client_secret=:secret WHERE id=1"
            ),
            {"secret": cipher.encrypt(b"synthetic-fixture").decode()},
        )

    monkeypatch.setattr(
        registry,
        "get_collector",
        lambda _: type("Collector", (), {"collect": AsyncMock(return_value=data)})(),
    )
    monkeypatch.setattr(graph_client, "GraphClient", lambda **_: object())
    from worker import dispatcher

    deliveries = []
    monkeypatch.setattr(dispatcher, "get_db_session", sessions)
    monkeypatch.setattr(
        dispatcher.celery_app,
        "send_task",
        lambda name, **kwargs: deliveries.append((name, kwargs)),
    )
    tasks.run_scan.run(1)
    dispatcher.tick()
    for name, delivery in deliveries:
        assert name == "worker.tasks.evaluate_control"
        tasks.evaluate_control.run(**delivery["kwargs"])
    with database.connect() as c:
        scan = c.execute(text("SELECT * FROM scan WHERE id=1")).mappings().one()
        results = (
            c.execute(text("SELECT * FROM scan_result ORDER BY id")).mappings().all()
        )
        assert scan["status"] == "completed"
        assert scan["compliance_score"] == compliance
        assert scan["coverage_score"] == coverage
        assert scan["not_assessable_count"] == 1
        assert results[0]["status"] == expected
        assert results[1]["status"] == "not_assessable"
        provenance = results[0]["provenance"]
        assert provenance["metadata_digest"] == scan["metadata_digest"]
        assert provenance["correlation_id"] == scan["correlation_id"]
        assert provenance["input_digest"] == canonical_digest(data)
        assert provenance["policy_source"]
        assert provenance["opa_version"]
    # Redelivery preserves exact first result and summary without recapture.
    tasks.run_scan.run(1)
    with database.connect() as c:
        assert (
            c.execute(text("SELECT * FROM scan_result ORDER BY id")).mappings().all()
            == results
        )
