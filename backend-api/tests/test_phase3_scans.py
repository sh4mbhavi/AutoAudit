"""Phase 3 selection, frozen inputs and complete response semantics."""

import hashlib
import json
from datetime import datetime
from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock
from uuid import UUID

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient
from pydantic import ValidationError

from app.api.v1 import scans
from app.models.compliance import Scan
from app.models.scan_result import ScanResult
from app.schemas.scan import ScanListItem, ScanRead, ScanResultRead, ScanSummary


@pytest.fixture
def api(monkeypatch):
    metadata = {
        "platform": "m365",
        "name": "Tést",
        "controls": [
            {"control_id": "1.1", "automation_status": "automated"},
            {"control_id": "1.2", "automation_status": "manual"},
            {"control_id": "2.1", "automation_status": "not_implemented"},
        ],
    }
    reader = MagicMock()
    reader.get_benchmark_metadata.return_value = metadata
    reader.list_controls.return_value = metadata["controls"]
    monkeypatch.setattr(scans, "get_file_reader", lambda: reader)
    queue = MagicMock(return_value=SimpleNamespace(id="fixture-task"))
    monkeypatch.setattr(scans, "queue_scan", queue)
    db = MagicMock()
    db.execute = AsyncMock(return_value=MagicMock())
    db.execute.return_value.scalar_one_or_none.return_value = SimpleNamespace(id=1)

    async def flush():
        for call in db.add.call_args_list:
            if isinstance(call.args[0], Scan):
                call.args[0].id = 9

    db.flush = AsyncMock(side_effect=flush)
    db.commit = AsyncMock()
    db.refresh = AsyncMock()
    app = FastAPI()
    app.include_router(scans.router)
    app.dependency_overrides[scans.get_current_user] = lambda: SimpleNamespace(id=7)
    app.dependency_overrides[scans.get_async_session] = lambda: db
    return TestClient(app), db, metadata, queue, reader


def create(api, ids):
    return api[0].post(
        "/scans/",
        json={
            "m365_connection_id": 1,
            "framework": "cis",
            "benchmark": "m365",
            "version": "v1",
            "control_ids": ids,
        },
    )


@pytest.mark.parametrize(
    "ids,code",
    [
        ([], "empty_selection"),
        (["unknown"], "unknown_control_ids"),
        (["1.1", "unknown"], "unknown_control_ids"),
    ],
)
def test_invalid_selection_rejected_before_mutation(api, ids, code):
    response = create(api, ids)
    assert response.status_code == 422
    assert response.json()["detail"]["code"] == code
    if code == "unknown_control_ids":
        assert response.json()["detail"]["unknown_control_ids"] == ["unknown"]
    api[1].add.assert_not_called()
    api[1].flush.assert_not_awaited()
    api[1].commit.assert_not_awaited()
    api[3].assert_not_called()


def test_empty_benchmark_rejected_before_mutation(api):
    api[2]["controls"].clear()
    assert create(api, None).status_code == 422
    api[1].add.assert_not_called()


@pytest.mark.parametrize(
    "ids,selected", [(None, {"1.1", "1.2", "2.1"}), (["1.2", "1.2"], {"1.2"})]
)
def test_creation_freezes_metadata_and_explicit_selection(api, ids, selected):
    assert create(api, ids).status_code == 201
    records = [call.args[0] for call in api[1].add.call_args_list]
    scan = next(record for record in records if isinstance(record, Scan))
    assert getattr(scan, "selected_count", None) == len(selected)
    assert scan.semantics_version == "phase3-v1"
    assert UUID(scan.correlation_id).version == 4
    assert scan.metadata_snapshot == api[2]
    expected = hashlib.sha256(
        json.dumps(
            api[2], sort_keys=True, separators=(",", ":"), ensure_ascii=False
        ).encode()
    ).hexdigest()
    assert scan.metadata_digest == expected
    api[4].get_benchmark_metadata.assert_called_once()
    results = [record for record in records if isinstance(record, ScanResult)]
    assert len(results) == 3
    for result in results:
        assert result.selected is (result.control_id in selected)
        assert result.status == ("pending" if result.selected else "skipped")
        assert result.reason_code == (None if result.selected else "unselected")
    api[2]["name"] = "Changed after scan creation"
    assert scan.metadata_snapshot["name"] == "Tést"


@pytest.mark.parametrize("schema", [ScanRead, ScanListItem, ScanSummary])
def test_scan_contract_has_nullable_legacy_attribution_and_all_counts(schema):
    expected = {
        "selected_count",
        "coverage_score",
        "indeterminate_count",
        "not_assessable_count",
        "pending_count",
        "semantics_version",
        "metadata_digest",
        "correlation_id",
    }
    assert expected <= schema.model_fields.keys()
    assert schema.model_fields["selected_count"].default is None
    assert schema.model_fields["semantics_version"].default is None


def test_result_contract_is_typed_and_preserves_legacy_unknowns():
    data = dict(
        id=1,
        scan_id=1,
        control_id="1.1",
        status="not_assessable",
        message=None,
        evidence=None,
        created_at=datetime.now(),
        updated_at=datetime.now(),
    )
    result = ScanResultRead(**data)
    assert getattr(result, "selected", "missing") is None
    assert result.reason_code is None and result.provenance is None
    with pytest.raises(ValidationError):
        ScanResultRead(**{**data, "status": "made_up"})


def test_summary_includes_every_state_and_preserves_legacy_score(api):
    scan = SimpleNamespace(
        id=1,
        status="running",
        framework="cis",
        benchmark="m365",
        version="v1",
        started_at=datetime.now(),
        finished_at=None,
        compliance_score=47,
        total_controls=7,
        passed_count=1,
        failed_count=1,
        skipped_count=1,
        error_count=1,
        indeterminate_count=1,
        not_assessable_count=1,
        pending_count=1,
        selected_count=None,
        coverage_score=None,
        semantics_version=None,
        metadata_digest=None,
        correlation_id=None,
    )
    first, second = MagicMock(), MagicMock()
    first.scalar_one_or_none.return_value = scan
    states = [
        "pending",
        "passed",
        "failed",
        "error",
        "skipped",
        "indeterminate",
        "not_assessable",
    ]
    second.all.return_value = [(f"1.{i}", state) for i, state in enumerate(states)]
    api[1].execute.side_effect = [first, second]
    response = api[0].get("/scans/1/summary")
    assert response.status_code == 200, response.text
    body = response.json()
    assert all(body["categories"][0].get(state) == 1 for state in states)
    assert body["selected_count"] is None and body["coverage_score"] is None
    assert float(body["compliance_score"]) == 47


def test_invalid_status_filter_rejected(api):
    assert api[0].get("/scans/1/results?status_filter=nonsense").status_code == 422


def test_unselected_terminal_snapshot_records_no_execution(api):
    api[2]["controls"][1]["data_collector_id"] = "manual_collector"
    assert create(api, ["1.1"]).status_code == 201
    records = [call.args[0] for call in api[1].add.call_args_list]
    scan = next(record for record in records if isinstance(record, Scan))
    result = next(
        record
        for record in records
        if isinstance(record, ScanResult) and record.control_id == "1.2"
    )
    snapshot = result.provenance
    assert snapshot is not None
    assert snapshot["schema_version"] == 1
    assert snapshot["control_id"] == "1.2"
    assert snapshot["collector_id"] == "manual_collector"
    assert snapshot["metadata_digest"] == scan.metadata_digest
    assert snapshot["correlation_id"] == scan.correlation_id
    assert snapshot["provenance_status"] == "not_executed"
    assert snapshot["reason_code"] == "unselected"
    assert datetime.fromisoformat(snapshot["recorded_at"]).tzinfo is not None
    for key in [
        "policy_digest",
        "policy_source",
        "engine_git_sha",
        "engine_image_digest",
        "input_digest",
        "evaluation_started_at",
        "opa_version",
        "collection_started_at",
        "collection_completed_at",
        "evaluated_at",
    ]:
        assert snapshot[key] is None
