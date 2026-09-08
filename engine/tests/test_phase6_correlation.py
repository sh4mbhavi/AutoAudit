"""Correlation crosses collector HTTP, OPA and authenticated PowerShell boundaries."""

import asyncio
import logging
from unittest.mock import AsyncMock, MagicMock

from worker import tasks


def test_pipeline_preserves_correlation_without_cross_task_leak(monkeypatch, caplog):
    from collectors import graph_client, registry
    from opa_client import opa_client
    from types import SimpleNamespace

    request_ids = []
    client = graph_client.GraphClient.__new__(graph_client.GraphClient)
    client._get_access_token = AsyncMock(return_value="synthetic-token")
    # Phase 9 pools one httpx.AsyncClient per GraphClient instead of opening a
    # new one inside an `async with` for every request, so the substitute is the
    # client itself rather than an async context manager around it.
    http = MagicMock()
    http.is_closed = False
    http.aclose = AsyncMock()
    http.request = AsyncMock(
        return_value=MagicMock(content=b"{}", json=lambda: {}, status_code=200)
    )
    monkeypatch.setattr(graph_client.httpx, "AsyncClient", lambda **_: http)
    monkeypatch.setattr(graph_client, "GraphClient", lambda **_: client)

    async def collect(graph):
        await graph.get("/users")
        request_ids.append(http.request.call_args.kwargs["headers"].get("X-Request-ID"))
        return {}

    monkeypatch.setattr(
        registry, "get_collector", lambda _: SimpleNamespace(collect=collect)
    )
    monkeypatch.setattr(
        opa_client, "runtime_version", AsyncMock(return_value="synthetic")
    )
    monkeypatch.setattr(
        opa_client,
        "_execute",
        AsyncMock(
            return_value={
                "result": [
                    {
                        "expressions": [
                            {
                                "value": {
                                    "opa_version": "synthetic",
                                    "result": {
                                        "compliant": None,
                                        "message": "unknown",
                                        "details": {},
                                        "affected_resources": [],
                                    },
                                }
                            }
                        ]
                    }
                ]
            }
        ),
    )

    async def run():
        for correlation in ("request-one", "request-two"):
            await tasks._evaluate_control_async(
                "1.1.1",
                "entra.synthetic",
                "1.1.1_admin_cloud_only.rego",
                {
                    "tenant_id": "synthetic",
                    "client_id": "synthetic",
                    "client_secret": "synthetic",  # pragma: allowlist secret - synthetic fixture or migration revision
                },
                "cis",
                "microsoft-365-foundations",
                "v6.0.0",
                {"correlation_id": correlation},
            )

    with caplog.at_level(logging.INFO):
        asyncio.run(run())
    assert request_ids == ["request-one", "request-two"]
    assert any(
        getattr(record, "correlation_id", None) == "request-one"
        and "opa" in record.message
        for record in caplog.records
    )
    assert "synthetic-token" not in caplog.text


def test_powershell_http_carries_same_request_id(monkeypatch, caplog):
    import httpx
    from collectors import powershell_client
    from powershell.service import main
    from fastapi.testclient import TestClient
    from tests.test_phase5_powershell_boundary import (
        make_client,
        payload,
        SECRET,
        OP,
        COLLECTOR,
    )
    from worker.correlation import request_id

    seen = []

    def handle(request):
        seen.append(request.headers.get("X-Request-ID"))
        return httpx.Response(200, json={"success": True, "data": []})

    original = httpx.AsyncClient
    monkeypatch.setattr(
        powershell_client.httpx,
        "AsyncClient",
        lambda **kwargs: original(transport=httpx.MockTransport(handle), **kwargs),
    )
    token = request_id.set("powershell-fixture")
    try:
        asyncio.run(
            make_client("http://powershell-service:8001").run_operation(OP, COLLECTOR)
        )
    finally:
        request_id.reset(token)
    assert seen == ["powershell-fixture"]
    monkeypatch.setenv("POWERSHELL_SERVICE_SECRET", SECRET)
    monkeypatch.setattr(main, "execute_operation", lambda **_: [])
    with caplog.at_level(logging.INFO), TestClient(main.app) as client:
        response = client.post(
            "/execute",
            json=payload(),
            headers={"X-Service-Secret": SECRET, "X-Request-ID": seen[0]},
        )
    assert response.status_code == 200
    assert any(
        getattr(record, "correlation_id", None) == "powershell-fixture"
        and "powershell_operation_completed" in record.message
        for record in caplog.records
    )
    assert SECRET not in caplog.text
