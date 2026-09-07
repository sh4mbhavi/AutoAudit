"""SharePoint can only execute after selected-tenant identity proof."""

import asyncio
from unittest.mock import AsyncMock, MagicMock

import pytest
from worker import tasks

TENANT = "00000000-0000-4000-8000-000000000001"
OTHER = "00000000-0000-4000-8000-000000000002"


def credentials():
    return dict(
        tenant_id=TENANT,
        client_id=OTHER,
        client_secret="synthetic",  # pragma: allowlist secret - synthetic fixture or migration revision
        sharepoint_admin_url="https://contoso-admin.sharepoint.com",
        sharepoint_tenant_id=TENANT,
        sharepoint_certificate_alias="contoso",
    )


@pytest.mark.parametrize(
    "change", ["missing", "tenant", "host", "unproven", "forbidden"]
)
def test_unproven_sharepoint_never_executes_or_evaluates(monkeypatch, change):
    from collectors import graph_client, powershell_client, registry
    from opa_client import opa_client

    creds = credentials()
    site = {
        "webUrl": "https://contoso.sharepoint.com",
        "sharepointIds": {"tenantId": TENANT},
    }
    if change == "missing":
        creds["sharepoint_admin_url"] = None
    if change == "tenant":
        creds["sharepoint_tenant_id"] = OTHER
    if change == "host":
        site["webUrl"] = "https://foreign.sharepoint.com"
    if change == "unproven":
        site["sharepointIds"] = {}
    graph = MagicMock()
    graph.get = AsyncMock(
        return_value=site,
        side_effect=RuntimeError("synthetic forbidden")
        if change == "forbidden"
        else None,
    )
    monkeypatch.setattr(graph_client, "GraphClient", MagicMock(return_value=graph))
    power = MagicMock()
    monkeypatch.setattr(powershell_client, "PowerShellClient", power)
    collector = MagicMock()
    collector.collect = AsyncMock(return_value={})
    monkeypatch.setattr(registry, "get_collector", lambda _: collector)
    opa = AsyncMock()
    monkeypatch.setattr(opa_client, "evaluate_snapshot", opa)
    result = asyncio.run(
        tasks._evaluate_control_async(
            "1.1.1",
            "sharepoint.pnp.tenant",
            "1.1.1_admin_cloud_only.rego",
            creds,
            "cis",
            "microsoft-365-foundations",
            "v6.0.0",
        )
    )
    assert result["compliant"] is None
    assert result["provenance"]["reason_code"] == "sharepoint_tenant_unverified"
    power.assert_not_called()
    collector.collect.assert_not_called()
    opa.assert_not_called()


def test_matching_identity_uses_connection_bound_url_and_alias(monkeypatch):
    from collectors import graph_client, powershell_client, registry
    from opa_client import opa_client
    from worker.result_contract import OPAResult
    from types import SimpleNamespace

    graph = MagicMock()
    graph.get = AsyncMock(
        return_value={
            "webUrl": "https://contoso.sharepoint.com/",
            "sharepointIds": {"tenantId": TENANT},
        }
    )
    monkeypatch.setattr(graph_client, "GraphClient", MagicMock(return_value=graph))
    power = MagicMock()
    monkeypatch.setattr(powershell_client, "PowerShellClient", power)
    collector = MagicMock()
    collector.collect = AsyncMock(return_value={})
    monkeypatch.setattr(registry, "get_collector", lambda _: collector)
    monkeypatch.setattr(
        opa_client, "runtime_version", AsyncMock(return_value="synthetic")
    )
    monkeypatch.setattr(
        opa_client,
        "evaluate_snapshot",
        AsyncMock(
            return_value=SimpleNamespace(
                opa_version="synthetic",
                result=OPAResult(
                    compliant=None, message="unknown", details={}, affected_resources=[]
                ),
            )
        ),
    )
    asyncio.run(
        tasks._evaluate_control_async(
            "1.1.1",
            "sharepoint.pnp.tenant",
            "1.1.1_admin_cloud_only.rego",
            credentials(),
            "cis",
            "microsoft-365-foundations",
            "v6.0.0",
        )
    )
    assert (
        power.call_args.kwargs["sharepoint_admin_url"]
        == credentials()["sharepoint_admin_url"]
    )
    assert power.call_args.kwargs["certificate_alias"] == "contoso"
    graph.get.assert_awaited_once_with(
        "/sites/root", params={"$select": "webUrl,sharepointIds"}
    )
