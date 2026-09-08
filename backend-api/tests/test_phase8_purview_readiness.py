"""Phase 8 readiness: non-Graph permissions and the latent Purview checks.

Two things are under test, and both are about refusing to answer a question the
build cannot answer:

* ``NON_GRAPH_PERMISSIONS`` is consulted before the Graph probe table, so
  Exchange.Manage, Exchange.ManageAsApp and SharePoint.Admin name the
  authorization system that actually grants them instead of rendering the
  misleading "No automatic probe is defined for this permission." Status and
  severity are unchanged from today's fallback, so ``ready`` is computed
  identically; only the message changes. A Graph path for any of these three
  would produce a confidently wrong pass or fail, so the overlap is forbidden.

* The Purview checks are latent. ``evaluate_scan_readiness`` emits none of them
  unless a caller resolves a ``PurviewScope``, and no call site does today, so
  existing readiness output is byte-identical. The moment a ``compliance.*``
  control is promoted to ``ready`` the binding check arms itself and an
  unconfigured connection becomes a critical failure.

Nothing here touches the network or a database: Graph auth, token acquisition
and the probe client are all replaced with local doubles.
"""

import asyncio
import json
import re
from pathlib import Path
from types import SimpleNamespace

import pytest

from app.services import scan_readiness
from app.services.scan_readiness import (
    NON_GRAPH_PERMISSIONS,
    PERMISSION_PROBES,
    PURVIEW_ORGANIZATION_RE,
    PurviewScope,
    ReadinessCheck,
    evaluate_scan_readiness,
    purview_in_scope,
    purview_readiness_checks,
)

REPO = Path(__file__).resolve().parents[2]
LIVE_METADATA = (
    REPO
    / "engine"
    / "policies"
    / "cis"
    / "microsoft-365-foundations"
    / "v6.0.0"
    / "metadata.json"
)

NON_GRAPH = ("Exchange.Manage", "Exchange.ManageAsApp", "SharePoint.Admin")

PURVIEW_KEYS = (
    "purview_binding",
    "purview_licensing",
    "purview_authentication",
    "purview_object_shape",
)

VALID_ORGANIZATION = "contoso.onmicrosoft.com"
TENANT_GUID = "6ba7b810-9dad-11d1-80b4-00c04fd430c8"


class _FakeResponse:
    def __init__(self, status_code: int = 200):
        self.status_code = status_code
        self.text = ""

    def json(self):
        return {}


class _FakeAsyncClient:
    """Records the Graph paths readiness actually requested."""

    requested: list[str] = []

    def __init__(self, *args, **kwargs):
        self.args = args
        self.kwargs = kwargs

    async def __aenter__(self):
        return self

    async def __aexit__(self, *exc_info):
        return False

    async def get(self, path, headers=None):
        type(self).requested.append(path)
        return _FakeResponse(200)


def _isolate_graph(monkeypatch):
    """Replace tenant authentication and the probe client with local doubles."""

    async def _validate(**kwargs):
        return {"id": "tenant"}

    async def _token(**kwargs):
        return "synthetic-token"

    _FakeAsyncClient.requested = []
    monkeypatch.setattr(scan_readiness, "validate_m365_connection", _validate)
    monkeypatch.setattr(scan_readiness, "acquire_graph_access_token", _token)
    monkeypatch.setattr(
        scan_readiness, "httpx", SimpleNamespace(AsyncClient=_FakeAsyncClient)
    )
    return _FakeAsyncClient


def _readiness(monkeypatch, required_permissions, **kwargs):
    _isolate_graph(monkeypatch)
    return asyncio.run(
        evaluate_scan_readiness(  # nosec B106 # synthetic fixture, not a credential
            tenant_id="00000000-0000-0000-0000-000000000001",
            client_id="00000000-0000-0000-0000-000000000002",
            client_secret="synthetic-secret",  # pragma: allowlist secret - synthetic fixture
            required_permissions=list(required_permissions),
            **kwargs,
        )
    )


def _check(result, key: str) -> ReadinessCheck:
    return next(check for check in result.checks if check.key == key)


def test_non_graph_permissions_have_no_graph_probe():
    # A Graph path for one of these would answer a question Graph is not asked.
    assert set(NON_GRAPH_PERMISSIONS) & set(PERMISSION_PROBES) == set()
    assert set(NON_GRAPH_PERMISSIONS) == set(NON_GRAPH)
    for permission, authority in NON_GRAPH_PERMISSIONS.items():
        assert authority.strip() == authority and authority


@pytest.mark.parametrize("permission", NON_GRAPH)
def test_non_graph_permission_message(monkeypatch, permission):
    result = _readiness(monkeypatch, [permission])
    check = _check(result, f"perm_{permission}")

    assert check.status == "warn"
    assert check.severity == "warning"
    assert check.label == f"Permission: {permission}"
    assert "Not a Microsoft Graph permission" in check.message
    assert NON_GRAPH_PERMISSIONS[permission] in check.message
    assert permission in result.unverified_permissions
    # The misleading fallback no longer renders for these three.
    assert all("No automatic probe is defined" not in c.message for c in result.checks)
    # Only the baseline Graph permissions were actually requested over the wire.
    assert sorted(_FakeAsyncClient.requested) == sorted(
        PERMISSION_PROBES[p] for p in scan_readiness.CRITICAL_BASELINE_PERMISSIONS
    )


def test_non_graph_permissions_do_not_change_readiness(monkeypatch):
    result = _readiness(monkeypatch, list(NON_GRAPH))
    assert result.ready is True
    assert result.missing_permissions == []
    assert result.unverified_permissions == sorted(NON_GRAPH)
    assert (
        result.summary == "Ready with warnings: some controls may be skipped or fail."
    )


def test_purview_scope_default_emits_nothing(monkeypatch):
    result = _readiness(monkeypatch, ["Sites.Read.All", *NON_GRAPH])
    assert [c.key for c in result.checks if c.key.startswith("purview_")] == []


def test_purview_in_scope_detection():
    assert purview_in_scope([]) is False
    assert (
        purview_in_scope(
            [
                {
                    "automation_status": "blocked",
                    "data_collector_id": "compliance.purview.dlp_policies",
                }
            ]
        )
        is False
    )
    assert (
        purview_in_scope(
            [
                {
                    "automation_status": "ready",
                    "data_collector_id": "compliance.purview.dlp_policies",
                }
            ]
        )
        is True
    )
    assert (
        purview_in_scope(
            [
                {
                    "automation_status": "ready",
                    "data_collector_id": "sharepoint.pnp.tenant",
                }
            ]
        )
        is False
    )
    assert (
        purview_in_scope([{"automation_status": "ready", "data_collector_id": None}])
        is False
    )

    # Live benchmark: no compliance control is ready, so Purview stays latent.
    controls = json.loads(LIVE_METADATA.read_text())["controls"]
    assert purview_in_scope(controls) is False


def test_out_of_scope_emits_one_advisory_check():
    checks = purview_readiness_checks(PurviewScope(in_scope=False))
    assert len(checks) == 1
    assert checks[0].key == "purview_binding"
    assert checks[0].status == "warn"
    assert checks[0].severity == "warning"
    assert "remain automation_status=blocked" in checks[0].message


def test_in_scope_unconfigured_is_a_critical_failure(monkeypatch):
    scope = PurviewScope(in_scope=True)
    binding = purview_readiness_checks(scope)[0]
    assert binding.key == "purview_binding"
    assert binding.status == "fail"
    assert binding.severity == "critical"
    assert "no Purview certificate binding" in binding.message

    result = _readiness(monkeypatch, ["Sites.Read.All"], purview_scope=scope)
    assert result.ready is False
    assert result.summary == "Not ready: resolve critical checks."
    assert _check(result, "purview_binding").status == "fail"


def test_in_scope_guid_organization_is_a_critical_failure():
    checks = purview_readiness_checks(
        PurviewScope(
            in_scope=True,
            compliance_certificate_alias="purview-audit",
            compliance_organization=TENANT_GUID,
        )
    )
    assert checks[0].status == "fail"
    assert checks[0].severity == "critical"
    assert ".onmicrosoft.com" in checks[0].message
    assert TENANT_GUID not in checks[0].message
    assert PURVIEW_ORGANIZATION_RE.match(TENANT_GUID) is None


def test_in_scope_configured_passes_binding_only(monkeypatch):
    scope = PurviewScope(
        in_scope=True,
        compliance_certificate_alias="purview-audit",
        compliance_organization=VALID_ORGANIZATION,
    )
    checks = purview_readiness_checks(scope)
    assert checks[0].key == "purview_binding"
    assert checks[0].status == "pass"
    assert checks[0].severity == "critical"
    for check in checks[1:]:
        assert check.status == "warn"
        assert check.severity == "warning"

    # A configured binding is not a critical failure, so the scan stays startable.
    result = _readiness(monkeypatch, ["Sites.Read.All"], purview_scope=scope)
    assert result.ready is True
    assert [c.key for c in result.checks if c.key.startswith("purview_")] == list(
        PURVIEW_KEYS
    )


def test_licensing_never_passes_and_leaks_nothing():
    scopes = [
        PurviewScope(in_scope=False),
        PurviewScope(in_scope=True),
        PurviewScope(in_scope=True, compliance_certificate_alias="purview-audit"),
        PurviewScope(in_scope=True, compliance_organization=VALID_ORGANIZATION),
        PurviewScope(
            in_scope=True,
            compliance_certificate_alias="purview-audit",
            compliance_organization=TENANT_GUID,
        ),
        PurviewScope(
            in_scope=True,
            compliance_certificate_alias="purview-audit",
            compliance_organization="",
        ),
        PurviewScope(
            in_scope=True,
            compliance_certificate_alias="purview-audit",
            compliance_organization=VALID_ORGANIZATION,
        ),
    ]

    seen = 0
    for scope in scopes:
        for check in purview_readiness_checks(scope):
            if check.key != "purview_licensing":
                continue
            seen += 1
            assert check.status == "warn"
            assert check.status != "pass"
            assert "UNVERIFIED" in check.message
            # No SKU part number, service plan id or tenant value is ever placed
            # in the message. The only digits are the CIS control reference and
            # the licensing tier the benchmark itself names.
            residue = check.message.replace("3.2.2", "").replace("E5 Level 1", "")
            assert not any(character.isdigit() for character in residue)
            assert re.search(r"[0-9a-fA-F]{8}-[0-9a-fA-F]{4}", check.message) is None
            assert re.search(r"[0-9a-fA-F]{8,}", check.message) is None
            assert VALID_ORGANIZATION not in check.message
            assert "purview-audit" not in check.message
            assert TENANT_GUID not in check.message

    # Every in-scope call emitted one licensing check; the out-of-scope call emitted none.
    assert seen == len(scopes) - 1


def test_check_order_is_fixed():
    checks = purview_readiness_checks(
        PurviewScope(
            in_scope=True,
            compliance_certificate_alias="purview-audit",
            compliance_organization=VALID_ORGANIZATION,
        )
    )
    assert [check.key for check in checks] == list(PURVIEW_KEYS)
