"""Contract tests for the Security & Compliance collectors.

Microsoft documents no return properties for Get-DlpCompliancePolicy or
Get-LabelPolicy, so every shape this codebase is willing to read is declared in
collectors/compliance/shape.py and pinned here. The recurring theme of these
tests is that unreadable evidence must stay unreadable: it may never collapse
into a zero, a shorter list, or a judgement fact that reads True.
"""

import asyncio
from pathlib import Path
import sys
from unittest.mock import AsyncMock, Mock

import pytest

ENGINE = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ENGINE))

DLP_COLLECTOR = "compliance.dlp_compliance_policy"
LABEL_COLLECTOR = "compliance.label_policy"
DLP_OP = "compliance.dlp_compliance_policy.read"
LABEL_OP = "compliance.label_policy.read"

TENANT_ID = "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"
CLIENT_ID = "12345678-1234-1234-1234-123456789abc"
ORGANIZATION = "contoso.onmicrosoft.com"

TEAMS_ENABLE_POLICY = {
    "Name": "Teams DLP",
    "Mode": "Enable",
    "Workload": "Exchange, Teams",
    "TeamsLocation": ["All"],
    "TeamsLocationException": [{"Name": "x"}],
}
NON_TEAMS_POLICY = {
    "Name": "Exchange only",
    "Mode": "Disable",
    "Workload": "Exchange, SharePoint",
    "TeamsLocation": [],
    "TeamsLocationException": [],
}
PUBLISHED_LABEL_POLICY = {
    "Name": "Published policy",
    "Type": "PublishedSensitivityLabel",
    "ExchangeLocation": ["All"],
    "SharePointLocation": [],
    "OneDriveLocation": [],
    "ModernGroupLocation": [],
}
OTHER_LABEL_POLICY = {
    "Name": "Label definition",
    "Type": "Label",
    "ExchangeLocation": [],
    "SharePointLocation": [],
    "OneDriveLocation": [],
    "ModernGroupLocation": [],
}


def collect(collector_id, response):
    from collectors.registry import get_collector

    client = type("Client", (), {"run_operation": AsyncMock(return_value=response)})()
    return asyncio.run(get_collector(collector_id).collect(client))


def make_client(**overrides):
    """A client with no MSAL network path, so token acquisition is observable."""
    from collectors.powershell_client import PowerShellClient

    client = PowerShellClient.__new__(PowerShellClient)
    client.tenant_id = TENANT_ID
    client.client_id = CLIENT_ID
    client.sharepoint_admin_url = "https://contoso-admin.sharepoint.com"
    client.certificate_alias = "spo"
    client.compliance_certificate_alias = "ipps"
    client.compliance_organization = ORGANIZATION
    client.service_url = "https://powershell.example.test"
    client.service_secret = "s" * 40  # pragma: allowlist secret
    client.service_ca_file = None
    client._msal_app = Mock()
    client._msal_app.acquire_token_for_client.return_value = {
        "access_token": "synthetic-token"
    }
    for name, value in overrides.items():
        setattr(client, name, value)
    return client


def test_success_projection():
    result = collect(DLP_COLLECTOR, [TEAMS_ENABLE_POLICY, NON_TEAMS_POLICY])

    assert result == {
        "dlp_policies": [
            {
                "name": "Teams DLP",
                "mode": "Enable",
                "workload_includes_teams": True,
                "teams_location": ["All"],
                "teams_location_exception": ["x"],
            },
            {
                "name": "Exchange only",
                "mode": "Disable",
                "workload_includes_teams": False,
                "teams_location": [],
                "teams_location_exception": [],
            },
        ],
        "total_policies": 2,
        "enabled_policy_count": 1,
        "dlp_policy_modes": ["Disable", "Enable"],
        "teams_policies": [
            {
                "name": "Teams DLP",
                "mode": "Enable",
                "workload_includes_teams": True,
                "teams_location": ["All"],
                "teams_location_exception": ["x"],
            }
        ],
        "teams_policy_count": 1,
        "teams_policy_mode_enable_count": 1,
        "teams_enforcing_policy_count": 1,
        "teams_location_exception_names": ["x"],
    }


@pytest.mark.parametrize("collector_id", [DLP_COLLECTOR, LABEL_COLLECTOR])
def test_empty_population_is_zero_not_true(collector_id):
    result = collect(collector_id, None)

    assert result["total_policies"] == 0
    counts = {key: value for key, value in result.items() if key.endswith("_count")}
    assert counts and all(value == 0 for value in counts.values()), counts
    assert not any(value is True for value in result.values())
    if collector_id == DLP_COLLECTOR:
        assert result["teams_enforcing_policy_count"] == 0
        assert result["teams_location_exception_names"] == []
    else:
        assert result["published_label_policy_location_scopes"] == []


def test_single_object_response_is_normalised():
    dlp = collect(DLP_COLLECTOR, dict(TEAMS_ENABLE_POLICY))
    assert dlp["total_policies"] == 1
    assert len(dlp["dlp_policies"]) == 1

    label = collect(LABEL_COLLECTOR, dict(PUBLISHED_LABEL_POLICY))
    assert label["total_policies"] == 1
    assert label["published_label_policy_count"] == 1


@pytest.mark.parametrize("collector_id", [DLP_COLLECTOR, LABEL_COLLECTOR])
@pytest.mark.parametrize(
    "envelope",
    [
        {"error": "AccessDenied"},
        {"collector_error": "throttled"},
        {"errors": ["partial collection"]},
        [{"Name": "a", "Mode": "Enable", "Type": "Label", "error": "partial"}],
    ],
)
def test_collector_error_envelope_is_rejected(collector_id, envelope):
    with pytest.raises(ValueError, match="collection error"):
        collect(collector_id, envelope)


@pytest.mark.parametrize("collector_id", [DLP_COLLECTOR, LABEL_COLLECTOR])
@pytest.mark.parametrize("response", ["malformed", 42, [1, 2]])
def test_malformed_response_is_rejected(collector_id, response):
    with pytest.raises(ValueError, match="PowerShell"):
        collect(collector_id, response)


@pytest.mark.parametrize(
    "record",
    [
        {"Mode": "Enable", "Workload": "Teams"},
        {"Name": "", "Mode": "Enable", "Workload": "Teams"},
        {"Name": 5, "Mode": "Enable", "Workload": "Teams"},
        {"Name": "a", "Workload": "Teams"},
        {"Name": "a", "Mode": None, "Workload": "Teams"},
        {"Name": "a", "Mode": 5, "Workload": "Teams"},
        {"Name": "a", "Mode": "", "Workload": "Teams"},
        {"Name": "a", "Mode": True, "Workload": "Teams"},
    ],
)
def test_missing_identity_or_mode_raises(record):
    with pytest.raises(ValueError, match="incomplete"):
        collect(DLP_COLLECTOR, [record])
    # A malformed record cannot hide behind a well-formed one either.
    with pytest.raises(ValueError, match="incomplete"):
        collect(DLP_COLLECTOR, [TEAMS_ENABLE_POLICY, record])


@pytest.mark.parametrize(
    "record",
    [
        {"Name": "a", "Type": None},
        {"Name": "a", "Type": ""},
        {"Name": "a", "Type": 5},
        {"Type": "PublishedSensitivityLabel"},
        {"Name": "", "Type": "PublishedSensitivityLabel"},
    ],
)
def test_missing_label_identity_or_type_raises(record):
    with pytest.raises(ValueError, match="incomplete"):
        collect(LABEL_COLLECTOR, [record])


@pytest.mark.parametrize("workload", [{}, 5, True, None, ["Teams", 5], [None]])
def test_malformed_workload_raises(workload):
    record = dict(TEAMS_ENABLE_POLICY, Workload=workload)
    with pytest.raises(ValueError, match="malformed"):
        collect(DLP_COLLECTOR, [record])


def test_location_shape_poisons_the_whole_list():
    unreadable_location = dict(TEAMS_ENABLE_POLICY, TeamsLocation=[{"NoName": 1}])
    result = collect(DLP_COLLECTOR, [unreadable_location, NON_TEAMS_POLICY])
    assert result["teams_policy_count"] == 1
    assert result["teams_policies"][0]["teams_location"] is None
    # Not 0, and not a shorter list with the unreadable element dropped.
    assert result["teams_enforcing_policy_count"] is None

    mixed_exception = dict(TEAMS_ENABLE_POLICY, TeamsLocationException=["a", 7])
    result = collect(DLP_COLLECTOR, [mixed_exception])
    assert result["teams_policies"][0]["teams_location_exception"] is None
    assert result["teams_location_exception_names"] is None
    # The readable half of the audit is still decided.
    assert result["teams_enforcing_policy_count"] == 1


def test_teams_matching_is_conjunctive():
    specific = dict(TEAMS_ENABLE_POLICY, TeamsLocation=["Specific"])
    result = collect(DLP_COLLECTOR, [specific])

    assert result["teams_policy_count"] == 1
    assert result["teams_policy_mode_enable_count"] == 1
    assert result["teams_enforcing_policy_count"] == 0

    all_but_disabled = dict(TEAMS_ENABLE_POLICY, Mode="TestWithNotifications")
    result = collect(DLP_COLLECTOR, [all_but_disabled])
    assert result["teams_policy_mode_enable_count"] == 0
    assert result["teams_enforcing_policy_count"] == 0
    # An unrecognised Mode token is reported, never classified.
    assert result["dlp_policy_modes"] == ["TestWithNotifications"]


def test_label_published_filter_and_scopes():
    result = collect(LABEL_COLLECTOR, [PUBLISHED_LABEL_POLICY, OTHER_LABEL_POLICY])

    assert result["total_policies"] == 2
    assert result["published_label_policy_count"] == 1
    assert result["published_label_policies"] == [
        {
            "name": "Published policy",
            "type": "PublishedSensitivityLabel",
            "location_scopes": ["exchange"],
        }
    ]
    assert result["published_label_policy_location_scopes"] == ["exchange"]
    # Location contents never reach the return value, only scope names.
    assert "All" not in repr(result["published_label_policy_location_scopes"])


def test_label_location_shape_poisons_scopes():
    unreadable = dict(PUBLISHED_LABEL_POLICY, OneDriveLocation="All")
    result = collect(LABEL_COLLECTOR, [unreadable])

    assert result["published_label_policy_count"] == 1
    assert result["published_label_policies"][0]["location_scopes"] is None
    assert result["published_label_policy_location_scopes"] is None


@pytest.mark.parametrize("collector_id", [DLP_COLLECTOR, LABEL_COLLECTOR])
@pytest.mark.parametrize("message", ["403 Forbidden", "429 Too Many Requests"])
def test_403_and_429_never_return_an_assessment(collector_id, message):
    from collectors.powershell_client import PowerShellExecutionError
    from collectors.registry import get_collector

    client = type(
        "Client",
        (),
        {"run_operation": AsyncMock(side_effect=PowerShellExecutionError(message))},
    )()
    with pytest.raises(PowerShellExecutionError):
        asyncio.run(get_collector(collector_id).collect(client))


@pytest.mark.parametrize("operation_id", [DLP_OP, LABEL_OP])
def test_client_keeps_compliance_alias_separate(operation_id):
    collector_id = operation_id.rsplit(".", 1)[0]
    request = make_client()._request(operation_id, collector_id, {})

    assert request.compliance_certificate_alias == "ipps"
    assert request.compliance_organization == ORGANIZATION
    assert request.certificate_alias is None
    assert request.sharepoint_admin_url is None
    assert request.client_id == CLIENT_ID
    assert request.token is None and request.graph_token is None
    # -Organization is its own field; the tenant id is never overloaded into it.
    assert request.compliance_organization != request.tenant_id

    sharepoint = make_client()._request(
        "sharepoint.pnp.tenant.read", "sharepoint.pnp.tenant", {}
    )
    assert sharepoint.certificate_alias == "spo"
    assert sharepoint.compliance_certificate_alias is None
    assert sharepoint.compliance_organization is None


def test_compliance_acquires_no_token():
    client = make_client()
    request = client._request(DLP_OP, DLP_COLLECTOR, {})

    assert request.token is None
    client._msal_app.acquire_token_for_client.assert_not_called()

    exchange = make_client()
    exchange._request(
        "exchange.organization.organization_config.read",
        "exchange.organization.organization_config",
        {},
    )
    exchange._msal_app.acquire_token_for_client.assert_called()


@pytest.mark.parametrize("operation_id", [DLP_OP, LABEL_OP])
def test_compliance_refuses_docker_mode(operation_id):
    from collectors.powershell_client import PowerShellExecutionError

    collector_id = operation_id.rsplit(".", 1)[0]
    client = make_client(service_url=None)
    with pytest.raises(PowerShellExecutionError, match="Certificate authentication"):
        asyncio.run(client.run_operation(operation_id, collector_id))
    with pytest.raises(PowerShellExecutionError, match="Certificate authentication"):
        asyncio.run(client._run_via_docker(operation_id, collector_id, {}))


def test_registered_ids():
    from collectors.registry import DATA_COLLECTORS

    assert set(DATA_COLLECTORS) & {DLP_COLLECTOR, LABEL_COLLECTOR} == {
        DLP_COLLECTOR,
        LABEL_COLLECTOR,
    }
    pending = ENGINE / "collectors" / "_pending"
    assert not (pending / "compliance").exists()
    assert "Compliance" not in (pending / "README.md").read_text()
    assert not list(pending.rglob("*compliance*"))
