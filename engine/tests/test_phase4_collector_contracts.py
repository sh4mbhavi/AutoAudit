"""Mocked transport contracts for every Appendix B collector (no tenant access)."""

import asyncio
import json
from pathlib import Path
from unittest.mock import AsyncMock, patch

import httpx
import pytest

from collectors.graph_client import GraphClient
from collectors.registry import get_collector

GA = "62e90394-69f5-4237-9190-012177145e10"
ROLE = {"id": "role", "displayName": "Global Administrator"}
USER = {
    "id": "user",
    "@odata.type": "#microsoft.graph.user",
    "userPrincipalName": "admin@example.test",
}

# Successful collection responses and individual evidence signals that must survive normalization.
# Policy-level pass/fail expectations belong to the collector-to-OPA integration tests.
GRAPH_CASES = {
    "entra.roles.cloud_only_admins": (
        {
            "/directoryRoles": [ROLE],
            "/directoryRoles/role/members": [USER],
            "/users/user": {"onPremisesSyncEnabled": False},
        },
        "cloud_only_admin_count",
        1,
    ),
    "entra.roles.privileged_roles": (
        {"/directoryRoles": [ROLE], "/directoryRoles/role/members": [USER]},
        "global_admin_count",
        1,
    ),
    "entra.roles.admin_license_footprint": (
        {
            "/directoryRoles": [ROLE],
            "/directoryRoles/role/members": [USER],
            "/users/user": {},
            "/users/user/licenseDetails": [{"servicePlans": []}],
        },
        "admin_accounts_with_reduced_license_footprint",
        1,
    ),
    "entra.groups.groups": (
        {
            "/groups": [
                {
                    "id": "group",
                    "displayName": "Public group",
                    "groupTypes": ["Unified"],
                    "visibility": "Public",
                }
            ]
        },
        "public_groups_count",
        1,
    ),
    "entra.domains.password_policy": (
        {
            "/domains": [
                {
                    "id": "example.test",
                    "authenticationType": "Managed",
                    "passwordValidityPeriodInDays": 2147483647,
                }
            ]
        },
        "managed_domains_count",
        1,
    ),
    "entra.applications.apps_and_services_settings": (
        {
            "/admin/appsAndServices": {
                "isOfficeStoreEnabled": False,
                "isAppAndServicesTrialEnabled": False,
            }
        },
        "user_owned_apps_enabled",
        False,
    ),
    "entra.devices.enrollment_restrictions": (
        {
            "/deviceManagement/deviceEnrollmentConfigurations": [
                {
                    "id": "restriction",
                    "@odata.type": "#microsoft.graph.deviceEnrollmentPlatformRestrictionsConfiguration",
                    "iosRestriction": {"personalDeviceEnrollmentBlocked": True},
                }
            ]
        },
        "total_configurations",
        1,
    ),
    "entra.policies.authorization_policy": (
        {
            "/policies/authorizationPolicy": {
                "defaultUserRolePermissions": {"allowedToCreateApps": False}
            }
        },
        "allowed_to_create_apps",
        False,
    ),
    "entra.policies.admin_consent_request_policy": (
        {"/policies/adminConsentRequestPolicy": {"isEnabled": True, "reviewers": []}},
        "is_enabled",
        True,
    ),
    "entra.policies.b2b_policy": (
        {
            "/policies/crossTenantAccessPolicy/default": {
                "b2bCollaborationInbound": {"usersAndGroups": {"accessType": "blocked"}}
            },
            "/policies/crossTenantAccessPolicy/partners": [{"tenantId": "partner"}],
        },
        "partners_count",
        1,
    ),
    "entra.conditional_access.legacy_auth_block": (
        {
            "/identity/conditionalAccess/policies": [
                {
                    "id": "ca",
                    "displayName": "Block legacy authentication",
                    "state": "enabled",
                    "conditions": {
                        "users": {
                            "includeUsers": ["All"],
                            "excludeUsers": [],
                            "excludeGroups": [],
                            "excludeRoles": [],
                        },
                        "applications": {
                            "includeApplications": ["All"],
                            "excludeApplications": [],
                        },
                        "clientAppTypes": ["other", "exchangeActiveSync"],
                    },
                    "grantControls": {"builtInControls": ["block"]},
                }
            ]
        },
        "total_policies",
        1,
    ),
    "entra.authentication.mfa_fatigue_protection": (
        {
            "/policies/authenticationMethodsPolicy/authenticationMethodConfigurations/MicrosoftAuthenticator": {
                "state": "enabled",
                "featureSettings": {
                    "numberMatchingRequiredState": {"state": "enabled"}
                },
            }
        },
        "number_matching_enabled",
        True,
    ),
    "entra.authentication.password_protection": (
        {
            "/settings": [
                {
                    "templateId": "5cf42378-d67d-4f36-ba46-e8b86229381d",
                    "values": [{"name": "EnableBannedPasswordCheck", "value": "True"}],
                }
            ]
        },
        "banned_password_list_enabled",
        True,
    ),
    "entra.authentication.mfa_registration_report": (
        {
            "/reports/authenticationMethods/userRegistrationDetails": [
                {"id": "user", "isMfaRegistered": True, "isMfaCapable": True}
            ]
        },
        "mfa_capable_count",
        1,
    ),
    "entra.authentication.authentication_methods": (
        {
            "/policies/authenticationMethodsPolicy": {
                "authenticationMethodConfigurations": [
                    {"id": "Sms", "state": "disabled"}
                ]
            }
        },
        "sms_enabled",
        False,
    ),
    "entra.governance.pim_role_policies": (
        {
            "/policies/roleManagementPolicies": [
                {"id": "pim", "scopeId": f"/DirectoryRoles/{GA}"}
            ],
            "/roleManagement/directory/roleDefinitions": [{"templateId": GA}],
            "/policies/roleManagementPolicies/pim/rules": [
                {
                    "@odata.type": "#microsoft.graph.unifiedRoleManagementPolicyApprovalRule",
                    "id": "Approval_EndUser_Assignment",
                    "setting": {"isApprovalRequired": True},
                }
            ],
        },
        "global_admin_approval_required",
        True,
    ),
    "entra.governance.access_reviews": (
        {
            "/identityGovernance/accessReviews/definitions": [
                {"id": "review", "scope": {"query": "userType eq 'Guest'"}}
            ]
        },
        "guest_reviews_count",
        1,
    ),
}
PS_CASES = {
    "exchange.protection.safe_links_policy": (
        {"EnableSafeLinksForOffice": True},
        "safe_links_policies",
    ),
    "exchange.protection.malware_filter_policy": (
        {"IsDefault": True, "EnableFileFilter": True},
        "malware_filter_policies",
    ),
    "exchange.protection.safe_attachment_policy": (
        {
            "Name": "Built-In Protection Policy",
            "Enable": True,
            "Action": "Block",
            "QuarantineTag": "AdminOnlyAccessPolicy",
        },
        "safe_attachment_policies",
    ),
    "exchange.protection.atp_policy_o365": (
        {
            "EnableATPForSPOTeamsODB": True,
            "EnableSafeDocs": True,
            "AllowSafeDocsOpen": False,
        },
        "atp_policy",
    ),
    "exchange.protection.hosted_outbound_spam_filter": (
        {"IsDefault": True, "NotifyOutboundSpam": True},
        "outbound_spam_policies",
    ),
    "exchange.protection.anti_phish_policy": (
        {"IsDefault": True},
        "anti_phish_policies",
    ),
    "exchange.protection.teams_protection_policy": (
        {"ZapEnabled": True},
        "teams_protection_policy",
    ),
    "exchange.organization.organization_config": (
        {"AuditDisabled": False, "OAuth2ClientProfileEnabled": True},
        "organization_config",
    ),
    "exchange.organization.transport_config": (
        {"SmtpClientAuthenticationDisabled": True},
        "transport_config",
    ),
    "exchange.mailbox.mailbox_audit": (
        {"Name": "mailbox", "AuditBypassEnabled": True},
        "accounts_with_bypass_enabled",
    ),
    "exchange.mailbox.mailbox_audit_actions": (
        {"UserPrincipalName": "user@example.test", "AuditEnabled": True},
        "mailboxes",
    ),
    "exchange.transport.transport_rules": (
        {
            "Name": "rule",
            "State": "Enabled",
            "RedirectMessageTo": [],
            "BlindCopyTo": [],
            "SetSCL": -1,
            "SenderDomainIs": ["example.test"],
            "AutoForwardingMode": "Off",
        },
        "transport_rules",
    ),
    "exchange.transport.external_in_outlook": (
        {"Enabled": True},
        "external_in_outlook_settings",
    ),
}


def collect_graph(collector_id, routes=None, status=200, raw=None):
    routes = routes if routes is not None else GRAPH_CASES[collector_id][0]
    client = GraphClient.__new__(GraphClient)
    client._get_access_token = AsyncMock(return_value="synthetic")
    requests = []

    def respond(request):
        requests.append(request)
        path = request.url.path.removeprefix("/v1.0").removeprefix("/beta")
        payload = routes.get(path, {})
        if isinstance(payload, list):
            payload = {"value": payload}
        return httpx.Response(status, json=raw if raw is not None else payload)

    real_client = httpx.AsyncClient
    with patch(
        "collectors.graph_client.httpx.AsyncClient",
        side_effect=lambda: real_client(transport=httpx.MockTransport(respond)),
    ):
        result = asyncio.run(get_collector(collector_id).collect(client))
    return result, requests


@pytest.mark.parametrize("collector_id", GRAPH_CASES)
def test_graph_success_preserves_evidence(collector_id):
    result, requests = collect_graph(collector_id)
    _, key, expected = GRAPH_CASES[collector_id]
    assert result[key] == expected
    assert requests


@pytest.mark.parametrize("collector_id", GRAPH_CASES)
@pytest.mark.parametrize("status", [403, 429])
def test_graph_denied_and_throttled_never_return_assessment(collector_id, status):
    if collector_id.endswith("apps_and_services_settings"):
        result, _ = collect_graph(collector_id, status=status)
        assert result["collector_error"]
        assert result["user_owned_apps_enabled"] is None
    else:
        with pytest.raises(httpx.HTTPStatusError):
            collect_graph(collector_id, status=status)


@pytest.mark.parametrize("collector_id", GRAPH_CASES)
def test_graph_malformed_transport_never_returns_assessment(collector_id):
    if collector_id.endswith("apps_and_services_settings"):
        result, _ = collect_graph(collector_id, raw="malformed")
        assert result["collector_error"]
    else:
        with pytest.raises(ValueError, match="object"):
            collect_graph(collector_id, raw="malformed")


@pytest.mark.parametrize("collector_id", GRAPH_CASES)
def test_graph_empty_evidence_is_preserved(collector_id):
    routes = {
        path: [] if isinstance(data, list) else {}
        for path, data in GRAPH_CASES[collector_id][0].items()
    }
    result, _ = collect_graph(collector_id, routes=routes)
    _, key, _ = GRAPH_CASES[collector_id]
    assert result[key] in (None, False, 0)
    assert not any(value is True for value in result.values())


@pytest.mark.parametrize("collector_id", PS_CASES)
def test_powershell_success_preserves_evidence(collector_id):
    raw, key = PS_CASES[collector_id]
    client = type("Client", (), {"run_operation": AsyncMock(return_value=raw)})()
    result = asyncio.run(get_collector(collector_id).collect(client))
    assert result[key] in (raw, [raw])
    assert client.run_operation.await_args.args[1] == collector_id


@pytest.mark.parametrize("collector_id", PS_CASES)
@pytest.mark.parametrize("status", [403, 429])
def test_powershell_denied_and_throttled_never_return_assessment(collector_id, status):
    request = httpx.Request("POST", "https://powershell.example.test/run")
    error = httpx.HTTPStatusError(
        "synthetic failure",
        request=request,
        response=httpx.Response(status, request=request),
    )
    client = type("Client", (), {"run_operation": AsyncMock(side_effect=error)})()
    with pytest.raises(httpx.HTTPStatusError):
        asyncio.run(get_collector(collector_id).collect(client))


@pytest.mark.parametrize("collector_id", PS_CASES)
def test_powershell_malformed_evidence_is_rejected(collector_id):
    client = type(
        "Client", (), {"run_operation": AsyncMock(return_value="malformed")}
    )()
    with pytest.raises(ValueError, match="PowerShell"):
        asyncio.run(get_collector(collector_id).collect(client))


@pytest.mark.parametrize("collector_id", PS_CASES)
def test_powershell_empty_evidence_is_preserved(collector_id):
    client = type("Client", (), {"run_operation": AsyncMock(return_value=None)})()
    result = asyncio.run(get_collector(collector_id).collect(client))
    _, key = PS_CASES[collector_id]
    assert result[key] in (None, [], {})
    assert not any(value is True for value in result.values())


def test_inventory_covers_all_crosswalk_metadata_collectors():
    metadata = json.loads(
        (
            Path(__file__).parents[1]
            / "policies/cis/microsoft-365-foundations/v6.0.0/metadata.json"
        ).read_text()
    )
    controls = metadata["controls"]
    ids = "1.1.1 1.1.3 1.1.4 1.2.1 1.3.1 1.3.4 2.1.1 2.1.2 2.1.3 2.1.4 2.1.5 2.1.6 2.1.7 2.1.11 2.4.4 4.2 5.1.2.2 5.1.5.1 5.1.5.2 5.1.6.1 5.1.6.2 5.1.6.3 5.2.2.3 5.2.3.1 5.2.3.2 5.2.3.3 5.2.3.4 5.2.3.5 5.2.3.6 5.2.3.7 5.3.1 5.3.2 5.3.3 5.3.4 5.3.5 6.1.1 6.1.2 6.1.3 6.2.1 6.2.2 6.2.3 6.5.1 6.5.4 6.5.5".split()
    assert len(ids) == 44
    selected = {c["data_collector_id"] for c in controls if c["control_id"] in ids}
    assert selected == set(GRAPH_CASES) | set(PS_CASES)


PAGINATED_ROUTES = [
    (cid, path)
    for cid, (routes, _, _) in GRAPH_CASES.items()
    for path, payload in routes.items()
    if isinstance(payload, list)
]


@pytest.mark.parametrize("collector_id,path", PAGINATED_ROUTES)
def test_graph_collectors_follow_every_collection_next_link(collector_id, path):
    routes = dict(GRAPH_CASES[collector_id][0])
    expected = routes[path]
    routes[path] = (
        {
            "value": [],
            "@odata.nextLink": "https://graph.microsoft.com/beta" + path + "/next",
        }
        if collector_id
        not in {
            "entra.roles.cloud_only_admins",
            "entra.roles.privileged_roles",
            "entra.roles.admin_license_footprint",
            "entra.groups.groups",
            "entra.domains.password_policy",
            "entra.conditional_access.legacy_auth_block",
        }
        else {
            "value": [],
            "@odata.nextLink": "https://graph.microsoft.com/v1.0" + path + "/next",
        }
    )
    routes[path + "/next"] = expected
    result, requests = collect_graph(collector_id, routes=routes)
    _, key, value = GRAPH_CASES[collector_id]
    assert result[key] == value
    assert any(request.url.path.endswith(path + "/next") for request in requests)


@pytest.mark.parametrize(
    "payload",
    [
        {},
        {"value": None},
        {"value": {}},
        {"value": "bad"},
        {"value": [None]},
        {"value": ["bad"]},
    ],
)
def test_graph_collection_rejects_malformed_pages(payload):
    client = GraphClient.__new__(GraphClient)
    client.get = AsyncMock(return_value=payload)
    with pytest.raises(ValueError, match="collection"):
        asyncio.run(client.get_all_pages("/users"))


@pytest.mark.parametrize(
    "next_link",
    [
        "https://untrusted.example.test/users",
        "https://graph.microsoft.com/beta/users",
        "/users",
        123,
    ],
)
def test_graph_collection_rejects_unexpected_next_link(next_link):
    client = GraphClient.__new__(GraphClient)
    client.get = AsyncMock(
        side_effect=[{"value": [], "@odata.nextLink": next_link}, {"value": []}]
    )
    with pytest.raises(ValueError, match="nextLink"):
        asyncio.run(client.get_all_pages("/users"))


def test_graph_pagination_limit_never_returns_partial_evidence():
    client = GraphClient.__new__(GraphClient)
    client.get = AsyncMock(
        return_value={
            "value": [{"id": "user"}],
            "@odata.nextLink": "https://graph.microsoft.com/v1.0/users?$skiptoken=next",
        }
    )
    with pytest.raises(ValueError, match="incomplete"):
        asyncio.run(client.get_all_pages("/users", max_pages=2))


@pytest.mark.parametrize("status", [403, 429])
def test_graph_later_page_failure_discards_partial_collection(status):
    client = GraphClient.__new__(GraphClient)
    request = httpx.Request("GET", "https://graph.microsoft.com/v1.0/users")
    failure = httpx.HTTPStatusError(
        "synthetic", request=request, response=httpx.Response(status, request=request)
    )
    client.get = AsyncMock(
        side_effect=[
            {"value": [{"id": "user"}], "@odata.nextLink": str(request.url)},
            failure,
        ]
    )
    with pytest.raises(httpx.HTTPStatusError):
        asyncio.run(client.get_all_pages("/users"))


@pytest.mark.parametrize("value", [None, "False", 0, "invalid"])
def test_cloud_only_unknown_sync_is_not_counted_cloud_only(value):
    cid = "entra.roles.cloud_only_admins"
    routes = dict(GRAPH_CASES[cid][0])
    routes["/users/user"] = {} if value is None else {"onPremisesSyncEnabled": value}
    result, _ = collect_graph(cid, routes=routes)
    assert result["admin_accounts"][0]["on_premises_sync_enabled"] is None
    assert result["cloud_only_admin_count"] == 0


@pytest.mark.parametrize(
    "license_data",
    [
        [{}],
        [{"servicePlans": None}],
        [{"servicePlans": [{}]}],
        [
            {
                "servicePlans": [
                    {"servicePlanName": "EXCHANGE_S_STANDARD", "appliesTo": "User"}
                ]
            }
        ],
    ],
)
def test_missing_license_plan_evidence_never_claims_reduced_footprint(license_data):
    cid = "entra.roles.admin_license_footprint"
    routes = dict(GRAPH_CASES[cid][0])
    routes["/users/user/licenseDetails"] = license_data
    with pytest.raises(ValueError, match="license"):
        collect_graph(cid, routes=routes)


@pytest.mark.parametrize("state", [None, "unknown", False, 0])
def test_unknown_authentication_method_state_is_not_disabled(state):
    cid = "entra.authentication.authentication_methods"
    result, _ = collect_graph(
        cid,
        routes={
            "/policies/authenticationMethodsPolicy": {
                "authenticationMethodConfigurations": [{"id": "Sms", "state": state}]
            }
        },
    )
    assert result["sms_enabled"] is None


@pytest.mark.parametrize("collector_id", PS_CASES)
def test_powershell_partial_property_evidence_does_not_fabricate_properties(
    collector_id,
):
    raw = {"Name": "partial"}
    client = type("Client", (), {"run_operation": AsyncMock(return_value=raw)})()
    if collector_id == "exchange.transport.transport_rules":
        with pytest.raises(ValueError):
            asyncio.run(get_collector(collector_id).collect(client))
        return
    result = asyncio.run(get_collector(collector_id).collect(client))
    _, key = PS_CASES[collector_id]
    assert result[key] in (raw, [raw])
    if "default_policy" in result:
        assert result["default_policy"] in (None, raw)


@pytest.mark.parametrize("collector_id", PS_CASES)
def test_powershell_mixed_malformed_records_are_rejected(collector_id):
    client = type(
        "Client",
        (),
        {"run_operation": AsyncMock(return_value=[{"Name": "partial"}, None])},
    )()
    with pytest.raises(ValueError, match="PowerShell"):
        asyncio.run(get_collector(collector_id).collect(client))


def test_powershell_partial_transport_query_failure_is_not_returned():
    client = type(
        "Client",
        (),
        {
            "run_operation": AsyncMock(
                side_effect=[
                    [PS_CASES["exchange.transport.transport_rules"][0]],
                    RuntimeError("second query unavailable"),
                ]
            )
        },
    )()
    with pytest.raises(RuntimeError, match="second query"):
        asyncio.run(get_collector("exchange.transport.transport_rules").collect(client))


@pytest.mark.parametrize("collector_id", GRAPH_CASES)
def test_graph_partial_properties_do_not_invent_positive_signals(collector_id):
    routes = {
        path: [{}] if isinstance(data, list) else {}
        for path, data in GRAPH_CASES[collector_id][0].items()
    }
    try:
        result, _ = collect_graph(collector_id, routes=routes)
    except (ValueError, KeyError):
        return  # Invalid identity/shape fails collection instead of assessing partial evidence.
    assert not any(value is True for value in result.values())


@pytest.mark.parametrize("field", ["excludeUsers", "excludeGroups", "excludeRoles"])
def test_legacy_auth_exclusions_do_not_claim_all_users(field):
    cid = "entra.conditional_access.legacy_auth_block"
    routes = json.loads(json.dumps(GRAPH_CASES[cid][0]))
    routes["/identity/conditionalAccess/policies"][0]["conditions"]["users"][field] = [
        "excluded"
    ]
    result, _ = collect_graph(cid, routes=routes)
    assert result["conditional_access_policies"][0]["targets_all_users"] is False


def test_legacy_auth_app_exclusions_do_not_claim_all_apps():
    cid = "entra.conditional_access.legacy_auth_block"
    routes = json.loads(json.dumps(GRAPH_CASES[cid][0]))
    routes["/identity/conditionalAccess/policies"][0]["conditions"]["applications"][
        "excludeApplications"
    ] = ["excluded"]
    result, _ = collect_graph(cid, routes=routes)
    assert result["conditional_access_policies"][0]["targets_all_apps"] is False


def test_enrollment_restrictions_are_categorized_by_graph_type():
    result, _ = collect_graph("entra.devices.enrollment_restrictions")
    assert len(result["platform_restrictions"]) == 1


@pytest.mark.parametrize("value", ["false", "true", 1])
def test_mfa_counts_only_explicit_boolean_capability(value):
    cid = "entra.authentication.mfa_registration_report"
    result, _ = collect_graph(
        cid,
        routes={
            "/reports/authenticationMethods/userRegistrationDetails": [
                {"isMfaRegistered": value, "isMfaCapable": value}
            ]
        },
    )
    assert result["mfa_capable_count"] == 0
    assert result["mfa_registered_count"] == 0


def test_disabled_authenticator_does_not_claim_fatigue_protection():
    cid = "entra.authentication.mfa_fatigue_protection"
    routes = json.loads(json.dumps(GRAPH_CASES[cid][0]))
    routes[next(iter(routes))]["state"] = "disabled"
    result, _ = collect_graph(cid, routes=routes)
    assert result["number_matching_enabled"] is False


def test_unknown_authenticator_state_preserves_unknown_protection():
    cid = "entra.authentication.mfa_fatigue_protection"
    routes = json.loads(json.dumps(GRAPH_CASES[cid][0]))
    routes[next(iter(routes))].pop("state", None)
    result, _ = collect_graph(cid, routes=routes)
    assert result["number_matching_enabled"] is None


def test_legacy_auth_missing_exclusion_evidence_preserves_unknown_scope():
    cid = "entra.conditional_access.legacy_auth_block"
    routes = json.loads(json.dumps(GRAPH_CASES[cid][0]))
    conditions = routes["/identity/conditionalAccess/policies"][0]["conditions"]
    conditions["users"].pop("excludeUsers")
    conditions["applications"].pop("excludeApplications")
    result, _ = collect_graph(cid, routes=routes)
    assert result["conditional_access_policies"][0]["targets_all_users"] is None
    assert result["conditional_access_policies"][0]["targets_all_apps"] is None


def test_antiphish_collects_rules_needed_for_assignment_evaluation():
    policy = {"Name": "policy"}
    rule = {
        "Name": "rule",
        "State": "Enabled",
        "AntiPhishPolicy": "policy",
        "RecipientDomainIs": ["example.test"],
    }
    client = type(
        "Client", (), {"run_operation": AsyncMock(side_effect=[policy, rule])}
    )()
    result = asyncio.run(
        get_collector("exchange.protection.anti_phish_policy").collect(client)
    )
    assert result["anti_phish_rules"] == [rule]
    assert client.run_operation.await_args.args == (
        "exchange.protection.anti_phish_policy.rules",
        "exchange.protection.anti_phish_policy",
    )


def test_antiphish_rule_failure_does_not_return_partial_policy_evidence():
    client = type(
        "Client",
        (),
        {
            "run_operation": AsyncMock(
                side_effect=[[{"Name": "policy"}], RuntimeError("rules unavailable")]
            )
        },
    )()
    with pytest.raises(RuntimeError, match="rules unavailable"):
        asyncio.run(
            get_collector("exchange.protection.anti_phish_policy").collect(client)
        )


@pytest.mark.parametrize(
    "envelope",
    [
        {"success": True},
        {"success": "true", "data": []},
        {"success": True, "data": [], "error": "partial failure"},
        {"success": True, "data": [], "errors": ["partial failure"]},
        [],
        None,
    ],
)
def test_powershell_service_rejects_missing_malformed_or_partial_envelope(envelope):
    from collectors.powershell_client import PowerShellClient, PowerShellExecutionError

    client = PowerShellClient.__new__(PowerShellClient)
    client.tenant_id = "contoso.onmicrosoft.com"
    client.service_secret = (
        "synthetic-service-secret-for-envelope-test"  # pragma: allowlist secret
    )
    client.service_ca_file = None
    client.service_url = "https://powershell.example.test"
    client._msal_app = type(
        "Msal",
        (),
        {
            "acquire_token_for_client": lambda self, scopes: {
                "access_token": "synthetic"
            }
        },
    )()
    real_client = httpx.AsyncClient
    with patch(
        "collectors.powershell_client.httpx.AsyncClient",
        side_effect=lambda **kwargs: real_client(
            transport=httpx.MockTransport(
                lambda req: httpx.Response(200, json=envelope)
            ),
            **kwargs,
        ),
    ):
        with pytest.raises(PowerShellExecutionError):
            asyncio.run(
                client._run_via_service(
                    "exchange.mailbox.mailbox_audit.read",
                    "exchange.mailbox.mailbox_audit",
                    {},
                )
            )


@pytest.mark.parametrize(
    "restrictions,expected",
    [
        ([], None),
        (
            [
                {
                    "priority": 0,
                    "iosRestriction": {"personalDeviceEnrollmentBlocked": True},
                }
            ],
            None,
        ),
        ([{"priority": 1}], None),
    ],
)
def test_enrollment_partial_default_scope_never_claims_all_personal_devices_blocked(
    restrictions, expected
):
    for restriction in restrictions:
        restriction["@odata.type"] = (
            "#microsoft.graph.deviceEnrollmentPlatformRestrictionsConfiguration"
        )
    result, _ = collect_graph(
        "entra.devices.enrollment_restrictions",
        routes={"/deviceManagement/deviceEnrollmentConfigurations": restrictions},
    )
    assert result["personal_devices_blocked"] is expected


@pytest.mark.parametrize("blocked", [True, False])
def test_enrollment_complete_default_scope_checks_every_platform(blocked):
    restriction = {
        "@odata.type": "#microsoft.graph.deviceEnrollmentPlatformRestrictionsConfiguration",
        "deviceEnrollmentConfigurationType": "defaultPlatformRestrictions",
        "priority": 0,
    }
    for platform in (
        "androidRestriction",
        "iosRestriction",
        "windowsRestriction",
        "macOSRestriction",
        "windowsMobileRestriction",
    ):
        restriction[platform] = {"personalDeviceEnrollmentBlocked": True}
    restriction["macOSRestriction"]["personalDeviceEnrollmentBlocked"] = blocked
    result, _ = collect_graph(
        "entra.devices.enrollment_restrictions",
        routes={"/deviceManagement/deviceEnrollmentConfigurations": [restriction]},
    )
    assert result["personal_devices_blocked"] is blocked


@pytest.mark.parametrize("auth_type", [None, "unknown", ""])
def test_unknown_domain_authentication_is_not_classified_federated(auth_type):
    result, _ = collect_graph(
        "entra.domains.password_policy",
        routes={"/domains": [{"id": "example.test", "authenticationType": auth_type}]},
    )
    assert result["domains"][0]["is_managed"] is None


@pytest.mark.parametrize(
    "collector_id",
    [
        "entra.roles.cloud_only_admins",
        "entra.roles.admin_license_footprint",
        "entra.roles.privileged_roles",
    ],
)
@pytest.mark.parametrize(
    "member", [{"@odata.type": "#microsoft.graph.user"}, {"id": "user"}]
)
def test_partial_role_member_identity_cannot_disappear_from_assessment(
    collector_id, member
):
    routes = dict(GRAPH_CASES[collector_id][0])
    routes["/directoryRoles/role/members"] = [USER, member]
    with pytest.raises(ValueError, match="member"):
        collect_graph(collector_id, routes=routes)


@pytest.mark.parametrize(
    "group",
    [
        {},
        {"id": "unknown", "groupTypes": ["Unified"]},
        {"id": "unknown", "groupTypes": ["Unified"], "visibility": None},
    ],
)
def test_partial_group_population_cannot_disappear_into_compliant_public_count(group):
    with pytest.raises(ValueError, match="group"):
        collect_graph("entra.groups.groups", routes={"/groups": [group]})


@pytest.mark.parametrize(
    "rule", [{}, {"Name": "partial", "SetSCL": "invalid"}, {"error": "failed record"}]
)
def test_partial_transport_population_cannot_disappear_into_safe_filtered_lists(rule):
    client = type(
        "Client",
        (),
        {
            "run_operation": AsyncMock(
                side_effect=[[rule], [{"AutoForwardingMode": "Off"}]]
            )
        },
    )()
    with pytest.raises(ValueError):
        asyncio.run(get_collector("exchange.transport.transport_rules").collect(client))


@pytest.mark.parametrize("collector_id", PS_CASES)
def test_powershell_error_records_cannot_be_mistaken_for_policy_records(collector_id):
    client = type(
        "Client",
        (),
        {"run_operation": AsyncMock(return_value={"error": "partial collection"})},
    )()
    with pytest.raises(ValueError, match="PowerShell"):
        asyncio.run(get_collector(collector_id).collect(client))


def test_graph_error_envelope_cannot_be_stripped_from_paginated_records():
    with pytest.raises(ValueError, match="error"):
        collect_graph(
            "entra.groups.groups",
            routes={"/groups": {"value": [], "error": {"code": "AccessDenied"}}},
        )


@pytest.mark.parametrize(
    "field,value",
    [("State", "unknown"), ("State", ""), ("SetSCL", False), ("SetSCL", -0.5)],
)
def test_malformed_transport_state_or_scl_cannot_hide_a_rule(field, value):
    rule = dict(PS_CASES["exchange.transport.transport_rules"][0])
    rule[field] = value
    client = type(
        "Client",
        (),
        {
            "run_operation": AsyncMock(
                side_effect=[[rule], [{"AutoForwardingMode": "Off"}]]
            )
        },
    )()
    with pytest.raises(ValueError):
        asyncio.run(get_collector("exchange.transport.transport_rules").collect(client))


def test_graph_error_bearing_records_cannot_be_normalized_into_safe_population():
    with pytest.raises(ValueError, match="error"):
        collect_graph(
            "entra.groups.groups",
            routes={
                "/groups": [
                    {
                        "id": "group",
                        "groupTypes": [],
                        "visibility": "Private",
                        "error": "partial",
                    }
                ]
            },
        )
