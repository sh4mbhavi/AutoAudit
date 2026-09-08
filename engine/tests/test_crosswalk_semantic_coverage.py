"""Appendix B must remain wired to directly executed, typed semantic cases.

The fixture is a reviewed oracle, not derived from the Rego implementation.
These checks verify its wiring, its matching direct Rego assertions, and the real
OPA outcomes. OPA is required so missing tooling cannot silently skip this gate.
"""

from __future__ import annotations

import json
import os
from pathlib import Path
import re
import shutil
import subprocess

import pytest

ENGINE = Path(__file__).resolve().parents[1]
POLICIES = ENGINE / "policies" / "cis" / "microsoft-365-foundations" / "v6.0.0"
REGO_TEST = ENGINE / "tests" / "test_crosswalk_semantics.rego"
FIXTURE = json.loads(
    (ENGINE / "tests" / "fixtures" / "crosswalk_semantics.json").read_text()
)["phase4_crosswalk"]
CONTROLS = FIXTURE["controls"]
APPENDIX_B_IDS = frozenset(
    "1.1.1 1.1.3 1.1.4 1.2.1 1.3.1 1.3.4 2.1.1 2.1.2 2.1.3 2.1.4 "
    "2.1.5 2.1.6 2.1.7 2.1.11 2.4.4 4.2 5.1.2.2 5.1.5.1 5.1.5.2 "
    "5.1.6.1 5.1.6.2 5.1.6.3 5.2.2.3 5.2.3.1 5.2.3.2 5.2.3.3 5.2.3.4 "
    "5.2.3.5 5.2.3.6 5.2.3.7 5.3.1 5.3.2 5.3.3 5.3.4 5.3.5 6.1.1 "
    "6.1.2 6.1.3 6.2.1 6.2.2 6.2.3 6.5.1 6.5.4 6.5.5".split()
)
REQUIRED_CASES = {
    "pass",
    "fail",
    "missing",
    "malformed",
    "partial",
    "boundary",
    "collector_error",
}


def test_crosswalk_population_is_exactly_appendix_b():
    assert len(APPENDIX_B_IDS) == 44
    assert set(CONTROLS) == APPENDIX_B_IDS
    assert FIXTURE["benchmark"] == "cis/microsoft-365-foundations/v6.0.0"


@pytest.mark.parametrize("control_id", sorted(CONTROLS))
def test_crosswalk_wiring_and_direct_assertions(control_id):
    control = CONTROLS[control_id]
    metadata = json.loads((POLICIES / "metadata.json").read_text())
    row = next(c for c in metadata["controls"] if c["control_id"] == control_id)
    assert row["policy_file"] == control["policy_file"]
    assert row["data_collector_id"] == control["collector_id"]
    assert (POLICIES / control["policy_file"]).is_file()
    assert REQUIRED_CASES <= control["cases"].keys()
    assert control["boundary_reason"].strip()
    assert control["cases"]["pass"]["expected"] is True
    assert control["cases"]["fail"]["expected"] is False
    for name in ("missing", "malformed", "partial", "collector_error"):
        assert control["cases"][name]["expected"] is None

    source = REGO_TEST.read_text()
    suffix = control_id.replace(".", "_")
    for name, case in control["cases"].items():
        body = re.search(
            rf"test_control_{suffix}_{name} if \{{\n(.*?)\n\}}", source, re.DOTALL
        )
        assert body, f"Missing direct semantic test: {control_id}/{name}"
        evidence = re.search(r"evidence := (.+)", body[1])
        assert evidence
        assert json.loads(evidence[1]) == case["input"]
        assert (
            f"data.cis.microsoft_365_foundations.v6_0_0.control_{suffix}.result "
            "with input as evidence"
        ) in body[1]
        assert f"has_compliance(result, {json.dumps(case['expected'])})" in body[1]


@pytest.fixture(scope="module")
def executed_semantic_cases():
    binary = os.environ.get("OPA_BINARY") or shutil.which("opa")
    assert (
        binary
    ), "Install the pinned OPA binary or set OPA_BINARY; semantic coverage is mandatory"
    completed = subprocess.run(
        [binary, "test", str(ENGINE / "policies"), str(REGO_TEST), "--format=json"],
        text=True,
        capture_output=True,
        timeout=60,
        check=False,
    )
    assert completed.returncode in (0, 2), completed.stderr or completed.stdout
    results = json.loads(completed.stdout)
    assert results, "OPA executed no semantic tests"
    return {result["name"]: result for result in results}


@pytest.mark.parametrize("control_id", sorted(CONTROLS))
def test_every_crosswalk_case_executes_and_passes(control_id, executed_semantic_cases):
    suffix = control_id.replace(".", "_")
    for name in CONTROLS[control_id]["cases"]:
        key = f"test_control_{suffix}_{name}"
        assert key in executed_semantic_cases, f"OPA did not execute {key}"
        result = executed_semantic_cases[key]
        assert not result.get("fail"), result
        assert not result.get("error"), result
        assert not result.get("skip"), result


@pytest.fixture(scope="module")
def collected_crosswalk_evidence():
    """Exercise real collectors with complete Graph/PowerShell response fixtures."""
    import asyncio
    from copy import deepcopy
    from unittest.mock import AsyncMock

    from collectors.registry import get_collector
    from tests.test_phase4_collector_contracts import GRAPH_CASES, collect_graph

    routes = {key: deepcopy(value[0]) for key, value in GRAPH_CASES.items()}
    for key in ("entra.roles.cloud_only_admins", "entra.roles.admin_license_footprint"):
        routes[key]["/users/user"].update(
            id="user", userPrincipalName="admin@example.test", displayName="Admin"
        )
    routes["entra.policies.authorization_policy"] = {
        "/policies/authorizationPolicy": {
            "defaultUserRolePermissions": {
                "allowedToCreateApps": False,
                "permissionGrantPoliciesAssigned": [],
            },
            "guestUserRoleId": "2af84b1e-32c8-42b7-82bc-daa82404023b",
            "allowInvitesFrom": "adminsAndGuestInviters",
        }
    }
    routes["entra.authentication.password_protection"] = {
        "/settings": [
            {
                "templateId": "5cf42378-d67d-4f36-ba46-e8b86229381d",
                "values": [
                    {"name": "EnableBannedPasswordCheck", "value": "True"},
                    {"name": "BannedPasswordList", "value": "company"},
                    {"name": "EnableBannedPasswordCheckOnPremises", "value": "True"},
                    {"name": "BannedPasswordCheckOnPremisesMode", "value": "Enforced"},
                ],
            }
        ]
    }
    routes["entra.authentication.authentication_methods"] = {
        "/policies/authenticationMethodsPolicy": {
            "authenticationMethodConfigurations": [
                {"id": method, "state": "disabled"}
                for method in ("Sms", "Voice", "Email")
            ],
            "systemCredentialPreferences": {"state": "enabled"},
        }
    }
    routes["entra.governance.access_reviews"] = {
        "/identityGovernance/accessReviews/definitions": [
            {"id": "guests", "scope": {"query": "userType eq 'Guest'"}},
            {
                "id": "roles",
                "scope": {"query": "/roleManagement/directory/roleAssignments"},
            },
        ]
    }
    pim_routes = routes["entra.governance.pim_role_policies"]
    pra = "e8611ab8-c189-46e8-94e1-60213ab1f814"
    pim_routes["/policies/roleManagementPolicies"].append(
        {"id": "pra", "scopeId": f"/DirectoryRoles/{pra}"}
    )
    pim_routes["/roleManagement/directory/roleDefinitions"].append({"templateId": pra})
    pim_routes["/policies/roleManagementPolicies/pra/rules"] = deepcopy(
        pim_routes["/policies/roleManagementPolicies/pim/rules"]
    )
    routes["entra.devices.enrollment_restrictions"] = {
        "/deviceManagement/deviceEnrollmentConfigurations": [
            {
                "id": "default",
                "@odata.type": "#microsoft.graph.deviceEnrollmentPlatformRestrictionsConfiguration",
                "deviceEnrollmentConfigurationType": "defaultPlatformRestrictions",
                **{
                    platform: {"personalDeviceEnrollmentBlocked": True}
                    for platform in (
                        "androidRestriction",
                        "iosRestriction",
                        "windowsRestriction",
                        "macOSRestriction",
                        "windowsMobileRestriction",
                    )
                },
            }
        ]
    }
    routes["entra.policies.b2b_policy"] = {
        "/policies/crossTenantAccessPolicy/default": {
            "b2bCollaborationInbound": {"usersAndGroups": {"accessType": "blocked"}}
        },
        "/policies/crossTenantAccessPolicy/partners": [{"tenantId": "partner"}],
    }
    routes["entra.groups.groups"]["/groups"][0]["displayName"] = "Public group"
    ca = routes["entra.conditional_access.legacy_auth_block"][
        "/identity/conditionalAccess/policies"
    ][0]
    ca.update(state="enabled", displayName="Block legacy")
    ca["conditions"]["users"].update(excludeUsers=[], excludeGroups=[], excludeRoles=[])
    ca["conditions"]["applications"]["excludeApplications"] = []

    outputs = {key: collect_graph(key, value)[0] for key, value in routes.items()}
    passed = {key: value["cases"]["pass"]["input"] for key, value in CONTROLS.items()}
    malware = {
        **passed["2.1.3"]["malware_filter_policies"][0],
        **passed["2.1.11"]["default_policy"],
        "IsDefault": True,
    }
    ps_responses = {
        "Get-SafeLinksPolicy": passed["2.1.1"]["safe_links_policies"],
        "Get-MalwareFilterPolicy": malware,
        "Get-SafeAttachmentPolicy": passed["2.1.4"]["safe_attachment_policies"],
        "Get-AtpPolicyForO365": passed["2.1.5"]["atp_policy"],
        "Get-HostedOutboundSpamFilterPolicy": {
            **passed["2.1.6"]["default_policy"],
            "Name": "Default",
            "AutoForwardingMode": "Off",
            "IsDefault": True,
        },
        "Get-AntiPhishPolicy": passed["2.1.7"]["anti_phish_policies"],
        "Get-AntiPhishRule": passed["2.1.7"]["anti_phish_rules"],
        "Get-TeamsProtectionPolicy": {"ZapEnabled": True},
        "Get-OrganizationConfig": {
            "AuditDisabled": False,
            "OAuth2ClientProfileEnabled": True,
            "RejectDirectSend": True,
        },
        "Get-TransportConfig": {"SmtpClientAuthenticationDisabled": True},
        "Get-TransportRule": [],
        "Get-ExternalInOutlook": {"Enabled": True, "AllowList": []},
    }

    async def response(operation_id, collector_id, **params):
        from powershell.service.operations import validate_operation

        cmdlet = validate_operation(operation_id, collector_id, params).command
        if cmdlet.startswith("Get-MailboxAuditBypassAssociation"):
            return []
        if cmdlet.startswith("Get-EXOMailbox") or cmdlet.startswith("Get-Mailbox "):
            return passed["6.1.2"]["mailboxes"]
        assert cmdlet in ps_responses, f"Unmodelled cmdlet: {cmdlet}"
        return deepcopy(ps_responses[cmdlet])

    for collector_id in {
        control["collector_id"] for control in CONTROLS.values()
    } - routes.keys():
        client = type(
            "Client", (), {"run_operation": AsyncMock(side_effect=response)}
        )()
        outputs[collector_id] = asyncio.run(get_collector(collector_id).collect(client))
    return outputs


@pytest.mark.parametrize("control_id", sorted(CONTROLS))
def test_real_collector_output_is_assessed_by_captured_policy(
    control_id, collected_crosswalk_evidence
):
    control = CONTROLS[control_id]
    binary = os.environ.get("OPA_BINARY") or shutil.which("opa")
    assert binary, "The pinned OPA binary is required"
    completed = subprocess.run(
        [
            binary,
            "eval",
            "--format=json",
            "--stdin-input",
            "--data",
            str(POLICIES / control["policy_file"]),
            f"data.cis.microsoft_365_foundations.v6_0_0.control_{control_id.replace('.', '_')}.result",
        ],
        input=json.dumps(collected_crosswalk_evidence[control["collector_id"]]),
        text=True,
        capture_output=True,
        timeout=10,
        check=False,
    )
    assert completed.returncode == 0, completed.stderr or completed.stdout
    result = json.loads(completed.stdout)["result"][0]["expressions"][0]["value"]
    # The fixtures deliberately contain one global admin and one public group.
    assert result["compliant"] is (control_id not in {"1.1.3", "1.2.1"}), result
