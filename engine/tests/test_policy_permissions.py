"""POL-05: v6 ready policy declarations must match the permissions offered to scans.

This deliberately validates the documented block-list annotation format without
adding a YAML/OPA dependency to Python wiring tests. Endpoint-level decisions and
Microsoft sources are recorded in docs/compliance/phase-2/PERMISSIONS.md.
"""

import json
import re
from pathlib import Path

import pytest

POLICY_DIR = (
    Path(__file__).resolve().parents[1]
    / "policies/cis/microsoft-365-foundations/v6.0.0"
)
CONTROLS = json.loads((POLICY_DIR / "metadata.json").read_text())["controls"]
READY = [control for control in CONTROLS if control["automation_status"] == "ready"]


@pytest.mark.parametrize("control", READY, ids=lambda c: c["control_id"])
def test_ready_policy_permission_annotations_match_metadata(control):
    text = (POLICY_DIR / control["policy_file"]).read_text()
    # Require the permissions to be inside OPA's custom metadata, not an ignored
    # top-level YAML key (the original 5.1.4.5 defect).
    custom = re.search(r"^# custom:\n((?:#(?:  .*|)\n)+)", text, re.MULTILINE)
    assert custom, f"{control['control_id']}: missing custom metadata"
    permission_block = re.search(
        r"^#   requires_permissions:\n((?:#   (?:  )?- [A-Za-z0-9.-]+\n)+)",
        custom[1],
        re.MULTILINE,
    )
    assert permission_block, f"{control['control_id']}: missing permission block"
    permissions = re.findall(r"- ([A-Za-z0-9.-]+)", permission_block[1])
    assert len(permissions) == len(set(permissions)), "Duplicate permission annotations"
    assert set(permissions) == set(control["requires_permissions"])


# These collector-wide requirements are pinned to the documented read endpoints,
# so editing both policy and metadata to the same wrong value cannot hide drift.
# RoleManagement.Read.Directory covers both PIM policy/rules and roleDefinitions;
# the policy-only scope cannot authorize the collector's roleDefinitions request.
RECONCILED_REQUIREMENTS = {
    "exchange.mailbox.mailboxes": {"Exchange.ManageAsApp"},
    "exchange.dns.dns_security_records": {"Domain.Read.All"},
    "entra.devices.enrollment_restrictions": {"DeviceManagementServiceConfig.Read.All"},
    "entra.devices.device_registration_policy": {"Policy.Read.DeviceConfiguration"},
    "entra.authentication.password_protection": {"GroupSettings.Read.All"},
    "entra.governance.pim_role_policies": {"RoleManagement.Read.Directory"},
}


@pytest.mark.parametrize(
    "control",
    [c for c in READY if c["data_collector_id"] in RECONCILED_REQUIREMENTS],
    ids=lambda c: c["control_id"],
)
def test_reconciled_collectors_declare_documented_read_permissions(control):
    assert (
        set(control["requires_permissions"])
        == RECONCILED_REQUIREMENTS[control["data_collector_id"]]
    )
