"""DLP compliance policy collector.

CIS Microsoft 365 Foundations Benchmark Controls:
    v6.0.0: 3.2.1, 3.2.2

Control Descriptions:
    3.2.1 - Ensure DLP policies are enabled
    3.2.2 - Ensure DLP policies are enabled for Microsoft Teams

Both controls remain automation_status 'blocked' and their Rego lives in
engine/policies/candidate/, so no scan dispatches this collector today. It is
registered because a non-ready control must still name a real collector.

Connection Method: Security & Compliance PowerShell (via the PowerShell HTTP service)
Authentication: certificate-based Connect-IPPSSession (see collectors/compliance/__init__.py)
Required Cmdlets: Get-DlpCompliancePolicy
Required Permissions: Exchange.ManageAsApp + Global Reader or Security Reader
"""

from typing import Any

from collectors.compliance.shape import (
    DLP_MODE_ENABLE,
    TEAMS_LOCATION_ALL,
    location_names,
    mode_token,
    workload_includes_teams,
)
from collectors.powershell_base import BasePowerShellCollector, powershell_records
from collectors.powershell_client import PowerShellClient


class DlpCompliancePolicyDataCollector(BasePowerShellCollector):
    """Collects DLP compliance policies for CIS compliance evaluation.

    The whole returned population is validated before anything is filtered: a
    policy whose identity, mode or workload cannot be read makes the collection
    incomplete, and incomplete collection is an error rather than a smaller
    population that would read downstream as evidence of absence.
    """

    async def collect(self, client: PowerShellClient) -> dict[str, Any]:
        """Collect DLP compliance policy data.

        Returns:
            Dict containing the projected policies, the objective counts CIS
            3.2.1 and 3.2.2 evaluate, and the TeamsLocationException names the
            benchmark asks an auditor -- not this engine -- to judge.
        """
        raw = await client.run_operation(
            "compliance.dlp_compliance_policy.read", "compliance.dlp_compliance_policy"
        )
        records = powershell_records(raw)

        policies: list[dict[str, Any]] = []
        for record in records:
            name = record.get("Name")
            mode = mode_token(record.get("Mode"))
            if not isinstance(name, str) or not name.strip() or not mode:
                raise ValueError(
                    "PowerShell DLP policy identity or mode evidence is incomplete"
                )
            includes_teams = workload_includes_teams(record.get("Workload"))
            if includes_teams is None:
                raise ValueError("PowerShell DLP policy workload evidence is malformed")
            policies.append(
                {
                    "name": name.strip(),
                    "mode": mode,
                    "workload_includes_teams": includes_teams,
                    "teams_location": location_names(record.get("TeamsLocation")),
                    "teams_location_exception": location_names(
                        record.get("TeamsLocationException")
                    ),
                }
            )

        enable = DLP_MODE_ENABLE.casefold()
        teams_policies = [
            policy for policy in policies if policy["workload_includes_teams"] is True
        ]
        mode_enable = [
            policy for policy in teams_policies if policy["mode"].casefold() == enable
        ]

        # One unreadable location makes the "TeamsLocation includes All" half of
        # the audit unknown for the tenant, not zero for the tenant.
        if any(policy["teams_location"] is None for policy in teams_policies):
            enforcing_count: int | None = None
        else:
            enforcing_count = sum(
                1
                for policy in mode_enable
                if any(
                    location.casefold() == TEAMS_LOCATION_ALL.casefold()
                    for location in policy["teams_location"]
                )
            )

        exceptions = [policy["teams_location_exception"] for policy in teams_policies]
        if any(value is None for value in exceptions):
            exception_names: list[str] | None = None
        else:
            exception_names = sorted({name for value in exceptions for name in value})

        return {
            "dlp_policies": policies,
            "total_policies": len(records),
            "enabled_policy_count": sum(
                1 for policy in policies if policy["mode"].casefold() == enable
            ),
            "dlp_policy_modes": sorted({policy["mode"] for policy in policies}),
            "teams_policies": teams_policies,
            "teams_policy_count": len(teams_policies),
            "teams_policy_mode_enable_count": len(mode_enable),
            "teams_enforcing_policy_count": enforcing_count,
            "teams_location_exception_names": exception_names,
        }
