"""Sensitivity label policy collector.

CIS Microsoft 365 Foundations Benchmark Controls:
    v6.0.0: 3.3.1

Control Descriptions:
    3.3.1 - Ensure Information Protection sensitivity label policies are published

The control remains automation_status 'blocked' and its Rego lives in
engine/policies/candidate/, so no scan dispatches this collector today. It is
registered because a non-ready control must still name a real collector.

Connection Method: Security & Compliance PowerShell (via the PowerShell HTTP service)
Authentication: certificate-based Connect-IPPSSession (see collectors/compliance/__init__.py)
Required Cmdlets: Get-LabelPolicy
Required Permissions: Exchange.ManageAsApp + Global Reader or Security Reader
"""

from typing import Any

from collectors.compliance.shape import (
    LABEL_LOCATION_PROPERTIES,
    LABEL_LOCATION_SCOPES,
    PUBLISHED_SENSITIVITY_LABEL_TYPE,
    location_names,
)
from collectors.powershell_base import BasePowerShellCollector, powershell_records
from collectors.powershell_client import PowerShellClient


def _location_scopes(record: dict[str, Any]) -> list[str] | None:
    """Which of the four label locations are populated, by scope name only.

    The contents of a location are tenant principals, groups and site URLs, so
    only the property name is ever projected. That is exactly what CIS 3.3.1
    asks the auditor to review, and it carries no tenant identifier.
    """
    scopes: list[str] = []
    for prop in LABEL_LOCATION_PROPERTIES:
        names = location_names(record.get(prop))
        if names is None:
            return None
        if names:
            scopes.append(LABEL_LOCATION_SCOPES[prop])
    return sorted(scopes)


class LabelPolicyDataCollector(BasePowerShellCollector):
    """Collects sensitivity label policies for CIS compliance evaluation.

    The whole returned population is validated before anything is filtered: a
    policy whose identity or type cannot be read makes the collection
    incomplete, and incomplete collection is an error rather than a smaller
    population that would read downstream as evidence of absence.
    """

    async def collect(self, client: PowerShellClient) -> dict[str, Any]:
        """Collect sensitivity label policy data.

        Returns:
            Dict containing the projected policies, the published subset CIS
            3.3.1 counts, and the location scopes the benchmark asks an auditor
            -- not this engine -- to judge.
        """
        raw = await client.run_operation(
            "compliance.label_policy.read", "compliance.label_policy"
        )
        records = powershell_records(raw)

        policies: list[dict[str, Any]] = []
        for record in records:
            name = record.get("Name")
            policy_type = record.get("Type")
            if (
                not isinstance(name, str)
                or not name.strip()
                or not isinstance(policy_type, str)
                or not policy_type.strip()
            ):
                raise ValueError(
                    "PowerShell sensitivity label policy identity or type "
                    "evidence is incomplete"
                )
            policies.append(
                {
                    "name": name.strip(),
                    "type": policy_type.strip(),
                    "location_scopes": _location_scopes(record),
                }
            )

        published_type = PUBLISHED_SENSITIVITY_LABEL_TYPE.casefold()
        published = [
            policy for policy in policies if policy["type"].casefold() == published_type
        ]

        # One unreadable location on one published policy makes the tenant's
        # published scope unknown, not smaller.
        if any(policy["location_scopes"] is None for policy in published):
            published_scopes: list[str] | None = None
        else:
            published_scopes = sorted(
                {scope for policy in published for scope in policy["location_scopes"]}
            )

        return {
            "label_policies": policies,
            "total_policies": len(records),
            "published_label_policies": published,
            "published_label_policy_count": len(published),
            "published_label_policy_location_scopes": published_scopes,
        }
