"""Anti-phish policy collector.

CIS Microsoft 365 Foundations Benchmark Controls:
    v6.0.0: 2.1.7

Connection Method: Exchange Online PowerShell (via Docker container)
Authentication: Client secret via MSAL -> access token passed to -AccessToken parameter
Required Cmdlets: Get-AntiPhishPolicy, Get-AntiPhishRule
Required Permissions: Exchange.ManageAsApp + Exchange role assignment
"""

from typing import Any

from collectors.powershell_base import BasePowerShellCollector, powershell_records
from collectors.powershell_client import PowerShellClient


class AntiPhishPolicyDataCollector(BasePowerShellCollector):
    """Collects anti-phishing policy for CIS compliance evaluation.

    This collector retrieves anti-phishing policy configuration
    to verify proper phishing protection is enabled.
    """

    async def collect(self, client: PowerShellClient) -> dict[str, Any]:
        """Collect anti-phish policy data.

        Returns:
            Dict containing:
            - anti_phish_policies: List of anti-phishing policies
            - default_policy: The default policy (Office365 AntiPhish Default)
        """
        policies = await client.run_operation(
            "exchange.protection.anti_phish_policy.read",
            "exchange.protection.anti_phish_policy",
        )

        # Handle None, single policy, or list
        policies = powershell_records(policies)

        rules = powershell_records(
            await client.run_operation(
                "exchange.protection.anti_phish_policy.rules",
                "exchange.protection.anti_phish_policy",
            )
        )

        # Find default policy
        default_policy = next((p for p in policies if p.get("IsDefault")), None)

        return {
            "anti_phish_policies": policies,
            "anti_phish_rules": rules,
            "total_policies": len(policies),
            "default_policy": default_policy,
        }
