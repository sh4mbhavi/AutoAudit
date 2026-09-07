"""Cloud-only admins data collector.

CIS-1.1.1: Ensure Administrative accounts are cloud-only.
Administrative accounts should not be synced from on-premises Active Directory.
"""

from typing import Any

from collectors.base import BaseDataCollector
from collectors.concurrency import gather_bounded
from collectors.graph_client import GraphClient


class CloudOnlyAdminsDataCollector(BaseDataCollector):
    """Collects admin accounts and checks if they are cloud-only."""

    # Roles that are considered administrative
    ADMIN_ROLE_NAMES = [
        "Global Administrator",
        "Privileged Role Administrator",
        "Privileged Authentication Administrator",
        "Security Administrator",
        "Exchange Administrator",
        "SharePoint Administrator",
        "Intune Administrator",
        "Application Administrator",
        "Cloud Application Administrator",
        "Azure AD Joined Device Local Administrator",
        "Compliance Administrator",
        "Conditional Access Administrator",
        "User Administrator",
    ]

    async def collect(self, client: GraphClient) -> dict[str, Any]:
        """Collect admin account information and check for on-prem sync.

        Returns:
            Dict with admin_accounts list, each containing:
            - userPrincipalName
            - displayName
            - on_premises_sync_enabled
            - admin_roles (list of roles the user holds)
        """
        # Get all directory roles
        roles = await client.get_directory_roles()

        # Find admin roles by name
        admin_roles = [
            role for role in roles if role.get("displayName") in self.ADMIN_ROLE_NAMES
        ]

        # Membership first, details second.
        #
        # Phase 9 splits what was one interleaved loop into two passes so the
        # per-user detail requests can run with a bound instead of one at a
        # time. Role membership stays serial: it is one request per admin role
        # over a small fixed list, and keeping it serial preserves the exact
        # point at which malformed member evidence is rejected -- that rejection
        # now happens before any user detail request is spent, never after.
        role_memberships: dict[str, list[str]] = {}

        for role in admin_roles:
            role_name = role.get("displayName", "Unknown")
            members = await client.get_role_members(role["id"])

            for member in members:
                if not isinstance(member.get("@odata.type"), str) or not member.get(
                    "id"
                ):
                    raise ValueError("Incomplete role member identity evidence")
                # Only process user objects
                if member.get("@odata.type") != "#microsoft.graph.user":
                    continue

                user_id = member.get("id")
                if not user_id:
                    continue

                # Insertion order reproduces the original first-seen order, and
                # a repeated role name is appended exactly as it was before.
                role_memberships.setdefault(user_id, []).append(role_name)

        def _details(user_id: str):
            async def fetch():
                return await client.get(
                    f"/users/{user_id}",
                    params={
                        "$select": "id,userPrincipalName,displayName,onPremisesSyncEnabled"
                    },
                )

            return fetch

        ordered_ids = list(role_memberships)
        details = await gather_bounded([_details(user_id) for user_id in ordered_ids])

        admin_accounts = [
            {
                "id": user_id,
                "userPrincipalName": user_details.get("userPrincipalName"),
                "displayName": user_details.get("displayName"),
                "on_premises_sync_enabled": (
                    user_details.get("onPremisesSyncEnabled")
                    if isinstance(user_details.get("onPremisesSyncEnabled"), bool)
                    else None
                ),
                "admin_roles": role_memberships[user_id],
            }
            for user_id, user_details in zip(ordered_ids, details)
        ]

        return {
            "admin_accounts": admin_accounts,
            "total_admin_accounts": len(admin_accounts),
            "synced_admin_count": sum(
                1 for a in admin_accounts if a["on_premises_sync_enabled"] is True
            ),
            "cloud_only_admin_count": sum(
                1 for a in admin_accounts if a["on_premises_sync_enabled"] is False
            ),
        }
