"""Groups collector.

CIS Microsoft 365 Foundations Benchmark Controls:
    v6.0.0: 1.2.1, 5.1.3.1, 5.1.3.2

Connection Method: Microsoft Graph API
Required Scopes: Group.Read.All
Graph Endpoint: /groups
"""

from typing import Any

from collectors.base import BaseDataCollector
from collectors.graph_client import GraphClient


class GroupsDataCollector(BaseDataCollector):
    """Collects group information for CIS compliance evaluation.

    This collector retrieves group details including dynamic groups,
    public groups, and group settings needed for compliance evaluation.
    """

    async def collect(self, client: GraphClient) -> dict[str, Any]:
        """Collect group data.

        Returns:
            Dict containing:
            - groups: List of groups with properties
            - total_groups: Number of groups
            - dynamic_groups_count: Number of dynamic membership groups
            - public_groups_count: Number of public groups
        """
        # Get all groups with relevant properties
        groups = await client.get_all_pages(
            "/groups",
            params={
                "$select": "id,displayName,groupTypes,membershipRule,visibility,securityEnabled,mailEnabled"
            },
        )

        # Validate classification evidence before filtering: omitted visibility
        # must not disappear into an apparently safe empty public-group list.
        for group in groups:
            if not group.get("id") or not isinstance(group.get("groupTypes"), list):
                raise ValueError("Incomplete group identity or type evidence")
            visibility = group.get("visibility")
            known_private_security_group = (
                "visibility" in group
                and visibility is None
                and group.get("securityEnabled") is True
                and "Unified" not in group["groupTypes"]
            )
            if (
                visibility not in ("Public", "Private", "HiddenMembership")
                and not known_private_security_group
            ):
                raise ValueError("Incomplete group visibility evidence")

        # Categorize groups
        dynamic_groups = [
            g for g in groups if "DynamicMembership" in g.get("groupTypes", [])
        ]
        public_groups = [g for g in groups if g.get("visibility") == "Public"]
        security_groups = [g for g in groups if g.get("securityEnabled")]
        m365_groups = [g for g in groups if "Unified" in g.get("groupTypes", [])]

        return {
            "groups": groups,
            "total_groups": len(groups),
            "dynamic_groups": dynamic_groups,
            "dynamic_groups_count": len(dynamic_groups),
            "public_groups": public_groups,
            "public_groups_count": len(public_groups),
            "security_groups_count": len(security_groups),
            "m365_groups_count": len(m365_groups),
        }
