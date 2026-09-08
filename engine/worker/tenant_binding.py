"""Fail-closed proof that selected Graph and SharePoint identities agree."""

import re
from uuid import UUID
from urllib.parse import urlsplit


async def verify_sharepoint_tenant(credentials: dict, graph_client_type) -> bool:
    """Use authenticated Graph root-site identifiers, never global configuration.

    A missing Sites.Read.All grant or missing tenant facet is indeterminate.
    Sovereign/multi-geo URLs require a separately verified implementation.
    """
    try:
        tenant_id = UUID(credentials["tenant_id"])
        if tenant_id != UUID(credentials["sharepoint_tenant_id"]):
            return False
        admin = credentials["sharepoint_admin_url"]
        if not isinstance(admin, str) or not re.fullmatch(
            r"https://[a-z0-9][a-z0-9-]*-admin\.sharepoint\.com/?", admin
        ):
            return False
        alias = credentials["sharepoint_certificate_alias"]
        if not isinstance(alias, str) or not re.fullmatch(
            r"[A-Za-z0-9][A-Za-z0-9_-]{0,63}", alias
        ):
            return False
        graph = graph_client_type(
            tenant_id=credentials["tenant_id"],
            client_id=credentials["client_id"],
            client_secret=credentials["client_secret"],
        )
        site = await graph.get(
            "/sites/root", params={"$select": "webUrl,sharepointIds"}
        )
        if UUID(site["sharepointIds"]["tenantId"]) != tenant_id:
            return False
        root = urlsplit(site["webUrl"])
        expected_host = urlsplit(admin).hostname.replace(
            "-admin.sharepoint.com", ".sharepoint.com"
        )
        return (
            root.scheme == "https"
            and root.hostname == expected_host
            and root.netloc == expected_host
            and root.path in {"", "/"}
            and not root.query
            and not root.fragment
        )
    except Exception:
        # Authentication, permissions, malformed/absent evidence all fail closed.
        return False
