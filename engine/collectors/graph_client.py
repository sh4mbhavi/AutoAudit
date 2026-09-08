"""Microsoft Graph API client."""

from typing import Any

import httpx
from msal import ConfidentialClientApplication


class GraphClient:
    """Client for Microsoft Graph API."""

    GRAPH_BASE_URL = "https://graph.microsoft.com/v1.0"
    GRAPH_BETA_URL = "https://graph.microsoft.com/beta"

    def __init__(self, tenant_id: str, client_id: str, client_secret: str):
        self.tenant_id = tenant_id
        self.client_id = client_id
        self.client_secret = client_secret
        self._access_token: str | None = None

        # Initialize MSAL client
        self._msal_app = ConfidentialClientApplication(
            client_id=client_id,
            client_credential=client_secret,
            authority=f"https://login.microsoftonline.com/{tenant_id}",
        )

    async def _get_access_token(self) -> str:
        """Get or refresh the access token."""
        if self._access_token:
            return self._access_token

        # Acquire token for Graph API
        result = self._msal_app.acquire_token_for_client(
            scopes=["https://graph.microsoft.com/.default"]
        )

        if "access_token" not in result:
            raise RuntimeError("Graph token acquisition failed")

        self._access_token = result["access_token"]
        return self._access_token

    async def _request(
        self,
        method: str,
        endpoint: str,
        beta: bool = False,
        params: dict | None = None,
        json_data: dict | None = None,
    ) -> dict[str, Any]:
        """Make a read-only request to the Graph API."""
        if method != "GET" or json_data is not None:
            raise ValueError("Collectors permit GET requests without a body only")
        if (
            not isinstance(endpoint, str)
            or not endpoint.startswith("/")
            or endpoint.startswith("//")
        ):
            raise ValueError("Graph endpoint must be an API-relative path")
        token = await self._get_access_token()
        base_url = self.GRAPH_BETA_URL if beta else self.GRAPH_BASE_URL

        async with httpx.AsyncClient() as client:
            response = await client.request(
                method=method,
                url=f"{base_url}{endpoint}",
                headers={"Authorization": f"Bearer {token}"},
                params=params,
                json=json_data,
                timeout=60.0,
            )
            response.raise_for_status()
            payload = response.json() if response.content else {}
            if not isinstance(payload, dict):
                raise ValueError("Graph response must be an object")
            if any(
                payload.get(key) is not None for key in ("error", "collector_error")
            ):
                raise ValueError("Graph response contains a collection error")
            return payload

    async def get(
        self, endpoint: str, beta: bool = False, params: dict | None = None
    ) -> dict[str, Any]:
        """GET request to Graph API."""
        return await self._request("GET", endpoint, beta=beta, params=params)

    async def get_all_pages(
        self,
        endpoint: str,
        beta: bool = False,
        params: dict | None = None,
        max_pages: int = 100,
    ) -> list[dict[str, Any]]:
        """Get all pages of a paginated endpoint."""
        all_items: list[dict[str, Any]] = []
        current_endpoint = endpoint
        current_params = params

        for _ in range(max_pages):
            response = await self.get(
                current_endpoint, beta=beta, params=current_params
            )
            items = response.get("value")
            if not isinstance(items, list) or not all(
                isinstance(item, dict) for item in items
            ):
                raise ValueError(
                    "Graph collection response must contain an object list"
                )
            if any(
                item.get(key) is not None
                for item in items
                for key in ("error", "collector_error")
            ):
                raise ValueError("Graph collection record contains an error")
            all_items.extend(items)

            # Check for next page
            next_link = response.get("@odata.nextLink")
            if next_link is None:
                return all_items

            # Parse next link - it's a full URL
            base_url = self.GRAPH_BETA_URL if beta else self.GRAPH_BASE_URL
            if not isinstance(next_link, str) or not next_link.startswith(
                base_url + "/"
            ):
                raise ValueError(
                    "Graph nextLink must use the requested Graph API origin and version"
                )
            current_endpoint = next_link[len(base_url) :]
            current_params = None  # Params are in the URL

        raise ValueError("Graph collection incomplete: pagination limit reached")

    async def get_users(self) -> list[dict[str, Any]]:
        """Get all users."""
        return await self.get_all_pages(
            "/users",
            params={
                "$select": "id,userPrincipalName,displayName,accountEnabled,userType"
            },
        )

    async def get_directory_roles(self) -> list[dict[str, Any]]:
        """Get all directory roles."""
        return await self.get_all_pages("/directoryRoles")

    async def get_role_members(self, role_id: str) -> list[dict[str, Any]]:
        """Get members of a directory role."""
        return await self.get_all_pages(f"/directoryRoles/{role_id}/members")

    async def get_conditional_access_policies(self) -> list[dict[str, Any]]:
        """Get all Conditional Access policies."""
        return await self.get_all_pages("/identity/conditionalAccess/policies")

    async def get_authentication_methods(self, user_id: str) -> list[dict[str, Any]]:
        """Get authentication methods for a user."""
        response = await self.get(f"/users/{user_id}/authentication/methods", beta=True)
        return response.get("value", [])

    async def get_domains(self) -> list[dict[str, Any]]:
        """Get all domains."""
        return await self.get_all_pages("/domains")

    async def get_user_license_details(self, user_id: str) -> list[dict[str, Any]]:
        """Get license assignments and service plans for a user."""
        return await self.get_all_pages(
            f"/users/{user_id}/licenseDetails",
            params={"$select": "id,skuId,skuPartNumber,servicePlans"},
        )
