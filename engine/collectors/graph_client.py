"""Microsoft Graph API client.

One client instance owns one pooled ``httpx.AsyncClient`` and one MSAL token, so
a collection group that shares a client reuses both. Phase 9 adds explicit,
bounded retry for the transient failures Microsoft documents (429 with
``Retry-After``, 5xx, timeouts, connection resets) and never retries an
authorization or invalid-request failure -- retrying those turns a deterministic
"you may not read this" into repeated tenant load and still ends in the same
error. Pagination already refuses to truncate silently; that refusal is now its
own exception type so a caller can tell truncation apart from malformed evidence.
"""

import asyncio
import inspect
import logging
from dataclasses import dataclass
from email.utils import parsedate_to_datetime
from datetime import datetime, timezone
from typing import Any

import httpx
from msal import ConfidentialClientApplication
from worker.correlation import headers, event


class GraphCollectionIncomplete(ValueError):
    """Pagination reached its bound; the collection is truncated, not empty.

    A ValueError subclass so every existing caller and test that expects
    ValueError keeps working, while a caller that needs to distinguish
    truncation from malformed evidence can.
    """


# Transient by Microsoft's own documentation. 5xx and 429 are retried; every
# 4xx below 429 is a deterministic answer about the request or the caller's
# authorization and is never retried, because a retry cannot change it.
RETRYABLE_STATUS = frozenset({429, 500, 502, 503, 504})

# Connection resets, read/write failures and timeouts. Deliberately explicit
# rather than the httpx.TransportError parent: httpx.UnsupportedProtocol and
# httpx.ProxyError are also TransportError and are configuration faults.
RETRYABLE_EXCEPTIONS = (
    httpx.TimeoutException,
    httpx.ConnectError,
    httpx.ReadError,
    httpx.WriteError,
    httpx.RemoteProtocolError,
)


@dataclass(frozen=True)
class GraphRetryPolicy:
    """Bounded retry. Both bounds are required: attempts alone cannot bound
    wall-clock when a service returns a large ``Retry-After``."""

    max_attempts: int = 4
    base_seconds: float = 1.0
    max_delay_seconds: float = 30.0
    max_total_delay_seconds: float = 60.0

    def __post_init__(self) -> None:
        if self.max_attempts < 1:
            raise ValueError("max_attempts must be at least 1")
        if (
            min(self.base_seconds, self.max_delay_seconds, self.max_total_delay_seconds)
            < 0
        ):
            raise ValueError("retry delays must not be negative")

    def backoff(self, attempt: int) -> float:
        """Exponential backoff for the given 1-based attempt number."""
        return min(self.base_seconds * (2 ** (attempt - 1)), self.max_delay_seconds)


DEFAULT_RETRY = GraphRetryPolicy()


def parse_retry_after(value: str | None, now: datetime | None = None) -> float | None:
    """Return the server's requested delay in seconds, or None.

    RFC 9110 permits either delta-seconds or an HTTP-date. A malformed or past
    value yields None so the caller falls back to its own backoff rather than
    treating an unparseable header as "retry immediately".
    """
    if not isinstance(value, str) or not value.strip():
        return None
    text = value.strip()
    if text.isdigit():
        return float(text)
    try:
        when = parsedate_to_datetime(text)
    except (TypeError, ValueError):
        return None
    if when is None:
        return None
    if when.tzinfo is None:
        when = when.replace(tzinfo=timezone.utc)
    reference = now or datetime.now(timezone.utc)
    delta = (when - reference).total_seconds()
    return delta if delta > 0 else None


class GraphClient:
    """Client for Microsoft Graph API."""

    GRAPH_BASE_URL = "https://graph.microsoft.com/v1.0"
    GRAPH_BETA_URL = "https://graph.microsoft.com/beta"

    # Class-level defaults so an instance built with __new__ (the collector
    # contract tests do this) still has a defined transport and retry policy.
    _http: httpx.AsyncClient | None = None
    _retry: GraphRetryPolicy = DEFAULT_RETRY

    def __init__(
        self,
        tenant_id: str,
        client_id: str,
        client_secret: str,
        retry: GraphRetryPolicy | None = None,
    ):
        self.tenant_id = tenant_id
        self.client_id = client_id
        self.client_secret = client_secret
        self._access_token: str | None = None
        self._http = None
        self._retry = retry or DEFAULT_RETRY

        # Initialize MSAL client
        self._msal_app = ConfidentialClientApplication(
            client_id=client_id,
            client_credential=client_secret,
            authority=f"https://login.microsoftonline.com/{tenant_id}",
        )

    # ------------------------------------------------------------------
    # Pooled transport
    # ------------------------------------------------------------------

    def _transport(self) -> httpx.AsyncClient:
        """One pooled client per GraphClient.

        Constructed with no arguments: the per-request timeout below is the
        documented one, and a zero-argument construction is what the collector
        contract tests substitute a MockTransport into.
        """
        client = self._http
        if client is None or client.is_closed:
            client = httpx.AsyncClient()
            self._http = client
        return client

    async def aclose(self) -> None:
        """Release the pooled connections. Safe to call more than once."""
        client = self._http
        self._http = None
        if client is not None and not client.is_closed:
            await client.aclose()

    async def __aenter__(self) -> "GraphClient":
        return self

    async def __aexit__(self, *exc_info) -> None:
        await self.aclose()

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

    # ------------------------------------------------------------------
    # Requests
    # ------------------------------------------------------------------

    async def _sleep(self, seconds: float) -> None:
        await asyncio.sleep(seconds)

    async def _send(
        self,
        client: httpx.AsyncClient,
        method: str,
        url: str,
        token: str,
        params: dict | None,
        json_data: dict | None,
    ) -> httpx.Response:
        return await client.request(
            method=method,
            url=url,
            headers={"Authorization": f"Bearer {token}", **headers()},
            params=params,
            json=json_data,
            timeout=60.0,
        )

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
        retry = self._retry or DEFAULT_RETRY
        client = self._transport()
        spent = 0.0

        for attempt in range(1, retry.max_attempts + 1):
            event("graph_request")
            throttled: httpx.Response | None = None
            try:
                response = await self._send(
                    client, method, f"{base_url}{endpoint}", token, params, json_data
                )
            except RETRYABLE_EXCEPTIONS:
                # Timeout, connection reset, half-closed connection. The last
                # attempt re-raises exactly what a client without retry would.
                if attempt >= retry.max_attempts:
                    raise
                delay = retry.backoff(attempt)
            else:
                if response.status_code not in RETRYABLE_STATUS:
                    # Raises for every non-retryable status -- authorization and
                    # invalid-request answers are deterministic and a retry
                    # cannot change them. A 2xx falls through to validation.
                    response.raise_for_status()
                    payload = response.json() if response.content else {}
                    if not isinstance(payload, dict):
                        raise ValueError("Graph response must be an object")
                    if any(
                        payload.get(key) is not None
                        for key in ("error", "collector_error")
                    ):
                        raise ValueError("Graph response contains a collection error")
                    return payload
                if attempt >= retry.max_attempts:
                    # Bounded retry exhausted. Never a verdict: the caller sees
                    # the same transport error it would have seen with no retry.
                    response.raise_for_status()
                requested = parse_retry_after(response.headers.get("Retry-After"))
                delay = min(
                    requested if requested is not None else retry.backoff(attempt),
                    retry.max_delay_seconds,
                )
                throttled = response

            if delay > 0:
                # The wall-clock budget is checked only when a delay is actually
                # taken, so a zero-delay policy still performs its full attempt
                # count and a large Retry-After can never park a worker.
                remaining = retry.max_total_delay_seconds - spent
                if remaining <= 0:
                    if throttled is not None:
                        throttled.raise_for_status()
                    raise httpx.ConnectError("Graph retry budget exhausted")
                delay = min(delay, remaining)
                spent += delay
                event("graph_retry")
                await self._sleep(delay)
            else:
                event("graph_retry")

        raise RuntimeError("Graph request loop terminated without a result")

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

        raise GraphCollectionIncomplete(
            "Graph collection incomplete: pagination limit reached"
        )

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


async def release(client) -> bool:
    """Release a client's pooled transport, if it has one, and never raise.

    Tolerant by design, and deliberately so in two directions: several tests
    substitute a bare object or a MagicMock for a client, and a cleanup failure
    must never change the outcome of the collection or the verification the
    client was built for. Returns whether anything was actually closed.
    """
    close = getattr(client, "aclose", None)
    if not callable(close):
        return False
    try:
        outcome = close()
        if inspect.isawaitable(outcome):
            await outcome
    except Exception:  # noqa: BLE001 - a cleanup failure is never a verdict
        logging.getLogger(__name__).warning("graph_client_close_failed")
        return False
    return True


__all__ = [
    "GraphClient",
    "release",
    "GraphCollectionIncomplete",
    "GraphRetryPolicy",
    "DEFAULT_RETRY",
    "RETRYABLE_STATUS",
    "RETRYABLE_EXCEPTIONS",
    "parse_retry_after",
]
