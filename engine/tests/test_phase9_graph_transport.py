"""Pooled, throttling-aware Graph transport (PERF-02).

Three separate claims, tested separately:

* one client instance owns one connection pool and one token, so a fanned-out
  collection stops rebuilding both per control;
* a documented transient failure is retried, bounded by attempts AND by
  wall-clock, honouring Retry-After;
* an authorization or invalid-request answer is never retried, and no retry
  ever turns a failure into an assessment.
"""

import asyncio
from dataclasses import replace
from datetime import datetime, timedelta, timezone
from email.utils import format_datetime
from unittest.mock import AsyncMock, patch

import httpx
import pytest

from collectors import graph_client
from collectors.graph_client import (
    DEFAULT_RETRY,
    GraphClient,
    GraphCollectionIncomplete,
    GraphRetryPolicy,
    parse_retry_after,
)

# Production attempt counts, no real wall-clock. Every _client below records
# what it WOULD have slept instead of sleeping, so the retry schedule is
# asserted directly rather than waited out.
FAST = replace(DEFAULT_RETRY, base_seconds=0.0)


def _client(handler, retry=FAST):
    client = GraphClient.__new__(GraphClient)
    client._get_access_token = AsyncMock(return_value="synthetic")
    client._retry = retry
    client._http = httpx.AsyncClient(transport=httpx.MockTransport(handler))
    client.slept = []

    async def sleep(seconds):
        client.slept.append(seconds)

    client._sleep = sleep
    return client


def _run(client, coroutine):
    async def main():
        try:
            return await coroutine
        finally:
            await client.aclose()

    return asyncio.run(main())


# ---------------------------------------------------------------------------
# Pooling
# ---------------------------------------------------------------------------


def test_one_client_reuses_one_transport_across_requests():
    """Before Phase 9 a new httpx.AsyncClient -- a new pool, TCP connection and
    TLS handshake -- was constructed for EVERY Graph request, including every
    page of a paginated collection."""
    seen = []
    built = []

    def handler(request):
        seen.append(request)
        return httpx.Response(200, json={"value": []})

    client = _client(handler)
    transport = client._transport()
    # Count constructions, not the surviving reference: aclose() nulls _http, so
    # comparing it afterwards can never fail and proves nothing.
    real = httpx.AsyncClient
    with patch(
        "collectors.graph_client.httpx.AsyncClient",
        side_effect=lambda *a, **k: built.append(
            real(transport=httpx.MockTransport(handler))
        )
        or built[-1],
    ):
        asyncio.run(_both(client))
    assert len(seen) == 2
    # Two requests, zero new transports: both went through the pooled one.
    assert built == []
    assert client._http is transport
    asyncio.run(client.aclose())


async def _both(client):
    await client.get("/users")
    await client.get("/domains")


def test_the_token_is_cached_on_the_instance_so_a_group_acquires_once():
    """The MSAL round trip happens once per client, not once per request.

    Before Phase 9 a fresh GraphClient -- and a fresh ConfidentialClientApplication
    with an empty MSAL cache -- was constructed per control, so a 69-control scan
    acquired a token 69 times. One client per collection group makes it once per
    group, which is what this cache does.
    """
    calls = []
    client = GraphClient.__new__(GraphClient)
    client._retry = FAST
    client._access_token = None
    client._msal_app = type(
        "App",
        (),
        {
            "acquire_token_for_client": lambda self, scopes: (
                calls.append(scopes) or {"access_token": "synthetic"}
            )
        },
    )()
    client._http = httpx.AsyncClient(
        transport=httpx.MockTransport(
            lambda request: httpx.Response(200, json={"value": []})
        )
    )
    _run(client, _both(client))
    assert len(calls) == 1
    assert client._access_token == "synthetic"


def test_aclose_is_idempotent_and_a_closed_client_rebuilds_its_pool():
    client = _client(lambda request: httpx.Response(200, json={"value": []}))
    first = client._transport()
    asyncio.run(client.aclose())
    asyncio.run(client.aclose())
    assert client._http is None
    assert client._transport() is not first
    asyncio.run(client.aclose())


# ---------------------------------------------------------------------------
# Retry-After parsing
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("value", [None, "", "   ", "soon", "-5", "1.5"])
def test_unparseable_retry_after_falls_back_to_our_own_backoff(value):
    assert parse_retry_after(value) is None


def test_retry_after_delta_seconds():
    assert parse_retry_after("12") == 12.0


def test_retry_after_http_date():
    now = datetime(2026, 9, 6, 12, 0, 0, tzinfo=timezone.utc)
    later = format_datetime(now + timedelta(seconds=30), usegmt=True)
    assert parse_retry_after(later, now=now) == pytest.approx(30.0, abs=1.0)


def test_a_retry_after_date_in_the_past_is_not_a_negative_delay():
    now = datetime(2026, 9, 6, 12, 0, 0, tzinfo=timezone.utc)
    earlier = format_datetime(now - timedelta(seconds=30), usegmt=True)
    assert parse_retry_after(earlier, now=now) is None


# ---------------------------------------------------------------------------
# Retry behaviour
# ---------------------------------------------------------------------------


def test_a_429_is_retried_and_then_succeeds():
    attempts = []

    def handler(request):
        attempts.append(request)
        if len(attempts) < 3:
            return httpx.Response(429, headers={"Retry-After": "1"}, json={})
        return httpx.Response(200, json={"value": []})

    client = _client(handler)
    assert _run(client, client.get("/users")) == {"value": []}
    assert len(attempts) == 3


def test_retry_honours_the_servers_retry_after_rather_than_our_backoff():
    attempts = []

    def handler(request):
        attempts.append(request)
        if len(attempts) == 1:
            return httpx.Response(429, headers={"Retry-After": "7"}, json={})
        return httpx.Response(200, json={"value": []})

    client = _client(handler, retry=replace(DEFAULT_RETRY, base_seconds=1.0))
    _run(client, client.get("/users"))
    assert client.slept == [7.0]


def test_backoff_is_exponential_and_capped_when_the_server_says_nothing():
    client = _client(
        lambda request: httpx.Response(500, json={}),
        retry=replace(DEFAULT_RETRY, base_seconds=1.0, max_delay_seconds=2.0),
    )
    with pytest.raises(httpx.HTTPStatusError):
        _run(client, client.get("/users"))
    assert client.slept == [1.0, 2.0, 2.0]


def test_the_wall_clock_budget_bounds_a_large_retry_after():
    client = _client(
        lambda request: httpx.Response(429, headers={"Retry-After": "600"}, json={}),
        retry=GraphRetryPolicy(
            max_attempts=5,
            base_seconds=1.0,
            max_delay_seconds=600.0,
            max_total_delay_seconds=10.0,
        ),
    )
    with pytest.raises(httpx.HTTPStatusError):
        _run(client, client.get("/users"))
    # A tenant asking for ten minutes cannot park a worker for ten minutes.
    assert sum(client.slept) <= 10.0


def test_retry_exhaustion_still_raises_and_never_returns_an_assessment():
    attempts = []

    def handler(request):
        attempts.append(request)
        return httpx.Response(429, json={})

    client = _client(handler)
    with pytest.raises(httpx.HTTPStatusError):
        _run(client, client.get("/users"))
    assert len(attempts) == DEFAULT_RETRY.max_attempts


@pytest.mark.parametrize("status", [400, 401, 403, 404, 405, 409, 422])
def test_a_deterministic_answer_is_never_retried(status):
    """Anti-pattern guard: retrying these costs tenant requests and changes nothing."""
    attempts = []

    def handler(request):
        attempts.append(request)
        return httpx.Response(status, json={})

    client = _client(handler)
    with pytest.raises(httpx.HTTPStatusError):
        _run(client, client.get("/users"))
    assert len(attempts) == 1


def test_a_connection_reset_is_retried():
    attempts = []

    def handler(request):
        attempts.append(request)
        if len(attempts) == 1:
            raise httpx.ConnectError("reset", request=request)
        return httpx.Response(200, json={"value": []})

    client = _client(handler)
    assert _run(client, client.get("/users")) == {"value": []}
    assert len(attempts) == 2


def test_a_timeout_that_never_clears_re_raises_the_transport_error():
    attempts = []

    def handler(request):
        attempts.append(request)
        raise httpx.ReadTimeout("slow", request=request)

    client = _client(handler)
    with pytest.raises(httpx.TimeoutException):
        _run(client, client.get("/users"))
    assert len(attempts) == DEFAULT_RETRY.max_attempts


def test_a_non_get_is_rejected_before_the_token_is_acquired():
    client = _client(lambda request: httpx.Response(200, json={}))
    with pytest.raises(ValueError):
        _run(client, client._request("POST", "/users"))
    client._get_access_token.assert_not_called()


# ---------------------------------------------------------------------------
# Pagination
# ---------------------------------------------------------------------------


def test_the_pagination_bound_raises_a_named_truncation_error():
    client = GraphClient.__new__(GraphClient)
    client.get = AsyncMock(
        return_value={
            "value": [{"id": "user"}],
            "@odata.nextLink": "https://graph.microsoft.com/v1.0/users?$skiptoken=next",
        }
    )
    with pytest.raises(GraphCollectionIncomplete, match="incomplete"):
        asyncio.run(client.get_all_pages("/users", max_pages=2))
    # Still a ValueError, so every caller and test written before Phase 9 that
    # expects ValueError keeps working.
    assert issubclass(GraphCollectionIncomplete, ValueError)


def test_retry_policy_rejects_a_zero_attempt_budget():
    with pytest.raises(ValueError):
        GraphRetryPolicy(max_attempts=0)
    with pytest.raises(ValueError):
        GraphRetryPolicy(base_seconds=-1)


def test_the_module_default_is_bounded_on_both_axes():
    assert DEFAULT_RETRY.max_attempts >= 2
    assert DEFAULT_RETRY.max_total_delay_seconds > 0
    assert graph_client.RETRYABLE_STATUS == frozenset({429, 500, 502, 503, 504})
