"""Bounded, order-preserving concurrency for per-item collector requests (PERF-03).

Two things have to be true at once: the collectors that used a serial per-item
loop must get faster, and the evidence they emit must be byte-identical to what
the serial loop emitted. The second is not cosmetic -- ``provenance.input_digest``
is ``canonical_digest`` of the collector payload, and canonical_digest sorts dict
keys but PRESERVES list order, so a reordered fan-out changes a published audit
digest for an unchanged tenant.
"""

import asyncio
from unittest.mock import AsyncMock, patch

import httpx
import pytest

from collectors import graph_client
from collectors.concurrency import DEFAULT_LIMIT, collection_limit, gather_bounded
from collectors.registry import get_collector


def _run(coroutine):
    return asyncio.run(coroutine)


# ---------------------------------------------------------------------------
# The helper
# ---------------------------------------------------------------------------


def test_results_keep_their_input_order_regardless_of_completion_order():
    async def item(index, delay):
        await asyncio.sleep(delay)
        return index

    # Deliberately inverted: the last item finishes first.
    factories = [
        (lambda index=index, delay=delay: item(index, delay))
        for index, delay in enumerate([0.03, 0.02, 0.01, 0.0])
    ]
    assert _run(gather_bounded(factories, limit=4)) == [0, 1, 2, 3]


def test_never_more_than_the_limit_is_in_flight():
    live = 0
    peak = 0

    async def item():
        nonlocal live, peak
        live += 1
        peak = max(peak, live)
        await asyncio.sleep(0.01)
        live -= 1
        return True

    _run(gather_bounded([item for _ in range(20)], limit=3))
    assert peak == 3


def test_an_empty_batch_does_no_work():
    assert _run(gather_bounded([], limit=4)) == []


def test_a_zero_limit_is_refused_rather_than_treated_as_unbounded():
    with pytest.raises(ValueError):
        _run(gather_bounded([lambda: asyncio.sleep(0)], limit=0))


def test_the_lowest_input_index_failure_is_the_one_raised():
    """A serial loop raised the first failure in input order; so does this."""

    async def item(index):
        await asyncio.sleep(0.02 - index * 0.01)
        raise ValueError(f"item {index}")

    factories = [(lambda index=index: item(index)) for index in range(3)]
    with pytest.raises(ValueError, match="item 0"):
        _run(gather_bounded(factories, limit=3))


def test_no_further_item_is_started_after_a_failure_is_observed():
    started = []

    async def item(index):
        started.append(index)
        if index == 0:
            raise ValueError("first")
        await asyncio.sleep(0)
        return index

    factories = [(lambda index=index: item(index)) for index in range(50)]
    with pytest.raises(ValueError, match="first"):
        _run(gather_bounded(factories, limit=2))
    # At most `limit` items can already be in flight when the failure lands.
    assert len(started) <= 2


def test_a_partial_result_set_is_never_returned():
    async def ok():
        return 1

    async def bad():
        raise RuntimeError("boom")

    with pytest.raises(RuntimeError):
        _run(gather_bounded([ok, bad, ok], limit=3))


def test_the_configured_limit_comes_from_worker_settings():
    from worker import config

    assert collection_limit() == config.settings.GRAPH_MAX_CONCURRENCY
    assert 1 <= collection_limit() <= 16
    assert DEFAULT_LIMIT == 4


# ---------------------------------------------------------------------------
# The collectors that used a serial per-item loop
# ---------------------------------------------------------------------------


def _collect(collector_id, routes, status=200):
    """Drive a real collector through a MockTransport and record the requests."""
    client = graph_client.GraphClient.__new__(graph_client.GraphClient)
    client._get_access_token = AsyncMock(return_value="synthetic")
    requests = []

    def respond(request):
        requests.append(request)
        path = request.url.path.removeprefix("/v1.0").removeprefix("/beta")
        payload = routes.get(path, {})
        if isinstance(payload, list):
            payload = {"value": payload}
        return httpx.Response(status, json=payload)

    real = httpx.AsyncClient
    with patch(
        "collectors.graph_client.httpx.AsyncClient",
        side_effect=lambda *a, **k: real(transport=httpx.MockTransport(respond)),
    ):
        result = _run(get_collector(collector_id).collect(client))
    return result, requests


SETTINGS_CATALOG = {
    "/deviceManagement/configurationPolicies": [
        {"id": f"policy-{index}", "name": f"Policy {index}"} for index in range(6)
    ],
    **{
        f"/deviceManagement/configurationPolicies/policy-{index}/settings": [
            {"id": f"setting-{index}"}
        ]
        for index in range(6)
    },
}


def test_settings_catalog_emits_policies_in_page_order():
    """The Settings Catalog N+1 named in the phase brief.

    Bounded concurrency here means ADDING concurrency, not capping it -- the
    loop had none. What must not change is the order: Phase 8 digests this
    payload and a reordering would read as configuration drift.
    """
    result, requests = _collect(
        "entra.devices.configuration_policies", SETTINGS_CATALOG
    )
    assert result["total_configuration_policies"] == 6
    assert [policy["id"] for policy in result["configuration_policies"]] == [
        f"policy-{index}" for index in range(6)
    ]
    assert [policy["settings"] for policy in result["configuration_policies"]] == [
        [{"id": f"setting-{index}"}] for index in range(6)
    ]
    # One list request plus one per policy: the request COUNT is unchanged, only
    # the latency is. Reducing the count would need a Graph batch endpoint.
    assert len(requests) == 7


def test_settings_catalog_still_discards_the_whole_collection_on_a_denial():
    with pytest.raises(httpx.HTTPStatusError):
        _collect("entra.devices.configuration_policies", SETTINGS_CATALOG, status=403)


def test_settings_catalog_survives_an_empty_tenant():
    result, _ = _collect(
        "entra.devices.configuration_policies",
        {"/deviceManagement/configurationPolicies": []},
    )
    assert result == {
        "configuration_policies": [],
        "total_configuration_policies": 0,
    }


ASR_ROUTES = {
    "/deviceManagement/deviceConfigurations": [
        {
            "id": f"config-{index}",
            "@odata.type": "#microsoft.graph.windows10EndpointProtectionConfiguration",
            "displayName": f"Profile {index}",
        }
        for index in range(4)
    ],
    **{
        f"/deviceManagement/deviceConfigurations/config-{index}": {
            "defenderOfficeMacroCodeAllowWin32ImportsType": "block"
            if index
            else "audit"
        }
        for index in range(4)
    },
}


def test_asr_rules_first_weakest_profile_is_still_the_first_in_page_order():
    """asr_rules publishes the NAME of the weakest profile via details.policy_name.

    ``min`` returns the first minimum, so a reordered fan-out would publish a
    different profile name on a tie. gather_bounded preserving input order is
    what keeps that stable.
    """
    routes = dict(ASR_ROUTES)
    routes["/deviceManagement/deviceConfigurations/config-2"] = {
        "defenderOfficeMacroCodeAllowWin32ImportsType": "audit"
    }
    result, _ = _collect("entra.devices.asr_rules", routes)
    assert result["win32_api_rule_state"] == "audit"
    # Profile 0 and Profile 2 tie at "audit"; the first in page order wins.
    assert result["policy_name"] == "Profile 0"


def test_asr_rules_ignores_profiles_that_are_not_endpoint_protection():
    routes = {
        "/deviceManagement/deviceConfigurations": [
            {"id": "other", "@odata.type": "#microsoft.graph.windowsUpdateForBusiness"}
        ]
    }
    result, requests = _collect("entra.devices.asr_rules", routes)
    assert result["win32_api_rule_found"] is False
    # One list request and no per-profile detail request at all.
    assert len(requests) == 1


ADMIN_ROUTES = {
    "/directoryRoles": [{"id": "role", "displayName": "Global Administrator"}],
    "/directoryRoles/role/members": [
        {
            "id": f"user-{index}",
            "@odata.type": "#microsoft.graph.user",
            "userPrincipalName": f"admin{index}@example.test",
        }
        for index in range(5)
    ],
    **{
        f"/users/user-{index}": {
            "id": f"user-{index}",
            "userPrincipalName": f"admin{index}@example.test",
            "displayName": f"Admin {index}",
            "onPremisesSyncEnabled": index % 2 == 0,
        }
        for index in range(5)
    },
}


def test_cloud_only_admins_keeps_first_seen_member_order():
    result, _ = _collect("entra.roles.cloud_only_admins", ADMIN_ROUTES)
    assert [account["id"] for account in result["admin_accounts"]] == [
        f"user-{index}" for index in range(5)
    ]
    assert result["synced_admin_count"] == 3
    assert result["cloud_only_admin_count"] == 2


def test_cloud_only_admins_rejects_incomplete_member_identity_before_any_user_request():
    routes = dict(ADMIN_ROUTES)
    routes["/directoryRoles/role/members"] = [{"id": "user-0"}]
    with pytest.raises(ValueError, match="Incomplete role member identity"):
        _collect("entra.roles.cloud_only_admins", routes)


LICENCE_ROUTES = {
    **ADMIN_ROUTES,
    **{
        f"/users/user-{index}/licenseDetails": [
            {
                "skuPartNumber": "E5",
                "servicePlans": [
                    {
                        "servicePlanName": "EXCHANGE_S_ENTERPRISE",
                        "provisioningStatus": "Success",
                        "appliesTo": "User",
                    }
                ],
            }
        ]
        for index in range(5)
    },
}


def test_admin_license_footprint_keeps_first_seen_member_order():
    result, _ = _collect("entra.roles.admin_license_footprint", LICENCE_ROUTES)
    assert [account["id"] for account in result["admin_accounts"]] == [
        f"user-{index}" for index in range(5)
    ]
    assert result["admin_accounts_with_high_footprint_licenses"] == 5
    assert result["admin_accounts_with_reduced_license_footprint"] == 0


# ---------------------------------------------------------------------------
# The concurrency itself, not just its consequences
# ---------------------------------------------------------------------------


def _overlap(collector_id, routes, item_prefix):
    """Drive a collector and record the maximum overlap of its per-item reads.

    Order and count are the same under a serial loop and under bounded
    concurrency, so asserting them cannot show that concurrency exists. This
    measures it: it holds every per-item response open until the whole batch has
    arrived, which a serial loop can never satisfy.
    """
    client = graph_client.GraphClient.__new__(graph_client.GraphClient)
    client._get_access_token = AsyncMock(return_value="synthetic")
    live = 0
    peak = 0

    async def respond(request):
        nonlocal live, peak
        path = request.url.path.removeprefix("/v1.0").removeprefix("/beta")
        payload = routes.get(path, {})
        if isinstance(payload, list):
            payload = {"value": payload}
        if item_prefix in path:
            live += 1
            peak = max(peak, live)
            # Yield often enough for every other in-flight item to start.
            for _ in range(8):
                await asyncio.sleep(0)
            live -= 1
        return httpx.Response(200, json=payload)

    real = httpx.AsyncClient
    with patch(
        "collectors.graph_client.httpx.AsyncClient",
        side_effect=lambda *a, **k: real(transport=httpx.MockTransport(respond)),
    ):
        _run(get_collector(collector_id).collect(client))
    return peak


def test_the_settings_catalog_per_policy_reads_actually_overlap():
    """PERF-03, measured rather than inferred.

    Reverting this collector to a serial loop leaves its order and its request
    count unchanged -- so only this assertion can tell the two apart.
    """
    peak = _overlap(
        "entra.devices.configuration_policies",
        SETTINGS_CATALOG,
        "/settings",
    )
    assert peak > 1
    assert peak <= collection_limit()


def test_asr_rules_per_profile_reads_actually_overlap():
    peak = _overlap(
        "entra.devices.asr_rules",
        ASR_ROUTES,
        "/deviceConfigurations/config-",
    )
    assert peak > 1
    assert peak <= collection_limit()


def test_cloud_only_admins_per_user_reads_actually_overlap():
    peak = _overlap("entra.roles.cloud_only_admins", ADMIN_ROUTES, "/users/user-")
    assert peak > 1
    assert peak <= collection_limit()


def test_admin_license_footprint_per_user_reads_actually_overlap():
    peak = _overlap(
        "entra.roles.admin_license_footprint", LICENCE_ROUTES, "/users/user-"
    )
    assert peak > 1
    assert peak <= collection_limit()


def test_role_membership_reads_stay_serial():
    """Deliberate: keeping them serial preserves the exact point at which
    malformed member evidence is rejected -- now before any user request is
    spent, never after."""
    assert _overlap("entra.roles.cloud_only_admins", ADMIN_ROUTES, "/members") == 1
