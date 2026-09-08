"""Safe PowerShell session batching (PERF-04).

Before Phase 9 every reviewed cmdlet was its own pwsh process, its own
``Connect-*`` and its own ``Disconnect-*``. A tenant with 200 shared mailboxes
opened 201 Exchange sessions for CIS 1.2.2 alone.

Batching is only safe if the trust boundary does not move, so these tests assert
the boundary first and the saving second:

* every entry is validated against ITS OWN collector id, not once per batch;
* a batch is exactly one module and one tenant identity, because the module
  chooses the Connect verb, the certificate namespace and the secret environment
  variables the pwsh child is given;
* the child environment is still an allowlist plus that one module's secrets;
* a failing cmdlet aborts the whole batch, because a partial batch is a smaller
  population and not the tenant's configuration.
"""

import asyncio
import json
import os
from unittest.mock import Mock

import pytest

from powershell.service import executor, main
from powershell.service.executor import (
    BATCH_TIMEOUT_SECONDS,
    build_batch_script,
    execute_batch,
)
from powershell.service.operations import MAX_BATCH, OPERATIONS, validate_batch
from powershell.service.schemas import ExecuteBatchRequest

TENANT = "contoso.onmicrosoft.com"
READ = {
    "operation_id": "exchange.mailbox.mailboxes.read",
    "collector_id": "exchange.mailbox.mailboxes",
    "params": {},
}
USER = {
    "operation_id": "exchange.mailbox.mailboxes.user",
    "collector_id": "exchange.mailbox.mailboxes",
    "params": {"Identity": "shared@contoso.com"},
}
SHAREPOINT = {
    "operation_id": "sharepoint.pnp.tenant.read",
    "collector_id": "sharepoint.pnp.tenant",
    "params": {},
}


# ---------------------------------------------------------------------------
# The boundary
# ---------------------------------------------------------------------------


def test_every_entry_is_validated_against_its_own_collector_id():
    borrowed = dict(USER, collector_id="exchange.organization.organization_config")
    with pytest.raises(ValueError, match="not permitted"):
        validate_batch([READ, borrowed])


def test_an_unknown_operation_anywhere_in_the_batch_is_refused():
    with pytest.raises(ValueError, match="Unknown PowerShell operation"):
        validate_batch([READ, dict(READ, operation_id="Remove-Mailbox")])


def test_a_batch_must_be_exactly_one_module():
    with pytest.raises(ValueError, match="exactly one module"):
        validate_batch([READ, SHAREPOINT])


def test_a_batch_entry_may_not_carry_extra_fields():
    with pytest.raises(ValueError, match="batch entry fields"):
        validate_batch([dict(READ, module="Compliance")])


def test_an_empty_batch_is_refused():
    with pytest.raises(ValueError, match="at least one operation"):
        validate_batch([])


def test_the_batch_size_is_bounded():
    assert MAX_BATCH == 25
    with pytest.raises(ValueError, match="reviewed maximum size"):
        validate_batch([READ] * (MAX_BATCH + 1))


def test_a_batch_parameter_still_faces_the_restrictive_grammar():
    with pytest.raises(ValueError, match="Invalid PowerShell operation parameter"):
        validate_batch([dict(USER, params={"Identity": "'; Get-Secret; '"})])


def test_the_request_model_applies_every_module_rule_the_single_form_applies():
    # ExchangeOnline requires a token and forbids certificate fields.
    with pytest.raises(ValueError, match="token is required"):
        ExecuteBatchRequest(operations=[READ], tenant_id=TENANT)
    with pytest.raises(ValueError, match="only permitted for SharePointOnline"):
        ExecuteBatchRequest(
            operations=[READ],
            tenant_id=TENANT,
            token="t",
            certificate_alias="default",
        )
    # SharePointOnline requires its certificate fields and forbids a token.
    with pytest.raises(ValueError, match="SharePointOnline requires"):
        ExecuteBatchRequest(operations=[SHAREPOINT], tenant_id=TENANT)


def test_a_tenant_guid_can_never_reach_a_compliance_organization():
    with pytest.raises(ValueError, match="onmicrosoft.com domain"):
        ExecuteBatchRequest(
            operations=[
                {
                    "operation_id": "compliance.dlp_compliance_policy.read",
                    "collector_id": "compliance.dlp_compliance_policy",
                    "params": {},
                }
            ],
            tenant_id=TENANT,
            client_id="00000000-0000-0000-0000-000000000001",
            compliance_certificate_alias="default",
            compliance_organization="00000000-0000-0000-0000-000000000001",
        )


# ---------------------------------------------------------------------------
# The script
# ---------------------------------------------------------------------------


def test_the_batch_script_connects_once_and_disconnects_once():
    script = build_batch_script([READ, USER], TENANT)
    assert script.count("Connect-ExchangeOnline") == 1
    assert script.count("Disconnect-ExchangeOnline") == 1
    assert script.count("Import-Module ExchangeOnlineManagement") == 1
    assert "$ErrorActionPreference = 'Stop'" in script


def test_the_batch_script_contains_only_registry_command_text():
    script = build_batch_script([READ, USER], TENANT)
    for entry in (READ, USER):
        assert OPERATIONS[entry["operation_id"]].command in script
    # The only interpolated value anywhere is the reviewed UPN, single-quoted.
    assert "-Identity 'shared@contoso.com'" in script


def test_the_batch_script_emits_an_indexed_array_at_a_preserved_depth():
    script = build_batch_script([READ, USER], TENANT)
    assert "index = 0" in script and "index = 1" in script
    # Depth 12, not 10. The wrapper costs TWO levels: the pscustomobject, and
    # the `data` value, which the single-operation script's pipeline unrolled
    # into the top-level array. Compensating by only one truncated a batched
    # payload one level earlier than the same cmdlet run singly, and PowerShell
    # replaces anything past -Depth with a type name rather than failing.
    assert "-Depth 12 -AsArray" in script


def test_a_single_operation_script_is_unchanged_by_the_refactor():
    single = executor.build_script(
        READ["operation_id"], READ["collector_id"], READ["params"], TENANT
    )
    assert "$result | ConvertTo-Json -Depth 10" in single
    assert "-AsArray" not in single


# ---------------------------------------------------------------------------
# Execution
# ---------------------------------------------------------------------------


def _run(monkeypatch, stdout, returncode=0):
    captured = {}

    def run(argv, **kwargs):
        captured["argv"] = argv
        captured["env"] = kwargs["env"]
        captured["timeout"] = kwargs["timeout"]
        return Mock(returncode=returncode, stdout=stdout, stderr="")

    monkeypatch.setattr(executor.subprocess, "run", run)
    return captured


def test_a_batch_returns_results_in_request_order(monkeypatch):
    captured = _run(
        monkeypatch,
        json.dumps([{"index": 1, "data": {"b": 2}}, {"index": 0, "data": {"a": 1}}]),
    )
    result = execute_batch([READ, USER], TENANT, token="synthetic")
    # The service reassembles by index, so a shell that emits out of order still
    # yields request order.
    assert result == [{"a": 1}, {"b": 2}]
    assert captured["timeout"] == BATCH_TIMEOUT_SECONDS


def test_the_batch_child_environment_is_an_allowlist(monkeypatch):
    monkeypatch.setenv("POWERSHELL_SERVICE_SECRET", "s" * 40)
    monkeypatch.setenv("SHAREPOINT_CERT_ALIASES", json.dumps({"default": {}}))
    monkeypatch.setenv("COMPLIANCE_CERT_ALIASES", json.dumps({"default": {}}))
    captured = _run(monkeypatch, json.dumps([{"index": 0, "data": None}]))
    execute_batch([READ], TENANT, token="synthetic")
    env = captured["env"]
    assert set(env) <= set(executor._ENV_ALLOWLIST) | {"EXO_TOKEN"}
    assert "POWERSHELL_SERVICE_SECRET" not in env
    assert "SHAREPOINT_CERT_ALIASES" not in env
    assert "COMPLIANCE_CERT_ALIASES" not in env
    assert env["EXO_TOKEN"] == "synthetic"
    # The script travels on the command line, the secret does not.
    assert "synthetic" not in " ".join(captured["argv"])


def test_a_failing_cmdlet_aborts_the_whole_batch(monkeypatch):
    _run(monkeypatch, "", returncode=1)
    with pytest.raises(executor.PowerShellExecutionError):
        execute_batch([READ, USER], TENANT, token="synthetic")


@pytest.mark.parametrize(
    "stdout",
    [
        "",
        "not json",
        json.dumps([{"index": 0, "data": None}]),  # one result for two operations
        json.dumps([{"index": 0, "data": None}, {"index": 0, "data": None}]),
        json.dumps([{"index": 0, "data": None}, {"index": 5, "data": None}]),
        json.dumps([{"index": 0, "data": None}, {"nope": 1}]),
        json.dumps({"index": 0, "data": None}),
    ],
)
def test_an_incomplete_or_malformed_batch_result_is_refused(monkeypatch, stdout):
    _run(monkeypatch, stdout)
    with pytest.raises(executor.PowerShellExecutionError):
        execute_batch([READ, USER], TENANT, token="synthetic")


def test_a_null_cmdlet_result_stays_null_rather_than_becoming_empty(monkeypatch):
    _run(
        monkeypatch,
        json.dumps([{"index": 0, "data": None}, {"index": 1, "data": None}]),
    )
    assert execute_batch([READ, USER], TENANT, token="synthetic") == [None, None]


# ---------------------------------------------------------------------------
# The service
# ---------------------------------------------------------------------------


def test_blocking_execution_runs_on_the_services_own_bounded_pool(monkeypatch):
    monkeypatch.setenv("POWERSHELL_MAX_CONCURRENCY", "3")
    monkeypatch.setattr(main, "_EXECUTION_POOL", None)
    pool = main.execution_pool()
    assert pool._max_workers == 3
    assert main.execution_pool() is pool
    pool.shutdown(wait=False)
    monkeypatch.setattr(main, "_EXECUTION_POOL", None)


@pytest.mark.parametrize("value", ["0", "33", "many", ""])
def test_a_misconfigured_concurrency_bound_fails_startup_closed(monkeypatch, value):
    monkeypatch.setenv("POWERSHELL_MAX_CONCURRENCY", value)
    with pytest.raises(RuntimeError, match="POWERSHELL_MAX_CONCURRENCY"):
        main._max_concurrency()


def test_the_default_bound_is_small(monkeypatch):
    monkeypatch.delenv("POWERSHELL_MAX_CONCURRENCY", raising=False)
    assert main._max_concurrency() == 4


def test_both_execution_endpoints_are_async_so_the_offload_is_explicit():
    assert asyncio.iscoroutinefunction(main.execute)
    assert asyncio.iscoroutinefunction(main.execute_many)


def test_the_batch_endpoint_authenticates_and_never_echoes_a_credential(monkeypatch):
    from fastapi.testclient import TestClient

    secret = "x" * 40
    monkeypatch.setenv("POWERSHELL_SERVICE_SECRET", secret)
    monkeypatch.setattr(main, "_EXECUTION_POOL", None)
    called = Mock(return_value=[None])
    monkeypatch.setattr(main, "execute_batch", called)
    with TestClient(main.app) as client:
        body = {
            "operations": [READ],
            "tenant_id": TENANT,
            "token": "sensitive-token",  # pragma: allowlist secret - synthetic
        }
        assert client.post("/execute-batch", json=body).status_code == 401
        called.assert_not_called()
        response = client.post(
            "/execute-batch", json=body, headers={"X-Service-Secret": secret}
        )
        assert response.status_code == 200 and response.json()["success"] is True
        invalid = client.post(
            "/execute-batch",
            json={**body, "operations": [dict(READ, cmdlet="Get-User")]},
            headers={"X-Service-Secret": secret},
        )
        assert invalid.status_code == 422
        assert "sensitive-token" not in invalid.text
    monkeypatch.setattr(main, "_EXECUTION_POOL", None)


def test_the_environment_the_service_process_holds_is_not_what_a_child_gets():
    # Documents the property the allowlist protects: os.environ is the parent's.
    assert "PATH" in os.environ
    assert set(executor._ENV_ALLOWLIST) == {
        "PATH",
        "HOME",
        "PSModulePath",
        "TMPDIR",
        "LANG",
    }


# ---------------------------------------------------------------------------
# The client, and the collector the batching exists for
# ---------------------------------------------------------------------------


def _service_client(monkeypatch, responses):
    """A PowerShellClient wired to a MockTransport standing in for the service."""
    import httpx
    from collectors import powershell_client

    seen = []

    def handle(request):
        seen.append(json.loads(request.content))
        return httpx.Response(200, json=responses.pop(0))

    real = httpx.AsyncClient
    monkeypatch.setattr(
        powershell_client.httpx,
        "AsyncClient",
        lambda **kwargs: real(transport=httpx.MockTransport(handle)),
    )
    client = powershell_client.PowerShellClient(
        tenant_id=TENANT,
        client_id="00000000-0000-0000-0000-000000000001",
        client_secret="synthetic",  # pragma: allowlist secret - synthetic fixture
        service_url="https://powershell.example.test",
        service_secret="s" * 40,
    )
    client._acquire_tokens = lambda module: ("synthetic", None)
    return client, seen


def test_run_operations_sends_one_batch_request(monkeypatch):
    client, seen = _service_client(
        monkeypatch, [{"success": True, "data": [{"a": 1}, {"b": 2}]}]
    )
    result = asyncio.run(
        client.run_operations(
            [
                (READ["operation_id"], READ["collector_id"], {}),
                (USER["operation_id"], USER["collector_id"], USER["params"]),
            ]
        )
    )
    assert result == [{"a": 1}, {"b": 2}]
    assert len(seen) == 1
    assert [entry["operation_id"] for entry in seen[0]["operations"]] == [
        READ["operation_id"],
        USER["operation_id"],
    ]


def test_run_operations_chunks_at_the_reviewed_maximum(monkeypatch):
    entries = [
        (
            USER["operation_id"],
            USER["collector_id"],
            {"Identity": f"shared{index}@contoso.com"},
        )
        for index in range(MAX_BATCH + 3)
    ]
    client, seen = _service_client(
        monkeypatch,
        [
            {"success": True, "data": [None] * MAX_BATCH},
            {"success": True, "data": [None] * 3},
        ],
    )
    result = asyncio.run(client.run_operations(entries))
    assert len(result) == MAX_BATCH + 3
    # Two sessions for 28 mailboxes, not 28.
    assert [len(request["operations"]) for request in seen] == [MAX_BATCH, 3]


def test_run_operations_refuses_a_short_service_response(monkeypatch):
    from collectors.powershell_client import PowerShellExecutionError

    client, _ = _service_client(monkeypatch, [{"success": True, "data": [{"a": 1}]}])
    with pytest.raises(PowerShellExecutionError, match="incomplete evidence"):
        asyncio.run(
            client.run_operations(
                [
                    (READ["operation_id"], READ["collector_id"], {}),
                    (USER["operation_id"], USER["collector_id"], USER["params"]),
                ]
            )
        )


def test_run_operations_refuses_a_certificate_module_without_the_service():
    from collectors.powershell_client import PowerShellClient, PowerShellExecutionError

    client = PowerShellClient(
        tenant_id=TENANT,
        client_id="00000000-0000-0000-0000-000000000001",
        client_secret="synthetic",  # pragma: allowlist secret - synthetic fixture
    )
    with pytest.raises(PowerShellExecutionError, match="HTTP service"):
        asyncio.run(
            client.run_operations(
                [(SHAREPOINT["operation_id"], SHAREPOINT["collector_id"], {})]
            )
        )


def test_the_mailboxes_collector_opens_one_session_for_every_shared_mailbox_lookup():
    """CIS 1.2.2 was the worst N+1 in the repository: one Exchange session per
    shared mailbox, sequentially awaited, each with its own 120-second budget."""
    from collectors.registry import get_collector

    mailboxes = [
        {
            "DisplayName": f"Shared {index}",
            "UserPrincipalName": f"shared{index}@contoso.com",
            "ExternalDirectoryObjectId": f"id-{index}",
        }
        for index in range(8)
    ]
    single_calls = []
    batch_calls = []

    class Client:
        async def run_operation(self, operation_id, collector_id, **params):
            single_calls.append(operation_id)
            return mailboxes

        async def run_operations(self, entries):
            batch_calls.append(entries)
            return [{"AccountDisabled": True} for _ in entries]

    result = asyncio.run(get_collector("exchange.mailbox.mailboxes").collect(Client()))
    assert result["total_shared_mailboxes"] == 8
    assert all(row["account_disabled"] is True for row in result["shared_mailboxes"])
    # One list read plus ONE batched lookup, not one lookup per mailbox.
    assert single_calls == ["exchange.mailbox.mailboxes.read"]
    assert len(batch_calls) == 1 and len(batch_calls[0]) == 8
    assert all(entry[1] == "exchange.mailbox.mailboxes" for entry in batch_calls[0])


def test_a_mailbox_without_a_upn_is_not_looked_up_and_stays_undecided():
    from collectors.registry import get_collector

    class Client:
        async def run_operation(self, operation_id, collector_id, **params):
            return [{"DisplayName": "No UPN"}]

        async def run_operations(self, entries):
            assert entries == []
            return []

    result = asyncio.run(get_collector("exchange.mailbox.mailboxes").collect(Client()))
    assert result["shared_mailboxes"][0]["account_disabled"] is None


def test_the_configured_batch_bound_can_only_lower_the_reviewed_ceiling():
    """POWERSHELL_MAX_BATCH must actually bound something.

    Found in review: the setting was documented as the bound on how many
    reviewed operations share one remote session and was read by nothing at all,
    so an operator lowering it changed no behaviour.
    """
    from collectors.powershell_client import PowerShellClient

    def build(batch_size):
        client = PowerShellClient.__new__(PowerShellClient)
        PowerShellClient.__init__(
            client,
            tenant_id=TENANT,
            client_id="00000000-0000-0000-0000-000000000001",
            client_secret="synthetic",  # pragma: allowlist secret - synthetic
            batch_size=batch_size,
        )
        return client

    assert build(5).batch_size == 5
    assert build(None).batch_size == MAX_BATCH
    # The ceiling is a property of what was reviewed, not of what an operator
    # configures: a larger value is clamped down, never honoured.
    assert build(MAX_BATCH * 4).batch_size == MAX_BATCH
    assert build(0).batch_size == 1


def test_the_worker_passes_the_configured_bound_to_the_client():
    import inspect

    from worker import tasks

    source = inspect.getsource(tasks._evaluate_collection_async)
    assert "batch_size=settings.POWERSHELL_MAX_BATCH" in source


def test_the_batch_transport_outlives_the_services_own_batch_budget(monkeypatch):
    """Found in review: the client gave up at 120s while the service had 300s.

    Any batch whose server-side execution landed between the two was abandoned
    here as a transport failure while the pwsh child ran on unheard.
    """
    import httpx
    from collectors import powershell_client

    seen = {}
    real = httpx.AsyncClient

    def build(**kwargs):
        seen["timeout"] = kwargs.get("timeout")
        return real(
            transport=httpx.MockTransport(
                lambda request: httpx.Response(
                    200, json={"success": True, "data": [None]}
                )
            )
        )

    monkeypatch.setattr(powershell_client.httpx, "AsyncClient", build)
    client = powershell_client.PowerShellClient(
        tenant_id=TENANT,
        client_id="00000000-0000-0000-0000-000000000001",
        client_secret="synthetic",  # pragma: allowlist secret - synthetic
        service_url="https://powershell.example.test",
        service_secret="s" * 40,
    )
    client._acquire_tokens = lambda module: ("synthetic", None)
    asyncio.run(
        client.run_operations([(READ["operation_id"], READ["collector_id"], {})])
    )
    assert seen["timeout"] > BATCH_TIMEOUT_SECONDS
