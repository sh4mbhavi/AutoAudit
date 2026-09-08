"""Security regression tests for the privileged PowerShell execution boundary."""

from pathlib import Path
import sys

import pytest

ENGINE = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ENGINE))


def test_service_rejects_arbitrary_cmdlet_contract():
    from powershell.service.schemas import ExecuteRequest

    with pytest.raises(ValueError):
        ExecuteRequest(
            module="ExchangeOnline",
            cmdlet="Remove-Mailbox",
            params={},
            tenant_id="contoso.onmicrosoft.com",
            token="token",
        )


@pytest.mark.parametrize(
    "cmdlet",
    [
        "Remove-Mailbox",
        "Get-User; Remove-Mailbox",
        "Get-User | Invoke-Expression",
        "& { Get-User }",
    ],
)
def test_script_builder_has_no_arbitrary_execution_contract(cmdlet):
    from powershell.service.executor import build_script

    with pytest.raises((ValueError, TypeError)):
        build_script(
            module="ExchangeOnline",
            cmdlet=cmdlet,
            params={},
            tenant_id="contoso.onmicrosoft.com",
        )


@pytest.mark.parametrize(
    "operation_id,collector_id,params",
    [
        ("Remove-Mailbox", "exchange.mailbox.mailboxes", {}),
        ("exchange.mailbox.mailboxes.read", "exchange.mailbox.mailbox_audit", {}),
        (
            "exchange.mailbox.mailboxes.user",
            "exchange.mailbox.mailboxes",
            {"Identity": "a@contoso.com;Remove-Mailbox"},
        ),
        (
            "exchange.mailbox.mailboxes.user",
            "exchange.mailbox.mailboxes",
            {"Identity": "$(Get-Secret)@contoso.com"},
        ),
        (
            "exchange.mailbox.mailboxes.user",
            "exchange.mailbox.mailboxes",
            {"Identity": {"script": "Get-Secret"}},
        ),
        (
            "exchange.mailbox.mailboxes.user",
            "exchange.mailbox.mailboxes",
            {"Identity": True},
        ),
        (
            "exchange.mailbox.mailboxes.user",
            "exchange.mailbox.mailboxes",
            {"Identity": ["a@contoso.com"]},
        ),
        (
            "exchange.mailbox.mailboxes.user",
            "exchange.mailbox.mailboxes",
            {"Identity": "a@contoso.com", "Verbose": True},
        ),
        (
            "exchange.mailbox.mailboxes.read",
            "exchange.mailbox.mailboxes",
            {"ResultSize": "Unlimited"},
        ),
    ],
)
def test_operation_registry_rejects_untrusted_execution_inputs(
    operation_id, collector_id, params
):
    from powershell.service.operations import validate_operation

    with pytest.raises(ValueError):
        validate_operation(operation_id, collector_id, params)


def test_registered_powershell_collectors_all_use_allowlisted_operations():
    import ast
    from collectors.powershell_base import BasePowerShellCollector
    from collectors.registry import DATA_COLLECTORS
    from powershell.service.operations import OPERATIONS, validate_operation

    for collector_id, collector in DATA_COLLECTORS.items():
        if not issubclass(collector, BasePowerShellCollector):
            continue
        source = Path(sys.modules[collector.__module__].__file__).read_text()
        calls = [
            node
            for node in ast.walk(ast.parse(source))
            if isinstance(node, ast.Call)
            and isinstance(node.func, ast.Attribute)
            and node.func.attr == "run_operation"
        ]
        assert calls, collector_id
        assert "run_cmdlet" not in source
        for call in calls:
            op_id, caller_id = [ast.literal_eval(arg) for arg in call.args]
            assert caller_id == collector_id
            parameters = {"Identity": "shared@contoso.com"} if call.keywords else {}
            validate_operation(op_id, caller_id, parameters)
    permitted = {
        collector_id
        for operation in OPERATIONS.values()
        for collector_id in operation.collectors
    }
    assert permitted <= DATA_COLLECTORS.keys()


def test_service_rejects_unauthenticated_request_before_execution(monkeypatch):
    from fastapi.testclient import TestClient
    from powershell.service import main

    monkeypatch.setenv("POWERSHELL_SERVICE_SECRET", "s" * 40)
    response = TestClient(main.app).post(
        "/execute",
        json={
            "operation_id": "exchange.organization.organization_config.read",
            "collector_id": "exchange.organization.organization_config",
            "tenant_id": "contoso.onmicrosoft.com",
            "token": "token",
        },
    )
    assert response.status_code == 401


def test_client_has_no_generic_execution_method():
    from collectors.powershell_client import PowerShellClient

    assert not hasattr(PowerShellClient, "run_cmdlet")
    assert not hasattr(PowerShellClient, "_build_script")


OP = "exchange.organization.organization_config.read"
COLLECTOR = "exchange.organization.organization_config"
SECRET = "synthetic-service-secret-" + "s" * 32  # pragma: allowlist secret


def payload(**updates):
    return {
        "operation_id": OP,
        "collector_id": COLLECTOR,
        "tenant_id": "contoso.onmicrosoft.com",
        "token": "sensitive-token",
        **updates,
    }


@pytest.fixture
def service(monkeypatch):
    from fastapi.testclient import TestClient
    from powershell.service import main
    from unittest.mock import Mock

    monkeypatch.setenv("POWERSHELL_SERVICE_SECRET", SECRET)
    execute = Mock(return_value={"AuditDisabled": False})
    monkeypatch.setattr(main, "execute_operation", execute)
    with TestClient(main.app) as client:
        yield client, execute


@pytest.mark.parametrize(
    "headers",
    [
        {},
        {"X-Service-Secret": "wrong"},
        {"Authorization": f"Bearer {SECRET}"},
    ],  # pragma: allowlist secret
)
def test_http_rejects_missing_wrong_or_wrong_header_credentials(service, headers):
    client, execute = service
    assert client.post("/execute", json=payload(), headers=headers).status_code == 401
    execute.assert_not_called()


def test_http_authentication_uses_constant_time_comparison(service, monkeypatch):
    from powershell.service import main
    from unittest.mock import Mock

    compare = Mock(wraps=main.hmac.compare_digest)
    monkeypatch.setattr(main.hmac, "compare_digest", compare)
    client, execute = service
    response = client.post(
        "/execute", json=payload(), headers={"X-Service-Secret": SECRET}
    )
    assert response.status_code == 200 and response.json()["success"] is True
    execute.assert_called_once()
    compare.assert_called_once_with(SECRET.encode(), SECRET.encode())


@pytest.mark.parametrize(
    "updates",
    [
        {"operation_id": "Remove-Mailbox"},
        {"operation_id": OP + "; whoami"},
        {"operation_id": OP + "\nGet-Secret"},
        {"collector_id": "exchange.mailbox.mailboxes"},
        {"module": "Compliance"},
        {"cmdlet": "Get-User"},
        {"script": "Get-Secret"},
        {"params": {"Identity": "a@contoso.com"}},
        {"params": {"Verbose;Get-Secret": True}},
        {"params": {"ScriptBlock": "{Get-Secret}"}},
        {"params": []},
        {"tenant_id": "contoso.com; Get-Secret"},
        {"tenant_id": "$(Get-Secret).com"},
        {"tenant_id": "contoso.com\nGet-Secret"},
        {"tenant_id": "contoso.com`whoami"},
        {"certificate_path": "/secrets/client.pfx"},
        {"certificate_password": "secret"},  # pragma: allowlist secret
        {"certificate_alias": "other"},
        {"graph_token": "unexpected"},
    ],
)
def test_http_rejects_invalid_inputs_without_echoing_credentials(service, updates):
    client, execute = service
    response = client.post(
        "/execute", json=payload(**updates), headers={"X-Service-Secret": SECRET}
    )
    assert response.status_code == 422
    execute.assert_not_called()
    assert "sensitive-token" not in response.text


@pytest.mark.parametrize("secret", [None, "", "short", " " * 40, "x" * 31, "é" * 40])
def test_service_startup_fails_without_valid_secret(monkeypatch, secret):
    from fastapi.testclient import TestClient
    from powershell.service.main import app

    if secret is None:
        monkeypatch.delenv("POWERSHELL_SERVICE_SECRET", raising=False)
    else:
        monkeypatch.setenv("POWERSHELL_SERVICE_SECRET", secret)
    with pytest.raises(RuntimeError, match="POWERSHELL_SERVICE_SECRET"):
        with TestClient(app):
            pass


def sharepoint_payload(**updates):
    return payload(
        operation_id="sharepoint.pnp.tenant.read",
        collector_id="sharepoint.pnp.tenant",
        token=None,
        client_id="12345678-1234-1234-1234-123456789abc",
        sharepoint_admin_url="https://contoso-admin.sharepoint.com",
        certificate_alias="contoso",
        **updates,
    )


@pytest.mark.parametrize(
    "field,value",
    [
        ("certificate_alias", "/secrets/tenant.pfx"),
        ("certificate_alias", "../tenant"),
        ("certificate_alias", "tenant;Get-Secret"),
        ("certificate_alias", "$env:CERT"),
        ("sharepoint_admin_url", "https://attacker.example"),
        ("sharepoint_admin_url", "https://contoso-admin.sharepoint.com/$(Get-Secret)"),
        (
            "sharepoint_admin_url",
            "https://contoso-admin.sharepoint.com@attacker.example",
        ),
        ("sharepoint_admin_url", 'https://contoso-admin.sharepoint.com";Get-Secret'),
        ("client_id", 'client";Get-Secret'),
        ("token", "not-permitted"),
    ],
)
def test_sharepoint_request_validates_certificate_and_connection_fields(
    service, field, value
):
    client, execute = service
    request = sharepoint_payload()
    request[field] = value
    assert (
        client.post(
            "/execute", json=request, headers={"X-Service-Secret": SECRET}
        ).status_code
        == 422
    )
    execute.assert_not_called()


def make_client(service_url=None):
    from collectors.powershell_client import PowerShellClient
    from unittest.mock import Mock

    client = PowerShellClient.__new__(PowerShellClient)
    client.tenant_id = "contoso.onmicrosoft.com"
    client.client_id = "12345678-1234-1234-1234-123456789abc"
    client.sharepoint_admin_url = "https://contoso-admin.sharepoint.com"
    client.certificate_alias = "contoso"
    client.service_url = service_url
    client.service_secret = SECRET
    client.service_ca_file = None
    client._msal_app = Mock()
    client._msal_app.acquire_token_for_client.return_value = {
        "access_token": "sensitive-token"
    }
    client._ensure_docker_image = Mock()
    return client


@pytest.mark.parametrize(
    "path", ["run_operation", "_run_via_service", "_run_via_docker"]
)
@pytest.mark.parametrize(
    "operation,collector,params",
    [
        ("Get-User;Remove-Mailbox", COLLECTOR, {}),
        (OP, "wrong-collector", {}),
        (OP, COLLECTOR, {"Verbose": True}),
        (
            "exchange.mailbox.mailboxes.user",
            "exchange.mailbox.mailboxes",
            {"Identity": "${Get-Secret}@contoso.com"},
        ),
    ],
)
def test_every_client_execution_path_validates_before_io(
    path, operation, collector, params
):
    import asyncio

    client = make_client("http://powershell-service:8001")
    with pytest.raises(ValueError):
        if path == "run_operation":
            asyncio.run(client.run_operation(operation, collector, **params))
        else:
            asyncio.run(getattr(client, path)(operation, collector, params))
    client._msal_app.acquire_token_for_client.assert_not_called()
    client._ensure_docker_image.assert_not_called()


def test_local_docker_uses_shared_script_and_no_secrets_in_argv(monkeypatch):
    import asyncio
    from unittest.mock import Mock
    from collectors import powershell_client
    from powershell.service.executor import build_script

    client = make_client()
    run = Mock(
        return_value=type(
            "Result", (), {"returncode": 0, "stdout": '{"AuditDisabled":false}'}
        )()
    )
    monkeypatch.setattr(powershell_client.subprocess, "run", run)
    assert asyncio.run(client.run_operation(OP, COLLECTOR)) == {"AuditDisabled": False}
    args, kwargs = run.call_args_list[0]
    assert "sensitive-token" not in repr(args)
    assert kwargs["env"]["EXO_TOKEN"] == "sensitive-token"
    assert kwargs["input"] == build_script(OP, COLLECTOR, {}, client.tenant_id)
    assert kwargs["timeout"] == 120
    command = args[0]
    assert command[-4:] == ["-NoProfile", "-NonInteractive", "-File", "/dev/stdin"]
    name = command[command.index("--name") + 1]
    assert run.call_args_list[1].args[0] == ["docker", "rm", "-f", name]


def test_service_client_transmits_only_fixed_contract_and_auth(monkeypatch):
    import asyncio
    import httpx
    from collectors import powershell_client

    client = make_client("http://powershell-service:8001")
    seen = []

    def handle(request):
        import json

        seen.append(json.loads(request.content))
        assert request.headers["X-Service-Secret"] == SECRET
        return httpx.Response(200, json={"success": True, "data": []})

    original = httpx.AsyncClient
    monkeypatch.setattr(
        powershell_client.httpx,
        "AsyncClient",
        lambda **kwargs: original(transport=httpx.MockTransport(handle), **kwargs),
    )
    assert asyncio.run(client.run_operation(OP, COLLECTOR)) == []
    assert seen == [payload(params={})]


@pytest.mark.parametrize("failure", ["process", "json", "launch"])
def test_executor_errors_never_echo_credentials(monkeypatch, failure):
    from unittest.mock import Mock
    from powershell.service import executor

    run = Mock(
        return_value=type(
            "Result",
            (),
            {
                "returncode": 1 if failure == "process" else 0,
                "stdout": "sensitive-token",
                "stderr": "sensitive-token",
            },
        )()
    )
    if failure == "launch":
        run.side_effect = OSError("sensitive-token")
    monkeypatch.setattr(executor.subprocess, "run", run)
    with pytest.raises(executor.PowerShellExecutionError) as error:
        executor.execute_operation(**payload(params={}))
    assert "sensitive-token" not in str(error.value)


def test_service_client_adds_private_ca_without_replacing_public_trust(monkeypatch):
    import asyncio
    from unittest.mock import Mock
    from collectors import powershell_client

    client = make_client("https://powershell-service:8001")
    client.service_ca_file = "/run/secrets/internal-ca.pem"
    context = Mock()
    monkeypatch.setattr(
        powershell_client.ssl, "create_default_context", Mock(return_value=context)
    )
    context.load_verify_locations.side_effect = OSError("bad CA")
    with pytest.raises(powershell_client.PowerShellExecutionError, match="CA"):
        asyncio.run(client.run_operation(OP, COLLECTOR))
    context.load_verify_locations.assert_called_once_with(
        cafile="/run/secrets/internal-ca.pem"
    )


@pytest.mark.parametrize(
    "identity",
    [
        "shared@contoso.com;Remove-Mailbox",
        "shared@contoso.com|Get-Secret",
        "$(Get-Secret)@contoso.com",
        "${env:SECRET}@contoso.com",
        "a'@contoso.com",
        'a"@contoso.com',
        "a`@contoso.com",
        "a{Get-Secret}@contoso.com",
        "a}@contoso.com",
        "a&@contoso.com",
        "a(@contoso.com",
        "a)@contoso.com",
        "a\n@contoso.com",
        "a\r@contoso.com",
        "a\x00@contoso.com",
        "a\\@contoso.com",
        "a/@contoso.com",
        "",
        None,
        123,
        True,
        [],
        {},
    ],
)
def test_parameter_metacharacters_types_and_scriptblocks_are_rejected(identity):
    from powershell.service.operations import operation_command

    with pytest.raises(ValueError):
        operation_command(
            "exchange.mailbox.mailboxes.user",
            "exchange.mailbox.mailboxes",
            {"Identity": identity},
        )


def test_all_operations_construct_only_their_reviewed_module_and_command():
    from powershell.service.operations import OPERATIONS
    from powershell.service.executor import build_script

    assert len(OPERATIONS) == 25
    for operation_id, operation in OPERATIONS.items():
        params = (
            {"Identity": "shared+audit@contoso.com"} if operation.parameters else {}
        )
        script = build_script(
            operation_id,
            next(iter(operation.collectors)),
            params,
            "contoso.onmicrosoft.com",
            client_id="12345678-1234-1234-1234-123456789abc",
            sharepoint_admin_url="https://contoso-admin.sharepoint.com",
        )
        assert operation.command in script
        assert "$ErrorActionPreference = 'Stop'" in script
        assert (
            "Import-Module PnP.PowerShell" in script
            if operation.module == "SharePointOnline"
            else "Import-Module ExchangeOnlineManagement" in script
        )
        assert operation.command.startswith("Get-")
        if params:
            assert "-Identity 'shared+audit@contoso.com'" in script


def test_executor_resolves_certificate_from_mounted_alias_only(monkeypatch, tmp_path):
    import json
    from unittest.mock import Mock
    from powershell.service import executor

    certificate, password = tmp_path / "cert.pfx", tmp_path / "password"
    certificate.write_bytes(b"synthetic")
    password.write_text("synthetic-password")
    monkeypatch.setenv(
        "SHAREPOINT_CERT_ALIASES",
        json.dumps(
            {
                "contoso": {
                    "path": str(certificate),
                    "password_file": str(password),
                }
            }
        ),
    )
    run = Mock(return_value=type("Result", (), {"returncode": 0, "stdout": "{}"})())
    monkeypatch.setattr(executor.subprocess, "run", run)
    request = sharepoint_payload()
    assert executor.execute_operation(**request, params={}) == {}
    assert run.call_args.kwargs["env"]["SPO_CERT_PATH"] == str(certificate)
    assert run.call_args.kwargs["env"]["SPO_CERT_PASSWORD_FILE"] == str(password)
    assert str(certificate) not in repr(run.call_args.args)
    run.reset_mock()
    request["certificate_alias"] = "unconfigured"
    with pytest.raises(ValueError, match="Unknown certificate alias"):
        executor.execute_operation(**request, params={})
    run.assert_not_called()


def test_health_is_public_without_executing_operations(service):
    client, execute = service
    assert client.get("/health").json() == {"status": "ok"}
    execute.assert_not_called()


def test_local_docker_timeout_removes_owned_container(monkeypatch):
    import asyncio
    import subprocess
    from unittest.mock import Mock
    from collectors import powershell_client

    run = Mock(
        side_effect=[subprocess.TimeoutExpired("docker", 120), Mock(returncode=0)]
    )
    monkeypatch.setattr(powershell_client.subprocess, "run", run)
    with pytest.raises(
        powershell_client.PowerShellExecutionError, match="execution failed"
    ):
        asyncio.run(make_client().run_operation(OP, COLLECTOR))
    command = run.call_args_list[0].args[0]
    name = command[command.index("--name") + 1]
    assert name.startswith("autoaudit-collection-")
    assert run.call_args_list[1].args[0] == ["docker", "rm", "-f", name]
    assert "sensitive-token" not in repr([call.args for call in run.call_args_list])
