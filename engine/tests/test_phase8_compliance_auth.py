"""Security tests for Compliance (Purview/SCC) certificate authentication.

Connect-IPPSSession is certificate-only here: Microsoft documents no app-only
access-token form, and -CertificateThumbPrint is Windows-only. These tests pin
the emitted connection form, the module-scoped certificate alias namespace, and
the explicit child-process environment allowlist.
"""

import json
from pathlib import Path
import sys

import pytest

ENGINE = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ENGINE))

DLP_OP = "compliance.dlp_compliance_policy.read"
DLP_COLLECTOR = "compliance.dlp_compliance_policy"
LABEL_OP = "compliance.label_policy.read"
LABEL_COLLECTOR = "compliance.label_policy"

# Deliberately different from CLIENT_ID and from ORGANIZATION so a test can
# assert the tenant_id never reaches the Compliance script.
TENANT_ID = "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"
CLIENT_ID = "12345678-1234-1234-1234-123456789abc"
ORGANIZATION = "contoso.onmicrosoft.com"

ENV_ALLOWLIST = {"PATH", "HOME", "PSModulePath", "TMPDIR", "LANG"}
FORBIDDEN_ENV = (
    "POWERSHELL_SERVICE_SECRET",
    "SHAREPOINT_CERT_ALIASES",
    "COMPLIANCE_CERT_ALIASES",
    "AWS_SECRET_ACCESS_KEY",
)


def compliance_payload(**updates):
    request = {
        "operation_id": DLP_OP,
        "collector_id": DLP_COLLECTOR,
        "params": {},
        "tenant_id": TENANT_ID,
        "client_id": CLIENT_ID,
        "compliance_certificate_alias": "contoso",
        "compliance_organization": ORGANIZATION,
    }
    request.update(updates)
    return request


def certificate_alias_map(tmp_path, alias, name="cert"):
    certificate = tmp_path / f"{name}.pfx"
    password = tmp_path / f"{name}.password"
    certificate.write_bytes(b"synthetic")
    password.write_text("synthetic-password")  # pragma: allowlist secret
    mapping = {alias: {"path": str(certificate), "password_file": str(password)}}
    return json.dumps(mapping), str(certificate), str(password)


def mock_run(monkeypatch, stdout="{}"):
    from unittest.mock import Mock
    from powershell.service import executor

    run = Mock(return_value=type("Result", (), {"returncode": 0, "stdout": stdout})())
    monkeypatch.setattr(executor.subprocess, "run", run)
    return run


def test_compliance_script_uses_documented_certificate_form():
    from powershell.service.executor import build_script

    script = build_script(
        DLP_OP,
        DLP_COLLECTOR,
        {},
        TENANT_ID,
        client_id=CLIENT_ID,
        compliance_organization=ORGANIZATION,
    )
    assert "$ErrorActionPreference = 'Stop'" in script
    assert "Import-Module ExchangeOnlineManagement" in script
    assert "-CertificateFilePath $env:IPPS_CERT_PATH" in script
    assert "-CertificatePassword $pwd" in script
    assert f'-AppID "{CLIENT_ID}"' in script
    assert f'-Organization "{ORGANIZATION}"' in script
    assert "$env:IPPS_CERT_PASSWORD_FILE" in script
    # Windows-only, undocumented, and shell-exit forms are never emitted.
    assert "-CertificateThumbPrint" not in script
    assert "-AccessToken" not in script
    assert "exit 0" not in script
    # tenant_id is not part of the Compliance connection at all.
    assert TENANT_ID not in script


def test_compliance_rejects_guid_organization():
    from powershell.service.executor import build_script
    from powershell.service.schemas import ExecuteRequest

    with pytest.raises(ValueError, match=r"\.onmicrosoft\.com"):
        build_script(
            DLP_OP,
            DLP_COLLECTOR,
            {},
            TENANT_ID,
            client_id=CLIENT_ID,
            compliance_organization=CLIENT_ID,
        )
    with pytest.raises(ValueError, match=r"\.onmicrosoft\.com"):
        ExecuteRequest(**compliance_payload(compliance_organization=CLIENT_ID))


def test_compliance_rejects_missing_organization():
    from powershell.service.executor import build_script

    with pytest.raises(ValueError):
        build_script(DLP_OP, DLP_COLLECTOR, {}, TENANT_ID, client_id=CLIENT_ID)
    with pytest.raises(ValueError):
        build_script(
            DLP_OP,
            DLP_COLLECTOR,
            {},
            TENANT_ID,
            compliance_organization=ORGANIZATION,
        )


@pytest.mark.parametrize(
    "updates,message",
    [
        ({"client_id": None}, "Compliance requires client_id"),
        (
            {"compliance_certificate_alias": None},
            "Compliance requires compliance_certificate_alias",
        ),
        (
            {"compliance_organization": None},
            "Compliance requires compliance_organization",
        ),
        ({"token": "synthetic-token"}, "Compliance must not include token"),
        (
            {"graph_token": "synthetic-graph-token"},
            "Compliance must not include graph_token",
        ),
        (
            {"sharepoint_admin_url": "https://contoso-admin.sharepoint.com"},
            "Compliance must not include sharepoint_admin_url",
        ),
        (
            {"certificate_alias": "contoso"},
            "Compliance must not include certificate_alias; "
            "use compliance_certificate_alias",
        ),
    ],
)
def test_check_module_auth_fields_compliance_matrix(updates, message):
    from powershell.service.schemas import ExecuteRequest

    with pytest.raises(ValueError, match=message):
        ExecuteRequest(**compliance_payload(**updates))


def test_check_module_auth_fields_accepts_a_complete_compliance_request():
    from powershell.service.schemas import ExecuteRequest

    for operation_id, collector_id in (
        (DLP_OP, DLP_COLLECTOR),
        (LABEL_OP, LABEL_COLLECTOR),
    ):
        request = ExecuteRequest(
            **compliance_payload(operation_id=operation_id, collector_id=collector_id)
        )
        assert request.module == "Compliance"
        assert request.token is None and request.graph_token is None
        assert request.compliance_organization == ORGANIZATION


def test_certificate_fields_still_rejected_for_token_modules():
    from powershell.service.schemas import ExecuteRequest

    base = {
        "operation_id": "exchange.organization.organization_config.read",
        "collector_id": "exchange.organization.organization_config",
        "params": {},
        "tenant_id": TENANT_ID,
        "token": "synthetic-token",
    }
    for field, value in (
        ("compliance_certificate_alias", "contoso"),
        ("compliance_organization", ORGANIZATION),
    ):
        with pytest.raises(
            ValueError, match="only permitted for SharePointOnline and Compliance"
        ):
            ExecuteRequest(**base, **{field: value})


def test_sharepoint_rejects_compliance_authentication_fields():
    from powershell.service.schemas import ExecuteRequest

    base = {
        "operation_id": "sharepoint.pnp.tenant.read",
        "collector_id": "sharepoint.pnp.tenant",
        "params": {},
        "tenant_id": TENANT_ID,
        "client_id": CLIENT_ID,
        "sharepoint_admin_url": "https://contoso-admin.sharepoint.com",
        "certificate_alias": "contoso",
    }
    for field, value in (
        ("compliance_certificate_alias", "contoso"),
        ("compliance_organization", ORGANIZATION),
    ):
        with pytest.raises(
            ValueError, match="Compliance authentication fields are only permitted"
        ):
            ExecuteRequest(**base, **{field: value})


def test_alias_namespace_is_selected_from_the_operation_module(monkeypatch, tmp_path):
    from powershell.service import executor

    shared, _, _ = certificate_alias_map(tmp_path, "shared", name="sharepoint")
    other, _, _ = certificate_alias_map(tmp_path, "other", name="compliance")
    monkeypatch.setenv("SHAREPOINT_CERT_ALIASES", shared)
    monkeypatch.setenv("COMPLIANCE_CERT_ALIASES", other)
    run = mock_run(monkeypatch)

    # 'shared' resolves under SharePointOnline but must not leak into Compliance.
    assert executor.resolve_certificate_alias("SharePointOnline", "shared")
    with pytest.raises(ValueError, match="Unknown certificate alias"):
        executor.execute_operation(
            **compliance_payload(compliance_certificate_alias="shared")
        )
    run.assert_not_called()

    with pytest.raises(ValueError, match="not available for this module"):
        executor.resolve_certificate_alias("Teams", "shared")
    with pytest.raises(ValueError, match="not available for this module"):
        executor.resolve_certificate_alias("ExchangeOnline", "shared")


def test_compliance_execution_sets_only_its_own_cert_env(monkeypatch, tmp_path):
    from powershell.service import executor

    aliases, certificate, password = certificate_alias_map(tmp_path, "contoso")
    monkeypatch.setenv("COMPLIANCE_CERT_ALIASES", aliases)
    run = mock_run(monkeypatch)

    assert executor.execute_operation(**compliance_payload()) == {}
    env = run.call_args.kwargs["env"]
    assert env["IPPS_CERT_PATH"] == certificate
    assert env["IPPS_CERT_PASSWORD_FILE"] == password
    for name in ("EXO_TOKEN", "GRAPH_TOKEN", "TEAMS_TOKEN", "SPO_CERT_PATH"):
        assert name not in env
    assert certificate not in repr(run.call_args.args)
    assert password not in repr(run.call_args.args)


def test_child_env_is_an_allowlist(monkeypatch, tmp_path):
    from powershell.service import executor
    from powershell.service.operations import OPERATIONS

    aliases, _, _ = certificate_alias_map(tmp_path, "contoso")
    monkeypatch.setenv("PATH", "/usr/bin:/bin")
    monkeypatch.setenv("POWERSHELL_SERVICE_SECRET", "s" * 40)
    monkeypatch.setenv("SHAREPOINT_CERT_ALIASES", aliases)
    monkeypatch.setenv("COMPLIANCE_CERT_ALIASES", aliases)
    monkeypatch.setenv(
        "AWS_SECRET_ACCESS_KEY",
        "synthetic-aws-secret",  # pragma: allowlist secret
    )
    run = mock_run(monkeypatch)

    requests = {
        "ExchangeOnline": (
            {
                "operation_id": "exchange.organization.organization_config.read",
                "collector_id": "exchange.organization.organization_config",
                "params": {},
                "tenant_id": TENANT_ID,
                "token": "synthetic-token",
            },
            {"EXO_TOKEN"},
        ),
        "Compliance": (
            compliance_payload(),
            {"IPPS_CERT_PATH", "IPPS_CERT_PASSWORD_FILE"},
        ),
        "SharePointOnline": (
            {
                "operation_id": "sharepoint.pnp.tenant.read",
                "collector_id": "sharepoint.pnp.tenant",
                "params": {},
                "tenant_id": TENANT_ID,
                "client_id": CLIENT_ID,
                "sharepoint_admin_url": "https://contoso-admin.sharepoint.com",
                "certificate_alias": "contoso",
            },
            {"SPO_CERT_PATH", "SPO_CERT_PASSWORD_FILE"},
        ),
    }
    # Every module that has a registered operation is exercised. Teams has none,
    # so no Teams request can be built; this assertion fails the day one is added.
    assert set(requests) == {operation.module for operation in OPERATIONS.values()}

    for module, (request, secrets) in requests.items():
        run.reset_mock()
        executor.execute_operation(**request)
        env = run.call_args.kwargs["env"]
        assert set(env) <= ENV_ALLOWLIST | secrets, module
        assert secrets <= set(env), module
        for name in FORBIDDEN_ENV:
            assert name not in env, module


def test_two_new_operations_are_read_only():
    from powershell.service.operations import OPERATIONS

    for operation_id in (DLP_OP, LABEL_OP):
        command = OPERATIONS[operation_id].command
        assert command.startswith("Get-")
        assert ";" not in command
        assert "$(" not in command
        for verb in ("Set-", "Remove-", "New-", "Invoke-"):
            assert verb not in command
        segments = command.split("|")
        for segment in segments[1:]:
            assert segment.strip().startswith("Select-Object"), command
