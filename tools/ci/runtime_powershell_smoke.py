#!/usr/bin/env python3
"""Run the real local Docker transport/interpreter using synthetic M365 cmdlets."""

import asyncio
from pathlib import Path
import subprocess
import sys
from unittest.mock import Mock, patch

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "engine"))
from collectors import powershell_client

IMAGE = "mcr.microsoft.com/powershell:7.5-mariner-2.0"
OP = "exchange.organization.organization_config.read"
COLLECTOR = "exchange.organization.organization_config"
STUBS = """
function Import-Module { param($Name) }
function Connect-ExchangeOnline { param($AccessToken, $Organization, [switch]$ShowBanner) }
function Get-OrganizationConfig { [pscustomobject]@{ AuditDisabled = $false } }
function Disconnect-ExchangeOnline { param([switch]$Confirm, $ErrorAction) }
"""


def main():
    run = subprocess.run
    pulled = run(["docker", "pull", IMAGE], capture_output=True, text=True, timeout=180)
    if pulled.returncode:
        raise RuntimeError("PowerShell interpreter image pull failed")
    client = powershell_client.PowerShellClient.__new__(
        powershell_client.PowerShellClient
    )
    client.tenant_id = "synthetic.onmicrosoft.com"
    client.client_id = "synthetic"
    client.service_url = None
    client.service_secret = None
    client.service_ca_file = None
    client.sharepoint_admin_url = None
    client.certificate_alias = None
    client.DOCKER_IMAGE = IMAGE
    client._msal_app = Mock()
    client._msal_app.acquire_token_for_client.return_value = {
        "access_token": "synthetic-runtime-token"
    }
    client._ensure_docker_image = Mock()
    original_script = powershell_client.build_script
    for timeout in (False, True):
        names = []

        def observed(command, **kwargs):
            if command[:2] == ["docker", "run"]:
                names.append(command[command.index("--name") + 1])
                assert "synthetic-runtime-token" not in repr(command)
                if timeout:
                    kwargs["timeout"] = 2
            return run(command, **kwargs)

        def script(*args, **kwargs):
            return (
                STUBS
                + ("Start-Sleep -Seconds 30\n" if timeout else "")
                + original_script(*args, **kwargs)
            )

        with (
            patch.object(powershell_client.subprocess, "run", observed),
            patch.object(powershell_client, "build_script", script),
        ):
            if timeout:
                try:
                    asyncio.run(client.run_operation(OP, COLLECTOR))
                except powershell_client.PowerShellExecutionError as error:
                    assert str(error) == "PowerShell Docker execution failed"
                else:
                    raise AssertionError("Expected interpreter timeout")
            else:
                assert asyncio.run(client.run_operation(OP, COLLECTOR)) == {
                    "AuditDisabled": False
                }
        assert len(names) == 1
        result = run(["docker", "inspect", names[0]], capture_output=True, timeout=15)
        assert result.returncode != 0, "Owned container survived execution or timeout"
    print(
        "PASS: real PowerShell generated script returns clean JSON; normal and timed-out local containers removed; no tokens in argv"
    )


if __name__ == "__main__":
    main()
