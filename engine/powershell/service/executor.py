"""PowerShell command executor."""

import json
import os
import re
import subprocess
from types import MappingProxyType
from typing import Any, Dict, Optional

if __package__:
    from .operations import operation_command, validate_operation
else:
    from operations import operation_command, validate_operation

# NOTE: This validation function is duplicated in engine/worker/validators.py
# because the powershell service is an isolated package. Keep both copies in sync.

_TENANT_ID_GUID_RE = re.compile(
    r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$",
    re.IGNORECASE,
)

# Labels allow alphanumeric + hyphens; TLD must be alpha-only (2+ chars)
_TENANT_ID_DOMAIN_RE = re.compile(
    r"^[a-zA-Z0-9]([a-zA-Z0-9-]*[a-zA-Z0-9])?"
    r"(\.[a-zA-Z0-9]([a-zA-Z0-9-]*[a-zA-Z0-9])?)*"
    r"\.[a-zA-Z]{2,}$"
)


def validate_tenant_id(value: str) -> str:
    """Validate that a tenant_id is a GUID or domain name.

    Prevents PowerShell command injection by ensuring the value contains
    only characters that are structurally safe for interpolation.
    """
    stripped = value.strip()
    if not stripped:
        raise ValueError("tenant_id must not be empty")
    if _TENANT_ID_GUID_RE.match(stripped) or _TENANT_ID_DOMAIN_RE.match(stripped):
        return stripped
    raise ValueError(
        f"Invalid tenant_id format: {stripped!r}. "
        "Must be a GUID (e.g. 12345678-1234-1234-1234-123456789abc) "
        "or a domain name (e.g. contoso.onmicrosoft.com)."
    )


class PowerShellExecutionError(Exception):
    """Raised when PowerShell execution fails."""

    pass


# The alias namespace is chosen server-side from the validated operation's
# module, never from the request body, so a Compliance request can never
# resolve a SharePoint certificate and vice versa.
_CERT_ALIAS_ENV = MappingProxyType(
    {
        "SharePointOnline": "SHAREPOINT_CERT_ALIASES",
        "Compliance": "COMPLIANCE_CERT_ALIASES",
    }
)

# Everything a pwsh child is allowed to inherit. Module secrets are added
# explicitly per module; nothing else ever reaches the child environment.
_ENV_ALLOWLIST = ("PATH", "HOME", "PSModulePath", "TMPDIR", "LANG")


def resolve_certificate_alias(module: str, alias: str) -> tuple[str, str]:
    """Resolve a certificate alias to mounted PFX and password file paths.

    Alias mapping comes from the module's own alias environment variable
    (JSON object). Request bodies never supply filesystem paths or secrets.
    """
    if type(module) is not str or module not in _CERT_ALIAS_ENV:
        raise ValueError("Certificate authentication is not available for this module")
    env_name = _CERT_ALIAS_ENV[module]
    if type(alias) is not str or not re.fullmatch(
        r"[A-Za-z0-9][A-Za-z0-9_-]{0,63}", alias
    ):
        raise ValueError("Invalid certificate alias")
    raw = os.environ.get(env_name)
    if not raw or not raw.strip():
        raise ValueError(f"{env_name} is not configured")

    try:
        mapping = json.loads(raw)
    except json.JSONDecodeError:
        raise ValueError(f"{env_name} is not valid JSON") from None

    if not isinstance(mapping, dict):
        raise ValueError(f"{env_name} must be a JSON object")

    entry = mapping.get(alias)
    if not isinstance(entry, dict):
        raise ValueError("Unknown certificate alias")

    cert_path = entry.get("path")
    password_file = entry.get("password_file")
    if not isinstance(cert_path, str) or not cert_path.strip():
        raise ValueError("Unknown certificate alias")
    if not isinstance(password_file, str) or not password_file.strip():
        raise ValueError("Unknown certificate alias")

    cert_path = cert_path.strip()
    password_file = password_file.strip()
    if not os.path.isfile(cert_path) or not os.path.isfile(password_file):
        raise ValueError("Certificate is not available for the requested alias")

    return cert_path, password_file


def resolve_sharepoint_certificate(alias: str) -> tuple[str, str]:
    return resolve_certificate_alias("SharePointOnline", alias)


def build_script(
    operation_id: str,
    collector_id: str,
    params: Dict[str, Any],
    tenant_id: str,
    client_id: Optional[str] = None,
    sharepoint_admin_url: Optional[str] = None,
    compliance_organization: Optional[str] = None,
) -> str:
    """Build the PowerShell script to execute.

    Args:
        operation_id: Reviewed operation in the immutable registry
        collector_id: Registered collector permitted to run the operation
        params: Parameters for the cmdlet
        tenant_id: Azure AD tenant ID
        client_id: App registration client ID (SharePointOnline, Compliance)
        sharepoint_admin_url: SharePoint admin URL (SharePointOnline)
        compliance_organization: Primary .onmicrosoft.com domain (Compliance)

    Returns:
        PowerShell script as a string
    """
    tenant_id = validate_tenant_id(tenant_id)
    operation = validate_operation(operation_id, collector_id, params)
    module = operation.module
    command = operation_command(operation_id, collector_id, params)

    if module == "ExchangeOnline":
        return f"""
$ErrorActionPreference = 'Stop'
Import-Module ExchangeOnlineManagement
Connect-ExchangeOnline -AccessToken $env:EXO_TOKEN -Organization "{tenant_id}" -ShowBanner:$false
try {{
    $result = {command}
    if ($null -eq $result) {{
        Write-Output 'null'
    }} else {{
        $result | ConvertTo-Json -Depth 10
    }}
}} finally {{
    Disconnect-ExchangeOnline -Confirm:$false -ErrorAction SilentlyContinue
}}
"""
    elif module == "Compliance":
        # Certificate-only. App-only access-token auth for Connect-IPPSSession is
        # not documented by Microsoft, and -CertificateThumbPrint is Windows-only,
        # so neither form is ever emitted. tenant_id is not interpolated here:
        # -Organization takes the primary .onmicrosoft.com domain, which a tenant
        # GUID is not.
        if not client_id or not compliance_organization:
            raise ValueError(
                "Compliance requires client_id and compliance_organization"
            )
        if not _TENANT_ID_GUID_RE.fullmatch(client_id):
            raise ValueError("Invalid client_id format")
        if _TENANT_ID_GUID_RE.fullmatch(compliance_organization) or not re.fullmatch(
            r"[A-Za-z0-9][A-Za-z0-9-]{0,62}\.onmicrosoft\.com",
            compliance_organization,
            re.IGNORECASE,
        ):
            raise ValueError(
                "compliance_organization must be the tenant primary "
                ".onmicrosoft.com domain, not a tenant GUID"
            )
        return f"""
$ErrorActionPreference = 'Stop'
Import-Module ExchangeOnlineManagement
$pwd = ConvertTo-SecureString (Get-Content -Raw $env:IPPS_CERT_PASSWORD_FILE).Trim() -AsPlainText -Force
Connect-IPPSSession -CertificateFilePath $env:IPPS_CERT_PATH -CertificatePassword $pwd -AppID "{client_id}" -Organization "{compliance_organization}"
try {{
    $result = {command}
    if ($null -eq $result) {{
        Write-Output 'null'
    }} else {{
        $result | ConvertTo-Json -Depth 10
    }}
}} finally {{
    Disconnect-ExchangeOnline -Confirm:$false -ErrorAction SilentlyContinue
}}
"""
    elif module == "Teams":
        return f"""
$ErrorActionPreference = 'Stop'
Import-Module MicrosoftTeams
Connect-MicrosoftTeams -AccessTokens @($env:GRAPH_TOKEN, $env:TEAMS_TOKEN) -TenantId "{tenant_id}"
try {{
    $result = {command}
    if ($null -eq $result) {{
        Write-Output 'null'
    }} else {{
        $result | ConvertTo-Json -Depth 10
    }}
}} finally {{
    Disconnect-MicrosoftTeams -ErrorAction SilentlyContinue
}}
"""
    elif module == "SharePointOnline":
        if not client_id or not sharepoint_admin_url:
            raise ValueError(
                "SharePointOnline requires client_id and sharepoint_admin_url"
            )
        if not re.fullmatch(
            r"https://[A-Za-z0-9](?:[A-Za-z0-9-]*[A-Za-z0-9])?-admin\.sharepoint\.com",
            sharepoint_admin_url,
            re.IGNORECASE,
        ):
            raise ValueError("Invalid SharePoint admin URL")
        if not _TENANT_ID_GUID_RE.fullmatch(client_id):
            raise ValueError("Invalid client_id format")
        return f"""
$ErrorActionPreference = 'Stop'
Import-Module PnP.PowerShell
$pwd = ConvertTo-SecureString (Get-Content -Raw $env:SPO_CERT_PASSWORD_FILE).Trim() -AsPlainText -Force
Connect-PnPOnline -Url "{sharepoint_admin_url}" -ClientId "{client_id}" -Tenant "{tenant_id}" -CertificatePath $env:SPO_CERT_PATH -CertificatePassword $pwd
try {{
    $result = {command}
    if ($null -eq $result) {{
        Write-Output 'null'
    }} else {{
        $result | ConvertTo-Json -Depth 10
    }}
}} finally {{
    Disconnect-PnPOnline
}}
"""
    else:
        raise ValueError(f"Unsupported module: {module}")


def execute_operation(
    operation_id: str,
    collector_id: str,
    params: Dict[str, Any],
    tenant_id: str,
    token: Optional[str] = None,
    graph_token: Optional[str] = None,
    client_id: Optional[str] = None,
    sharepoint_admin_url: Optional[str] = None,
    certificate_alias: Optional[str] = None,
    compliance_certificate_alias: Optional[str] = None,
    compliance_organization: Optional[str] = None,
) -> Optional[Dict[str, Any]]:
    """Execute a validated read-only operation and return the result.

    Args:
        operation_id: Reviewed operation in the immutable registry
        collector_id: Registered collector permitted to run the operation
        params: Parameters for the cmdlet
        tenant_id: Azure AD tenant ID
        token: Access token for Exchange/Teams
        graph_token: Graph API token (required for Teams)
        client_id: App registration client ID (SharePointOnline, Compliance)
        sharepoint_admin_url: SharePoint admin URL (SharePointOnline)
        certificate_alias: Certificate alias resolved from SHAREPOINT_CERT_ALIASES
        compliance_certificate_alias: Alias resolved from COMPLIANCE_CERT_ALIASES
        compliance_organization: Primary .onmicrosoft.com domain (Compliance)

    Returns:
        Parsed JSON output from the cmdlet

    Raises:
        PowerShellExecutionError: If execution fails
        ValueError: If required module fields are missing
    """
    # Revalidate at the executor boundary, including direct Python callers.
    if __package__:
        from .schemas import ExecuteRequest
    else:
        from schemas import ExecuteRequest
    request = ExecuteRequest(
        operation_id=operation_id,
        collector_id=collector_id,
        params=params,
        tenant_id=tenant_id,
        token=token,
        graph_token=graph_token,
        client_id=client_id,
        sharepoint_admin_url=sharepoint_admin_url,
        certificate_alias=certificate_alias,
        compliance_certificate_alias=compliance_certificate_alias,
        compliance_organization=compliance_organization,
    )
    module = request.module
    # The child process gets an explicit allowlist plus only this module's own
    # secrets. The service secret and every certificate alias map stay in the
    # parent, so no pwsh child can read them.
    env = {name: os.environ[name] for name in _ENV_ALLOWLIST if name in os.environ}
    if module == "SharePointOnline":
        if not certificate_alias:
            raise ValueError("SharePointOnline requires certificate_alias")
        cert_path, password_file = resolve_certificate_alias(
            "SharePointOnline", certificate_alias
        )
        env["SPO_CERT_PATH"] = cert_path
        env["SPO_CERT_PASSWORD_FILE"] = password_file
        script = build_script(
            operation_id,
            collector_id,
            params,
            tenant_id,
            client_id=client_id,
            sharepoint_admin_url=sharepoint_admin_url,
        )
    elif module == "Compliance":
        if not compliance_certificate_alias:
            raise ValueError("Compliance requires compliance_certificate_alias")
        cert_path, password_file = resolve_certificate_alias(
            "Compliance", compliance_certificate_alias
        )
        env["IPPS_CERT_PATH"] = cert_path
        env["IPPS_CERT_PASSWORD_FILE"] = password_file
        script = build_script(
            operation_id,
            collector_id,
            params,
            tenant_id,
            client_id=client_id,
            compliance_organization=compliance_organization,
        )
    else:
        script = build_script(operation_id, collector_id, params, tenant_id)
        assert token is not None
        if module == "Teams":
            assert graph_token is not None
            env["GRAPH_TOKEN"] = graph_token
            env["TEAMS_TOKEN"] = token
        else:
            env["EXO_TOKEN"] = token

    # Execute PowerShell
    try:
        proc = subprocess.run(
            ["pwsh", "-NoProfile", "-NonInteractive", "-Command", script],
            capture_output=True,
            text=True,
            timeout=120,
            env=env,
        )
    except subprocess.TimeoutExpired:
        raise PowerShellExecutionError(
            "PowerShell execution timed out after 120 seconds"
        )
    except Exception:
        raise PowerShellExecutionError("Failed to launch PowerShell") from None

    if proc.returncode != 0:
        raise PowerShellExecutionError("PowerShell operation failed")

    # Parse JSON output
    stdout = proc.stdout.strip()
    if not stdout or stdout == "null":
        return None

    try:
        return json.loads(stdout)
    except json.JSONDecodeError:
        raise PowerShellExecutionError("PowerShell returned malformed JSON") from None
