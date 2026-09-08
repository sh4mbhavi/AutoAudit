# Pre-scan readiness checks for M365 scans.
# Purpose: this file checks whether the selected M365 connection and benchmark are ready enough to start a scan.

from __future__ import annotations
from dataclasses import dataclass
import httpx
import logging
import re
from app.services.m365_graph import (
    M365ConnectionError,
    acquire_graph_access_token,
    validate_m365_connection,
)

logger = logging.getLogger("api")

# These permissions are critical for the current M365 benchmarks, so we always probe them and treat failures as critical.
CRITICAL_BASELINE_PERMISSIONS = {
    "Organization.Read.All",
    "User.Read.All",
    "RoleManagement.Read.Directory",
}

# Simple Graph endpoints used to test each permission.
# If a permission has no probe yet, readiness reports it as "unverified".
PERMISSION_PROBES: dict[str, str] = {
    "Sites.Read.All": "/v1.0/sites/root?$select=webUrl,sharepointIds",
    "Organization.Read.All": "/v1.0/organization?$top=1&$select=id",
    "User.Read.All": "/v1.0/users?$top=1&$select=id",
    "RoleManagement.Read.Directory": "/v1.0/directoryRoles?$select=id",
    "Group.Read.All": "/v1.0/groups?$top=1&$select=id",
    "Domain.Read.All": "/v1.0/domains?$top=1&$select=id",
    "Policy.Read.All": "/v1.0/policies/authorizationPolicy?$select=id",
    "OrgSettings-Forms.Read.All": "/beta/admin/forms/settings",
    "OrgSettings-AppsAndServices.Read.All": "/beta/admin/appsAndServices",
}

# Permissions that Microsoft Graph does not grant and cannot answer for.
# Probing these against Graph would return a confidently wrong pass or fail, so readiness
# names the authorization system that actually grants them and reports them as unverified.
NON_GRAPH_PERMISSIONS: dict[str, str] = {
    "Exchange.Manage": "Exchange Online PowerShell app-only authorization (resourceAppId 00000002-0000-0ff1-ce00-000000000000)",
    "Exchange.ManageAsApp": "Exchange Online / Exchange Online Protection app-only authorization (Exchange.ManageAsApp, role id 455e5cd2-84e8-4751-8344-5672145dfa17), plus a directory role such as Global Reader or Security Reader",
    "SharePoint.Admin": "SharePoint Online administrative authorization used by the PnP certificate connection",
}

# The Purview/SCC organization parameter is the tenant primary .onmicrosoft.com domain.
# A tenant GUID is accepted by Entra but is not accepted by Connect-IPPSSession -Organization.
PURVIEW_ORGANIZATION_RE = re.compile(
    r"^[A-Za-z0-9][A-Za-z0-9-]{0,62}\.onmicrosoft\.com$", re.IGNORECASE
)


@dataclass
# One item shown in the readiness UI.
class ReadinessCheck:
    key: str
    label: str
    status: str
    severity: str
    message: str


@dataclass
# Final readiness payload returned to the API layer.
class ReadinessResult:
    ready: bool
    summary: str
    required_permissions: list[str]
    missing_permissions: list[str]
    unverified_permissions: list[str]
    checks: list[ReadinessCheck]


# Return a short Graph error message when a probe fails.
def extract_graph_error_detail(response: httpx.Response) -> str | None:
    try:
        payload = response.json()
    except Exception:
        payload = None

    if isinstance(payload, dict):
        error = payload.get("error")
        if isinstance(error, dict):
            message = error.get("message")
            if isinstance(message, str) and message.strip():
                return message.strip()
        detail = payload.get("detail")
        if isinstance(detail, str) and detail.strip():
            return detail.strip()

    text = (response.text or "").strip()
    if text:
        return text.splitlines()[0].strip()

    return None


# Return the permissions declared for controls marked as ready.
# The scan engine only runs controls whose 'automation_status' is 'ready', so readiness follows the same rule and ignores manual or blocked controls.
def extract_required_permissions(controls: list[dict]) -> list[str]:
    permissions: set[str] = set()

    for control in controls:
        if control.get("automation_status") != "ready":
            continue
        if str(control.get("data_collector_id", "")).startswith("sharepoint.pnp."):
            # Runtime identity proof is required in addition to the control's permissions.
            permissions.add("Sites.Read.All")
        required = control.get("requires_permissions") or []
        for permission in required:
            if isinstance(permission, str) and permission.strip():
                permissions.add(permission.strip())

    return sorted(permissions)


@dataclass(frozen=True)
# The Purview/SCC binding for the selected connection, resolved by the caller.
# Nothing here is read from the tenant; readiness only inspects what is configured.
class PurviewScope:
    in_scope: bool
    compliance_certificate_alias: str | None = None
    compliance_organization: str | None = None


# Purview readiness is latent: it applies only once a compliance.* control is actually dispatched.
# The engine dispatches 'ready' controls only, so a blocked compliance control is out of scope.
def purview_in_scope(controls: list[dict]) -> bool:
    return any(
        control.get("automation_status") == "ready"
        and str(control.get("data_collector_id") or "").startswith("compliance.")
        for control in controls
    )


# Build the Purview checks for a resolved scope.
# Pure and offline: no probe exists for Purview, and an entitlement check that cannot decide
# entitlement would be a check in name only, so the unverified state is reported instead.
def purview_readiness_checks(scope: PurviewScope) -> list[ReadinessCheck]:
    if not scope.in_scope:
        return [
            ReadinessCheck(
                key="purview_binding",
                label="Purview certificate binding",
                status="warn",
                severity="warning",
                message=(
                    "Purview collection is not configured. CIS 3.2.1, 3.2.2 and 3.3.1 "
                    "remain automation_status=blocked pending live-tenant validation of "
                    "certificate-based Connect-IPPSSession."
                ),
            )
        ]

    alias = (scope.compliance_certificate_alias or "").strip()
    organization = (scope.compliance_organization or "").strip()
    if not alias or not organization:
        binding = ReadinessCheck(
            key="purview_binding",
            label="Purview certificate binding",
            status="fail",
            severity="critical",
            message=(
                "The selected connection has no Purview certificate binding. Set "
                "compliance_certificate_alias and compliance_organization before scanning "
                "a Purview control."
            ),
        )
    elif not PURVIEW_ORGANIZATION_RE.match(organization):
        binding = ReadinessCheck(
            key="purview_binding",
            label="Purview certificate binding",
            status="fail",
            severity="critical",
            message=(
                "compliance_organization must be the tenant primary .onmicrosoft.com "
                "domain, not a tenant GUID."
            ),
        )
    else:
        binding = ReadinessCheck(
            key="purview_binding",
            label="Purview certificate binding",
            status="pass",
            severity="critical",
            message="Purview certificate binding is configured for the selected connection.",
        )

    return [
        binding,
        ReadinessCheck(
            key="purview_licensing",
            label="Purview entitlement",
            status="warn",
            severity="warning",
            message=(
                "Purview entitlement is UNVERIFIED. The service-plan identifiers that "
                "entitle Purview DLP and Information Protection could not be cited from "
                "Microsoft primary documentation, so no licensing probe is performed and "
                "no entitlement claim is made. CIS 3.2.2 is E5 Level 1 only."
            ),
        ),
        ReadinessCheck(
            key="purview_authentication",
            label="Purview certificate authentication",
            status="warn",
            severity="warning",
            message=(
                "Certificate-based Connect-IPPSSession has not been executed against any "
                "tenant by this build. Live validation on an approved non-production "
                "licensed tenant is required before CIS 3.2.1, 3.2.2 and 3.3.1 can be "
                "promoted."
            ),
        ),
        ReadinessCheck(
            key="purview_object_shape",
            label="Purview object shape contract",
            status="warn",
            severity="warning",
            message=(
                "Microsoft documents no returned object properties for "
                "Get-DlpCompliancePolicy or Get-LabelPolicy. The collectors accept only "
                "the declared shapes and refuse anything else rather than coercing it."
            ),
        ),
    ]


# Check whether a tenant looks ready before starting a scan.
# Flow:
# 1. validate the saved M365 app credentials
# 2. get a Microsoft Graph access token
# 3. probe the permissions declared by benchmark metadata
# 4. return pass / warn / fail results for the UI
# This is only a pre-check. It does not start the scan.
async def evaluate_scan_readiness(
    *,
    tenant_id: str,
    client_id: str,
    client_secret: str,
    required_permissions: list[str],
    purview_scope: PurviewScope | None = None,
) -> ReadinessResult:
    checks: list[ReadinessCheck] = []
    missing_permissions: set[str] = set()
    unverified_permissions: set[str] = set()

    # First prove the saved app credentials can authenticate at all.
    try:
        await validate_m365_connection(
            tenant_id=tenant_id,
            client_id=client_id,
            client_secret=client_secret,
        )
        checks.append(
            ReadinessCheck(
                key="connection_auth",
                label="M365 connection authentication",
                status="pass",
                severity="critical",
                message="Successfully authenticated and queried tenant information.",
            )
        )
    except M365ConnectionError as exc:
        checks.append(
            ReadinessCheck(
                key="connection_auth",
                label="M365 connection authentication",
                status="fail",
                severity="critical",
                message=str(exc),
            )
        )
        return ReadinessResult(
            ready=False,
            summary="Not ready: connection authentication failed.",
            required_permissions=required_permissions,
            missing_permissions=[],
            unverified_permissions=[],
            checks=checks,
        )

    # If login worked, get the access token used for permission probes.
    try:
        access_token = await acquire_graph_access_token(
            tenant_id=tenant_id,
            client_id=client_id,
            client_secret=client_secret,
        )
    except M365ConnectionError as exc:
        checks.append(
            ReadinessCheck(
                key="token_acquisition",
                label="Graph access token acquisition",
                status="fail",
                severity="critical",
                message=str(exc),
            )
        )
        return ReadinessResult(
            ready=False,
            summary="Not ready: failed to acquire Graph access token.",
            required_permissions=required_permissions,
            missing_permissions=[],
            unverified_permissions=[],
            checks=checks,
        )

    # Always check a small baseline set because these permissions are commonly needed even when the benchmark declares only a few extra permissions.
    permissions_to_probe = sorted(
        set(required_permissions).union(CRITICAL_BASELINE_PERMISSIONS)
    )

    async with httpx.AsyncClient(
        base_url="https://graph.microsoft.com",
        timeout=12.0,
    ) as http:
        for permission in permissions_to_probe:
            # Graph cannot answer for a permission it does not grant, so name the system that does.
            if permission in NON_GRAPH_PERMISSIONS:
                unverified_permissions.add(permission)
                checks.append(
                    ReadinessCheck(
                        key=f"perm_{permission}",
                        label=f"Permission: {permission}",
                        status="warn",
                        severity="warning",
                        message=(
                            "Not a Microsoft Graph permission. Granted by "
                            f"{NON_GRAPH_PERMISSIONS[permission]}. It cannot be probed "
                            "through Graph; verify it in the app registration and the "
                            "tenant's admin roles."
                        ),
                    )
                )
                continue

            probe_path = PERMISSION_PROBES.get(permission)
            if not probe_path:
                unverified_permissions.add(permission)
                checks.append(
                    ReadinessCheck(
                        key=f"perm_{permission}",
                        label=f"Permission: {permission}",
                        status="warn",
                        severity="warning",
                        message="No automatic probe is defined for this permission.",
                    )
                )
                continue

            # Each probe is a lightweight Graph request that exercises one permission without starting the real scan workflow.
            try:
                response = await http.get(
                    probe_path,
                    headers={"Authorization": f"Bearer {access_token}"},
                )
            except Exception:
                logger.warning(
                    "Readiness probe request failed for permission %s; marking unverified",
                    permission,
                    exc_info=True,
                )
                unverified_permissions.add(permission)
                checks.append(
                    ReadinessCheck(
                        key=f"perm_{permission}",
                        label=f"Permission: {permission}",
                        status="warn",
                        severity="warning",
                        message="Could not verify this permission due to a network/API error.",
                    )
                )
                continue

            if 200 <= response.status_code < 300:
                checks.append(
                    ReadinessCheck(
                        key=f"perm_{permission}",
                        label=f"Permission: {permission}",
                        status="pass",
                        severity=(
                            "critical"
                            if permission in CRITICAL_BASELINE_PERMISSIONS
                            else "warning"
                        ),
                        message="Permission probe succeeded.",
                    )
                )
                continue

            if response.status_code in (401, 403):
                missing_permissions.add(permission)
                is_critical = permission in CRITICAL_BASELINE_PERMISSIONS
                checks.append(
                    ReadinessCheck(
                        key=f"perm_{permission}",
                        label=f"Permission: {permission}",
                        status="fail" if is_critical else "warn",
                        severity="critical" if is_critical else "warning",
                        message="Permission probe was denied. Grant admin consent for this permission.",
                    )
                )
                continue

            unverified_permissions.add(permission)
            checks.append(
                ReadinessCheck(
                    key=f"perm_{permission}",
                    label=f"Permission: {permission}",
                    status="warn",
                    severity="warning",
                    message=(
                        f"Permission probe returned HTTP {response.status_code}"
                        + (
                            f": {detail}"
                            if (detail := extract_graph_error_detail(response))
                            else "."
                        )
                    ),
                )
            )

    # Latent by default: with no Purview scope resolved, readiness output is unchanged.
    # Once a compliance.* control is promoted to ready, an unconfigured binding is a critical failure.
    if purview_scope is not None:
        checks.extend(purview_readiness_checks(purview_scope))

    has_critical_failure = any(
        check.status == "fail" and check.severity == "critical" for check in checks
    )
    ready = not has_critical_failure
    summary = "Ready to start scan." if ready else "Not ready: resolve critical checks."
    if ready and (missing_permissions or unverified_permissions):
        summary = "Ready with warnings: some controls may be skipped or fail."

    # Return the full details so the UI can show both the headline status and the per-permission breakdown.
    return ReadinessResult(
        ready=ready,
        summary=summary,
        required_permissions=required_permissions,
        missing_permissions=sorted(missing_permissions),
        unverified_permissions=sorted(unverified_permissions),
        checks=checks,
    )
