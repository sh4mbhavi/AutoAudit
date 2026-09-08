"""Client for fixed, read-only M365 collection operations.

The HTTP service and local Docker mode use the same operation registry and script
builder. OAuth tokens are supplied through process environment or authenticated
HTTP; callers never supply command text. Unregistered Teams/Compliance collectors
must receive reviewed operation entries before they can be enabled.
"""

import json
import os
import ssl
import subprocess
from uuid import uuid4
from pathlib import Path
from typing import Any

import httpx
from msal import ConfidentialClientApplication

from worker.validators import validate_tenant_id
from worker.correlation import headers as correlation_headers, event
from powershell.service.executor import build_script
from powershell.service.operations import validate_operation
from powershell.service.schemas import ExecuteRequest


class PowerShellExecutionError(Exception):
    """Raised when PowerShell execution fails."""

    pass


class PowerShellClient:
    """Client for PowerShell-based M365 connections using Docker or HTTP service."""

    # Service-specific scopes for token acquisition
    EXCHANGE_SCOPE = "https://outlook.office365.com/.default"
    TEAMS_SCOPE = "https://api.interfaces.records.teams.microsoft.com/.default"
    COMPLIANCE_SCOPE = "https://ps.compliance.protection.outlook.com/.default"

    DOCKER_IMAGE = "autoaudit-powershell"

    def __init__(
        self,
        tenant_id: str,
        client_id: str,
        client_secret: str,
        service_url: str | None = None,
        sharepoint_admin_url: str | None = None,
        certificate_alias: str | None = None,
        service_secret: str | None = None,
        service_ca_file: str | None = None,
    ):
        """Initialize PowerShell client.

        Args:
            tenant_id: Azure AD tenant ID
            client_id: Application (client) ID
            client_secret: Client secret for authentication
            service_url: Optional URL of PowerShell HTTP service (e.g., http://powershell-service:8001).
                         If provided, uses HTTP instead of spawning Docker containers.
            sharepoint_admin_url: SharePoint admin URL (required for SharePointOnline)
            certificate_alias: Certificate alias resolved by the PowerShell service
                               (required for SharePointOnline)
            service_secret: Shared credential sent to the HTTP service.
            service_ca_file: Optional private CA added to default TLS trust roots.
        """
        self.tenant_id = validate_tenant_id(tenant_id)
        self.client_id = client_id
        self.client_secret = client_secret
        self.service_url = service_url
        self.service_secret = service_secret
        self.service_ca_file = service_ca_file
        self.sharepoint_admin_url = sharepoint_admin_url
        self.certificate_alias = certificate_alias
        self._msal_app = ConfidentialClientApplication(
            client_id=client_id,
            client_credential=client_secret,
            authority=f"https://login.microsoftonline.com/{self.tenant_id}",
        )
        self._image_checked = False

    def _ensure_docker_image(self) -> None:
        """Build Docker image if it doesn't exist."""
        if self._image_checked:
            return

        # Check if Docker is available
        try:
            subprocess.run(
                ["docker", "--version"],
                capture_output=True,
                check=True,
            )
        except FileNotFoundError:
            raise PowerShellExecutionError(
                "Docker is not installed or not in PATH.\n"
                "Install Docker from: https://docs.docker.com/get-docker/"
            )
        except subprocess.CalledProcessError:
            raise PowerShellExecutionError("Docker check failed") from None

        # Check if image exists
        result = subprocess.run(
            ["docker", "images", "-q", self.DOCKER_IMAGE],
            capture_output=True,
            text=True,
        )
        if not result.stdout.strip():
            print(
                f"Building {self.DOCKER_IMAGE} Docker image (this may take a few minutes)..."
            )
            dockerfile_dir = Path(__file__).parent.parent / "docker" / "powershell"
            build_result = subprocess.run(
                ["docker", "build", "-t", self.DOCKER_IMAGE, str(dockerfile_dir)],
                capture_output=True,
                text=True,
            )
            if build_result.returncode != 0:
                raise PowerShellExecutionError(
                    "Failed to build PowerShell Docker image"
                )
            print(f"Docker image {self.DOCKER_IMAGE} built successfully.")

        self._image_checked = True

    async def run_operation(
        self, operation_id: str, collector_id: str, **params: Any
    ) -> Any:
        """Run a reviewed operation on behalf of its permitted collector."""
        operation = validate_operation(operation_id, collector_id, params)
        event("powershell_operation_requested")
        if operation.module == "SharePointOnline" and not self.service_url:
            raise PowerShellExecutionError(
                "SharePointOnline requires the PowerShell HTTP service"
            )
        if self.service_url:
            return await self._run_via_service(operation_id, collector_id, params)
        return await self._run_via_docker(operation_id, collector_id, params)

    def _acquire_tokens(self, module: str) -> tuple[str | None, str | None]:
        if module == "SharePointOnline":
            return None, None
        scopes = {
            "ExchangeOnline": self.EXCHANGE_SCOPE,
            "Compliance": self.COMPLIANCE_SCOPE,
            "Teams": self.TEAMS_SCOPE,
        }
        if module not in scopes:
            raise ValueError("Unknown PowerShell module")

        def acquire(scope: str) -> str:
            result = self._msal_app.acquire_token_for_client(scopes=[scope])
            if (
                not isinstance(result.get("access_token"), str)
                or not result["access_token"]
            ):
                raise PowerShellExecutionError("PowerShell token acquisition failed")
            return result["access_token"]

        graph_token = (
            acquire("https://graph.microsoft.com/.default")
            if module == "Teams"
            else None
        )
        return acquire(scopes[module]), graph_token

    def _request(
        self, operation_id: str, collector_id: str, params: dict[str, Any]
    ) -> ExecuteRequest:
        operation = validate_operation(operation_id, collector_id, params)
        # Validate all caller-controlled configuration before acquiring credentials.
        is_sharepoint = operation.module == "SharePointOnline"
        request = ExecuteRequest(
            operation_id=operation_id,
            collector_id=collector_id,
            params=params,
            tenant_id=self.tenant_id,
            token=None if is_sharepoint else "pending",
            graph_token="pending" if operation.module == "Teams" else None,
            client_id=self.client_id if is_sharepoint else None,
            sharepoint_admin_url=self.sharepoint_admin_url if is_sharepoint else None,
            certificate_alias=self.certificate_alias if is_sharepoint else None,
        )
        token, graph_token = self._acquire_tokens(operation.module)
        return ExecuteRequest(
            **{**request.model_dump(), "token": token, "graph_token": graph_token}
        )

    async def _run_via_service(
        self, operation_id: str, collector_id: str, params: dict[str, Any]
    ) -> Any:
        validate_operation(operation_id, collector_id, params)
        if not self.service_secret:
            raise PowerShellExecutionError(
                "PowerShell service credentials are required"
            )
        request = self._request(operation_id, collector_id, params)
        verify: ssl.SSLContext | bool = True
        if self.service_ca_file:
            try:
                verify = ssl.create_default_context()
                verify.load_verify_locations(cafile=self.service_ca_file)
            except (OSError, ssl.SSLError):
                raise PowerShellExecutionError(
                    "PowerShell service CA configuration is invalid"
                ) from None
        try:
            async with httpx.AsyncClient(timeout=120.0, verify=verify) as client:
                response = await client.post(
                    f"{self.service_url}/execute",
                    json=request.model_dump(exclude_none=True),
                    headers={
                        "X-Service-Secret": self.service_secret,
                        **correlation_headers(),
                    },
                )
                response.raise_for_status()
        except httpx.HTTPError:
            raise PowerShellExecutionError(
                "PowerShell service request failed"
            ) from None
        try:
            result = response.json()
        except ValueError:
            raise PowerShellExecutionError(
                "Malformed PowerShell service response"
            ) from None
        if not isinstance(result, dict) or result.get("success") is not True:
            raise PowerShellExecutionError(
                "PowerShell service did not report explicit success"
            )
        if "data" not in result or result.get("error") or result.get("errors"):
            raise PowerShellExecutionError(
                "PowerShell service returned incomplete evidence"
            )
        return result["data"]

    async def _run_via_docker(
        self, operation_id: str, collector_id: str, params: dict[str, Any]
    ) -> Any:
        operation = validate_operation(operation_id, collector_id, params)
        if operation.module == "SharePointOnline":
            raise PowerShellExecutionError(
                "SharePointOnline requires the PowerShell HTTP service"
            )
        request = self._request(operation_id, collector_id, params)
        script = build_script(operation_id, collector_id, params, request.tenant_id)
        self._ensure_docker_image()
        # Pass only variable names in argv. Docker reads secret values from the
        # subprocess environment, so tokens never appear in process listings.
        env = os.environ.copy()
        names = (
            ["GRAPH_TOKEN", "TEAMS_TOKEN"]
            if operation.module == "Teams"
            else ["EXO_TOKEN"]
        )
        if operation.module == "Teams":
            env.update(GRAPH_TOKEN=request.graph_token, TEAMS_TOKEN=request.token)
        else:
            env["EXO_TOKEN"] = request.token
        container_name = "autoaudit-collection-" + uuid4().hex
        docker_cmd = [
            "docker",
            "run",
            "--rm",
            "-i",
            "--name",
            container_name,
            "--entrypoint",
            "pwsh",
        ]
        for name in names:
            docker_cmd.extend(["-e", name])
        docker_cmd.extend(
            [self.DOCKER_IMAGE, "-NoProfile", "-NonInteractive", "-File", "/dev/stdin"]
        )
        try:
            proc = subprocess.run(
                docker_cmd,
                input=script,
                env=env,
                capture_output=True,
                text=True,
                timeout=120,
            )
        except (OSError, subprocess.SubprocessError):
            raise PowerShellExecutionError(
                "PowerShell Docker execution failed"
            ) from None
        finally:
            # Killing the CLI on timeout does not stop the daemon-owned container.
            # Remove only this invocation's uniquely named container on every exit.
            try:
                subprocess.run(
                    ["docker", "rm", "-f", container_name],
                    capture_output=True,
                    timeout=15,
                    check=False,
                )
            except (OSError, subprocess.SubprocessError):
                pass
        if proc.returncode != 0:
            raise PowerShellExecutionError("PowerShell operation failed")
        try:
            return json.loads(proc.stdout)
        except (ValueError, TypeError):
            raise PowerShellExecutionError(
                "PowerShell returned malformed JSON"
            ) from None
