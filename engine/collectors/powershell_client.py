"""Client for fixed, read-only M365 collection operations.

The HTTP service and local Docker mode use the same operation registry and script
builder. OAuth tokens are supplied through process environment or authenticated
HTTP; callers never supply command text. Unregistered Teams collectors must
receive reviewed operation entries before they can be enabled.
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
from powershell.service.executor import (
    BATCH_TIMEOUT_SECONDS,
    build_batch_script,
    build_script,
)
from powershell.service.operations import (
    MAX_BATCH,
    validate_batch,
    validate_entries,
    validate_operation,
)
from powershell.service.schemas import ExecuteBatchRequest, ExecuteRequest


# Modules whose pwsh session authenticates from a certificate the service holds.
# No token is acquired or transmitted for these, and they cannot run in Docker
# mode because only the HTTP service resolves a certificate alias.
CERTIFICATE_MODULES = frozenset({"SharePointOnline", "Compliance"})


class PowerShellExecutionError(Exception):
    """Raised when PowerShell execution fails."""

    pass


class PowerShellClient:
    """Client for PowerShell-based M365 connections using Docker or HTTP service."""

    # Service-specific scopes for token acquisition
    EXCHANGE_SCOPE = "https://outlook.office365.com/.default"
    TEAMS_SCOPE = "https://api.interfaces.records.teams.microsoft.com/.default"

    DOCKER_IMAGE = "autoaudit-powershell"

    # Class-level so an instance built with __new__ (the boundary tests do this)
    # still has the reviewed ceiling rather than no bound at all.
    batch_size: int = MAX_BATCH

    def __init__(
        self,
        tenant_id: str,
        client_id: str,
        client_secret: str,
        service_url: str | None = None,
        sharepoint_admin_url: str | None = None,
        certificate_alias: str | None = None,
        compliance_certificate_alias: str | None = None,
        compliance_organization: str | None = None,
        service_secret: str | None = None,
        service_ca_file: str | None = None,
        batch_size: int | None = None,
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
            compliance_certificate_alias: Certificate alias resolved by the PowerShell
                               service from its own Compliance namespace
                               (required for Compliance). Deliberately separate from
                               certificate_alias so a Compliance request can never
                               carry a SharePoint certificate.
            compliance_organization: Tenant primary .onmicrosoft.com domain passed to
                               Connect-IPPSSession -Organization (required for Compliance)
            service_secret: Shared credential sent to the HTTP service.
            service_ca_file: Optional private CA added to default TLS trust roots.
        """
        self.tenant_id = validate_tenant_id(tenant_id)
        self.client_id = client_id
        self.client_secret = client_secret
        self.service_url = service_url
        self.service_secret = service_secret
        self.service_ca_file = service_ca_file
        # How many reviewed operations may share one remote session. MAX_BATCH
        # is the reviewed ceiling and a deployment may only lower it, never
        # raise it: the ceiling is a property of what was reviewed, not of what
        # an operator configures.
        # None means unset. A configured 0 is a misconfiguration, not a request
        # for the default, and is clamped to the smallest legal batch.
        self.batch_size = (
            MAX_BATCH if batch_size is None else max(1, min(batch_size, MAX_BATCH))
        )
        self.sharepoint_admin_url = sharepoint_admin_url
        self.certificate_alias = certificate_alias
        self.compliance_certificate_alias = compliance_certificate_alias
        self.compliance_organization = compliance_organization
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
        if operation.module in CERTIFICATE_MODULES and not self.service_url:
            raise PowerShellExecutionError(
                "Certificate authentication requires the PowerShell HTTP service"
            )
        if self.service_url:
            return await self._run_via_service(operation_id, collector_id, params)
        return await self._run_via_docker(operation_id, collector_id, params)

    async def run_operations(self, entries: list[tuple[str, str, dict]]) -> list[Any]:
        """Run several reviewed operations of one module in one remote session.

        ``entries`` is a list of ``(operation_id, collector_id, params)``. Every
        entry is validated against its own collector id -- batching is not a way
        to run an operation under a collector that may not run it -- and the
        batch must resolve to exactly one module, because the module chooses the
        Connect verb and the secrets the pwsh child is given.

        Results come back in request order. Longer lists are split into chunks of
        the reviewed maximum rather than rejected, so a caller does not have to
        know the bound; each chunk is its own session.
        """
        if not entries:
            return []
        prepared = [
            {
                "operation_id": operation_id,
                "collector_id": collector_id,
                "params": params,
            }
            for operation_id, collector_id, params in entries
        ]
        # Validate the whole list first -- every entry against its own collector
        # id, and one module across all of them -- then split it into sessions.
        # Each session is bounded by validate_batch inside the transport.
        module, _ = validate_entries(prepared)
        event("powershell_batch_requested")
        if module in CERTIFICATE_MODULES and not self.service_url:
            raise PowerShellExecutionError(
                "Certificate authentication requires the PowerShell HTTP service"
            )
        results: list[Any] = []
        for start in range(0, len(prepared), self.batch_size):
            chunk = prepared[start : start + self.batch_size]
            if self.service_url:
                results.extend(await self._run_batch_via_service(chunk))
            else:
                results.extend(await self._run_batch_via_docker(chunk))
        return results

    def _batch_request(self, entries: list[dict]) -> ExecuteBatchRequest:
        module, _ = validate_batch(entries)
        is_certificate = module in CERTIFICATE_MODULES
        is_sharepoint = module == "SharePointOnline"
        is_compliance = module == "Compliance"
        # Validate all caller-controlled configuration before acquiring credentials.
        request = ExecuteBatchRequest(
            operations=entries,
            tenant_id=self.tenant_id,
            token=None if is_certificate else "pending",
            graph_token="pending" if module == "Teams" else None,
            client_id=self.client_id if is_certificate else None,
            sharepoint_admin_url=self.sharepoint_admin_url if is_sharepoint else None,
            certificate_alias=self.certificate_alias if is_sharepoint else None,
            compliance_certificate_alias=(
                self.compliance_certificate_alias if is_compliance else None
            ),
            compliance_organization=(
                self.compliance_organization if is_compliance else None
            ),
        )
        token, graph_token = self._acquire_tokens(module)
        return ExecuteBatchRequest(
            **{**request.model_dump(), "token": token, "graph_token": graph_token}
        )

    async def _run_batch_via_service(self, entries: list[dict]) -> list[Any]:
        validate_batch(entries)
        if not self.service_secret:
            raise PowerShellExecutionError(
                "PowerShell service credentials are required"
            )
        request = self._batch_request(entries)
        # A batch is many cmdlets in one session, so it needs more than the
        # single-operation budget -- and MORE than the service's own budget for
        # it, or a batch the service completes at 200 seconds is abandoned here
        # as a transport error while the pwsh child runs on unheard.
        result = await self._post(
            "/execute-batch",
            request.model_dump(exclude_none=True),
            timeout=BATCH_TIMEOUT_SECONDS + 30.0,
        )
        data = result["data"]
        if not isinstance(data, list) or len(data) != len(entries):
            raise PowerShellExecutionError(
                "PowerShell service returned incomplete evidence"
            )
        return data

    async def _run_batch_via_docker(self, entries: list[dict]) -> list[Any]:
        module, _ = validate_batch(entries)
        if module in CERTIFICATE_MODULES:
            raise PowerShellExecutionError(
                "Certificate authentication requires the PowerShell HTTP service"
            )
        request = self._batch_request(entries)
        script = build_batch_script(entries, request.tenant_id)
        payload = self._docker_run(script, module, request.token, request.graph_token)
        if not isinstance(payload, list) or len(payload) != len(entries):
            raise PowerShellExecutionError(
                "PowerShell returned an incomplete batch result"
            )
        results: list[Any] = [None] * len(entries)
        seen = set()
        for record in payload:
            if not isinstance(record, dict) or set(record) != {"index", "data"}:
                raise PowerShellExecutionError("PowerShell batch record is malformed")
            index = record["index"]
            if type(index) is not int or not 0 <= index < len(entries) or index in seen:
                raise PowerShellExecutionError(
                    "PowerShell batch record index is invalid"
                )
            seen.add(index)
            results[index] = record["data"]
        return results

    def _acquire_tokens(self, module: str) -> tuple[str | None, str | None]:
        # Certificate modules authenticate inside the service's pwsh child from a
        # certificate the service holds, so no token is acquired or transmitted.
        if module in CERTIFICATE_MODULES:
            return None, None
        scopes = {
            "ExchangeOnline": self.EXCHANGE_SCOPE,
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
        is_certificate = operation.module in CERTIFICATE_MODULES
        is_sharepoint = operation.module == "SharePointOnline"
        is_compliance = operation.module == "Compliance"
        request = ExecuteRequest(
            operation_id=operation_id,
            collector_id=collector_id,
            params=params,
            tenant_id=self.tenant_id,
            token=None if is_certificate else "pending",
            graph_token="pending" if operation.module == "Teams" else None,
            client_id=self.client_id if is_certificate else None,
            sharepoint_admin_url=self.sharepoint_admin_url if is_sharepoint else None,
            certificate_alias=self.certificate_alias if is_sharepoint else None,
            compliance_certificate_alias=(
                self.compliance_certificate_alias if is_compliance else None
            ),
            compliance_organization=(
                self.compliance_organization if is_compliance else None
            ),
        )
        token, graph_token = self._acquire_tokens(operation.module)
        return ExecuteRequest(
            **{**request.model_dump(), "token": token, "graph_token": graph_token}
        )

    async def _post(self, path: str, body: dict, timeout: float = 120.0) -> dict:
        """One authenticated POST to the service, with the shared failure envelope.

        Shared by /execute and /execute-batch so the two paths cannot diverge on
        TLS trust, redaction or what counts as an explicit success.
        """
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
            async with httpx.AsyncClient(timeout=timeout, verify=verify) as client:
                response = await client.post(
                    f"{self.service_url}{path}",
                    json=body,
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
        return result

    async def _run_via_service(
        self, operation_id: str, collector_id: str, params: dict[str, Any]
    ) -> Any:
        validate_operation(operation_id, collector_id, params)
        if not self.service_secret:
            raise PowerShellExecutionError(
                "PowerShell service credentials are required"
            )
        request = self._request(operation_id, collector_id, params)
        result = await self._post("/execute", request.model_dump(exclude_none=True))
        return result["data"]

    async def _run_via_docker(
        self, operation_id: str, collector_id: str, params: dict[str, Any]
    ) -> Any:
        operation = validate_operation(operation_id, collector_id, params)
        if operation.module in CERTIFICATE_MODULES:
            raise PowerShellExecutionError(
                "Certificate authentication requires the PowerShell HTTP service"
            )
        request = self._request(operation_id, collector_id, params)
        script = build_script(operation_id, collector_id, params, request.tenant_id)
        return self._docker_run(
            script, operation.module, request.token, request.graph_token
        )

    def _docker_run(
        self, script: str, module: str, token: str | None, graph_token: str | None
    ) -> Any:
        """Run one script in one uniquely named container and parse its JSON.

        Shared by the single-operation and batched Docker paths: the container
        naming, the argv shape, the timeout and the guaranteed ``docker rm -f``
        are all one definition.
        """
        self._ensure_docker_image()
        # Pass only variable names in argv. Docker reads secret values from the
        # subprocess environment, so tokens never appear in process listings.
        env = os.environ.copy()
        names = ["GRAPH_TOKEN", "TEAMS_TOKEN"] if module == "Teams" else ["EXO_TOKEN"]
        if module == "Teams":
            env.update(GRAPH_TOKEN=graph_token, TEAMS_TOKEN=token)
        else:
            env["EXO_TOKEN"] = token
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
