"""OPA (Open Policy Agent) client for policy evaluation."""

import asyncio
from worker.correlation import event, headers
import hashlib
import json
import re
import shutil
from dataclasses import dataclass
from pathlib import Path
from tempfile import TemporaryDirectory

import httpx

from worker.result_contract import OPAResult

from worker.config import settings


@dataclass(frozen=True)
class SnapshotEvaluation:
    result: OPAResult
    opa_version: str
    policy_digest: str


class OPAClient:
    """Client for querying Open Policy Agent for policy evaluation."""

    def __init__(self, base_url: str | None = None):
        """Initialize OPA client.

        Args:
            base_url: OPA server URL. Defaults to OPA_URL from settings.
        """
        self.base_url = (base_url or settings.OPA_URL).rstrip("/")

    async def evaluate_policy(self, package_path: str, input_data: dict) -> OPAResult:
        """Evaluate a policy against input data.

        Args:
            package_path: The OPA package path (e.g., "cis/microsoft_365_foundations/v3_1_0/control_1_1_1")
            input_data: The data to evaluate (facts collected from the cloud)

        Returns:
            The evaluation result from OPA, typically containing:
            - compliant: bool
            - message: str
            - affected_resources: list
            - details: dict
        """
        # Convert package path to OPA URL format
        # e.g., "cis.microsoft_365_foundations.v3_1_0.control_1_1_1" -> "cis/microsoft_365_foundations/v3_1_0/control_1_1_1"
        url_path = package_path.replace(".", "/")

        # Query the specific "result" rule within the package
        # This gives us the compliance result directly without extra nesting
        async with httpx.AsyncClient(timeout=30.0) as client:
            response = await client.post(
                f"{self.base_url}/v1/data/{url_path}/result",
                json={"input": input_data},
                headers=headers(),
            )
            response.raise_for_status()
            result = response.json()

        # OPA returns {"result": {...}} - extract the result
        return OPAResult.model_validate(result.get("result"))

    async def _execute(
        self, arguments: list[str], input_data: dict | None = None
    ) -> dict:
        process = await asyncio.create_subprocess_exec(
            shutil.which(settings.OPA_BINARY) or settings.OPA_BINARY,
            *arguments,
            stdin=asyncio.subprocess.PIPE,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
            env={},
        )
        try:
            stdout, _ = await asyncio.wait_for(
                process.communicate(
                    json.dumps(input_data, allow_nan=False).encode()
                    if input_data is not None
                    else None
                ),
                timeout=35,
            )
        except BaseException:
            if process.returncode is None:
                process.kill()
            await process.wait()
            raise
        if process.returncode:
            raise ValueError("OPA evaluation failed or returned no result")
        try:
            return json.loads(stdout)
        except ValueError:
            raise ValueError("OPA returned invalid JSON") from None

    async def runtime_version(self) -> str:
        response = await self._execute(
            ["eval", "--format=json", "opa.runtime().version"]
        )
        try:
            version = response["result"][0]["expressions"][0]["value"]
            if not isinstance(version, str) or not version:
                raise ValueError("OPA version missing")
            return version
        except (KeyError, IndexError, TypeError, ValueError):
            raise ValueError("OPA version unavailable") from None

    async def evaluate_snapshot(
        self, package_path: str, input_data: dict, policy_source: str
    ) -> SnapshotEvaluation:
        """Evaluate precisely the retained source, with input only on stdin.

        The local CLI avoids attributing a local digest to a mutable remote
        policy. The same evaluation returns the actual OPA runtime version.
        """
        package = package_path.replace("/", ".")
        event("opa_evaluation_started")
        if not re.fullmatch(
            r"[a-zA-Z_][a-zA-Z_0-9]*(?:\.[a-zA-Z_][a-zA-Z_0-9]*)*", package
        ):
            raise ValueError("Invalid policy package")
        query = (
            '{"result": data.'
            + package
            + '.result, "opa_version": opa.runtime().version}'
        )
        with TemporaryDirectory(prefix="autoaudit-policy-") as directory:
            policy = Path(directory) / "policy.rego"
            policy.write_text(policy_source, encoding="utf-8")
            response = await self._execute(
                [
                    "eval",
                    "--format=json",
                    "--fail",
                    "--strict-builtin-errors",
                    "--timeout=30s",
                    "--stdin-input",
                    "--data",
                    str(policy),
                    query,
                ],
                input_data,
            )
            try:
                rows = response["result"]
                if len(rows) != 1 or len(rows[0]["expressions"]) != 1:
                    raise ValueError("Ambiguous OPA output")
                value = rows[0]["expressions"][0]["value"]
                version = value["opa_version"]
                if not isinstance(version, str) or not version:
                    raise ValueError("OPA version missing")
                result = OPAResult.model_validate(value["result"])
            except (KeyError, TypeError, ValueError):
                raise ValueError("OPA returned an invalid result contract") from None
            event("opa_evaluation_completed")
            return SnapshotEvaluation(
                result, version, hashlib.sha256(policy_source.encode()).hexdigest()
            )

    async def health_check(self) -> bool:
        """Check if OPA server is healthy.

        Returns:
            True if OPA is responding, False otherwise.
        """
        try:
            async with httpx.AsyncClient(timeout=5.0) as client:
                response = await client.get(f"{self.base_url}/health")
                return response.status_code == 200
        except Exception:
            return False


# Default client instance
opa_client = OPAClient()
