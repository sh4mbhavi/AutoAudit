"""Captured-policy evaluations use reproducible artifacts, not mutable service state."""

import asyncio
import hashlib
import os

import pytest

from opa_client import OPAClient

OPA = os.environ.get("OPA_BINARY")
POLICY = """package test.control
import rego.v1
result := {"compliant": input.secure, "message": "Synthetic result", "affected_resources": [], "details": {}}
"""


@pytest.mark.skipif(not OPA, reason="Set OPA_BINARY to run real OPA snapshot tests")
@pytest.mark.parametrize(
    "value,expected", [(True, "passed"), (False, "failed"), (None, "indeterminate")]
)
def test_exact_snapshot_evaluated(value, expected):
    evaluated = asyncio.run(
        OPAClient().evaluate_snapshot("test/control", {"secure": value}, POLICY)
    )
    assert evaluated.result.status == expected
    assert evaluated.opa_version
    assert evaluated.policy_digest == hashlib.sha256(POLICY.encode()).hexdigest()


@pytest.mark.skipif(not OPA, reason="Set OPA_BINARY to run real OPA snapshot tests")
@pytest.mark.parametrize(
    "policy",
    [
        POLICY.replace("input.secure", '"true"'),
        "package test.control\nimport rego.v1\nresult := 1",
        "package test.control\nimport rego.v1\nother := true",
        "not valid rego",
    ],
)
def test_undefined_malformed_and_compile_errors_are_errors(policy):
    with pytest.raises(ValueError):
        asyncio.run(OPAClient().evaluate_snapshot("test/control", {}, policy))


@pytest.mark.skipif(not OPA, reason="Set OPA_BINARY to run real OPA snapshot tests")
def test_runtime_version_available_without_policy_success():
    version = asyncio.run(OPAClient().runtime_version())
    assert version.startswith("1.")
