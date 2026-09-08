#!/usr/bin/env python3
"""Measure what one scan costs, before and after the Phase 9 execution change.

**This is not a live-tenant load test.** No tenant is contacted. Every Graph
response and every PowerShell result comes from a synthetic transport in this
file, and the numbers below are therefore exact counts of what the engine
*would* issue against a tenant of the stated shape -- not latency measured
against Microsoft.

That is the honest thing this repository can measure without a licensed
non-production tenant, and it is enough to answer the questions Phase 9's
verification checklist actually asks:

* how many collector executions does a full 69-control scan perform?
* how many Graph requests, and how many PowerShell sessions?
* how many of those change when evidence is collected once and fanned out?

Two topologies are exercised against the same synthetic tenant:

``per_control``    one collector execution per ready control -- the shape the
                   engine had before Phase 9.
``per_collector``  one execution per distinct ``data_collector_id``, fanned out
                   to every control that names it -- the Phase 9 shape.

Wall time and peak allocation are reported too, but read them as the cost of the
engine's own work on synthetic evidence: with no network in the loop they are
dominated by parsing, not by collection.

Usage:
    uv run --frozen --project engine --extra dev \\
        python tools/perf/scan_load_report.py --tenant-size 25
    ... --json report.json      # write the machine-readable form
"""

import argparse
import asyncio
import json
import sys
import time
import tracemalloc
from collections import Counter
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "engine"))

import httpx  # noqa: E402
from collectors.registry import get_collector  # noqa: E402
from collectors.routing import uses_powershell  # noqa: E402
from worker.execution_plan import build_collection_plan  # noqa: E402

METADATA_PATH = (
    ROOT / "engine/policies/cis/microsoft-365-foundations/v6.0.0/metadata.json"
)


class SyntheticTenant:
    """A tenant whose every collection endpoint answers plausibly and emptily.

    Shaped, not empty: a list endpoint returns ``size`` objects carrying the
    identity fields collectors validate, so the per-item request loops that
    Phase 9 bounds actually fire. Item endpoints answer with an object that
    carries no signal, so nothing here can be mistaken for a tenant verdict.
    """

    def __init__(self, size: int):
        self.size = size
        self.graph_requests = 0
        self.powershell_sessions = 0
        self.powershell_operations = 0

    # -- Graph ---------------------------------------------------------------

    def respond(self, request: httpx.Request) -> httpx.Response:
        self.graph_requests += 1
        path = request.url.path.removeprefix("/v1.0").removeprefix("/beta")
        segments = [segment for segment in path.split("/") if segment]
        # A path whose last segment looks like a generated id is an item read;
        # anything else is treated as a collection.
        if segments and segments[-1].startswith("synthetic-"):
            return httpx.Response(200, json=self._item(segments[-1]))
        if len(segments) >= 2 and segments[-2].startswith("synthetic-"):
            return httpx.Response(200, json={"value": self._items(segments[-1])})
        return httpx.Response(
            200, json={"value": self._items(segments[-1] if segments else "")}
        )

    # A few list endpoints need a specific shape before the collector that reads
    # them will issue its per-item requests at all. Without these the Graph N+1
    # loops never fire and the measurement silently reports no per-item cost.
    SHAPES = {
        "directoryRoles": {"displayName": "Global Administrator"},
        "deviceConfigurations": {
            "@odata.type": "#microsoft.graph.windows10EndpointProtectionConfiguration"
        },
    }

    def _items(self, kind: str) -> list[dict]:
        shape = self.SHAPES.get(kind, {})
        return [
            {
                "id": f"synthetic-{kind}-{index}",
                "displayName": f"Synthetic {kind} {index}",
                "@odata.type": "#microsoft.graph.user",
                "userPrincipalName": f"synthetic{index}@example.invalid",
                "@odata.count": index,
                **shape,
            }
            for index in range(self.size)
        ]

    def _item(self, identifier: str) -> dict:
        return {
            "id": identifier,
            "displayName": identifier,
            "userPrincipalName": f"{identifier}@example.invalid",
            "value": [],
        }

    # -- PowerShell ----------------------------------------------------------

    def client(self, shape: str = "records") -> "SyntheticPowerShellClient":
        return SyntheticPowerShellClient(self, shape)

    def counters(self) -> tuple[int, int, int]:
        return (
            self.graph_requests,
            self.powershell_sessions,
            self.powershell_operations,
        )

    def restore(self, counters: tuple[int, int, int]) -> None:
        (
            self.graph_requests,
            self.powershell_sessions,
            self.powershell_operations,
        ) = counters


class SyntheticPowerShellClient:
    """Counts remote sessions the way the service opens them.

    ``run_operation`` is one pwsh process, one Connect and one Disconnect.
    ``run_operations`` is one session for the whole batch, which is exactly the
    saving Phase 9 claims.
    """

    def __init__(self, tenant: SyntheticTenant, shape: str = "records"):
        self.tenant = tenant
        self.shape = shape

    async def run_operation(self, operation_id, collector_id, **params):
        self.tenant.powershell_sessions += 1
        self.tenant.powershell_operations += 1
        records = self._records()
        # Roughly half the reviewed operations are singleton reads
        # (Get-OrganizationConfig, Get-PnPTenant) and half are population reads,
        # and nothing in the registry declares which. run_collector offers both
        # shapes and keeps whichever the collector accepts.
        if self.shape == "records":
            return records
        return records[0] if records else {}

    def _records(self):
        return [
            {
                "Name": f"synthetic-{index}",
                "UserPrincipalName": f"synthetic{index}@example.invalid",
                "DisplayName": f"Synthetic {index}",
                "State": "Enabled",
                "RedirectMessageTo": [],
                "BlindCopyTo": [],
                "SenderDomainIs": [],
                "SetSCL": None,
                "Guid": f"synthetic-{index}",
                "Enabled": True,
            }
            for index in range(self.tenant.size)
        ]

    async def run_operations(self, entries):
        self.tenant.powershell_sessions += 1
        self.tenant.powershell_operations += len(entries)
        return [{"AccountDisabled": True} for _ in entries]


def ready_controls() -> list[dict]:
    metadata = json.loads(METADATA_PATH.read_text(encoding="utf-8"))
    return [
        control
        for control in metadata["controls"]
        if control["automation_status"] == "ready"
    ]


async def _collect_once(collector_id, tenant: SyntheticTenant, shape="records"):
    from collectors.graph_client import GraphClient

    collector = get_collector(collector_id)
    if uses_powershell(collector_id):
        await collector.collect(tenant.client(shape))
        return
    client = GraphClient.__new__(GraphClient)
    # No tenant, so no token acquisition: the cache is pre-filled with a literal
    # the MockTransport ignores. Nothing here ever reaches Microsoft.
    client._access_token = "synthetic"  # nosec B105 - not a credential
    client._retry = GraphClient._retry
    client._http = httpx.AsyncClient(transport=httpx.MockTransport(tenant.respond))
    try:
        await collector.collect(client)
    finally:
        await client.aclose()


def run_collector(collector_id, tenant: SyntheticTenant, failures: Counter) -> None:
    """Run one collector, offering the singleton PowerShell shape as a fallback.

    A collector that rejects the synthetic evidence outright is COUNTED, not
    hidden: its requests are excluded from both columns equally, so the delta
    stays meaningful and the exclusion is named in the report.
    """
    before = tenant.counters()
    last = None
    for shape in ("records", "object"):
        try:
            asyncio.run(_collect_once(collector_id, tenant, shape))
            return
        except Exception as exc:  # noqa: BLE001 - counted, not hidden
            last = exc
            tenant.restore(before)
        if not uses_powershell(collector_id):
            break
    failures[f"{collector_id}: {type(last).__name__}"] += 1


def measure(topology: str, size: int) -> dict:
    """Run one full scan under one topology and report what it cost."""
    controls = ready_controls()
    if topology == "per_control":
        executions = [control["data_collector_id"] for control in controls]
    elif topology == "per_collector":
        groups, _ = build_collection_plan(
            [
                ({"id": index, "control_id": control["control_id"]}, control)
                for index, control in enumerate(controls)
            ]
        )
        executions = [group.collector_id for group in groups]
    else:  # pragma: no cover - argparse constrains this
        raise ValueError(f"Unknown topology: {topology}")

    # Warm up before measuring. Without this the first topology measured pays
    # for the lazy import of ~43 collector modules, the metadata parse and every
    # first-touch allocation, and main() always runs per_control first -- so the
    # time and memory rows reported a saving that was purely measurement order,
    # and their sign flipped when the two columns were swapped.
    warm = SyntheticTenant(1)
    for collector_id in sorted(set(executions)):
        run_collector(collector_id, warm, Counter())

    tenant = SyntheticTenant(size)
    failures: Counter = Counter()
    tracemalloc.start()
    started = time.perf_counter()
    for collector_id in executions:
        run_collector(collector_id, tenant, failures)
    elapsed = time.perf_counter() - started
    _, peak = tracemalloc.get_traced_memory()
    tracemalloc.stop()

    return {
        "topology": topology,
        "controls": len(controls),
        "collector_executions": len(executions),
        "graph_requests": tenant.graph_requests,
        "powershell_sessions": tenant.powershell_sessions,
        "powershell_operations": tenant.powershell_operations,
        "seconds": round(elapsed, 3),
        "peak_allocated_bytes": peak,
        "collections_that_raised": sum(failures.values()),
        "error_rate": round(sum(failures.values()) / max(len(executions), 1), 3),
        "raised_by": dict(sorted(failures.items())),
    }


def render(report: dict) -> str:
    before, after = report["before"], report["after"]
    sessions_before = before["powershell_operations"]
    sessions_after = after["powershell_sessions"]
    rows = [
        ("collector executions", "collector_executions"),
        ("Graph requests", "graph_requests"),
        ("PowerShell sessions", "powershell_sessions"),
        ("...if each op were a session", "powershell_operations"),
        ("seconds (engine work only)", "seconds"),
        ("peak allocated bytes", "peak_allocated_bytes"),  # measured after warm-up
        ("collections that raised", "collections_that_raised"),
    ]
    width = max(len(label) for label, _ in rows)
    lines = [
        f"Synthetic tenant size: {report['tenant_size']} items per collection",
        "No tenant was contacted. These are exact counts of what the engine",
        "would issue, not latency measured against Microsoft.",
        "",
        "Both columns run the CURRENT collectors, so only the execution",
        "TOPOLOGY differs between them. Read the PowerShell rows together: the",
        "pre-Phase-9 engine opened one session per reviewed OPERATION, so its",
        "true session count is the per_control 'if each op were a session'",
        "figure, and the Phase 9 count is per_collector 'PowerShell sessions'.",
        "Both topologies are measured after a warm-up pass, so the time and",
        "memory rows are not measurement-order artifacts.",
        "",
        f"{'':<{width}}  {'per_control':>14}  {'per_collector':>14}  {'delta':>10}",
    ]
    for label, key in rows:
        old, new = before[key], after[key]
        delta = new - old
        lines.append(
            f"{label:<{width}}  {old:>14}  {new:>14}  {delta:>+10.3f}"
            if isinstance(old, float)
            else f"{label:<{width}}  {old:>14}  {new:>14}  {delta:>+10}"
        )
    lines.append("")
    lines.append(
        "PowerShell sessions, pre-Phase-9 shape vs Phase 9 shape: "
        f"{sessions_before} -> {sessions_after} "
        f"({sessions_after - sessions_before:+d})"
    )
    for side in (before, after):
        if side["raised_by"]:
            lines.append("")
            lines.append(f"{side['topology']} collections that raised:")
            for reason, count in side["raised_by"].items():
                lines.append(f"  {count} x {reason}")
    return "\n".join(lines)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--tenant-size",
        type=int,
        default=10,
        help="items returned by every synthetic collection endpoint",
    )
    parser.add_argument("--json", type=Path, help="also write the report as JSON")
    arguments = parser.parse_args()
    if arguments.tenant_size < 0:
        parser.error("--tenant-size must not be negative")

    report = {
        "harness": "tools/perf/scan_load_report.py",
        "live_tenant": False,
        "benchmark": "cis/microsoft-365-foundations/v6.0.0",
        "tenant_size": arguments.tenant_size,
        "before": measure("per_control", arguments.tenant_size),
        "after": measure("per_collector", arguments.tenant_size),
    }
    print(render(report))
    if arguments.json:
        arguments.json.parent.mkdir(parents=True, exist_ok=True)
        arguments.json.write_text(json.dumps(report, indent=2) + "\n")
        print(f"\nWrote {arguments.json}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
