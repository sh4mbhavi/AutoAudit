"""The scan execution plan, keyed by ``data_collector_id``.

Until Phase 9 the unit of work was one control. A full CIS v6.0.0 scan therefore
ran 69 collections across 43 distinct collectors and re-collected 26 payloads it
already held -- once for every control beyond the first that names the same
collector. This module turns the pending result rows into an ordered plan of
collection groups, one per distinct collector, so the collection happens once and
is fanned out to each of that collector's policies.

Three properties matter and are all pure functions of the frozen metadata
snapshot and the pending rows, so they can be asserted without a database:

* **Determinism.** Groups are ordered by collector id and members by control id,
  so the same scan always produces the same plan, the same outbox identities and
  the same order of execution.
* **Completeness.** Every dispatchable result appears in exactly one group.
  ``build_collection_plan`` also returns the results it could not map, so the
  caller can fall back rather than silently dropping a control.
* **Identity.** A group's outbox identity is ``uuid5`` over the scan and the
  collector, exactly as Phase 6's per-result identity was ``uuid5`` over the scan
  and the result. Duplicate orchestration and reconciler recovery converge on the
  same row instead of creating a second one.

Nothing here touches evidence, credentials or the broker. What crosses the broker
is still identifiers only: a scan id, a collector id and a connection id.
"""

from dataclasses import dataclass
from uuid import NAMESPACE_URL, uuid5

CONTROL_TASK = "worker.tasks.evaluate_control"
COLLECTION_TASK = "worker.tasks.evaluate_collection"


@dataclass(frozen=True)
class PlannedControl:
    """One control that will be judged against a shared collection."""

    result_id: int
    control_id: str
    policy_file: str | None


@dataclass(frozen=True)
class CollectionGroup:
    """One collector execution and every control that consumes its evidence."""

    collector_id: str
    members: tuple[PlannedControl, ...]

    @property
    def shared(self) -> bool:
        return len(self.members) > 1


def collection_dispatch_id(scan_id: int, collector_id: str) -> str:
    """Deterministic outbox identity for one collection group."""
    return str(
        uuid5(NAMESPACE_URL, f"autoaudit:scan:{scan_id}:collector:{collector_id}")
    )


def control_dispatch_id(scan_id: int, result_id: int | None) -> str:
    """Deterministic outbox identity for one control, unchanged from Phase 6."""
    return str(uuid5(NAMESPACE_URL, f"autoaudit:scan:{scan_id}:result:{result_id}"))


def index_controls(metadata: object) -> dict[str, dict]:
    """Map control_id to its frozen metadata entry.

    Tolerant of a malformed snapshot: a corrupt metadata document must reach the
    deadline/failure path with an empty plan, not raise inside orchestration.
    """
    controls = metadata.get("controls") if isinstance(metadata, dict) else None
    if not isinstance(controls, list):
        return {}
    return {
        control["control_id"]: control
        for control in controls
        if isinstance(control, dict) and isinstance(control.get("control_id"), str)
    }


def build_collection_plan(
    pairs: list[tuple[dict, dict]],
) -> tuple[list[CollectionGroup], list[dict]]:
    """Group ``(result_row, control_metadata)`` pairs by collector.

    Returns ``(groups, unplannable)``. A pair whose control names no collector is
    returned in ``unplannable`` rather than dropped, so the caller decides -- the
    orchestrator has already rejected those before it gets here, but the
    reconciler can meet one after a partial failure and must not lose it.
    """
    grouped: dict[str, list[PlannedControl]] = {}
    unplannable: list[dict] = []
    for result, control in pairs:
        collector_id = (control or {}).get("data_collector_id")
        ready = (control or {}).get("automation_status", "ready") == "ready"
        if not isinstance(collector_id, str) or not collector_id or not ready:
            # A control that is not ready is not plannable even when it names a
            # collector -- 29 non-ready CIS v6.0.0 controls do. The orchestrator
            # has already rejected those, but the reconciler can meet one, and a
            # collection group whose members the task will refuse would be
            # republished until the whole scan failed on retry exhaustion.
            unplannable.append(result)
            continue
        grouped.setdefault(collector_id, []).append(
            PlannedControl(
                result_id=result["id"],
                control_id=result["control_id"],
                policy_file=control.get("policy_file"),
            )
        )
    groups = [
        CollectionGroup(
            collector_id=collector_id,
            members=tuple(sorted(members, key=lambda member: member.control_id)),
        )
        for collector_id, members in sorted(grouped.items())
    ]
    return groups, unplannable


def plan_summary(groups: list[CollectionGroup]) -> dict:
    """Counts an operator can compare against the census, with no evidence in it."""
    return {
        "collections": len(groups),
        "controls": sum(len(group.members) for group in groups),
        "shared_collections": sum(1 for group in groups if group.shared),
    }
