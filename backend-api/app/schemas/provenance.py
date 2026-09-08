"""What execution provenance may leave the system, in exactly one place.

Phase 7 established this allowlist for the SOC 2 projection. Phase 9 makes it
the rule for every response that carries provenance, because it was never a
SOC 2-specific rule: ``policy_source`` holds the complete Rego source text the
worker captured, and file content does not leave in a response. Until Phase 9
the SOC 2 report withheld it while ``GET /scans/{id}`` and
``GET /scans/{id}/results`` published it verbatim on every row -- roughly 180 KB
of Rego across a 69-control scan, re-sent on every three-second poll.

Strictly an allowlist: a field added to the worker's provenance record is not
published until it is named here.
"""

PUBLISHABLE_PROVENANCE_FIELDS = (
    "schema_version",
    "provenance_status",
    "reason_code",
    "collector_id",
    "policy_file",
    "policy_digest",
    "input_digest",
    "engine_git_sha",
    "engine_image_digest",
    "opa_version",
    "metadata_digest",
    "correlation_id",
    "collection_started_at",
    "collection_completed_at",
    "evaluation_started_at",
    "evaluated_at",
    "recorded_at",
)


# What a SCAN RESULT row publishes: every provenance field the worker writes,
# minus policy_source. Deliberately a superset of the SOC 2 tuple above rather
# than the same tuple:
#
#   * control_id, framework, benchmark and benchmark_version are already columns
#     or scalars on the same responses, so echoing them publishes nothing new;
#   * engine_worktree_dirty and engine_source_digest are engine identity, are
#     what EVI-02 asked the worker to freeze, and were already published here.
#
# The Phase 9 change to this response is exactly one field: policy_source, the
# complete Rego source text, is no longer sent. The SOC 2 tuple above is
# untouched, so the Phase 7 and Phase 8 projections are byte-identical.
RESULT_PROVENANCE_FIELDS = PUBLISHABLE_PROVENANCE_FIELDS + (
    "control_id",
    "framework",
    "benchmark",
    "benchmark_version",
    "engine_worktree_dirty",
    "engine_source_digest",
)

# Never published in any response, at any depth. Named rather than merely
# omitted so the reason survives the next person to edit the allowlists.
WITHHELD_PROVENANCE_FIELDS = ("policy_source",)


def publishable_provenance(
    provenance: object, fields: tuple[str, ...] = RESULT_PROVENANCE_FIELDS
) -> dict | None:
    """Project one provenance record onto an allowlist.

    ``None`` in, ``None`` out: a result that never executed has no provenance and
    must not acquire an empty object that reads like one.
    """
    if not isinstance(provenance, dict):
        return None
    return {field: provenance[field] for field in fields if field in provenance}
