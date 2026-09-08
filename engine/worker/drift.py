"""Configuration drift: comparability, the comparison algorithm and its persistence.

The drift algorithm exists exactly once, here. The backend never computes drift;
it reads the five Phase 8 tables, owns baseline governance and notification-thread
transitions, and re-triggers a computation by enqueueing a worker task. There is
no scheduler: drift is computed when a scan finalises and on an explicit request.

WHAT THIS MODULE MAY NOT DO. Nothing here creates, promotes, infers or alters a
SOC 2 rating, and no statement in this module writes ``scan``, ``scan_result`` or
any mapping table. Drift is a report about two observations that were already
recorded; it decides nothing new about a control.

TWO STREAMS THAT NEVER CROSS. A configuration event is derived only from
``scan_result_factprint``; an evaluation event only from ``scan_result.status``
and ``reason_code``. A fact moving cannot manufacture a verdict change and a
verdict moving cannot manufacture a configuration change. The one place they meet
is ``detail.facts_identical`` on an evaluation event: the same facts producing a
different verdict is an engine or a policy problem, not tenant drift, and saying
so is the single most diagnostic signal this module emits.

COMPARABILITY IS A LOOKUP KEY, NOT A CHECK. ``comparability_key`` digests the
whole comparability tuple and a baseline is looked up BY that key, so comparing
two incomparable scans is structurally impossible rather than merely rejected.
The configuration axis deliberately omits ``policy_corpus_digest`` — editing a
Rego file cannot change tenant configuration — while the evaluation axis includes
it, because editing a Rego file certainly can change a verdict.

ORDERING USES THE SURROGATE KEY, NEVER A TIMESTAMP. A current scan must have a
strictly greater ``scan.id`` than the baseline's scan. Phase 6 left naive
timestamp columns that PostgreSQL's ``now()`` misreads on a non-UTC server, so an
ordering built on them would silently invert; a monotonic surrogate key cannot.

ZERO EVENTS IS NOT A PASS. A run reports zero events when the compared
observations were identical for every comparable control. It never means the
tenant was not changed between two scans, and it never means a control passed.
An axis that could not be compared is RECORDED on the run with its reason; a
comparison failure is never silently skipped.
"""

import hashlib
import json
import logging
from dataclasses import dataclass
from datetime import datetime, timezone

from sqlalchemy import text
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from worker.config import settings
from worker.factprint import canonical_json

logger = logging.getLogger(__name__)

DRIFT_VERSION = "phase8-drift-v1"
RETENTION_POLICY_VERSION = "phase8-draft-1"
# The only result semantics this comparison understands. A legacy scan predates
# the Phase 3 contract and its statuses do not mean the same thing.
SEMANTICS_VERSION = "phase3-v1"

RUN_TRIGGERS = ("scan_finalised", "api_request")

# PostgreSQL SQLSTATE for a unique violation. A duplicate delivery is exactly
# this and nothing else; 23514 (check violation) is a defect, not a redelivery.
UNIQUE_VIOLATION = "23505"

# Why an axis was not comparable. Declared here so the engine never imports from
# backend-api; app/models/drift.py declares the identical tuple next to the table.
COMPARABILITY_REASONS = (
    "baseline_not_active",
    "scan_not_completed",
    "scan_not_owned",
    "scan_predates_baseline",
    "configuration_key_mismatch",
    "evaluation_key_mismatch",
    "semantics_version_mismatch",
    "fingerprints_unavailable",
    "baseline_facts_absent",
    "current_facts_absent",
    "drift_version_mismatch",
    "fingerprint_key_rotated",
)

# Phase 3 result semantics, split by what they say about assessment.
ASSESSED = frozenset({"passed", "failed"})
VISIBLE_UNASSESSED = frozenset({"indeterminate", "error", "not_assessable"})
OUT_OF_SCOPE = frozenset({"skipped", "pending"})

# Severities the benchmark itself may pin. Anything else is not transcribed.
PINNED_SEVERITIES = ("critical", "high", "medium", "low")
INFORMATIONAL = "informational"

# Per-control reasons the configuration axis could not compare a control.
SKIP_PROJECTION_CHANGED = "projection_changed"
SKIP_FACTS_ABSENT_BOTH = "facts_absent_both"
SKIP_CONTROL_ABSENT_BASELINE = "control_absent_baseline"
SKIP_CONTROL_ABSENT_CURRENT = "control_absent_current"

# The closed notification vocabulary. A notification carries a summary code and
# summary counts and nothing else; there is no column on drift_notification that
# could hold a control id, a fact name, a member ref, a digest or a value.
SUMMARY_CONFIGURATION_CRITICAL = "configuration_changed_critical"
SUMMARY_CONFIGURATION_HIGH = "configuration_changed_high"
SUMMARY_COVERAGE_LOST = "coverage_lost"
SUMMARY_EVALUATION_STATUS_CHANGED = "evaluation_status_changed"
SUMMARY_RUN_NOT_COMPARABLE = "run_not_comparable"
SUMMARY_RUN_FINGERPRINTS_UNAVAILABLE = "run_fingerprints_unavailable"

# The five identity fields a scan freezes into connection_snapshot that decide
# whether two scans looked at the same tenant identity. The two Phase 8
# compliance certificate fields are deliberately NOT here: no compliance control
# is dispatched (3.2.1 / 3.2.2 / 3.3.1 stay blocked), so they cannot change an
# observation, and this construction must stay byte-identical to the backend's.
CONNECTION_IDENTITY_FIELDS = (
    "tenant_id",
    "client_id",
    "sharepoint_admin_url",
    "sharepoint_tenant_id",
    "sharepoint_certificate_alias",
)


def _utc_now() -> datetime:
    """An aware UTC instant. Every Phase 8 column it feeds is timestamptz."""
    return datetime.now(timezone.utc)


def _sha256(value: object) -> str:
    """Unkeyed sha256 over canonical JSON.

    Every preimage built with this covers public artefacts and surrogate keys
    only — benchmark identifiers, digests that are already keyed, and row ids.
    A tenant value is never digested here: those are HMAC'd in worker.factprint,
    because an unkeyed digest of a low-entropy value is a lookup table.
    """
    return hashlib.sha256(canonical_json(value).encode()).hexdigest()


def connection_identity_digest(connection_snapshot: dict | None) -> str:
    """Digest the frozen connection identity a scan was executed under."""
    snapshot = connection_snapshot if isinstance(connection_snapshot, dict) else {}
    return _sha256({key: snapshot.get(key) for key in CONNECTION_IDENTITY_FIELDS})


def comparability_key(axis: str, scan: dict) -> str:
    """The baseline lookup key for one comparability axis.

    ``policy_corpus_digest`` is ABSENT from the configuration preimage (absent,
    not null): a Rego edit cannot change tenant configuration. It is present on
    the evaluation preimage, because a Rego edit can certainly change a verdict.
    """
    if axis not in ("configuration", "evaluation"):
        raise ValueError("Unsupported comparability axis")
    base = {
        "v": DRIFT_VERSION,
        "axis": axis,
        "user_id": scan["user_id"],
        "m365_connection_id": scan["m365_connection_id"],
        "framework": scan["framework"],
        "benchmark": scan["benchmark"],
        "version": scan["version"],
        "metadata_digest": scan["metadata_digest"],
        "semantics_version": scan["semantics_version"],
        "connection_identity_digest": connection_identity_digest(
            scan["connection_snapshot"]
        ),
    }
    if axis == "evaluation":
        base["policy_corpus_digest"] = scan["policy_corpus_digest"]
    return _sha256(base)


def observation_digest(rows: list[dict]) -> str:
    """Digest a whole observation.

    ``rows`` are the per-control entries ``observation_rows`` produces: a
    ``control_id``, the result ``status`` and ``reason_code``, and the control's
    ``{field_name: value_digest}`` map. Entries are ordered by their own
    canonical JSON so the digest cannot depend on row arrival order.
    """
    entries = [
        [
            row.get("control_id"),
            row.get("status"),
            row.get("reason_code"),
            dict(row.get("value_digests") or {}),
        ]
        for row in rows
    ]
    entries.sort(key=canonical_json)
    return _sha256(entries)


def event_key(
    baseline_id: int,
    control_id: str,
    event_class: str,
    change_type: str,
    fact_name: str | None,
    member_ref: str | None,
) -> str:
    """The stable identity of one finding against one baseline.

    ``current_scan_id`` and ``drift_run_id`` are deliberately NOT in the
    preimage. The same finding therefore keeps the same key in every run against
    that baseline, so an accepted_risk decision suppresses it instead of it
    reappearing as new noise on the next scan.
    """
    return _sha256(
        {
            "v": DRIFT_VERSION,
            "baseline_id": baseline_id,
            "control_id": control_id,
            "event_class": event_class,
            "change_type": change_type,
            "fact_name": fact_name,
            "member_ref": member_ref,
        }
    )


# ----------------------------------------------------------------------------
# Observation loading. Read-only, and it reads exactly three tables.
# ----------------------------------------------------------------------------

SELECT_SCAN = text("""
    SELECT id, user_id, m365_connection_id, framework, benchmark, version,
           status, semantics_version, metadata_digest, metadata_snapshot,
           policy_corpus_digest, connection_snapshot, correlation_id
    FROM scan WHERE id = :id
""")

SELECT_RESULTS = text("""
    SELECT control_id, status, reason_code, selected
    FROM scan_result WHERE scan_id = :id
""")

# key_id rides along so the run can record which fingerprint key the compared
# facts were produced under: a key rotation is then visible in the evidence
# rather than silently changing every value digest.
SELECT_FACTS = text("""
    SELECT control_id, collector_id, projection_id, field_name, field_kind,
           value_digest, member_digests, member_tokens, observed_value, key_id
    FROM scan_result_factprint WHERE scan_id = :id
""")

SELECT_ACTIVE_BASELINE = text("""
    SELECT id, user_id, scan_id, m365_connection_id, framework, benchmark,
           version, metadata_digest, policy_corpus_digest, semantics_version,
           connection_identity_digest, configuration_key, evaluation_key,
           observation_digest, control_count, factprint_field_count, status,
           drift_version, retention_policy_version, key_id
    FROM drift_baseline
    WHERE configuration_key = :configuration_key AND status = 'active'
    FOR UPDATE
""")

SELECT_BASELINE_BY_ID = text("""
    SELECT id, user_id, scan_id, m365_connection_id, framework, benchmark,
           version, metadata_digest, policy_corpus_digest, semantics_version,
           connection_identity_digest, configuration_key, evaluation_key,
           observation_digest, control_count, factprint_field_count, status,
           drift_version, retention_policy_version, key_id
    FROM drift_baseline WHERE id = :id
    FOR UPDATE
""")


def load_observation(session: Session, scan_id: int) -> dict | None:
    """Load one scan's comparable observation, or None when the scan is gone."""
    scan = session.execute(SELECT_SCAN, {"id": scan_id}).mappings().first()
    if scan is None:
        return None
    results = session.execute(SELECT_RESULTS, {"id": scan_id}).mappings().all()
    facts = session.execute(SELECT_FACTS, {"id": scan_id}).mappings().all()
    return {
        "scan": dict(scan),
        "results": [dict(row) for row in results],
        "facts": [dict(row) for row in facts],
    }


# ----------------------------------------------------------------------------
# The pure comparison.
# ----------------------------------------------------------------------------


@dataclass(frozen=True)
class DriftComputation:
    """Everything one comparison decided, before anything is written."""

    status: str
    configuration_comparable: bool
    evaluation_comparable: bool
    axis_reasons: dict[str, list[str]]
    events: tuple[dict, ...]
    event_counts: dict[str, dict[str, int]]
    event_set_digest: str
    controls_compared: int
    controls_skipped: dict[str, list[str]]
    baseline_observation_digest: str
    current_observation_digest: str
    key_id: str | None = None
    baseline_configuration_key: str = ""
    current_configuration_key: str = ""
    baseline_evaluation_key: str = ""
    current_evaluation_key: str = ""
    baseline_id: int | None = None
    baseline_scan_id: int | None = None
    current_scan_id: int | None = None
    user_id: int | None = None
    correlation_id: str | None = None
    framework: str = ""
    benchmark: str = ""
    version: str = ""
    suppressed_event_count: int = 0


def _facts_by_control(facts: list[dict]) -> dict[str, dict[str, dict]]:
    grouped: dict[str, dict[str, dict]] = {}
    for row in facts:
        grouped.setdefault(row["control_id"], {})[row["field_name"]] = row
    return grouped


def _control_facts_digest(fields: dict[str, dict] | None) -> str | None:
    """Digest one control's declared facts, or None when it has none."""
    if not fields:
        return None
    return _sha256({name: row["value_digest"] for name, row in fields.items()})


def observation_rows(results: list[dict], facts: list[dict]) -> list[dict]:
    """Per-control entries for observation_digest."""
    grouped = _facts_by_control(facts)
    statuses = {row["control_id"]: row for row in results}
    rows = []
    for control_id in sorted(set(statuses) | set(grouped)):
        result = statuses.get(control_id) or {}
        rows.append(
            {
                "control_id": control_id,
                "status": result.get("status"),
                "reason_code": result.get("reason_code"),
                "value_digests": {
                    name: row["value_digest"]
                    for name, row in sorted(grouped.get(control_id, {}).items())
                },
            }
        )
    return rows


def _severity_index(metadata_snapshot: object) -> dict[str, object]:
    """The benchmark severity the CURRENT scan pinned, read verbatim.

    Comparability required metadata_digest equality through the key, so the two
    scans pinned the same benchmark metadata and this index is unambiguous.
    """
    entries = None
    if isinstance(metadata_snapshot, dict):
        entries = metadata_snapshot.get("controls")
    index: dict[str, object] = {}
    for entry in entries if isinstance(entries, list) else []:
        if isinstance(entry, dict) and isinstance(entry.get("control_id"), str):
            index[entry["control_id"]] = entry.get("severity")
    return index


def _transcribe_severity(
    index: dict[str, object], control_id: str, basis: str
) -> tuple[str, str]:
    """Transcribe the pinned severity. Nothing is judged and nothing is invented."""
    value = index.get(control_id)
    if isinstance(value, str) and value in PINNED_SEVERITIES:
        return value, basis
    return INFORMATIONAL, "severity_unavailable"


def _comparability(
    baseline_row: dict,
    baseline_facts: list[dict],
    current_scan: dict,
    current_facts: list[dict],
) -> tuple[bool, bool, dict[str, list[str]]]:
    """Decide both axes and record every reason either one failed."""
    shared: list[str] = []
    if baseline_row.get("status") != "active":
        shared.append("baseline_not_active")
    if current_scan.get("status") != "completed":
        shared.append("scan_not_completed")
    if current_scan.get("user_id") != baseline_row.get("user_id"):
        shared.append("scan_not_owned")
    baseline_scan_id = baseline_row.get("scan_id")
    current_id = current_scan.get("id")
    # The surrogate key orders the two observations. Never a timestamp: Phase 6's
    # naive columns are misread by PostgreSQL now() on a non-UTC server.
    if not (
        isinstance(current_id, int)
        and isinstance(baseline_scan_id, int)
        and current_id > baseline_scan_id
    ):
        shared.append("scan_predates_baseline")
    if current_scan.get("semantics_version") != SEMANTICS_VERSION:
        shared.append("semantics_version_mismatch")
    if baseline_row.get("drift_version") != DRIFT_VERSION:
        # Cannot fire against a baseline this version established; it exists so a
        # future drift version cannot silently reinterpret an older baseline.
        shared.append("drift_version_mismatch")

    configuration = list(shared)
    evaluation = list(shared)
    if comparability_key("configuration", current_scan) != baseline_row.get(
        "configuration_key"
    ):
        configuration.append("configuration_key_mismatch")
    if comparability_key("evaluation", current_scan) != baseline_row.get(
        "evaluation_key"
    ):
        evaluation.append("evaluation_key_mismatch")

    # Facts gate the configuration axis only. The evaluation axis is fully live
    # with no fingerprint key configured at all.
    if not baseline_facts and not current_facts:
        configuration.append("fingerprints_unavailable")
    else:
        if not baseline_facts:
            configuration.append("baseline_facts_absent")
        if not current_facts:
            configuration.append("current_facts_absent")
        # Every value_digest is an HMAC under the configured fingerprint key, so
        # rotating that key changes every digest even when the tenant is
        # byte-identical. Comparing across a rotation would manufacture a
        # configuration-changed event for every declared fact against a tenant
        # nobody touched. A rotation is an honest "cannot compare", not drift.
        baseline_key_id = baseline_row.get("key_id")
        current_key_id = _facts_key_id(current_facts)
        if baseline_key_id and current_key_id and baseline_key_id != current_key_id:
            configuration.append("fingerprint_key_rotated")

    return (
        not configuration,
        not evaluation,
        {"configuration": configuration, "evaluation": evaluation},
    )


def _event(
    baseline_id: int,
    control_id: str,
    collector_id: str | None,
    event_class: str,
    change_type: str,
    fact_name: str | None,
    member_ref: str | None,
    previous_value: object,
    current_value: object,
    previous_digest: str | None,
    current_digest: str | None,
    severity: str,
    severity_basis: str,
    detail: dict | None = None,
) -> dict:
    return {
        "control_id": control_id,
        "collector_id": collector_id,
        "event_class": event_class,
        "change_type": change_type,
        "fact_name": fact_name,
        "member_ref": member_ref,
        "previous_value": previous_value,
        "current_value": current_value,
        "previous_digest": previous_digest,
        "current_digest": current_digest,
        "severity": severity,
        "severity_basis": severity_basis,
        "event_key": event_key(
            baseline_id, control_id, event_class, change_type, fact_name, member_ref
        ),
        "detail": detail,
    }


def _member_tokens(row: dict) -> dict[str, str]:
    """Map each member digest to its token, when the two arrays correspond.

    ``member_digests`` and ``member_tokens`` are written as parallel arrays by
    the projection that produced them. When their lengths disagree the mapping
    is unknown and the event carries no token rather than a guessed one.
    """
    digests = list(row.get("member_digests") or [])
    tokens = list(row.get("member_tokens") or [])
    if len(digests) != len(tokens):
        return {}
    return dict(zip(digests, tokens))


def _enum_set_events(
    baseline_id: int,
    control_id: str,
    collector_id: str | None,
    field_name: str,
    baseline_field: dict,
    current_field: dict,
    severity: str,
    severity_basis: str,
) -> list[dict]:
    """One event per member that entered or left the set."""
    baseline_members = list(baseline_field.get("member_digests") or [])
    current_members = list(current_field.get("member_digests") or [])
    baseline_map = _member_tokens(baseline_field)
    current_map = _member_tokens(current_field)
    added = sorted(set(current_members) - set(baseline_members))
    removed = sorted(set(baseline_members) - set(current_members))
    if not added and not removed:
        # Defensive: the value digests differ while the member sets do not. That
        # is impossible for the current construction, so it is reported as an
        # unattributed change rather than dropped.
        return [
            _event(
                baseline_id,
                control_id,
                collector_id,
                "configuration",
                "changed",
                field_name,
                None,
                None,
                None,
                baseline_field["value_digest"],
                current_field["value_digest"],
                severity,
                severity_basis,
            )
        ]
    events = []
    for member in added:
        events.append(
            _event(
                baseline_id,
                control_id,
                collector_id,
                "configuration",
                "added",
                field_name,
                member,
                None,
                current_map.get(member),
                None,
                current_field["value_digest"],
                severity,
                severity_basis,
            )
        )
    for member in removed:
        events.append(
            _event(
                baseline_id,
                control_id,
                collector_id,
                "configuration",
                "removed",
                field_name,
                member,
                baseline_map.get(member),
                None,
                baseline_field["value_digest"],
                None,
                severity,
                severity_basis,
            )
        )
    return events


def _configuration_events(
    baseline_id: int,
    baseline: dict,
    current: dict,
    index: dict[str, object],
) -> tuple[list[dict], list[str], dict[str, list[str]]]:
    """Configuration events, the controls compared, and why others were not."""
    baseline_facts = _facts_by_control(baseline["facts"])
    current_facts = _facts_by_control(current["facts"])
    in_both_results = {row["control_id"] for row in baseline["results"]} & {
        row["control_id"] for row in current["results"]
    }
    events: list[dict] = []
    compared: list[str] = []
    skipped: dict[str, list[str]] = {}

    for control_id in sorted(
        set(baseline_facts) | set(current_facts) | in_both_results
    ):
        baseline_fields = baseline_facts.get(control_id)
        current_fields = current_facts.get(control_id)
        if not baseline_fields and not current_fields:
            skipped.setdefault(SKIP_FACTS_ABSENT_BOTH, []).append(control_id)
            continue
        if not baseline_fields:
            skipped.setdefault(SKIP_CONTROL_ABSENT_BASELINE, []).append(control_id)
            continue
        if not current_fields:
            skipped.setdefault(SKIP_CONTROL_ABSENT_CURRENT, []).append(control_id)
            continue
        shared = set(baseline_fields) & set(current_fields)
        if any(
            baseline_fields[name]["projection_id"]
            != current_fields[name]["projection_id"]
            for name in shared
        ):
            # A collector normalisation change is a code change, not tenant
            # drift. The configuration axis emits nothing for this control; the
            # evaluation comparison still proceeds.
            skipped.setdefault(SKIP_PROJECTION_CHANGED, []).append(control_id)
            continue
        compared.append(control_id)

        for field_name in sorted(set(baseline_fields) | set(current_fields)):
            baseline_field = baseline_fields.get(field_name)
            current_field = current_fields.get(field_name)
            collector_id = (current_field or baseline_field).get("collector_id")
            severity, basis = _transcribe_severity(
                index, control_id, "benchmark_severity"
            )
            if baseline_field is None:
                events.append(
                    _event(
                        baseline_id,
                        control_id,
                        collector_id,
                        "configuration",
                        "added",
                        field_name,
                        None,
                        None,
                        current_field["observed_value"],
                        None,
                        current_field["value_digest"],
                        severity,
                        basis,
                    )
                )
                continue
            if current_field is None:
                events.append(
                    _event(
                        baseline_id,
                        control_id,
                        collector_id,
                        "configuration",
                        "removed",
                        field_name,
                        None,
                        baseline_field["observed_value"],
                        None,
                        baseline_field["value_digest"],
                        None,
                        severity,
                        basis,
                    )
                )
                continue
            if baseline_field["value_digest"] == current_field["value_digest"]:
                continue
            if current_field["field_kind"] == "enum_set":
                events.extend(
                    _enum_set_events(
                        baseline_id,
                        control_id,
                        collector_id,
                        field_name,
                        baseline_field,
                        current_field,
                        severity,
                        basis,
                    )
                )
                continue
            previous_observed = baseline_field["observed_value"]
            current_observed = current_field["observed_value"]
            if (previous_observed is None) != (current_observed is None):
                # Unknown to known, or known to unknown. That is an observability
                # change, not a configuration change, and the value pair makes
                # the event self-describing.
                severity, basis = INFORMATIONAL, "observability_change"
            events.append(
                _event(
                    baseline_id,
                    control_id,
                    collector_id,
                    "configuration",
                    "changed",
                    field_name,
                    None,
                    previous_observed,
                    current_observed,
                    baseline_field["value_digest"],
                    current_field["value_digest"],
                    severity,
                    basis,
                )
            )
    return events, compared, skipped


def _is_assessed(status: object) -> bool:
    """Only an explicit Phase 3 assessment counts as one.

    An absent row, an out-of-scope status, a visible-but-unassessed status and
    any status this contract does not recognise are all NOT assessments. That
    keeps 'coverage_gained' out of reach of an unknown token: nothing can become
    an assessment by being unrecognised.
    """
    if status in ASSESSED:
        return True
    if status is None or status in VISIBLE_UNASSESSED or status in OUT_OF_SCOPE:
        return False
    logger.warning("drift_unrecognised_result_status status=%s", status)
    return False


def _evaluation_events(
    baseline_id: int,
    baseline: dict,
    current: dict,
    index: dict[str, object],
) -> tuple[list[dict], list[str]]:
    """Evaluation events, derived only from result status and reason code."""
    baseline_results = {row["control_id"]: row for row in baseline["results"]}
    current_results = {row["control_id"]: row for row in current["results"]}
    baseline_facts = _facts_by_control(baseline["facts"])
    current_facts = _facts_by_control(current["facts"])
    events: list[dict] = []
    compared = sorted(set(baseline_results) | set(current_results))

    for control_id in compared:
        baseline_row = baseline_results.get(control_id) or {}
        current_row = current_results.get(control_id) or {}
        # An absent row is out of scope, exactly like 'skipped' or 'pending'.
        previous_status = baseline_row.get("status")
        current_status = current_row.get("status")
        previous_assessed = _is_assessed(previous_status)
        current_assessed = _is_assessed(current_status)

        if previous_assessed and current_assessed:
            if previous_status == current_status:
                continue
            change_type = "status_changed"
            if previous_status == "passed" and current_status == "failed":
                severity, basis = _transcribe_severity(
                    index, control_id, "evaluation_transition"
                )
            else:
                severity, basis = INFORMATIONAL, "evaluation_transition"
        elif previous_assessed:
            change_type = "coverage_lost"
            severity, basis = _transcribe_severity(index, control_id, "coverage_loss")
        elif current_assessed:
            change_type = "coverage_gained"
            # NOT 'coverage_loss': severity_basis is a durable, closed-vocabulary
            # column published verbatim to clients, and a query asking "which
            # controls did we lose visibility of?" filters on exactly that value.
            # Stamping a gain with the loss basis answers that question wrongly.
            severity, basis = INFORMATIONAL, "observability_change"
        else:
            if previous_status == current_status:
                continue
            # Both sides unassessed and differing: nothing was decided either
            # way, so nothing more severe than informational can be claimed.
            change_type = "status_changed"
            severity, basis = INFORMATIONAL, "evaluation_transition"

        previous_digest = _control_facts_digest(baseline_facts.get(control_id))
        current_digest = _control_facts_digest(current_facts.get(control_id))
        events.append(
            _event(
                baseline_id,
                control_id,
                None,
                "evaluation",
                change_type,
                None,
                None,
                previous_status,
                current_status,
                previous_digest,
                current_digest,
                severity,
                basis,
                {
                    "previous_reason_code": baseline_row.get("reason_code"),
                    "current_reason_code": current_row.get("reason_code"),
                    # Same facts, different verdict is an engine or policy
                    # problem, not tenant drift. It must be visible.
                    "facts_identical": bool(
                        previous_digest is not None
                        and current_digest is not None
                        and previous_digest == current_digest
                    ),
                },
            )
        )
    return events, compared


def _event_sort_key(event: dict) -> tuple:
    return (
        event["event_class"],
        event["control_id"],
        event["fact_name"] or "",
        event["member_ref"] or "",
        event["change_type"],
    )


def _event_counts(events: list[dict]) -> dict[str, dict[str, int]]:
    counts: dict[str, dict[str, int]] = {"configuration": {}, "evaluation": {}}
    for event in events:
        bucket = counts[event["event_class"]]
        bucket[event["severity"]] = bucket.get(event["severity"], 0) + 1
    return counts


def _facts_key_id(facts: list[dict]) -> str | None:
    """The single fingerprint key the compared facts were produced under."""
    identifiers = {row.get("key_id") for row in facts if row.get("key_id")}
    return identifiers.pop() if len(identifiers) == 1 else None


def compare(baseline: dict, current: dict) -> DriftComputation:
    """Compare two observations. Pure: no session, no clock, no writes.

    ``baseline`` is ``{"baseline": <drift_baseline row>, "scan": ..., "results":
    [...], "facts": [...]}`` and ``current`` is the same without the baseline
    row. Both sides are plain dicts, so this is callable with no database.
    """
    baseline_row = baseline["baseline"]
    baseline_side = {
        "results": list(baseline.get("results") or []),
        "facts": list(baseline.get("facts") or []),
    }
    current_side = {
        "results": list(current.get("results") or []),
        "facts": list(current.get("facts") or []),
    }
    current_scan = current["scan"]
    baseline_id = baseline_row["id"]

    configuration_comparable, evaluation_comparable, axis_reasons = _comparability(
        baseline_row,
        baseline_side["facts"],
        current_scan,
        current_side["facts"],
    )
    index = _severity_index(current_scan.get("metadata_snapshot"))

    events: list[dict] = []
    compared: set[str] = set()
    skipped: dict[str, list[str]] = {}
    if configuration_comparable:
        configuration, configuration_compared, skipped = _configuration_events(
            baseline_id, baseline_side, current_side, index
        )
        events.extend(configuration)
        compared.update(configuration_compared)
    if evaluation_comparable:
        evaluation, evaluation_compared = _evaluation_events(
            baseline_id, baseline_side, current_side, index
        )
        events.extend(evaluation)
        compared.update(evaluation_compared)

    events.sort(key=_event_sort_key)
    limit = settings.DRIFT_MAX_EVENTS_PER_RUN
    suppressed = 0
    if len(events) > limit:
        # A truncated event set must never be readable as a complete one, so the
        # run is written with zero events and says exactly why.
        suppressed = len(events)
        events = []
        status = "event_limit_exceeded"
    elif not configuration_comparable and not evaluation_comparable:
        reasons = set(axis_reasons["configuration"]) | set(axis_reasons["evaluation"])
        status = (
            "fingerprints_unavailable"
            if "fingerprints_unavailable" in reasons
            else "not_comparable"
        )
    else:
        status = "completed"

    return DriftComputation(
        status=status,
        configuration_comparable=configuration_comparable,
        evaluation_comparable=evaluation_comparable,
        axis_reasons=axis_reasons,
        events=tuple(events),
        event_counts=_event_counts(events),
        event_set_digest=_sha256(sorted(event["event_key"] for event in events)),
        controls_compared=len(compared),
        controls_skipped={
            reason: sorted(controls) for reason, controls in sorted(skipped.items())
        },
        baseline_observation_digest=observation_digest(
            observation_rows(baseline_side["results"], baseline_side["facts"])
        ),
        current_observation_digest=observation_digest(
            observation_rows(current_side["results"], current_side["facts"])
        ),
        key_id=_facts_key_id(current_side["facts"]),
        baseline_configuration_key=baseline_row.get("configuration_key") or "",
        current_configuration_key=comparability_key("configuration", current_scan),
        baseline_evaluation_key=baseline_row.get("evaluation_key") or "",
        current_evaluation_key=comparability_key("evaluation", current_scan),
        baseline_id=baseline_id,
        baseline_scan_id=baseline_row.get("scan_id"),
        current_scan_id=current_scan.get("id"),
        user_id=current_scan.get("user_id"),
        correlation_id=current_scan.get("correlation_id"),
        framework=current_scan.get("framework") or "",
        benchmark=current_scan.get("benchmark") or "",
        version=current_scan.get("version") or "",
        suppressed_event_count=suppressed,
    )


# ----------------------------------------------------------------------------
# Routing. Closed, deterministic, in-database only: no SMTP, no webhook, no
# egress of any kind. The recipient is always the scan owner, because
# comparability already proved the baseline and the scan share one user.
# ----------------------------------------------------------------------------


def _routing(event: dict) -> tuple[str, str] | None:
    """The routing rule and summary code for one event, or None for no thread."""
    if event["severity_basis"] == "coverage_loss" and (
        event["change_type"] == "coverage_lost"
    ):
        # At any severity: losing the ability to see a control is itself the
        # finding. coverage_gained is not routed — there is no summary code for
        # it, and announcing a gain as 'coverage_lost' would be a false statement.
        return "owner_coverage_loss", SUMMARY_COVERAGE_LOST
    if event["severity"] in ("critical", "high"):
        if event["event_class"] == "configuration":
            return "owner_high_or_above", (
                SUMMARY_CONFIGURATION_CRITICAL
                if event["severity"] == "critical"
                else SUMMARY_CONFIGURATION_HIGH
            )
        return "owner_high_or_above", SUMMARY_EVALUATION_STATUS_CHANGED
    return None


RUN_SCOPE_ROUTING = {
    "not_comparable": ("owner_not_comparable", SUMMARY_RUN_NOT_COMPARABLE),
    "fingerprints_unavailable": (
        "owner_fingerprints_unavailable",
        SUMMARY_RUN_FINGERPRINTS_UNAVAILABLE,
    ),
}


def run_thread_key(
    baseline_id: int, current_scan_id: int | None, summary_code: str
) -> str:
    """The thread identity of a run-scope notification."""
    return _sha256(
        {
            "v": DRIFT_VERSION,
            "scope": "run",
            "baseline_id": baseline_id,
            "current_scan_id": current_scan_id,
            "summary_code": summary_code,
        }
    )


# ----------------------------------------------------------------------------
# Persistence. One transaction, three append-only tables, and nothing else.
# ----------------------------------------------------------------------------

INSERT_RUN = text("""
    INSERT INTO drift_run (
        baseline_id, baseline_scan_id, current_scan_id, user_id,
        framework, benchmark, version, status, "trigger",
        configuration_comparable, evaluation_comparable, axis_reasons,
        baseline_configuration_key, current_configuration_key,
        baseline_evaluation_key, current_evaluation_key,
        baseline_observation_digest, current_observation_digest,
        controls_compared, controls_skipped, event_count, event_counts,
        event_set_digest, key_id, drift_version, retention_policy_version,
        correlation_id, started_at, completed_at
    ) VALUES (
        :baseline_id, :baseline_scan_id, :current_scan_id, :user_id,
        :framework, :benchmark, :version, :status, :trigger,
        :configuration_comparable, :evaluation_comparable,
        CAST(:axis_reasons AS jsonb),
        :baseline_configuration_key, :current_configuration_key,
        :baseline_evaluation_key, :current_evaluation_key,
        :baseline_observation_digest, :current_observation_digest,
        :controls_compared, CAST(:controls_skipped AS jsonb), :event_count,
        CAST(:event_counts AS jsonb), :event_set_digest, :key_id,
        :drift_version, :retention_policy_version, :correlation_id,
        :run_opened, :run_closed
    )
    RETURNING id
""")

INSERT_EVENT = text("""
    INSERT INTO drift_event (
        drift_run_id, baseline_id, baseline_scan_id, current_scan_id, user_id,
        control_id, collector_id, event_class, change_type, fact_name,
        member_ref, previous_value, current_value, previous_digest,
        current_digest, severity, severity_basis, event_key, detail,
        correlation_id, drift_version, retention_policy_version, occurred_at
    ) VALUES (
        :drift_run_id, :baseline_id, :baseline_scan_id, :current_scan_id,
        :user_id, :control_id, :collector_id, :event_class, :change_type,
        :fact_name, :member_ref, CAST(:previous_value AS jsonb),
        CAST(:current_value AS jsonb), :previous_digest, :current_digest,
        :severity, :severity_basis, :event_key, CAST(:detail AS jsonb),
        :correlation_id, :drift_version, :retention_policy_version, :occurred_at
    )
    RETURNING id
""")

# A revision is written only when the thread does not exist yet. revision_number
# 1 is always the 'raised' revision, so a conflict on (thread_key, 1) is exactly
# "this thread already exists in some state" — which is how an accepted_risk
# decision keeps suppressing the same finding on every later run.
INSERT_NOTIFICATION = text("""
    INSERT INTO drift_notification (
        baseline_id, drift_run_id, drift_event_id, user_id, thread_key, scope,
        channel, routing_rule, revision_number, action, state_after, severity,
        summary_code, summary_counts, drift_version, retention_policy_version,
        occurred_at
    ) VALUES (
        :baseline_id, :drift_run_id, :drift_event_id, :user_id, :thread_key,
        :scope, 'inapp', :routing_rule, 1, 'raised', 'open', :severity,
        :summary_code, CAST(:summary_counts AS jsonb), :drift_version,
        :retention_policy_version, :occurred_at
    )
    ON CONFLICT (thread_key, revision_number) DO NOTHING
""")


def _json(value: object) -> str | None:
    return None if value is None else json.dumps(value)


def _write_events(
    session: Session, computation: DriftComputation, run_id: int, occurred: datetime
) -> list[tuple[int, dict]]:
    written = []
    for event in computation.events:
        identifier = session.execute(
            INSERT_EVENT,
            {
                "drift_run_id": run_id,
                "baseline_id": computation.baseline_id,
                "baseline_scan_id": computation.baseline_scan_id,
                "current_scan_id": computation.current_scan_id,
                "user_id": computation.user_id,
                "control_id": event["control_id"],
                "collector_id": event["collector_id"],
                "event_class": event["event_class"],
                "change_type": event["change_type"],
                "fact_name": event["fact_name"],
                "member_ref": event["member_ref"],
                "previous_value": _json(event["previous_value"]),
                "current_value": _json(event["current_value"]),
                "previous_digest": event["previous_digest"],
                "current_digest": event["current_digest"],
                "severity": event["severity"],
                "severity_basis": event["severity_basis"],
                "event_key": event["event_key"],
                "detail": _json(event["detail"]),
                "correlation_id": computation.correlation_id,
                "drift_version": DRIFT_VERSION,
                "retention_policy_version": RETENTION_POLICY_VERSION,
                "occurred_at": occurred,
            },
        ).scalar_one()
        written.append((identifier, event))
    return written


def _write_notifications(
    session: Session,
    computation: DriftComputation,
    run_id: int,
    events: list[tuple[int, dict]],
    occurred: datetime,
) -> int:
    """Raise one thread per routed finding. Payload is counts and codes only."""
    summary_counts = _json(computation.event_counts)
    raised = 0
    for identifier, event in events:
        routed = _routing(event)
        if routed is None:
            continue
        routing_rule, summary_code = routed
        result = session.execute(
            INSERT_NOTIFICATION,
            {
                "baseline_id": computation.baseline_id,
                "drift_run_id": run_id,
                "drift_event_id": identifier,
                "user_id": computation.user_id,
                # The event key IS the thread key, so the same finding against
                # the same baseline reopens nothing on a later run.
                "thread_key": event["event_key"],
                "scope": "event",
                "routing_rule": routing_rule,
                "severity": event["severity"],
                "summary_code": summary_code,
                "summary_counts": summary_counts,
                "drift_version": DRIFT_VERSION,
                "retention_policy_version": RETENTION_POLICY_VERSION,
                "occurred_at": occurred,
            },
        )
        raised += result.rowcount
    run_scope = RUN_SCOPE_ROUTING.get(computation.status)
    if run_scope is not None:
        routing_rule, summary_code = run_scope
        result = session.execute(
            INSERT_NOTIFICATION,
            {
                "baseline_id": computation.baseline_id,
                "drift_run_id": run_id,
                "drift_event_id": None,
                "user_id": computation.user_id,
                "thread_key": run_thread_key(
                    computation.baseline_id, computation.current_scan_id, summary_code
                ),
                "scope": "run",
                "routing_rule": routing_rule,
                # A run that could not compare decided nothing, so it cannot
                # carry a benchmark severity.
                "severity": INFORMATIONAL,
                "summary_code": summary_code,
                "summary_counts": summary_counts,
                "drift_version": DRIFT_VERSION,
                "retention_policy_version": RETENTION_POLICY_VERSION,
                "occurred_at": occurred,
            },
        )
        raised += result.rowcount
    return raised


def evaluate_scan_drift(
    session: Session,
    scan_id: int,
    *,
    trigger: str = "scan_finalised",
    baseline_id: int | None = None,
) -> dict:
    """Compare one completed scan against its baseline and record the result.

    Everything is computed in memory first; the writes are then one transaction
    against drift_run, drift_event and drift_notification. The caller owns the
    transaction boundary. The run insert runs inside a savepoint so a duplicate
    delivery unwinds only that statement and leaves the caller's session usable;
    anything else that fails propagates and takes the whole transaction with it.
    """
    if trigger not in RUN_TRIGGERS:
        raise ValueError("Unsupported drift trigger")
    opened = _utc_now()

    current = load_observation(session, scan_id)
    if current is None:
        return {"status": "scan_not_found", "scan_id": scan_id}
    current_scan = current["scan"]
    if current_scan["status"] != "completed":
        # A scan that has not finished is not an observation. The finalisation
        # hook may be delivered more than once; a stray call records nothing.
        return {"status": "scan_not_completed", "scan_id": scan_id}

    if baseline_id is None:
        row = (
            session.execute(
                SELECT_ACTIVE_BASELINE,
                {"configuration_key": comparability_key("configuration", current_scan)},
            )
            .mappings()
            .first()
        )
    else:
        row = (
            session.execute(SELECT_BASELINE_BY_ID, {"id": baseline_id})
            .mappings()
            .first()
        )
    if row is None:
        # A scan with no baseline is not a drift failure; nothing is written.
        return {"status": "no_baseline", "scan_id": scan_id}
    baseline_row = dict(row)

    baseline = load_observation(session, baseline_row["scan_id"])
    if baseline is None:
        return {
            "status": "baseline_scan_unavailable",
            "scan_id": scan_id,
            "baseline_id": baseline_row["id"],
        }

    computation = compare({"baseline": baseline_row, **baseline}, current)
    closed = _utc_now()

    try:
        with session.begin_nested():
            run_id = session.execute(
                INSERT_RUN,
                {
                    "baseline_id": computation.baseline_id,
                    "baseline_scan_id": computation.baseline_scan_id,
                    "current_scan_id": computation.current_scan_id,
                    "user_id": computation.user_id,
                    "framework": computation.framework,
                    "benchmark": computation.benchmark,
                    "version": computation.version,
                    "status": computation.status,
                    "trigger": trigger,
                    "configuration_comparable": computation.configuration_comparable,
                    "evaluation_comparable": computation.evaluation_comparable,
                    "axis_reasons": _json(computation.axis_reasons),
                    "baseline_configuration_key": computation.baseline_configuration_key,
                    "current_configuration_key": computation.current_configuration_key,
                    "baseline_evaluation_key": computation.baseline_evaluation_key,
                    "current_evaluation_key": computation.current_evaluation_key,
                    "baseline_observation_digest": (
                        computation.baseline_observation_digest
                    ),
                    "current_observation_digest": (
                        computation.current_observation_digest
                    ),
                    "controls_compared": computation.controls_compared,
                    "controls_skipped": _json(computation.controls_skipped),
                    "event_count": len(computation.events),
                    "event_counts": _json(computation.event_counts),
                    "event_set_digest": computation.event_set_digest,
                    "key_id": computation.key_id,
                    "drift_version": DRIFT_VERSION,
                    "retention_policy_version": RETENTION_POLICY_VERSION,
                    "correlation_id": computation.correlation_id,
                    "run_opened": opened,
                    "run_closed": closed,
                },
            ).scalar_one()
    except IntegrityError as error:
        # ONLY uq_drift_run_baseline_scan: this comparison is already recorded,
        # and recomputation is byte-identical, so a redelivery is a no-op. A
        # CHECK violation is also an IntegrityError and must NEVER be reported
        # as an ignored duplicate — that would hide a real defect behind a
        # success-shaped answer.
        if getattr(error.orig, "pgcode", None) != UNIQUE_VIOLATION:
            raise
        logger.info(
            "drift_run_duplicate baseline_id=%s scan_id=%s",
            baseline_row["id"],
            scan_id,
        )
        return {
            "status": "ignored",
            "scan_id": scan_id,
            "baseline_id": baseline_row["id"],
        }

    written = _write_events(session, computation, run_id, closed)
    raised = _write_notifications(session, computation, run_id, written, closed)

    return {
        "status": computation.status,
        "scan_id": scan_id,
        "baseline_id": computation.baseline_id,
        "drift_run_id": run_id,
        "event_count": len(computation.events),
        "notifications_raised": raised,
        "configuration_comparable": computation.configuration_comparable,
        "evaluation_comparable": computation.evaluation_comparable,
        "axis_reasons": computation.axis_reasons,
    }
