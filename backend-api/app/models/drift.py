"""Configuration drift: baselines, runs, events and notifications.

Drift is a comparison of two completed scans against a pinned baseline. It is
reporting only. Nothing in this module creates, promotes, infers or alters a SOC 2
rating, a scan result or a score, and no drift row is ever counted as automated
coverage.

Four things are enforced by the schema rather than by convention, and the
constraints below are where each one lives:

* a configuration event always names the fact that moved and an evaluation event
  never does (``ck_drift_event_fact_binding``);
* an event's value columns can only hold a short JSON scalar, so a raw tenant
  record cannot be stored even by a future bug
  (``ck_drift_event_previous_scalar`` / ``ck_drift_event_current_scalar`` and the
  two length CHECKs beside them);
* a notification carries summary counts and no evidence column at all, which is
  what ``FORBIDDEN_NOTIFICATION_COLUMNS`` documents and the model asserts;
* a baseline that has been superseded or revoked can never be made active again,
  and everything identifying the observation it was established from is frozen —
  enforced by the ``protect_phase8_drift_baseline`` trigger the migration adds.

``drift_run``, ``drift_event`` and ``drift_notification`` are append-only at the
database level. Remediation state is *derived* as the highest-revision row per
``thread_key``, which is why no mutable state column exists here.

Every table mirrors migration a3f5c1d90b47 exactly, constraint and index names
included, so an autogenerate diff against it is empty.
"""

from datetime import datetime
from typing import Optional

from sqlalchemy import (
    BigInteger,
    Boolean,
    CheckConstraint,
    DateTime,
    ForeignKey,
    Index,
    Integer,
    String,
    Text,
    text,
)
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import Mapped, mapped_column

from app.db.base import Base

# Re-exported so the projection vocabulary is declared exactly once, next to the
# table whose CHECK constraint enforces it.
from app.models.scan_result_factprint import FIELD_KINDS  # noqa: F401

# Lifecycle of a baseline. A baseline never returns to "active" once it leaves it.
BASELINE_STATUSES = ("active", "superseded", "revoked")

# How a run ended. Only "completed" may carry events; every other status reports
# zero events, and zero events never means the tenant did not change.
RUN_STATUSES = (
    "completed",
    "not_comparable",
    "fingerprints_unavailable",
    "event_limit_exceeded",
)

# What caused a run. There is no scheduler: drift is computed when a scan is
# finalised, and is additionally recomputable through an explicit API call.
RUN_TRIGGERS = ("scan_finalised", "api_request")

# The two event streams, which never cross. A configuration event is derived only
# from factprints; an evaluation event only from scan_result statuses.
EVENT_CLASSES = ("configuration", "evaluation")

CONFIGURATION_CHANGE_TYPES = ("added", "removed", "changed")

# coverage_lost / coverage_gained are first class on purpose: losing the ability
# to see a control must surface as itself rather than vanish into a status flip.
EVALUATION_CHANGE_TYPES = ("status_changed", "coverage_lost", "coverage_gained")

SEVERITIES = ("critical", "high", "medium", "low", "informational")

# Why an event carries the severity it carries. Severity is transcribed from the
# scan's pinned benchmark metadata and is never judged here; when the pinned
# value is missing or unrecognised the basis says so rather than inventing one.
SEVERITY_BASES = (
    "benchmark_severity",
    "evaluation_transition",
    "coverage_loss",
    "observability_change",
    "severity_unavailable",
)

NOTIFICATION_ACTIONS = (
    "raised",
    "acknowledged",
    "remediation_planned",
    "remediation_verified",
    "accepted_risk",
    "superseded",
)

NOTIFICATION_STATES = (
    "open",
    "acknowledged",
    "remediation_planned",
    "remediation_verified",
    "accepted_risk",
    "superseded",
)

# Routing is closed and deterministic, and the recipient is always the scan
# owner. There is no admin queue and no cross-tenant fan-out.
ROUTING_RULES = (
    "owner_high_or_above",
    "owner_coverage_loss",
    "owner_not_comparable",
    "owner_fingerprints_unavailable",
    "owner_action",
)

# Why an axis was not comparable. A failure is always recorded on the run rather
# than silently skipped, so "no events" is never mistaken for "no change".
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

# Columns that MUST NOT exist on drift_notification. The guarantee that a
# notification cannot leak evidence is made by schema construction, not by
# review: there is nowhere on that table to put a control id, a fact name, a
# member ref, a digest or an observed value in the first place.
FORBIDDEN_NOTIFICATION_COLUMNS = (
    "control_id",
    "fact_name",
    "previous_value",
    "current_value",
    "previous_digest",
    "current_digest",
    "member_ref",
    "collector_id",
    "message",
    "observed_value",
)


class DriftBaseline(Base):
    """The pinned observation every later scan is compared against."""

    __tablename__ = "drift_baseline"
    __table_args__ = (
        CheckConstraint(
            "status IN ('active','superseded','revoked')",
            name="ck_drift_baseline_status",
        ),
        CheckConstraint(
            "(status = 'superseded') = (superseded_at IS NOT NULL)",
            name="ck_drift_baseline_superseded",
        ),
        CheckConstraint(
            "superseded_by_id IS NULL OR superseded_by_id <> id",
            name="ck_drift_baseline_supersede_self",
        ),
        CheckConstraint(
            "note IS NULL OR length(note) <= 500",
            name="ck_drift_baseline_note_length",
        ),
        CheckConstraint("control_count >= 0", name="ck_drift_baseline_control_count"),
        CheckConstraint(
            "factprint_field_count >= 0", name="ck_drift_baseline_field_count"
        ),
        Index("uq_drift_baseline_scan", "scan_id", unique=True),
        # At most one active baseline per comparability tuple, enforced by a
        # partial unique index rather than by application convention.
        Index(
            "uq_drift_baseline_active_configuration",
            "configuration_key",
            unique=True,
            postgresql_where=text("status = 'active'"),
        ),
        Index("ix_drift_baseline_user_id", "user_id"),
    )

    id: Mapped[int] = mapped_column(BigInteger, primary_key=True, autoincrement=True)

    user_id: Mapped[Optional[int]] = mapped_column(
        ForeignKey("user.id", ondelete="SET NULL"), nullable=True
    )
    # RESTRICT: an established baseline pins the observation it was established
    # from, so that scan cannot be deleted out from under it.
    scan_id: Mapped[int] = mapped_column(
        ForeignKey("scan.id", ondelete="RESTRICT"), nullable=False
    )
    m365_connection_id: Mapped[Optional[int]] = mapped_column(
        ForeignKey("m365_connection.id", ondelete="SET NULL"), nullable=True
    )

    framework: Mapped[str] = mapped_column(String(50), nullable=False)
    benchmark: Mapped[str] = mapped_column(String(100), nullable=False)
    version: Mapped[str] = mapped_column(String(20), nullable=False)

    metadata_digest: Mapped[str] = mapped_column(String(64), nullable=False)
    policy_corpus_digest: Mapped[str] = mapped_column(String(64), nullable=False)
    semantics_version: Mapped[str] = mapped_column(String(30), nullable=False)
    connection_identity_digest: Mapped[str] = mapped_column(String(64), nullable=False)

    # Digests over the whole comparability tuple, and the LOOKUP key for a run:
    # comparing two incomparable scans is structurally impossible rather than
    # merely checked. The configuration axis deliberately omits the policy corpus
    # digest — a Rego edit cannot change tenant configuration.
    configuration_key: Mapped[str] = mapped_column(String(64), nullable=False)
    evaluation_key: Mapped[str] = mapped_column(String(64), nullable=False)

    observation_digest: Mapped[str] = mapped_column(String(64), nullable=False)

    control_count: Mapped[int] = mapped_column(Integer, nullable=False)
    factprint_field_count: Mapped[int] = mapped_column(Integer, nullable=False)

    status: Mapped[str] = mapped_column(String(20), nullable=False)
    superseded_by_id: Mapped[Optional[int]] = mapped_column(
        ForeignKey("drift_baseline.id", ondelete="SET NULL"), nullable=True
    )
    established_by_user_id: Mapped[Optional[int]] = mapped_column(
        ForeignKey("user.id", ondelete="SET NULL"), nullable=True
    )

    drift_version: Mapped[str] = mapped_column(String(30), nullable=False)
    retention_policy_version: Mapped[str] = mapped_column(String(40), nullable=False)

    # The fingerprint key the baseline's facts were produced under. Null when no
    # key was configured. A later scan under a DIFFERENT key cannot be compared on
    # the configuration axis: every value_digest is an HMAC, so a rotation would
    # otherwise report every fact as changed against a tenant nobody touched.
    key_id: Mapped[Optional[str]] = mapped_column(String(16), nullable=True)
    note: Mapped[Optional[str]] = mapped_column(Text, nullable=True)

    established_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False
    )
    superseded_at: Mapped[Optional[datetime]] = mapped_column(
        DateTime(timezone=True), nullable=True
    )


class DriftRun(Base):
    """One comparison of a current scan against a baseline."""

    __tablename__ = "drift_run"
    __table_args__ = (
        CheckConstraint(
            "status IN ('completed','not_comparable','fingerprints_unavailable',"
            "'event_limit_exceeded')",
            name="ck_drift_run_status",
        ),
        CheckConstraint(
            "trigger IN ('scan_finalised','api_request')",
            name="ck_drift_run_trigger",
        ),
        # A truncated or incomparable run must never be readable as a complete
        # one, so only a completed run may carry events at all.
        CheckConstraint(
            "(status = 'completed') OR event_count = 0",
            name="ck_drift_run_events_only_when_completed",
        ),
        CheckConstraint(
            "(status IN ('not_comparable','fingerprints_unavailable'))"
            " = (NOT configuration_comparable AND NOT evaluation_comparable)",
            name="ck_drift_run_not_comparable",
        ),
        CheckConstraint(
            "jsonb_typeof(axis_reasons) = 'object'",
            name="ck_drift_run_axis_reasons",
        ),
        CheckConstraint(
            "event_count >= 0 AND controls_compared >= 0",
            name="ck_drift_run_counts",
        ),
        Index(
            "uq_drift_run_baseline_scan",
            "baseline_id",
            "current_scan_id",
            unique=True,
        ),
        Index("ix_drift_run_user_id", "user_id"),
        Index("ix_drift_run_current_scan_id", "current_scan_id"),
    )

    id: Mapped[int] = mapped_column(BigInteger, primary_key=True, autoincrement=True)

    baseline_id: Mapped[int] = mapped_column(
        ForeignKey("drift_baseline.id", ondelete="RESTRICT"), nullable=False
    )
    baseline_scan_id: Mapped[Optional[int]] = mapped_column(
        ForeignKey("scan.id", ondelete="SET NULL"), nullable=True
    )
    current_scan_id: Mapped[Optional[int]] = mapped_column(
        ForeignKey("scan.id", ondelete="SET NULL"), nullable=True
    )
    user_id: Mapped[Optional[int]] = mapped_column(
        ForeignKey("user.id", ondelete="SET NULL"), nullable=True
    )

    framework: Mapped[str] = mapped_column(String(50), nullable=False)
    benchmark: Mapped[str] = mapped_column(String(100), nullable=False)
    version: Mapped[str] = mapped_column(String(20), nullable=False)

    status: Mapped[str] = mapped_column(String(30), nullable=False)
    trigger: Mapped[str] = mapped_column(String(24), nullable=False)

    # Both axes are always recorded, together with why. A run that could not
    # compare says so; it does not report an empty result.
    configuration_comparable: Mapped[bool] = mapped_column(Boolean, nullable=False)
    evaluation_comparable: Mapped[bool] = mapped_column(Boolean, nullable=False)
    axis_reasons: Mapped[dict] = mapped_column(JSONB, nullable=False)

    baseline_configuration_key: Mapped[str] = mapped_column(String(64), nullable=False)
    current_configuration_key: Mapped[str] = mapped_column(String(64), nullable=False)
    baseline_evaluation_key: Mapped[str] = mapped_column(String(64), nullable=False)
    current_evaluation_key: Mapped[str] = mapped_column(String(64), nullable=False)

    baseline_observation_digest: Mapped[Optional[str]] = mapped_column(
        String(64), nullable=True
    )
    current_observation_digest: Mapped[Optional[str]] = mapped_column(
        String(64), nullable=True
    )
    baseline_engine_source_digest: Mapped[Optional[str]] = mapped_column(
        String(64), nullable=True
    )
    current_engine_source_digest: Mapped[Optional[str]] = mapped_column(
        String(64), nullable=True
    )
    engine_changed: Mapped[Optional[bool]] = mapped_column(Boolean, nullable=True)

    controls_compared: Mapped[int] = mapped_column(Integer, nullable=False)
    # Per-control skip reasons, so a control that dropped out of the comparison
    # is visible rather than absent.
    controls_skipped: Mapped[dict] = mapped_column(JSONB, nullable=False)

    event_count: Mapped[int] = mapped_column(Integer, nullable=False)
    event_counts: Mapped[dict] = mapped_column(JSONB, nullable=False)
    # Digest over the sorted event keys: recomputing the same run produces the
    # same digest and inserts nothing, so replay is free and provable.
    event_set_digest: Mapped[str] = mapped_column(String(64), nullable=False)

    # Identifies the fingerprint key in force, never the key itself. NULL when no
    # key was configured, which is also why the run has no factprints to compare.
    key_id: Mapped[Optional[str]] = mapped_column(String(16), nullable=True)

    drift_version: Mapped[str] = mapped_column(String(30), nullable=False)
    retention_policy_version: Mapped[str] = mapped_column(String(40), nullable=False)
    correlation_id: Mapped[Optional[str]] = mapped_column(String(128), nullable=True)

    started_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False
    )
    completed_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False
    )


class DriftEvent(Base):
    """One observed difference between the baseline and the current scan."""

    __tablename__ = "drift_event"
    __table_args__ = (
        CheckConstraint(
            "event_class IN ('configuration','evaluation')",
            name="ck_drift_event_class",
        ),
        # The configuration/evaluation separation as a constraint rather than a
        # convention: a configuration event always names the fact that moved.
        CheckConstraint(
            "(event_class = 'configuration') = (fact_name IS NOT NULL)",
            name="ck_drift_event_fact_binding",
        ),
        CheckConstraint(
            "event_class <> 'configuration'"
            " OR change_type IN ('added','removed','changed')",
            name="ck_drift_event_config_change",
        ),
        CheckConstraint(
            "event_class <> 'evaluation'"
            " OR change_type IN ('status_changed','coverage_lost','coverage_gained')",
            name="ck_drift_event_eval_change",
        ),
        # No object, no array and nothing longer than 120 characters: an event
        # reports that a value moved, never the record it came from.
        CheckConstraint(
            "previous_value IS NULL"
            " OR jsonb_typeof(previous_value) NOT IN ('object','array')",
            name="ck_drift_event_previous_scalar",
        ),
        CheckConstraint(
            "current_value IS NULL"
            " OR jsonb_typeof(current_value) NOT IN ('object','array')",
            name="ck_drift_event_current_scalar",
        ),
        CheckConstraint(
            "previous_value IS NULL OR length(previous_value::text) <= 120",
            name="ck_drift_event_previous_len",
        ),
        CheckConstraint(
            "current_value IS NULL OR length(current_value::text) <= 120",
            name="ck_drift_event_current_len",
        ),
        CheckConstraint(
            "severity IN ('critical','high','medium','low','informational')",
            name="ck_drift_event_severity",
        ),
        CheckConstraint(
            "severity_basis IN ('benchmark_severity','evaluation_transition',"
            "'coverage_loss','observability_change','severity_unavailable')",
            name="ck_drift_event_severity_basis",
        ),
        CheckConstraint(
            "member_ref IS NULL OR member_ref ~ '^[0-9a-f]{64}$'",
            name="ck_drift_event_member_ref",
        ),
        CheckConstraint(
            "event_key ~ '^[0-9a-f]{64}$'",
            name="ck_drift_event_key",
        ),
        CheckConstraint(
            "detail IS NULL OR jsonb_typeof(detail) = 'object'",
            name="ck_drift_event_detail_object",
        ),
        Index("uq_drift_event_run_key", "drift_run_id", "event_key", unique=True),
        Index("ix_drift_event_user_id", "user_id"),
        Index("ix_drift_event_baseline_key", "baseline_id", "event_key"),
    )

    id: Mapped[int] = mapped_column(BigInteger, primary_key=True, autoincrement=True)

    drift_run_id: Mapped[int] = mapped_column(
        ForeignKey("drift_run.id", ondelete="RESTRICT"), nullable=False
    )
    baseline_id: Mapped[int] = mapped_column(
        ForeignKey("drift_baseline.id", ondelete="RESTRICT"), nullable=False
    )
    baseline_scan_id: Mapped[Optional[int]] = mapped_column(
        ForeignKey("scan.id", ondelete="SET NULL"), nullable=True
    )
    current_scan_id: Mapped[Optional[int]] = mapped_column(
        ForeignKey("scan.id", ondelete="SET NULL"), nullable=True
    )
    user_id: Mapped[Optional[int]] = mapped_column(
        ForeignKey("user.id", ondelete="SET NULL"), nullable=True
    )

    control_id: Mapped[str] = mapped_column(String(50), nullable=False)
    collector_id: Mapped[Optional[str]] = mapped_column(String(120), nullable=True)

    event_class: Mapped[str] = mapped_column(String(20), nullable=False)
    change_type: Mapped[str] = mapped_column(String(24), nullable=False)

    fact_name: Mapped[Optional[str]] = mapped_column(String(40), nullable=True)
    # A keyed pseudonym for one member of an enum set, never the member itself.
    member_ref: Mapped[Optional[str]] = mapped_column(String(64), nullable=True)

    previous_value: Mapped[Optional[object]] = mapped_column(JSONB, nullable=True)
    current_value: Mapped[Optional[object]] = mapped_column(JSONB, nullable=True)
    previous_digest: Mapped[Optional[str]] = mapped_column(String(64), nullable=True)
    current_digest: Mapped[Optional[str]] = mapped_column(String(64), nullable=True)

    # Transcribed from the scan's pinned benchmark metadata. Nothing here judges.
    severity: Mapped[str] = mapped_column(String(20), nullable=False)
    severity_basis: Mapped[str] = mapped_column(String(40), nullable=False)

    # Stable across every run against the same baseline, so an accepted risk
    # suppresses the same finding instead of it reappearing as new noise.
    event_key: Mapped[str] = mapped_column(String(64), nullable=False)

    detail: Mapped[Optional[dict]] = mapped_column(JSONB, nullable=True)

    correlation_id: Mapped[Optional[str]] = mapped_column(String(128), nullable=True)
    drift_version: Mapped[str] = mapped_column(String(30), nullable=False)
    retention_policy_version: Mapped[str] = mapped_column(String(40), nullable=False)

    occurred_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False
    )


class DriftNotification(Base):
    """One immutable revision in a notification thread's history.

    There is no value column here of any kind. See
    ``FORBIDDEN_NOTIFICATION_COLUMNS``: the guarantee that a notification cannot
    expose evidence is a property of this table's shape, not of a review.

    Delivery is in-database and API-read only. There is no SMTP, no webhook and
    no egress of any kind.
    """

    __tablename__ = "drift_notification"
    __table_args__ = (
        CheckConstraint("scope IN ('event','run')", name="ck_drift_notification_scope"),
        CheckConstraint("channel IN ('inapp')", name="ck_drift_notification_channel"),
        CheckConstraint(
            "routing_rule IN ('owner_high_or_above','owner_coverage_loss',"
            "'owner_not_comparable','owner_fingerprints_unavailable','owner_action')",
            name="ck_drift_notification_routing",
        ),
        CheckConstraint(
            "action IN ('raised','acknowledged','remediation_planned',"
            "'remediation_verified','accepted_risk','superseded')",
            name="ck_drift_notification_action",
        ),
        CheckConstraint(
            "state_after IN ('open','acknowledged','remediation_planned',"
            "'remediation_verified','accepted_risk','superseded')",
            name="ck_drift_notification_state",
        ),
        CheckConstraint(
            "(action = 'raised' AND state_after = 'open')"
            " OR (action <> 'raised' AND state_after = action)",
            name="ck_drift_notification_state_matches_action",
        ),
        CheckConstraint(
            "(action = 'raised') = (revision_number = 1)",
            name="ck_drift_notification_first_revision",
        ),
        CheckConstraint(
            "revision_number >= 1", name="ck_drift_notification_revision_positive"
        ),
        # Remediation is evidence-backed rather than a checkbox: the run that
        # proved it is named on the row that claims it.
        CheckConstraint(
            "(action = 'remediation_verified') = (verified_run_id IS NOT NULL)",
            name="ck_drift_notification_verified",
        ),
        CheckConstraint(
            "note IS NULL OR length(note) <= 1000",
            name="ck_drift_notification_note_length",
        ),
        CheckConstraint(
            "jsonb_typeof(summary_counts) = 'object'",
            name="ck_drift_notification_summary_object",
        ),
        CheckConstraint(
            "severity IN ('critical','high','medium','low','informational')",
            name="ck_drift_notification_severity",
        ),
        CheckConstraint(
            "thread_key ~ '^[0-9a-f]{64}$'",
            name="ck_drift_notification_thread_key",
        ),
        CheckConstraint(
            "(scope = 'event') = (drift_event_id IS NOT NULL OR revision_number > 1)",
            name="ck_drift_notification_event_scope",
        ),
        Index(
            "uq_drift_notification_revision",
            "thread_key",
            "revision_number",
            unique=True,
        ),
        Index("ix_drift_notification_user_id", "user_id"),
        Index("ix_drift_notification_baseline_id", "baseline_id"),
    )

    id: Mapped[int] = mapped_column(BigInteger, primary_key=True, autoincrement=True)

    baseline_id: Mapped[int] = mapped_column(
        ForeignKey("drift_baseline.id", ondelete="RESTRICT"), nullable=False
    )
    drift_run_id: Mapped[Optional[int]] = mapped_column(
        ForeignKey("drift_run.id", ondelete="SET NULL"), nullable=True
    )
    drift_event_id: Mapped[Optional[int]] = mapped_column(
        ForeignKey("drift_event.id", ondelete="SET NULL"), nullable=True
    )
    # The recipient. Always the scan owner; there is no admin queue and no
    # cross-tenant fan-out.
    user_id: Mapped[Optional[int]] = mapped_column(
        ForeignKey("user.id", ondelete="SET NULL"), nullable=True
    )

    thread_key: Mapped[str] = mapped_column(String(64), nullable=False)
    scope: Mapped[str] = mapped_column(String(10), nullable=False)
    channel: Mapped[str] = mapped_column(String(20), nullable=False)
    routing_rule: Mapped[str] = mapped_column(String(40), nullable=False)

    revision_number: Mapped[int] = mapped_column(Integer, nullable=False)
    action: Mapped[str] = mapped_column(String(24), nullable=False)
    state_after: Mapped[str] = mapped_column(String(24), nullable=False)

    severity: Mapped[str] = mapped_column(String(20), nullable=False)
    # A stable code and a count map. Never a rendered message, and never a
    # control id, fact name, member ref, digest or observed value.
    summary_code: Mapped[str] = mapped_column(String(60), nullable=False)
    summary_counts: Mapped[dict] = mapped_column(JSONB, nullable=False)

    actor_user_id: Mapped[Optional[int]] = mapped_column(
        ForeignKey("user.id", ondelete="SET NULL"), nullable=True
    )
    verified_run_id: Mapped[Optional[int]] = mapped_column(
        ForeignKey("drift_run.id", ondelete="SET NULL"), nullable=True
    )

    note: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    request_id: Mapped[Optional[str]] = mapped_column(String(128), nullable=True)

    drift_version: Mapped[str] = mapped_column(String(30), nullable=False)
    retention_policy_version: Mapped[str] = mapped_column(String(40), nullable=False)

    occurred_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False
    )
