/**
 * Response contract for the Phase 8 configuration drift API.
 *
 * These types mirror `backend-api/app/schemas/drift.py`. Four things they encode
 * deliberately, because the UI must not be able to undo them:
 *
 * - drift is a **periodic comparison of two completed scans** against a pinned
 *   baseline. `DriftRun` carries `is_real_time: false` and `changes_ratings:
 *   false` as constants, so a screen may never present it as monitoring and may
 *   never let it move a rating, a result or a score.
 * - every response that can carry events also carries `no_events_means`. Render
 *   it whenever an event list is shown empty: zero events is a statement about
 *   two compared observations, not about the tenant and never about a pass.
 * - `previous_value` and `current_value` are a closed union of short scalars.
 *   There is no shape here that could hold a raw tenant record, which is a
 *   property of the database CHECKs behind them, not of this file.
 * - `DriftEvent.counted_in_automated_coverage` is `false`. A drift event is
 *   never added to any coverage or compliance figure.
 *
 * There is no rating field anywhere in this file, and none may be added.
 */

/**
 * What moved. A configuration event names the tenant fact that changed; an
 * evaluation event names a change in what the engine could see or conclude.
 */
export type DriftEventClass = 'configuration' | 'evaluation';

/**
 * `coverage_lost` and `coverage_gained` are first-class: losing the ability to
 * observe a control is a finding in its own right, never a silent status flip.
 */
export type DriftChangeType =
  | 'added'
  | 'removed'
  | 'changed'
  | 'status_changed'
  | 'coverage_lost'
  | 'coverage_gained';

export type DriftSeverity =
  | 'critical'
  | 'high'
  | 'medium'
  | 'low'
  | 'informational';

/**
 * Where the severity came from. `severity_unavailable` is an honest answer, not
 * a default: the benchmark did not state one, so AutoAudit does not invent one.
 */
export type DriftSeverityBasis =
  | 'benchmark_severity'
  | 'evaluation_transition'
  | 'coverage_loss'
  | 'observability_change'
  | 'severity_unavailable';

/**
 * Only a `completed` run may carry events. The other three are runs that could
 * not produce a comparison, and an empty event list on one of them means
 * "nothing was compared", never "nothing changed".
 */
export type DriftRunStatus =
  | 'completed'
  | 'not_comparable'
  | 'fingerprints_unavailable'
  | 'event_limit_exceeded';

export type DriftBaselineStatus = 'active' | 'superseded' | 'revoked';

/** Derived from the newest revision of a thread, never stored on a row. */
export type DriftNotificationState =
  | 'open'
  | 'acknowledged'
  | 'remediation_planned'
  | 'remediation_verified'
  | 'accepted_risk'
  | 'superseded';

/**
 * Where one scan stands. `no_baseline`, `facts_unavailable` and `not_run` are
 * explicit answers rather than an empty list, because "nothing to show" and
 * "nothing changed" are not the same claim.
 */
export type DriftScanStatusCode =
  | 'no_baseline'
  | 'facts_unavailable'
  | 'not_run'
  | 'completed'
  | 'not_comparable'
  | 'fingerprints_unavailable'
  | 'event_limit_exceeded';

/** The pinned observation every later scan is compared against. */
export type DriftBaseline = {
  id: number;
  user_id?: number | null;
  scan_id: number;
  m365_connection_id?: number | null;
  framework: string;
  benchmark: string;
  version: string;
  metadata_digest: string;
  policy_corpus_digest: string;
  semantics_version: string;
  connection_identity_digest: string;
  /**
   * The baseline lookup key. Two scans with different keys are not comparable,
   * which is a structural fact rather than a warning to display.
   */
  configuration_key: string;
  evaluation_key: string;
  observation_digest: string;
  control_count: number;
  factprint_field_count: number;
  status: DriftBaselineStatus;
  superseded_by_id?: number | null;
  drift_version: string;
  retention_policy_version: string;
  note?: string | null;
  established_at: string;
  superseded_at?: string | null;
};

/** One comparison, including both comparability axes and why. */
export type DriftRun = {
  id: number;
  baseline_id: number;
  baseline_scan_id?: number | null;
  current_scan_id?: number | null;
  user_id?: number | null;
  framework: string;
  benchmark: string;
  version: string;
  status: DriftRunStatus;
  /** `scan_finalised` or `api_request`. There is no scheduler. */
  trigger: string;
  /**
   * Both axes are always reported, together with the reason. A run that could
   * not compare says so; never render it as a comparison that found nothing.
   */
  configuration_comparable: boolean;
  evaluation_comparable: boolean;
  axis_reasons: Record<string, unknown>;
  baseline_configuration_key: string;
  current_configuration_key: string;
  baseline_evaluation_key: string;
  current_evaluation_key: string;
  baseline_observation_digest?: string | null;
  current_observation_digest?: string | null;
  baseline_engine_source_digest?: string | null;
  current_engine_source_digest?: string | null;
  engine_changed?: boolean | null;
  controls_compared: number;
  /** Per-control skip reasons. A control that dropped out is visible, not absent. */
  controls_skipped: Record<string, unknown>;
  event_count: number;
  /**
   * Counts by class and severity as the run stored them. The SOC 2 report
   * narrows the same field to `Record<string, Record<string, number>>`; here it
   * is mirrored as the API declares it.
   */
  event_counts: Record<string, unknown>;
  event_set_digest: string;
  /** Identifies the fingerprint key in force, never the key itself. */
  key_id?: string | null;
  drift_version: string;
  retention_policy_version: string;
  correlation_id?: string | null;
  started_at: string;
  completed_at: string;
  /** Constants. Drift is periodic, moves no rating and is never coverage. */
  is_real_time: false;
  changes_ratings: false;
  counted_in_automated_coverage: false;
  /** Display this wherever an event list is shown empty. */
  no_events_means: string;
};

/** One observed difference. */
export type DriftEvent = {
  id: number;
  drift_run_id: number;
  baseline_id: number;
  control_id: string;
  collector_id: string | null;
  event_class: DriftEventClass;
  change_type: DriftChangeType;
  /** Present exactly when `event_class` is `configuration`. */
  fact_name: string | null;
  /** A keyed pseudonym for the member that moved. Never a tenant identifier. */
  member_ref: string | null;
  previous_value: boolean | number | string | null;
  current_value: boolean | number | string | null;
  previous_digest: string | null;
  current_digest: string | null;
  severity: DriftSeverity;
  severity_basis: DriftSeverityBasis;
  /** Stable across runs, so an accepted risk stays suppressed instead of recurring. */
  event_key: string;
  detail: Record<string, unknown> | null;
  occurred_at: string;
  counted_in_automated_coverage: false;
};

/**
 * One page of a run's events. `run_status` travels with the page because an
 * empty page means one thing on a completed run and something else entirely on
 * a run that could not compare at all.
 */
export type DriftEventList = {
  items: DriftEvent[];
  limit: number;
  offset: number;
  returned: number;
  run_status: string;
  no_events_means: string;
};

/** Where one scan stands with respect to drift. */
export type DriftScanStatus = {
  scan_id: number;
  drift_available: boolean;
  status: DriftScanStatusCode;
  run?: DriftRun | null;
  message: string;
  no_events_means: string;
};

/**
 * One immutable revision in a notification thread.
 *
 * Every field is a code or a count. There is no control id, fact name, member
 * ref, digest or observed value here, because there is none on the table.
 */
export type DriftNotificationRevision = {
  id: number;
  thread_key: string;
  scope: string;
  revision_number: number;
  /** `raised`, `acknowledged`, `remediation_planned`, and so on. */
  action: string;
  state_after: DriftNotificationState;
  severity: DriftSeverity;
  summary_code: string;
  summary_counts: Record<string, unknown>;
  routing_rule: string;
  actor_user_id?: number | null;
  /** The later run offered as evidence that remediation actually landed. */
  verified_run_id?: number | null;
  note?: string | null;
  occurred_at: string;
};

/** The derived current state of one notification thread. */
export type DriftNotificationThread = {
  thread_key: string;
  scope: string;
  baseline_id: number;
  drift_run_id?: number | null;
  drift_event_id?: number | null;
  user_id?: number | null;
  severity: DriftSeverity;
  summary_code: string;
  summary_counts: Record<string, unknown>;
  routing_rule: string;
  /** Derived from the highest-revision row, never stored. */
  state: DriftNotificationState;
  current_revision_number: number;
  remediation_evidenced: boolean;
  raised_at: string;
  updated_at: string;
};
