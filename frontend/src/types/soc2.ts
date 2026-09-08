/**
 * Response contract for `GET /v1/scans/{id}/soc2-report`.
 *
 * These types mirror `backend-api/app/schemas/soc2.py`. Three things they encode
 * deliberately, because the UI must not be able to undo them:
 *
 * - `configuration_rating` is a human-owned GRC judgment copied verbatim from the
 *   pinned crosswalk. `rating_is_computed` is always `false`. Nothing in the scan
 *   result may be used to derive, promote or override it.
 * - coverage always carries `assessed_count` **and** `applicable_count`. A bare
 *   percentage is never a complete statement, so never render one alone.
 * - `manual_residual_evidence` is a separate stream with
 *   `counted_in_automated_coverage: false`. It must not be added to any automated
 *   coverage figure.
 */

/** Whatever the pinned mapping's own `rating_vocabulary` allows (today Yes/Partial/No). */
export type Soc2Rating = string;

export type Soc2ProjectionStatus = 'available' | 'no_projection';

export type Soc2AssessmentCompleteness =
  | 'complete'
  | 'partial'
  | 'not_assessed'
  | 'not_applicable'
  | 'no_automated_coverage';

/** The pinned mapping's approval block, verbatim. `approved` is false today. */
export type Soc2Approval = {
  approved: boolean;
  reviewer_name?: string | null;
  reviewer_role?: string | null;
  approved_at?: string | null;
  decision_reference?: string | null;
  note?: string | null;
};

export type Soc2Identity = {
  framework?: string | null;
  criteria_family?: string | null;
  authoritative_criteria?: string[];
};

export type Soc2ReportHeader = {
  mapping_id: string;
  mapping_version: string;
  mapping_digest: string;
  mapping_status?: string | null;
  schema_version?: number | null;
  soc2: Soc2Identity;
  benchmark?: Record<string, unknown>;
  source?: Record<string, unknown> | null;
  rating_vocabulary?: string[];
  approval: Soc2Approval;
  approval_pending: boolean;
  /** Must be displayed with the report; never suppress it. */
  not_a_certification: string;
  rating_ownership: string;
};

export type Soc2Provenance = {
  scan_id: number;
  scan_status: string;
  started_at?: string | null;
  finished_at?: string | null;
  framework: string;
  benchmark: string;
  benchmark_version: string;
  metadata_digest?: string | null;
  policy_corpus_digest?: string | null;
  mapping_id?: string | null;
  mapping_version?: string | null;
  mapping_digest?: string | null;
  correlation_id?: string | null;
  semantics_version?: string | null;
  lifecycle_version?: string | null;
  evidence_version?: string | null;
  connection_snapshot_present: boolean;
  rendered_from: 'pinned_mapping_snapshot';
  generated_at: string;
};

/** One mapped CIS control as the scan actually found it. */
export type Soc2ControlEvidence = {
  control_id: string;
  title?: string | null;
  /** Whether the scan's pinned benchmark defines this control at all. */
  in_benchmark: boolean;
  /** Whether the scan holds a result row for it. */
  in_scan: boolean;
  selected?: boolean | null;
  /**
   * A scan result status, or one of two synthetic ones. `missing_result` means
   * the pinned benchmark defines the control but the scan has no row - an
   * integrity gap that stays in the coverage denominator. `not_in_benchmark`
   * means the mapping cites a control this benchmark never had. Neither is ever
   * a pass, and neither is ever a tenant failure.
   */
  status: string;
  reason_code?: string | null;
  automation_status?: string | null;
  /** Execution provenance only; collected tenant payloads are never included. */
  provenance?: Record<string, unknown> | null;
};

/** Numerator and denominator are both required. Never render the percent alone. */
export type Soc2Coverage = {
  mapped_control_count: number;
  in_scan_count: number;
  /** Denominator: mapped controls this scan selected. */
  applicable_count: number;
  /** Numerator: of those, the ones that produced passed or failed. */
  assessed_count: number;
  passed_count: number;
  failed_count: number;
  indeterminate_count: number;
  error_count: number;
  not_assessable_count: number;
  pending_count: number;
  /** Controls with no result row at all. Unknown, never covered. */
  missing_result_count: number;
  unassessed_count: number;
  not_in_scope_count: number;
  missing_from_benchmark_count: number;
  coverage_percent?: number | null;
  compliance_percent?: number | null;
  assessment_completeness: Soc2AssessmentCompleteness;
  /** True when some selected control produced no assessment. Label it. */
  partial_assessment: boolean;
  coverage_statement: string;
};

export type Soc2ManualEvidence = {
  record_id: number;
  control_id: string;
  evidence_source: string;
  status: string;
  control_owner?: string | null;
  evidence_owner?: string | null;
  collection_period_start?: string | null;
  collection_period_end?: string | null;
  expires_at?: string | null;
  cadence?: string | null;
  reviewed_at?: string | null;
  current_revision_number: number;
  counted_in_automated_coverage: false;
};

export type Soc2Limitations = {
  residual_limitation?: string | null;
  residual_scope?: string | null;
};

export type Soc2PointOfFocus = {
  point_id: string;
  criterion: string;
  point_of_focus: string;
  /** Copied from the pinned mapping. Scan results never change this. */
  configuration_rating: Soc2Rating;
  rating_source: 'pinned_mapping';
  rating_is_computed: false;
  evidence_selector?: string | null;
  /** False when a selector was not understood; coverage is then incomplete. */
  selector_resolved: boolean;
  mapped_control_ids: string[];
  automated_evidence: Soc2ControlEvidence[];
  coverage: Soc2Coverage;
  manual_residual_evidence: Soc2ManualEvidence[];
  limitations: Soc2Limitations;
};

export type Soc2CriterionCoverage = {
  criterion: string;
  configuration_coverage_classification?: string | null;
};

export type Soc2Totals = {
  points_of_focus_count: number;
  unique_mapped_control_ids: number;
  rating_counts: Record<string, number>;
  criteria_count: number;
};

export type Soc2ManualEvidenceStream = {
  /** False means "could not be read", which is unknown, not none. */
  available: boolean;
  approved_record_count: number;
  counted_in_automated_coverage: false;
  note: string;
};

export type Soc2ResolutionFinding = {
  code: string;
  control_id: string;
  detail: string;
};

export type Soc2ReportResponse = {
  scan_id: number;
  projection_available: boolean;
  projection_status: Soc2ProjectionStatus;
  /** Shown as-is when `projection_available` is false. */
  message: string;
  header?: Soc2ReportHeader | null;
  provenance?: Soc2Provenance | null;
  criteria_coverage_summary?: Soc2CriterionCoverage[];
  points_of_focus?: Soc2PointOfFocus[];
  totals?: Soc2Totals | null;
  manual_evidence_stream?: Soc2ManualEvidenceStream | null;
  mapping_resolution_findings?: Soc2ResolutionFinding[];
};
