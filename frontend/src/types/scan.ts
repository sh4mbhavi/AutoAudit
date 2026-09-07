export type ScanResultStatus = 'pending' | 'passed' | 'failed' | 'indeterminate' | 'error' | 'skipped' | 'not_assessable';

type Count = number | string | null;

/** Optional fields preserve compatibility with historical scan responses. */
export type ScanAssessmentFields = {
  /**
   * Phase 9: widened from the literal 'phase3-v1' to match what the API's own
   * OpenAPI schema declares (`string | null`). The narrow literal was a frontend
   * assumption the backend never guaranteed, and it is what made the generated
   * ScanListItem unassignable here. getScanAssessment still tests for the exact
   * literal, so nothing about the legacy-scan decision changes.
   */
  semantics_version?: string | null;
  selected_count?: number | null;
  compliance_score?: number | string | null;
  coverage_score?: number | string | null;
  total_controls?: Count;
  passed_count?: Count;
  failed_count?: Count;
  error_count?: Count;
  skipped_count?: Count;
  indeterminate_count?: Count;
  not_assessable_count?: Count;
  pending_count?: Count;
};

/**
 * Provenance frozen when the scan was created, exposed on scan reads.
 * Additive and all optional: historical scans carry none of it.
 * `mapping_id` being null means the scan has no SOC 2 projection at all.
 */
export type ScanPinnedProvenanceFields = {
  metadata_digest?: string | null;
  policy_corpus_digest?: string | null;
  mapping_id?: string | null;
  mapping_version?: string | null;
  mapping_digest?: string | null;
  evidence_version?: 'phase7-v1' | string | null;
};

/** Response of `GET /v1/scans/{id}/provenance`. Never carries a snapshot body. */
export type ScanProvenance = ScanPinnedProvenanceFields & {
  scan_id: number;
  status: string;
  framework: string;
  benchmark: string;
  version: string;
  started_at: string;
  finished_at?: string | null;
  semantics_version?: string | null;
  lifecycle_version?: string | null;
  correlation_id?: string | null;
  dispatch_id?: string | null;
  selected_count?: number | null;
  total_controls: number;
  metadata_snapshot_present: boolean;
  metadata_control_count: number;
  connection_snapshot_present: boolean;
  /** Field names only; no tenant or client identifier is returned. */
  connection_snapshot_fields: string[];
  mapping_snapshot_present: boolean;
  mapping_status?: string | null;
  /** Straight from the pinned mapping's approval block. False today. */
  mapping_approved: boolean;
  mapping_points_of_focus_count: number;
  soc2_projection_available: boolean;
};

/**
 * One control result as the page reads it.
 *
 * Phase 9: `message` widened from `string | undefined` to match what the API's
 * own OpenAPI schema declares (`string | null`) -- the narrow form was a
 * frontend assumption the backend never made, and it is what made the generated
 * ScanResultRead unassignable here. `title` and `description` are not API
 * fields at all; they are optional labels some callers attach locally.
 */
export type ScanResult = {
  control_id?: string | number;
  status?: ScanResultStatus;
  selected?: boolean | null;
  reason_code?: string | null;
  provenance?: Record<string, unknown> | null;
  title?: string;
  description?: string;
  message?: string | null;
};
