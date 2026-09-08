export type ScanResultStatus = 'pending' | 'passed' | 'failed' | 'indeterminate' | 'error' | 'skipped' | 'not_assessable';

type Count = number | string | null;

/** Optional fields preserve compatibility with historical scan responses. */
export type ScanAssessmentFields = {
  semantics_version?: 'phase3-v1' | null;
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

export type ScanResult = {
  control_id?: string | number;
  status?: ScanResultStatus;
  selected?: boolean | null;
  reason_code?: string | null;
  provenance?: Record<string, unknown> | null;
  title?: string;
  description?: string;
  message?: string;
};
