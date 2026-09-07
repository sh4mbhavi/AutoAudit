// GENERATED FILE -- DO NOT EDIT.
//
// Produced from the backend's own OpenAPI schema by
// tools/frontend/generate_api_types.py. CI runs that script with --check, so an
// edit here, or a change to a backend response model that is not regenerated,
// fails the build rather than drifting silently.
//
// Regenerate with:
//   uv run --frozen --project backend-api python tools/frontend/generate_api_types.py

export interface ControlCategoryBreakdown {
  category: string;
  total: number;
  passed: number;
  failed: number;
  skipped: number;
  error: number;
  pending?: number;
  indeterminate?: number;
  not_assessable?: number;
}

export interface ScanCreatedResponse {
  id: number;
  status: string;
  message: string;
}

export interface ScanListItem {
  id: number;
  user_id: number;
  m365_connection_id: number | null;
  connection_name?: string | null;
  framework: string;
  benchmark: string;
  version: string;
  status: string;
  started_at: string;
  finished_at: string | null;
  compliance_score: string | null;
  total_controls: number;
  passed_count: number;
  failed_count: number;
  skipped_count: number;
  error_count: number;
  pending_count?: number;
  indeterminate_count?: number;
  not_assessable_count?: number;
  selected_count?: number | null;
  coverage_score?: string | null;
  semantics_version?: string | null;
  metadata_digest?: string | null;
  correlation_id?: string | null;
  dispatch_id?: string | null;
  dispatch_count?: number;
  last_progress_at?: string | null;
  deadline_at?: string | null;
  lifecycle_version?: string | null;
  mapping_id?: string | null;
  mapping_version?: string | null;
  mapping_digest?: string | null;
  policy_corpus_digest?: string | null;
  evidence_version?: string | null;
}

export interface ScanProvenanceRead {
  scan_id: number;
  status: string;
  framework: string;
  benchmark: string;
  version: string;
  started_at: string;
  finished_at?: string | null;
  semantics_version?: string | null;
  lifecycle_version?: string | null;
  evidence_version?: string | null;
  correlation_id?: string | null;
  dispatch_id?: string | null;
  selected_count?: number | null;
  total_controls?: number;
  metadata_digest?: string | null;
  metadata_snapshot_present?: boolean;
  metadata_control_count?: number;
  policy_corpus_digest?: string | null;
  connection_snapshot_present?: boolean;
  connection_snapshot_fields?: string[];
  mapping_id?: string | null;
  mapping_version?: string | null;
  mapping_digest?: string | null;
  mapping_snapshot_present?: boolean;
  mapping_status?: string | null;
  mapping_approved?: boolean;
  mapping_points_of_focus_count?: number;
  soc2_projection_available?: boolean;
}

export interface ScanRead {
  id: number;
  user_id: number;
  m365_connection_id: number | null;
  connection_name?: string | null;
  azure_connection_id: number | null;
  gcp_connection_id: number | null;
  aws_connection_id: number | null;
  framework: string;
  benchmark: string;
  version: string;
  status: string;
  started_at: string;
  finished_at: string | null;
  compliance_score: string | null;
  total_controls: number;
  passed_count: number;
  failed_count: number;
  skipped_count: number;
  error_count: number;
  pending_count?: number;
  indeterminate_count?: number;
  not_assessable_count?: number;
  selected_count?: number | null;
  coverage_score?: string | null;
  semantics_version?: string | null;
  metadata_digest?: string | null;
  correlation_id?: string | null;
  dispatch_id?: string | null;
  dispatch_count?: number;
  last_progress_at?: string | null;
  deadline_at?: string | null;
  lifecycle_version?: string | null;
  mapping_id?: string | null;
  mapping_version?: string | null;
  mapping_digest?: string | null;
  policy_corpus_digest?: string | null;
  evidence_version?: string | null;
  notes: string | null;
  results?: ScanResultRead[] | null;
}

export interface ScanResultRead {
  id: number;
  scan_id: number;
  control_id: string;
  status: "pending" | "passed" | "failed" | "indeterminate" | "error" | "skipped" | "not_assessable";
  selected?: boolean | null;
  reason_code?: string | null;
  provenance?: Record<string, unknown> | null;
  message: string | null;
  evidence: Record<string, unknown> | null;
  created_at: string;
  updated_at: string;
}

export interface ScanSummary {
  id: number;
  status: string;
  framework: string;
  benchmark: string;
  version: string;
  started_at: string;
  finished_at: string | null;
  compliance_score: string | null;
  total_controls: number;
  passed_count: number;
  failed_count: number;
  skipped_count: number;
  error_count: number;
  pending_count?: number;
  indeterminate_count?: number;
  not_assessable_count?: number;
  selected_count?: number | null;
  coverage_score?: string | null;
  semantics_version?: string | null;
  metadata_digest?: string | null;
  correlation_id?: string | null;
  dispatch_id?: string | null;
  dispatch_count?: number;
  last_progress_at?: string | null;
  deadline_at?: string | null;
  lifecycle_version?: string | null;
  mapping_id?: string | null;
  mapping_version?: string | null;
  mapping_digest?: string | null;
  policy_corpus_digest?: string | null;
  evidence_version?: string | null;
  categories: ControlCategoryBreakdown[];
}
