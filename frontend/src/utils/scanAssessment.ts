import type { ScanAssessmentFields, ScanResultStatus } from '../types/scan';

export const RESULT_LABELS: Record<ScanResultStatus, string> = {
  passed: 'Pass', failed: 'Fail', indeterminate: 'Indeterminate', error: 'Error',
  skipped: 'Skipped', not_assessable: 'Not assessable', pending: 'Pending',
};

function score(value: number | string | null | undefined): number | null {
  if (value === null || value === undefined || value === '') return null;
  const numeric = Number(value);
  return Number.isFinite(numeric) ? numeric : null;
}

export function getScanAssessment(scan: ScanAssessmentFields) {
  const counts: Record<ScanResultStatus, number> = {
    passed: Number(scan.passed_count || 0), failed: Number(scan.failed_count || 0),
    indeterminate: Number(scan.indeterminate_count || 0), error: Number(scan.error_count || 0),
    skipped: Number(scan.skipped_count || 0), not_assessable: Number(scan.not_assessable_count || 0),
    pending: 0,
  };
  const total = Number(scan.total_controls || 0);
  const done = Object.values(counts).reduce((sum, count) => sum + count, 0);
  counts.pending = Math.max(0, scan.pending_count == null ? total - done : Number(scan.pending_count));
  const assessed = counts.passed + counts.failed;
  const legacy = scan.semantics_version !== 'phase3-v1' || scan.selected_count == null;
  const selected = legacy ? null : scan.selected_count!;
  return {
    counts, total, done, assessed, selected, pending: counts.pending, legacy,
    compliance: score(scan.compliance_score),
    coverage: legacy ? null : score(scan.coverage_score),
    partial: selected !== null && assessed < selected,
  };
}

export function formatScore(value: number | null): string {
  return value === null ? 'Not assessed' : `${value}%`;
}
