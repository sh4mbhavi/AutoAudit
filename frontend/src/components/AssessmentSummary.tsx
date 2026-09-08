import type { ScanAssessmentFields, ScanResultStatus } from '../types/scan';
import { formatScore, getScanAssessment, RESULT_LABELS } from '../utils/scanAssessment';

export default function AssessmentSummary({ scan, className = '' }: { scan: ScanAssessmentFields; className?: string }) {
  const assessment = getScanAssessment(scan);
  return (
    <div className={`space-y-2 text-sm ${className}`} aria-label="Scan assessment summary">
      {assessment.legacy ? (
        <>
          <p>Legacy score: {assessment.compliance === null ? 'Unavailable' : formatScore(assessment.compliance)}</p>
          <p>Automated coverage unavailable for legacy scan</p>
        </>
      ) : (
        <>
          <p>Compliance among assessed: {formatScore(assessment.compliance)} ({assessment.counts.passed}/{assessment.assessed})</p>
          <p>Automated coverage: {assessment.coverage === null ? 'Unavailable' : formatScore(assessment.coverage)} ({assessment.assessed}/{assessment.selected} selected)</p>
          {assessment.partial && <p className="font-medium text-orange-500">Partial assessment</p>}
        </>
      )}
      <div className="flex flex-wrap gap-x-4 gap-y-1 text-xs">
        <span>Selected: {assessment.selected ?? 'Unknown'}</span>
        {(Object.keys(RESULT_LABELS) as ScanResultStatus[]).map((status) => (
          <span key={status}>{RESULT_LABELS[status]}: {assessment.counts[status]}</span>
        ))}
      </div>
    </div>
  );
}
