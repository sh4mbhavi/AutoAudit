import { describe, expect, it } from 'vitest';
import { getScanAssessment, RESULT_LABELS } from './scanAssessment';

const phase3 = { semantics_version: 'phase3-v1' as const, selected_count: 8, total_controls: 9, passed_count: 2, failed_count: 0, indeterminate_count: 2, error_count: 1, not_assessable_count: 2, skipped_count: 1, pending_count: 1, compliance_score: '100.00', coverage_score: '25.00' };

describe('scan assessment semantics', () => {
  it('uses persisted scores with assessed and selected denominators and partial assessment', () => {
    expect(getScanAssessment(phase3)).toMatchObject({ compliance: 100, coverage: 25, assessed: 2, selected: 8, partial: true, done: 8, pending: 1, legacy: false });
  });
  it.each(['pending', 'error', 'indeterminate', 'not_assessable'] as const)('does not treat an all-%s scan as compliant', (status) => {
    expect(getScanAssessment({ semantics_version: 'phase3-v1', selected_count: 2, total_controls: 2, [`${status}_count`]: 2, compliance_score: null, coverage_score: '0.00' })).toMatchObject({ compliance: null, coverage: 0, assessed: 0, partial: true });
  });
  it('keeps a null persisted score unknown even when old counts suggest a score', () => {
    expect(getScanAssessment({ ...phase3, compliance_score: null })).toMatchObject({ compliance: null });
  });
  it('preserves decimal percentages from the backend', () => {
    expect(getScanAssessment({ ...phase3, compliance_score: '66.67', coverage_score: 37.5 })).toMatchObject({ compliance: 66.67, coverage: 37.5 });
  });
  it('handles zero selections without division by zero', () => {
    expect(getScanAssessment({ semantics_version: 'phase3-v1', selected_count: 0, compliance_score: null, coverage_score: null })).toMatchObject({ compliance: null, coverage: null, partial: false, selected: 0 });
  });
  it.each([{ semantics_version: null, selected_count: null }, { semantics_version: 'phase3-v1' as const, selected_count: null }, {}])('marks missing historical selection provenance as legacy', (fields) => {
    expect(getScanAssessment({ passed_count: 5, failed_count: 0, compliance_score: '80', coverage_score: '100', ...fields })).toMatchObject({ legacy: true, compliance: 80, coverage: null, selected: null });
  });
  it('does not invent a legacy score when none was persisted', () => {
    expect(getScanAssessment({ passed_count: 5 })).toMatchObject({ legacy: true, compliance: null, coverage: null });
  });
  it('counts every terminal state in progress and clamps pending for older responses', () => {
    const { pending_count: _pending, ...scan } = phase3;
    expect(getScanAssessment(scan)).toMatchObject({ pending: 1, done: 8 });
    expect(getScanAssessment({ total_controls: 1, error_count: 3 }).pending).toBe(0);
  });
  it('labels every result state distinctly', () => {
    expect(RESULT_LABELS).toEqual({ passed: 'Pass', failed: 'Fail', error: 'Error', indeterminate: 'Indeterminate', not_assessable: 'Not assessable', skipped: 'Skipped', pending: 'Pending' });
  });
});
