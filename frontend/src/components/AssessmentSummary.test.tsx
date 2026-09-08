import React from 'react';
import { afterEach, describe, expect, it } from 'vitest';
import { cleanup, render, screen } from '@testing-library/react';
import AssessmentSummary from './AssessmentSummary';

afterEach(cleanup);
describe('AssessmentSummary', () => {
  it('qualifies 100% compliance with partial automated coverage and all state counts', () => {
    render(<AssessmentSummary scan={{ semantics_version: 'phase3-v1', selected_count: 5, passed_count: 1, failed_count: 0, indeterminate_count: 1, error_count: 1, not_assessable_count: 1, pending_count: 1, skipped_count: 2, compliance_score: '100.00', coverage_score: '20.00' }} />);
    expect(screen.getByText('Compliance among assessed: 100% (1/1)')).toBeInTheDocument();
    expect(screen.getByText('Automated coverage: 20% (1/5 selected)')).toBeInTheDocument();
    expect(screen.getByText('Partial assessment')).toBeInTheDocument();
    for (const label of ['Selected: 5', 'Indeterminate: 1', 'Not assessable: 1', 'Error: 1', 'Skipped: 2', 'Pending: 1']) expect(screen.getByText(label)).toBeInTheDocument();
  });
  it('shows Not assessed for zero evaluated controls', () => {
    render(<AssessmentSummary scan={{ semantics_version: 'phase3-v1', selected_count: 3, compliance_score: null, coverage_score: '0' }} />);
    expect(screen.getByText('Compliance among assessed: Not assessed (0/0)')).toBeInTheDocument();
    expect(screen.queryByText(/compliant/i)).not.toBeInTheDocument();
  });
  it('labels historical scores and unavailable coverage', () => {
    render(<AssessmentSummary scan={{ compliance_score: '90', passed_count: 9 }} />);
    expect(screen.getByText('Legacy score: 90%')).toBeInTheDocument();
    expect(screen.getByText('Automated coverage unavailable for legacy scan')).toBeInTheDocument();
    expect(screen.getByText('Selected: Unknown')).toBeInTheDocument();
  });
});
