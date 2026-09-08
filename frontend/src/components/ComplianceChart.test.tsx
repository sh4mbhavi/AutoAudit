import React from 'react';
import { afterEach, expect, it, vi } from 'vitest';
import { cleanup, render, screen } from '@testing-library/react';
import ComplianceChart from './ComplianceChart';
vi.mock('react-apexcharts', () => ({ default: (props: unknown) => <div data-testid="chart">{JSON.stringify(props)}</div> }));
afterEach(cleanup);
it('charts all seven states without counting unknown evidence as failed', () => {
  render(<ComplianceChart isDarkMode chartType="doughnut" scan={{ passed_count: 2, failed_count: 1, indeterminate_count: 3, error_count: 4, not_assessable_count: 5, skipped_count: 6, pending_count: 7 }} />);
  const chart = JSON.parse(screen.getByTestId('chart').textContent!);
  expect(chart.options.labels).toEqual(['Pass', 'Fail', 'Indeterminate', 'Error', 'Skipped', 'Not assessable', 'Pending']);
  expect(chart.series).toEqual([2, 1, 3, 4, 6, 5, 7]);
});
it('charts persisted compliance and coverage together, preserving null rather than zero', () => {
  render(<ComplianceChart isDarkMode={false} chartType="bar" scans={[
    { id: 1, status: 'completed', semantics_version: 'phase3-v1', selected_count: 4, compliance_score: '100', coverage_score: '25' },
    { id: 2, status: 'completed', semantics_version: 'phase3-v1', selected_count: 4, compliance_score: null, coverage_score: '0' },
    { id: 3, status: 'completed', compliance_score: '80' },
  ]} />);
  const chart = JSON.parse(screen.getByTestId('chart').textContent!);
  expect(chart.series).toEqual([{ name: 'Compliance among assessed', data: [null, null, 100] }, { name: 'Automated coverage', data: [null, 0, 25] }]);
  expect(screen.getByText(/Legacy scans have no comparable coverage/)).toBeInTheDocument();
  expect(screen.getByText(/Not assessed.*#2/)).toBeInTheDocument();
});
it('reports no scan data without fetching a route scan ID', () => {
  render(<ComplianceChart isDarkMode chartType="pie" />);
  expect(screen.getByText('No scan results available')).toBeInTheDocument();
});
