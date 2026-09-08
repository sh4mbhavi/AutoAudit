import React from 'react';
import { afterEach, expect, it, vi } from 'vitest';
import { cleanup, render, screen } from '@testing-library/react';
import { MemoryRouter } from 'react-router-dom';
import Dashboard from './Dashboard';
import { getScans } from '../api/client';
vi.mock('../context/AuthContext', () => ({ useAuth: () => ({ user: {id: 1} }) }));
vi.mock('../api/client', () => ({ getScans: vi.fn(), getConnections: vi.fn().mockResolvedValue([]), getBenchmarks: vi.fn().mockResolvedValue([]), getScan: vi.fn().mockResolvedValue({ id: 1, results: [] }) }));
vi.mock('react-apexcharts', () => ({ default: () => <div>Results chart</div> }));
afterEach(cleanup);
it('shows persisted assessment and partial coverage on the dashboard', async () => {
  vi.mocked(getScans).mockResolvedValue([{ id: 1, status: 'completed', semantics_version: 'phase3-v1', selected_count: 5, total_controls: 5, passed_count: 1, failed_count: 0, not_assessable_count: 2, indeterminate_count: 1, error_count: 1, compliance_score: '100', coverage_score: '20' }]);
  render(<MemoryRouter><Dashboard isDarkMode /></MemoryRouter>);
  expect((await screen.findAllByText('Partial assessment')).length).toBeGreaterThan(0);
  expect(screen.getAllByText('Automated coverage: 20% (1/5 selected)').length).toBeGreaterThan(0);
  expect(screen.getByText('Results chart')).toBeInTheDocument();
  expect(screen.queryByText('Failed to load scan')).not.toBeInTheDocument();
});
it('labels collection errors separately from failed controls in suggested follow-up', async () => {
  const { getScan } = await import('../api/client');
  vi.mocked(getScans).mockResolvedValue([{ id: 2, status: 'completed', semantics_version: 'phase3-v1', selected_count: 1, total_controls: 1, error_count: 1, compliance_score: null, coverage_score: 0 }]);
  vi.mocked(getScan).mockResolvedValue({ id: 2, results: [{ control_id: '1.1', status: 'error', message: 'Could not collect evidence' }] });
  render(<MemoryRouter><Dashboard isDarkMode /></MemoryRouter>);
  const followUp = await screen.findByRole('button', { name: /1.1.*Error.*Could not collect evidence/ });
  expect(followUp).toBeInTheDocument();
  expect(screen.queryByText('Top failing controls from the latest scan')).not.toBeInTheDocument();
  expect(screen.getAllByText('Compliance among assessed: Not assessed (0/0)').length).toBeGreaterThan(0);
});
it.each([
  { score: 0, passed: 0, failed: 2, selected: 2, coverage: 100, tone: 'bad', successIcon: false },
  { score: 50, passed: 1, failed: 1, selected: 2, coverage: 100, tone: 'bad', successIcon: false },
  { score: 100, passed: 1, failed: 0, selected: 2, coverage: 50, tone: 'warn', successIcon: false },
  { score: 100, passed: 2, failed: 0, selected: 2, coverage: 100, tone: 'good', successIcon: true },
])('uses $tone styling for $score% compliance at $coverage% coverage', async ({ score, passed, failed, selected, coverage, tone, successIcon }) => {
  vi.mocked(getScans).mockResolvedValue([{ id: 3, status: 'completed', semantics_version: 'phase3-v1', selected_count: selected, total_controls: selected, passed_count: passed, failed_count: failed, compliance_score: score, coverage_score: coverage }]);
  render(<MemoryRouter><Dashboard isDarkMode /></MemoryRouter>);
  const chip = await screen.findByText(`Compliance among assessed ${score}%`);
  expect(chip.className).toContain(`accent-${tone}`);
  expect(Boolean(chip.querySelector('.lucide-circle-check'))).toBe(successIcon);
});
