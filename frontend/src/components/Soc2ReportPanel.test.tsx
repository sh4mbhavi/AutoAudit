import React from 'react';
import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import { cleanup, fireEvent, render, screen, waitFor } from '@testing-library/react';

// Mock api/client so client.ts is never loaded (avoids VITE_API_URL throw).
vi.mock('../api/client', () => ({
  getSoc2Report: vi.fn(),
}));

import Soc2ReportPanel from './Soc2ReportPanel';
import { getSoc2Report } from '../api/client';
import type { Soc2ReportResponse } from '../types/soc2';

const mockGetSoc2Report = vi.mocked(getSoc2Report);

function makeReport(overrides: Partial<Soc2ReportResponse> = {}): Soc2ReportResponse {
  return {
    scan_id: 42,
    projection_available: true,
    projection_status: 'available',
    message: '',
    header: {
      mapping_id: 'soc2-cis-m365',
      mapping_version: '1.0.0',
      mapping_digest: 'abc123',
      soc2: {},
      approval: { approved: false },
      approval_pending: true,
      not_a_certification:
        'This is not a SOC 2 certification, attestation or audit opinion.',
      rating_ownership:
        'Configuration ratings are a human GRC judgment copied from the pinned crosswalk.',
    },
    points_of_focus: [
      {
        point_id: 'CC6.1-1',
        criterion: 'CC6.1',
        point_of_focus: 'Logical access is restricted to authorised users.',
        configuration_rating: 'Partial',
        rating_source: 'pinned_mapping',
        rating_is_computed: false,
        selector_resolved: true,
        mapped_control_ids: ['1.1.1'],
        automated_evidence: [],
        coverage: {
          mapped_control_count: 3,
          in_scan_count: 3,
          applicable_count: 3,
          assessed_count: 2,
          passed_count: 1,
          failed_count: 1,
          indeterminate_count: 1,
          error_count: 0,
          not_assessable_count: 0,
          pending_count: 0,
          missing_result_count: 0,
          unassessed_count: 1,
          not_in_scope_count: 0,
          missing_from_benchmark_count: 0,
          coverage_percent: 66.67,
          compliance_percent: 50,
          assessment_completeness: 'partial',
          partial_assessment: true,
          coverage_statement: '2 of 3 applicable controls assessed.',
        },
        manual_residual_evidence: [],
        limitations: {},
      },
    ],
    ...overrides,
  } as Soc2ReportResponse;
}

beforeEach(() => {
  mockGetSoc2Report.mockReset();
});

afterEach(() => {
  cleanup();
});

describe('Soc2ReportPanel', () => {
  it('does not fetch the report until it is opened', () => {
    render(<Soc2ReportPanel scanId={42} isDarkMode={false} />);
    expect(mockGetSoc2Report).not.toHaveBeenCalled();
  });

  it('fetches and renders the projection when opened', async () => {
    mockGetSoc2Report.mockResolvedValue(makeReport());
    render(<Soc2ReportPanel scanId={42} isDarkMode={false} />);

    fireEvent.click(screen.getByRole('button', { name: 'Show' }));

    await waitFor(() => {
      expect(mockGetSoc2Report).toHaveBeenCalledWith(42, expect.anything());
    });
    expect(
      await screen.findByText(
        'Logical access is restricted to authorised users.',
      ),
    ).toBeInTheDocument();
  });

  it('never suppresses the not-a-certification statement', async () => {
    mockGetSoc2Report.mockResolvedValue(makeReport());
    render(<Soc2ReportPanel scanId={42} isDarkMode={false} />);
    fireEvent.click(screen.getByRole('button', { name: 'Show' }));

    expect(
      await screen.findByText(
        'This is not a SOC 2 certification, attestation or audit opinion.',
      ),
    ).toBeInTheDocument();
  });

  it('shows both coverage numbers and never a bare percentage', async () => {
    mockGetSoc2Report.mockResolvedValue(makeReport());
    const { container } = render(
      <Soc2ReportPanel scanId={42} isDarkMode={false} />,
    );
    fireEvent.click(screen.getByRole('button', { name: 'Show' }));

    expect(
      await screen.findByText(/2 of 3 applicable control\(s\) assessed/),
    ).toBeInTheDocument();
    // The response carries coverage_percent and compliance_percent. Rendering
    // either alone is the thing the contract forbids.
    expect(container.textContent).not.toContain('66.67');
    expect(container.textContent).not.toContain('50%');
  });

  it('states that the report is owner-scoped and names no tenant', async () => {
    mockGetSoc2Report.mockResolvedValue(makeReport());
    render(<Soc2ReportPanel scanId={42} isDarkMode={false} />);
    fireEvent.click(screen.getByRole('button', { name: 'Show' }));

    expect(
      await screen.findByText(/Scoped to the account that owns this scan/),
    ).toBeInTheDocument();
  });

  it('renders the message verbatim when there is no projection', async () => {
    mockGetSoc2Report.mockResolvedValue(
      makeReport({
        projection_available: false,
        projection_status: 'no_projection',
        message: 'This scan pinned no SOC 2 mapping.',
        header: null,
        points_of_focus: [],
      }),
    );
    render(<Soc2ReportPanel scanId={42} isDarkMode={false} />);
    fireEvent.click(screen.getByRole('button', { name: 'Show' }));

    expect(
      await screen.findByText('This scan pinned no SOC 2 mapping.'),
    ).toBeInTheDocument();
  });

  it('surfaces a load failure rather than rendering an empty report', async () => {
    mockGetSoc2Report.mockRejectedValue(new Error('403 Forbidden'));
    render(<Soc2ReportPanel scanId={42} isDarkMode={false} />);
    fireEvent.click(screen.getByRole('button', { name: 'Show' }));

    expect(await screen.findByText('403 Forbidden')).toBeInTheDocument();
  });
});
