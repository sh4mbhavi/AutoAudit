import React from 'react';
import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import { act, cleanup, fireEvent, render, screen, waitFor } from '@testing-library/react';
import { MemoryRouter } from 'react-router-dom';
import ScanDetailPage from './ScanDetailPage';

// Mock react-router-dom hooks so we control the scanId param.
vi.mock('react-router-dom', async () => {
  const actual = await vi.importActual<typeof import('react-router-dom')>('react-router-dom');
  return {
    ...actual,
    useParams: vi.fn().mockReturnValue({ scanId: '42' }),
    useNavigate: vi.fn().mockReturnValue(vi.fn()),
  };
});

// Mock AuthContext so it never touches the real token storage.
vi.mock('../../context/AuthContext', () => ({
  useAuth: vi.fn().mockReturnValue({ user: {id: 1} }),
}));

// Mock api/client so client.ts is never loaded (avoids VITE_API_URL throw).
vi.mock('../../api/client', () => ({
  getScan: vi.fn(),
  cancelScan: vi.fn(),
}));

import { cancelScan, getScan } from '../../api/client';

// Minimal scan object that satisfies the ScanDetail type used in the component.
function makeScan(overrides: Record<string, unknown> = {}) {
  return {
    id: 42,
    status: 'completed',
    benchmark: 'CIS Microsoft 365',
    version: 'v3.0',
    connection_name: 'Test Connection',
    started_at: '2026-01-17T00:00:00Z',
    finished_at: '2026-01-17T01:00:00Z',
    total_controls: 3,
    passed_count: 2,
    failed_count: 1,
    error_count: 0,
    skipped_count: 0,
    results: [],
    ...overrides,
  };
}

function renderPage() {
  return render(
    <MemoryRouter>
      <ScanDetailPage />
    </MemoryRouter>
  );
}

// Wait until the loading spinner disappears (initial load complete).
function waitForLoaded() {
  return waitFor(() =>
    expect(screen.queryByText(/loading scan details/i)).not.toBeInTheDocument()
  );
}

beforeEach(() => vi.clearAllMocks());
afterEach(() => { cleanup(); vi.useRealTimers(); });

// --- Loading state ---

describe('ScanDetailPage loading state', () => {
  it('shows a loading indicator while the scan is being fetched', () => {
    // Never resolves — keeps the component in loading state
    vi.mocked(getScan).mockReturnValue(new Promise(() => {}));
    renderPage();
    expect(screen.getByText(/loading scan details/i)).toBeInTheDocument();
  });
});

// --- Error state ---

describe('ScanDetailPage error state', () => {
  it('shows an error message when getScan rejects', async () => {
    vi.mocked(getScan).mockRejectedValue(new Error('Network failure'));
    renderPage();
    await waitFor(() =>
      expect(screen.getByText(/failed to load scan/i)).toBeInTheDocument()
    );
  });

  it('displays the specific error message from the rejection', async () => {
    vi.mocked(getScan).mockRejectedValue(new Error('Scan not found'));
    renderPage();
    await waitFor(() =>
      expect(screen.getByText('Scan not found')).toBeInTheDocument()
    );
  });
});

// --- Scan details rendering ---

describe('ScanDetailPage scan details', () => {
  it('renders the scan benchmark name', async () => {
    vi.mocked(getScan).mockResolvedValue(makeScan());
    renderPage();
    await waitForLoaded();
    expect(screen.getByRole('heading', { name: /CIS Microsoft 365/i })).toBeInTheDocument();
  });

  it('renders the connection name', async () => {
    vi.mocked(getScan).mockResolvedValue(makeScan());
    renderPage();
    await waitForLoaded();
    expect(screen.getByText('Test Connection')).toBeInTheDocument();
  });
});

// --- getStatusText (private — tested via the rendered status badge) ---

describe('getStatusText', () => {
  it.each([
    ['completed', 'Completed'],
    ['failed', 'Failed'],
    ['cancelled', 'Cancelled'],
    ['running', 'Running'],
    [undefined, 'Pending'],
  ])('status %s renders badge text "%s"', async (status, expectedText) => {
    vi.mocked(getScan).mockResolvedValue(makeScan({ status }));
    renderPage();
    await waitForLoaded();
    expect(screen.getAllByText(expectedText as string).length).toBeGreaterThan(0);
  });
});

// --- getResultBadgeText (private — tested via rendered result cards) ---

describe('getResultBadgeText', () => {
  it.each([
    ['passed', 'Pass'],
    ['failed', 'Fail'],
    ['error', 'Error'],
    ['pending', 'Pending'],
  ])('result status %s renders badge text "%s"', async (status, expectedText) => {
    vi.mocked(getScan).mockResolvedValue(
      makeScan({
        status: 'completed',
        results: [{ control_id: '1.1', status, title: 'Test control' }],
      })
    );
    renderPage();
    await waitForLoaded();
    expect(screen.getByText(expectedText)).toBeInTheDocument();
  });
});

// --- Skipped results ---

describe('ScanDetailPage result filtering', () => {
  it('does not render results with status "skipped"', async () => {
    vi.mocked(getScan).mockResolvedValue(
      makeScan({
        status: 'completed',
        results: [
          { control_id: '1.1', status: 'passed', title: 'Visible control' },
          { control_id: '1.2', status: 'skipped', title: 'Hidden skipped control' },
        ],
      })
    );
    renderPage();
    await waitForLoaded();

    expect(screen.getByText('Visible control')).toBeInTheDocument();
    expect(screen.queryByText('Hidden skipped control')).not.toBeInTheDocument();
  });
});

// --- compareControlIdAscending (private — tested via DOM order of rendered results) ---

describe('compareControlIdAscending', () => {
  it('renders results sorted by control ID in ascending order', async () => {
    vi.mocked(getScan).mockResolvedValue(
      makeScan({
        status: 'completed',
        results: [
          { control_id: '2.1', status: 'passed', title: 'Control 2.1' },
          { control_id: '1.10', status: 'passed', title: 'Control 1.10' },
          { control_id: '1.1', status: 'passed', title: 'Control 1.1' },
          { control_id: '1.2', status: 'passed', title: 'Control 1.2' },
        ],
      })
    );

    const { container } = renderPage();
    await waitForLoaded();

    const controlIdSpans = container.querySelectorAll('[class*="font-mono"]');
    const renderedIds = Array.from(controlIdSpans).map((el) => el.textContent);
    expect(renderedIds).toEqual(['1.1', '1.2', '1.10', '2.1']);
  });

  it('sorts numeric segments correctly so 1.10 comes after 1.9', async () => {
    vi.mocked(getScan).mockResolvedValue(
      makeScan({
        status: 'completed',
        results: [
          { control_id: '1.10', status: 'passed', title: 'Control 1.10' },
          { control_id: '1.9', status: 'passed', title: 'Control 1.9' },
        ],
      })
    );

    const { container } = renderPage();
    await waitForLoaded();

    const controlIdSpans = container.querySelectorAll('[class*="font-mono"]');
    const renderedIds = Array.from(controlIdSpans).map((el) => el.textContent);
    expect(renderedIds).toEqual(['1.9', '1.10']);
  });
});

describe('Phase 3 scan detail', () => {
  it('distinguishes inconclusive results and counts them as finished', async () => {
    vi.mocked(getScan).mockResolvedValue(makeScan({ status: 'running', semantics_version: 'phase3-v1', total_controls: 6, selected_count: 5, passed_count: 1, failed_count: 0, error_count: 1, indeterminate_count: 1, not_assessable_count: 1, skipped_count: 1, pending_count: 1, compliance_score: '100', coverage_score: '20', results: [
      { control_id: '1.1', status: 'indeterminate', title: 'Missing evidence' },
      { control_id: '1.2', status: 'not_assessable', title: 'Manual check' },
    ] }));
    renderPage();
    await waitForLoaded();
    expect(screen.getByText('Indeterminate')).toBeInTheDocument();
    expect(screen.getByText('Not assessable')).toBeInTheDocument();
    expect(screen.getByText('Evaluating controls... 5 of 6 complete')).toBeInTheDocument();
    expect(screen.getByText('Partial assessment')).toBeInTheDocument();
    expect(screen.getByText('Automated coverage: 20% (1/5 selected)')).toBeInTheDocument();
  });
});


describe('scan cancellation', () => {
  it('cancels an active scan, shows busy state and stops polling', async () => {
    vi.useFakeTimers();
    vi.mocked(getScan).mockResolvedValue(makeScan({ status: 'running' }));
    let resolveCancel!: (value: { id: number; status: string; message: string }) => void;
    vi.mocked(cancelScan).mockReturnValue(new Promise(resolve => { resolveCancel = resolve; }));
    renderPage();
    await act(async () => {});
    fireEvent.click(screen.getByRole('button', { name: 'Cancel scan' }));
    expect(cancelScan).toHaveBeenCalledWith('42');
    expect(screen.getByRole('button', { name: 'Cancelling...' })).toBeDisabled();
    vi.mocked(getScan).mockResolvedValue(makeScan({ status: 'cancelled', pending_count: 0 }));
    await act(async () => { resolveCancel({ id: 42, status: 'cancelled', message: 'Scan cancelled' }); });
    expect(screen.getByText('Cancelled')).toBeInTheDocument();
    expect(screen.queryByText('Scan in Progress')).not.toBeInTheDocument();
    expect(screen.queryByRole('button', { name: 'Cancel scan' })).not.toBeInTheDocument();
    const callsAfterCancellation = vi.mocked(getScan).mock.calls.length;
    await act(async () => { await vi.advanceTimersByTimeAsync(9000); });
    expect(getScan).toHaveBeenCalledTimes(callsAfterCancellation);
  });

  it('does not poll a scan already cancelled', async () => {
    vi.useFakeTimers();
    vi.mocked(getScan).mockResolvedValue(makeScan({ status: 'cancelled' }));
    renderPage();
    await act(async () => {});
    await act(async () => { await vi.advanceTimersByTimeAsync(9000); });
    expect(getScan).toHaveBeenCalledOnce();
  });

  it('keeps the scan visible and allows retry if cancellation fails', async () => {
    vi.mocked(getScan).mockResolvedValue(makeScan({ status: 'pending' }));
    vi.mocked(cancelScan).mockRejectedValue(new Error('Cancellation unavailable'));
    renderPage();
    await waitForLoaded();
    fireEvent.click(screen.getByRole('button', { name: 'Cancel scan' }));
    expect(await screen.findByRole('alert')).toHaveTextContent('Cancellation unavailable');
    expect(screen.getByRole('heading', { name: 'CIS Microsoft 365' })).toBeInTheDocument();
    expect(screen.getByRole('button', { name: 'Cancel scan' })).toBeEnabled();
  });
});

describe('slow scan polling', () => {
  it('applies progress and terminal responses when every poll takes six seconds', async () => {
    vi.useFakeTimers();
    let pollCount = 0;
    vi.mocked(getScan)
      .mockResolvedValueOnce(makeScan({ status: 'running', connection_name: 'Initial state' }))
      .mockImplementation(() => new Promise(resolve => {
        const currentPoll = ++pollCount;
        setTimeout(() => resolve(makeScan({
          status: currentPoll === 1 ? 'running' : 'completed',
          connection_name: currentPoll === 1 ? 'Progress received' : 'Terminal received',
        })), 6000);
      }));
    renderPage();
    await act(async () => {});
    await act(async () => { await vi.advanceTimersByTimeAsync(9000); });
    expect(screen.getByText('Progress received')).toBeInTheDocument();
    await act(async () => { await vi.advanceTimersByTimeAsync(9000); });
    expect(screen.getByText('Terminal received')).toBeInTheDocument();
    expect(screen.queryByText('Scan in Progress')).not.toBeInTheDocument();
    await act(async () => { await vi.advanceTimersByTimeAsync(15000); });
    expect(getScan).toHaveBeenCalledTimes(3);
  });

  it('ignores a slow running response that arrives after cancellation', async () => {
    vi.useFakeTimers();
    vi.mocked(getScan)
      .mockResolvedValueOnce(makeScan({ status: 'running' }))
      .mockImplementationOnce(() => new Promise(resolve => {
        setTimeout(() => resolve(makeScan({ status: 'running' })), 6000);
      }))
      .mockResolvedValue(makeScan({ status: 'cancelled' }));
    vi.mocked(cancelScan).mockResolvedValue({ id: 42, status: 'cancelled', message: 'Scan cancelled' });
    renderPage();
    await act(async () => {});
    await act(async () => { await vi.advanceTimersByTimeAsync(3000); });
    fireEvent.click(screen.getByRole('button', { name: 'Cancel scan' }));
    await act(async () => {});
    await act(async () => { await vi.advanceTimersByTimeAsync(15000); });
    expect(screen.getByText('Cancelled')).toBeInTheDocument();
    expect(screen.queryByText('Scan in Progress')).not.toBeInTheDocument();
    expect(getScan).toHaveBeenCalledTimes(3);
  });
});
