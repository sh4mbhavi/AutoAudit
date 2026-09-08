import React from 'react';
import { afterEach, expect, it, vi } from 'vitest';
import { act, cleanup, render, screen } from '@testing-library/react';
import { MemoryRouter } from 'react-router-dom';
import ScansPage from './ScansPage';
import { getScans, type ScanListItem } from '../../api/client';

vi.mock('../../context/AuthContext', () => ({ useAuth: vi.fn().mockReturnValue({ user: { id: 1 } }) }));
vi.mock('../../api/client', () => ({
  getScans: vi.fn(),
  getConnections: vi.fn().mockResolvedValue([]),
  getBenchmarks: vi.fn().mockResolvedValue([]),
  getSettings: vi.fn().mockResolvedValue({}),
}));
afterEach(() => { cleanup(); vi.useRealTimers(); vi.clearAllMocks(); });

it('labels a cancelled scan accurately and does not poll it', async () => {
  vi.useFakeTimers();
    // A partial fixture: the page reads four fields, and spelling out the whole
  // generated ScanListItem here would assert nothing extra.
  vi.mocked(getScans).mockResolvedValue([
    { id: 42, status: 'cancelled', benchmark: 'CIS Microsoft 365', total_controls: 1 },
  ] as unknown as ScanListItem[]);
  render(<MemoryRouter><ScansPage /></MemoryRouter>);
  await act(async () => {});
  expect(screen.getByText('Cancelled')).toBeInTheDocument();
  await act(async () => { await vi.advanceTimersByTimeAsync(15000); });
  expect(getScans).toHaveBeenCalledOnce();
});
