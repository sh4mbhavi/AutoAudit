import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { act, cleanup, renderHook } from "@testing-library/react";
import { usePoll } from "./usePoll";

/** A document stand-in whose visibility the test controls. */
function fakeDocument() {
  const listeners = new Set<() => void>();
  return {
    hidden: false,
    addEventListener(_: "visibilitychange", handler: () => void): void {
      listeners.add(handler);
    },
    removeEventListener(_: "visibilitychange", handler: () => void): void {
      listeners.delete(handler);
    },
    show(): void {
      this.hidden = false;
      listeners.forEach(handler => handler());
    },
    hide(): void {
      this.hidden = true;
      listeners.forEach(handler => handler());
    },
    get listenerCount(): number {
      return listeners.size;
    },
  };
}

beforeEach(() => vi.useFakeTimers());
afterEach(() => {
  cleanup();
  vi.useRealTimers();
});

describe("usePoll", () => {
  it("does not poll at all while disabled", async () => {
    const run = vi.fn().mockResolvedValue(undefined);
    renderHook(() => usePoll(run, { intervalMs: 1000, enabled: false }));
    await act(async () => {
      await vi.advanceTimersByTimeAsync(10_000);
    });
    expect(run).not.toHaveBeenCalled();
  });

  it("waits for the previous tick to settle before scheduling the next", async () => {
    // A response slower than the interval must not let a second request start:
    // the old setInterval let two run at once and apply out of order.
    let settle!: () => void;
    const run = vi.fn().mockImplementation(
      () => new Promise<void>(resolve => { settle = resolve; }),
    );
    renderHook(() => usePoll(run, { intervalMs: 1000, enabled: true }));
    await act(async () => { await vi.advanceTimersByTimeAsync(1000); });
    expect(run).toHaveBeenCalledTimes(1);
    await act(async () => { await vi.advanceTimersByTimeAsync(10_000); });
    expect(run).toHaveBeenCalledTimes(1);
    await act(async () => { settle(); });
    await act(async () => { await vi.advanceTimersByTimeAsync(1000); });
    expect(run).toHaveBeenCalledTimes(2);
  });

  it("keeps a steady cadence while responses are fast", async () => {
    const run = vi.fn().mockResolvedValue(undefined);
    renderHook(() => usePoll(run, { intervalMs: 1000, enabled: true }));
    await act(async () => { await vi.advanceTimersByTimeAsync(3000); });
    expect(run).toHaveBeenCalledTimes(3);
  });

  it("stops polling in a hidden tab and resumes when it becomes visible", async () => {
    const view = fakeDocument();
    const run = vi.fn().mockResolvedValue(undefined);
    renderHook(() =>
      usePoll(run, { intervalMs: 1000, enabled: true, document: view }),
    );
    await act(async () => { await vi.advanceTimersByTimeAsync(1000); });
    expect(run).toHaveBeenCalledTimes(1);
    act(() => view.hide());
    await act(async () => { await vi.advanceTimersByTimeAsync(60_000); });
    expect(run).toHaveBeenCalledTimes(1);
    await act(async () => { view.show(); });
    // A tick was owed while hidden, so becoming visible runs it immediately
    // rather than waiting out another full interval.
    expect(run).toHaveBeenCalledTimes(2);
  });

  it("backs off on consecutive failures and resets on the first success", async () => {
    const run = vi
      .fn()
      .mockRejectedValueOnce(new Error("one"))
      .mockRejectedValueOnce(new Error("two"))
      .mockResolvedValue(undefined);
    renderHook(() => usePoll(run, { intervalMs: 1000, enabled: true }));
    await act(async () => { await vi.advanceTimersByTimeAsync(1000); });
    expect(run).toHaveBeenCalledTimes(1);
    // First failure doubles the delay: nothing at +1000, a call at +2000.
    await act(async () => { await vi.advanceTimersByTimeAsync(1000); });
    expect(run).toHaveBeenCalledTimes(1);
    await act(async () => { await vi.advanceTimersByTimeAsync(1000); });
    expect(run).toHaveBeenCalledTimes(2);
    // Second failure quadruples it.
    await act(async () => { await vi.advanceTimersByTimeAsync(3000); });
    expect(run).toHaveBeenCalledTimes(2);
    await act(async () => { await vi.advanceTimersByTimeAsync(1000); });
    expect(run).toHaveBeenCalledTimes(3);
    // That one succeeded, so the delay is back to the base interval.
    await act(async () => { await vi.advanceTimersByTimeAsync(1000); });
    expect(run).toHaveBeenCalledTimes(4);
  });

  it("never backs off past the ceiling", async () => {
    const run = vi.fn().mockRejectedValue(new Error("always"));
    renderHook(() =>
      usePoll(run, { intervalMs: 1000, enabled: true, maxIntervalMs: 2000 }),
    );
    await act(async () => { await vi.advanceTimersByTimeAsync(1000); });
    await act(async () => { await vi.advanceTimersByTimeAsync(2000); });
    await act(async () => { await vi.advanceTimersByTimeAsync(2000); });
    await act(async () => { await vi.advanceTimersByTimeAsync(2000); });
    expect(run).toHaveBeenCalledTimes(4);
  });

  it("aborts the in-flight request when it stops", async () => {
    let seen!: AbortSignal;
    const run = vi.fn().mockImplementation((signal: AbortSignal) => {
      seen = signal;
      return new Promise<void>(() => {});
    });
    const view = fakeDocument();
    const { unmount } = renderHook(() =>
      usePoll(run, { intervalMs: 1000, enabled: true, document: view }),
    );
    await act(async () => { await vi.advanceTimersByTimeAsync(1000); });
    expect(seen.aborted).toBe(false);
    unmount();
    expect(seen.aborted).toBe(true);
    expect(view.listenerCount).toBe(0);
  });

  it("stops when it is disabled mid-flight", async () => {
    const run = vi.fn().mockResolvedValue(undefined);
    const { rerender } = renderHook(
      ({ enabled }) => usePoll(run, { intervalMs: 1000, enabled }),
      { initialProps: { enabled: true } },
    );
    await act(async () => { await vi.advanceTimersByTimeAsync(1000); });
    expect(run).toHaveBeenCalledTimes(1);
    rerender({ enabled: false });
    await act(async () => { await vi.advanceTimersByTimeAsync(10_000); });
    expect(run).toHaveBeenCalledTimes(1);
  });

  it("does not restart the loop when the caller passes a new closure", async () => {
    const run = vi.fn().mockResolvedValue(undefined);
    const { rerender } = renderHook(() =>
      usePoll(() => run(), { intervalMs: 1000, enabled: true }),
    );
    rerender();
    rerender();
    await act(async () => { await vi.advanceTimersByTimeAsync(1000); });
    expect(run).toHaveBeenCalledTimes(1);
  });
});

describe("usePoll in-flight guard", () => {
  it("does not fork a second chain when the tab becomes visible mid-request", async () => {
    // Found in review: the timer handle was used as the "a tick is pending"
    // guard, but tick() clears it before awaiting, so during the whole
    // in-flight window a visibilitychange armed a second, parallel chain and
    // permanently doubled the request rate.
    const view = fakeDocument();
    let settle!: () => void;
    const run = vi.fn().mockImplementation(
      () => new Promise<void>(resolve => { settle = resolve; }),
    );
    renderHook(() =>
      usePoll(run, { intervalMs: 1000, enabled: true, document: view }),
    );
    await act(async () => { await vi.advanceTimersByTimeAsync(1000); });
    expect(run).toHaveBeenCalledTimes(1);
    // The request is still in flight. Three visibility flips must add nothing.
    act(() => { view.show(); view.show(); view.show(); });
    await act(async () => { await vi.advanceTimersByTimeAsync(5000); });
    expect(run).toHaveBeenCalledTimes(1);
    await act(async () => { settle(); });
    await act(async () => { await vi.advanceTimersByTimeAsync(1000); });
    expect(run).toHaveBeenCalledTimes(2);
    // Still exactly one chain: settling the second request and advancing one
    // more interval yields one more call, not two.
    await act(async () => { settle(); });
    await act(async () => { await vi.advanceTimersByTimeAsync(1000); });
    expect(run).toHaveBeenCalledTimes(3);
  });

  it("keeps exactly one chain across repeated hide/show cycles", async () => {
    const view = fakeDocument();
    const run = vi.fn().mockResolvedValue(undefined);
    renderHook(() =>
      usePoll(run, { intervalMs: 1000, enabled: true, document: view }),
    );
    for (let cycle = 0; cycle < 3; cycle += 1) {
      act(() => view.hide());
      await act(async () => { await vi.advanceTimersByTimeAsync(1000); });
      await act(async () => { view.show(); });
    }
    const after = run.mock.calls.length;
    await act(async () => { await vi.advanceTimersByTimeAsync(1000); });
    expect(run).toHaveBeenCalledTimes(after + 1);
  });
});
