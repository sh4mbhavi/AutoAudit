import { useEffect, useRef } from "react";

export type PollOptions = {
  /** Base delay between the end of one tick and the start of the next. */
  intervalMs: number;
  /** Poll only while this is true. Flipping it to false stops and aborts. */
  enabled: boolean;
  /** Ceiling for the failure backoff. Defaults to eight times the interval. */
  maxIntervalMs?: number;
  /** Test seam for `document`; production always uses the real one. */
  document?: VisibilitySource;
};

/** The only part of `document` this hook uses. A real Document satisfies it. */
export type VisibilitySource = {
  readonly hidden: boolean;
  addEventListener(type: "visibilitychange", handler: () => void): void;
  removeEventListener(type: "visibilitychange", handler: () => void): void;
};

/**
 * Poll without overlapping, without running in a hidden tab, and without
 * hammering a failing API.
 *
 * Before Phase 9 the scan list used a bare `setInterval`, so a response slower
 * than the interval let a second request start before the first returned and
 * two responses could be applied out of order; and the detail page re-armed a
 * flat three-second timer forever after an error. This hook fixes all three
 * problems in one testable place rather than in two pages:
 *
 * - **No overlap.** The next tick is scheduled only after the previous one
 *   settles, so the cadence is `interval + round trip` and never less.
 * - **No hidden-tab traffic.** A backgrounded tab stops polling and resumes on
 *   `visibilitychange`, running immediately if a tick was already due.
 * - **Backoff.** Consecutive failures double the delay up to `maxIntervalMs`;
 *   the first success resets it. A failing API is not polled at a flat rate.
 * - **Cancellation.** Each tick gets an `AbortSignal` that is aborted when the
 *   effect tears down, so a response cannot arrive into a stale component.
 *
 * `run` is read through a ref, so a caller may pass an inline function without
 * restarting the loop on every render.
 */
export function usePoll(
  run: (signal: AbortSignal) => Promise<void>,
  { intervalMs, enabled, maxIntervalMs, document: doc }: PollOptions,
): void {
  const runRef = useRef(run);
  runRef.current = run;

  useEffect(() => {
    if (!enabled) return;
    const view = doc ?? (typeof document === "undefined" ? undefined : document);
    const ceiling = maxIntervalMs ?? intervalMs * 8;

    let stopped = false;
    let timer: ReturnType<typeof setTimeout> | undefined;
    let controller: AbortController | undefined;
    let failures = 0;
    let due = false;
    // Explicit, because the timer handle is NOT an in-flight guard: tick()
    // clears it before awaiting, so for the whole duration of a request the
    // handle reads as "nothing pending" and a visibilitychange would arm a
    // second, parallel chain -- permanently doubling the request rate.
    let running = false;

    const delay = (): number =>
      Math.min(intervalMs * Math.pow(2, failures), ceiling);

    const schedule = (): void => {
      if (stopped || timer !== undefined) return;
      if (view?.hidden) {
        // Nothing is scheduled while hidden; the visibility listener restarts
        // the loop, and `due` records that a tick was owed in the meantime.
        due = true;
        return;
      }
      timer = setTimeout(tick, delay());
    };

    const tick = async (): Promise<void> => {
      timer = undefined;
      if (stopped || running) return;
      if (view?.hidden) {
        // The tab was hidden after this timer was armed. Record the tick as
        // owed and spend nothing; the visibility listener will run it.
        due = true;
        return;
      }
      due = false;
      running = true;
      controller = new AbortController();
      try {
        await runRef.current(controller.signal);
        failures = 0;
      } catch {
        // A poll failure is a reason to slow down, never a reason to stop: the
        // caller decides what a failed poll means for what it renders.
        failures += 1;
      } finally {
        running = false;
      }
      schedule();
    };

    const onVisibility = (): void => {
      if (stopped || view?.hidden || running) return;
      if (timer !== undefined) return;
      if (due) {
        void tick();
      } else {
        schedule();
      }
    };

    view?.addEventListener("visibilitychange", onVisibility);
    schedule();

    return () => {
      stopped = true;
      if (timer !== undefined) clearTimeout(timer);
      controller?.abort();
      view?.removeEventListener("visibilitychange", onVisibility);
    };
  }, [enabled, intervalMs, maxIntervalMs, doc]);
}
