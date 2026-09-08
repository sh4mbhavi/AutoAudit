"""Bounded, order-preserving concurrency for per-item collector requests.

Several collectors issue one request per item returned by a list call. Serial
execution makes those collectors O(n) round trips of latency; unbounded
concurrency replaces that with an unbounded burst against a throttled tenant
API, which is the anti-pattern this phase is explicitly forbidden from
introducing. ``gather_bounded`` sits between the two: at most ``limit`` requests
are ever in flight, results keep their input order, and the failure semantics are
the same ones a serial loop had.

Failure semantics, stated precisely because evidence depends on them:

* If any item fails, ``gather_bounded`` raises. It never returns a partial list,
  because a partially collected set is not the tenant's configuration.
* The exception raised is the one belonging to the **lowest input index** among
  the items that actually failed, so the same inputs always surface the same
  error. A serial loop raised the first failure in input order; this preserves
  that for every case a serial loop could reach.
* After the first failure is observed, items that have not started are not
  started at all. At most ``limit - 1`` further requests can already be in
  flight, so a denied or throttled collection costs a bounded overshoot rather
  than the whole list.
"""

import asyncio
from typing import Awaitable, Callable, Sequence, TypeVar

T = TypeVar("T")

# What a collector may run concurrently against one tenant. Small on purpose:
# Microsoft Graph throttles per application per tenant, and the point of this
# module is to remove serial latency, not to raise the burst rate.
DEFAULT_LIMIT = 4


def collection_limit() -> int:
    """The configured bound, resolved at call time.

    Read through the worker settings rather than an environment lookup of its
    own so there is exactly one place a deployment configures this, and read at
    call time so a test can set it without reimporting the collector.
    """
    from worker.config import settings

    return int(getattr(settings, "GRAPH_MAX_CONCURRENCY", DEFAULT_LIMIT))


class _Skipped:
    """Marker for an item deliberately not started after an earlier failure."""

    __slots__ = ()


_SKIPPED = _Skipped()


async def gather_bounded(
    factories: Sequence[Callable[[], Awaitable[T]]],
    limit: int | None = None,
) -> list[T]:
    """Run ``factories`` with at most ``limit`` in flight; return results in order.

    Each element must be a zero-argument callable returning an awaitable, not an
    awaitable itself: an awaitable created up front is already scheduled work,
    and the whole point here is that later items are never created when an
    earlier one has failed.
    """
    if limit is None:
        limit = collection_limit()
    if limit < 1:
        raise ValueError("Concurrency limit must be at least 1")
    if not factories:
        return []

    semaphore = asyncio.Semaphore(limit)
    failed = False
    results: list[object] = [_SKIPPED] * len(factories)
    errors: dict[int, BaseException] = {}

    async def run(index: int, factory: Callable[[], Awaitable[T]]) -> None:
        nonlocal failed
        async with semaphore:
            if failed:
                # An earlier item already failed and this one had not started.
                # Do not spend a tenant request on evidence that will be
                # discarded anyway.
                return
            try:
                results[index] = await factory()
            except asyncio.CancelledError:
                # Cooperative cancellation of the whole collection is not a
                # collector failure and must not be recorded as one.
                raise
            except Exception as exc:  # noqa: BLE001 - re-raised in input order
                failed = True
                errors[index] = exc

    await asyncio.gather(
        *(run(index, factory) for index, factory in enumerate(factories))
    )

    if errors:
        raise errors[min(errors)]
    if any(result is _SKIPPED for result in results):
        # Unreachable while errors is empty: an item is only skipped once a
        # failure has been recorded. Refuse to return a hole rather than trust
        # that invariant silently.
        raise RuntimeError("Bounded collection returned an incomplete result set")
    return results  # type: ignore[return-value]
