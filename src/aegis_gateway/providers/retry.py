import asyncio
import random
from collections.abc import Awaitable, Callable

RETRYABLE_STATUS_CODES = frozenset({429, 500, 502, 503, 504})


async def call_with_retry[T](
    fn: Callable[[], Awaitable[T]],
    *,
    is_retryable: Callable[[Exception], bool],
    max_attempts: int = 3,
    base_delay: float = 0.25,
    max_delay: float = 4.0,
) -> T:
    """Exponential backoff with full jitter (AWS's recommended formula, avoids the
    thundering-herd effect of synchronized retries) up to max_attempts total tries.
    Only retries exceptions `is_retryable` accepts — network/timeout errors and 5xx/429
    upstream responses, never 4xx client errors (bad request, invalid model, etc.),
    since retrying those just repeats the same failure.
    """
    last_exc: Exception | None = None
    for attempt in range(1, max_attempts + 1):
        try:
            return await fn()
        except Exception as exc:  # noqa: BLE001 - re-raised below if not retryable/exhausted
            if not is_retryable(exc) or attempt == max_attempts:
                raise
            last_exc = exc
            delay = min(max_delay, base_delay * (2 ** (attempt - 1)))
            # Jitter is timing-only (avoids synchronized retry storms), not
            # security-sensitive — the stdlib PRNG is the right tool here.
            await asyncio.sleep(random.uniform(0, delay))  # noqa: S311
    assert last_exc is not None  # loop always returns or raises
    raise last_exc
