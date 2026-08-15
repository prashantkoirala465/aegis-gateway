import asyncio
import time
from enum import Enum

from aegis_gateway.providers.errors import CircuitOpenError


class CircuitState(Enum):
    CLOSED = "closed"
    OPEN = "open"
    HALF_OPEN = "half_open"


class CircuitBreaker:
    """Per-provider circuit breaker: CLOSED (normal) -> OPEN (failing fast, no network
    calls) after `failure_threshold` consecutive failures -> HALF_OPEN (one probe call
    allowed) after `recovery_timeout` seconds -> CLOSED on success or back to OPEN on
    failure. asyncio.Lock-guarded since a single provider instance is shared across
    every concurrent request in the process.
    """

    def __init__(
        self,
        *,
        name: str,
        failure_threshold: int = 5,
        recovery_timeout: float = 30.0,
    ) -> None:
        self.name = name
        self._failure_threshold = failure_threshold
        self._recovery_timeout = recovery_timeout
        self._state = CircuitState.CLOSED
        self._failure_count = 0
        self._opened_at: float | None = None
        self._half_open_probe_in_flight = False
        self._lock = asyncio.Lock()

    @property
    def state(self) -> CircuitState:
        return self._state

    async def before_call(self) -> None:
        async with self._lock:
            if self._state == CircuitState.OPEN:
                assert self._opened_at is not None
                if time.monotonic() - self._opened_at >= self._recovery_timeout:
                    self._state = CircuitState.HALF_OPEN
                    self._half_open_probe_in_flight = True
                    return
                raise CircuitOpenError(f"circuit open for provider '{self.name}'")

            if self._state == CircuitState.HALF_OPEN:
                if self._half_open_probe_in_flight:
                    raise CircuitOpenError(
                        f"circuit half-open for provider '{self.name}', probe in flight"
                    )
                self._half_open_probe_in_flight = True

    async def record_success(self) -> None:
        async with self._lock:
            self._state = CircuitState.CLOSED
            self._failure_count = 0
            self._opened_at = None
            self._half_open_probe_in_flight = False

    async def record_failure(self) -> None:
        async with self._lock:
            self._half_open_probe_in_flight = False
            self._failure_count += 1
            if self._state == CircuitState.HALF_OPEN or (
                self._failure_count >= self._failure_threshold
            ):
                self._state = CircuitState.OPEN
                self._opened_at = time.monotonic()
