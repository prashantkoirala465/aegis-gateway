import time

import pytest

from aegis_gateway.providers.circuit_breaker import CircuitBreaker, CircuitState
from aegis_gateway.providers.errors import CircuitOpenError


async def test_closed_circuit_allows_calls() -> None:
    breaker = CircuitBreaker(name="test", failure_threshold=3, recovery_timeout=10)
    await breaker.before_call()
    await breaker.record_success()
    assert breaker.state == CircuitState.CLOSED


async def test_opens_after_threshold_failures() -> None:
    breaker = CircuitBreaker(name="test", failure_threshold=3, recovery_timeout=10)
    for _ in range(3):
        await breaker.before_call()
        await breaker.record_failure()
    assert breaker.state == CircuitState.OPEN

    with pytest.raises(CircuitOpenError):
        await breaker.before_call()


async def test_success_resets_failure_count() -> None:
    breaker = CircuitBreaker(name="test", failure_threshold=3, recovery_timeout=10)
    await breaker.before_call()
    await breaker.record_failure()
    await breaker.before_call()
    await breaker.record_failure()
    await breaker.before_call()
    await breaker.record_success()
    assert breaker.state == CircuitState.CLOSED

    # Two more failures shouldn't open it — the prior success reset the count.
    await breaker.before_call()
    await breaker.record_failure()
    assert breaker.state == CircuitState.CLOSED


async def test_half_open_after_recovery_timeout_then_closes_on_success() -> None:
    breaker = CircuitBreaker(name="test", failure_threshold=1, recovery_timeout=0.05)
    await breaker.before_call()
    await breaker.record_failure()
    assert breaker.state == CircuitState.OPEN

    time.sleep(0.06)
    await breaker.before_call()  # transitions to HALF_OPEN, allows the probe
    assert breaker.state == CircuitState.HALF_OPEN
    await breaker.record_success()
    assert breaker.state == CircuitState.CLOSED


async def test_half_open_failure_reopens_circuit() -> None:
    breaker = CircuitBreaker(name="test", failure_threshold=1, recovery_timeout=0.05)
    await breaker.before_call()
    await breaker.record_failure()

    time.sleep(0.06)
    await breaker.before_call()
    await breaker.record_failure()
    assert breaker.state == CircuitState.OPEN


async def test_half_open_rejects_concurrent_second_probe() -> None:
    breaker = CircuitBreaker(name="test", failure_threshold=1, recovery_timeout=0.05)
    await breaker.before_call()
    await breaker.record_failure()

    time.sleep(0.06)
    await breaker.before_call()  # first probe allowed through
    with pytest.raises(CircuitOpenError):
        await breaker.before_call()  # a second concurrent probe is rejected
