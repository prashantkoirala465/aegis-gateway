import pytest

from aegis_gateway.providers.retry import call_with_retry


class _RetryableError(Exception):
    pass


class _FatalError(Exception):
    pass


async def test_succeeds_first_try_without_retry() -> None:
    calls = 0

    async def fn() -> str:
        nonlocal calls
        calls += 1
        return "ok"

    result = await call_with_retry(fn, is_retryable=lambda exc: True, max_attempts=3)
    assert result == "ok"
    assert calls == 1


async def test_retries_then_succeeds() -> None:
    calls = 0

    async def fn() -> str:
        nonlocal calls
        calls += 1
        if calls < 3:
            raise _RetryableError("transient")
        return "ok"

    result = await call_with_retry(
        fn,
        is_retryable=lambda exc: isinstance(exc, _RetryableError),
        max_attempts=5,
        base_delay=0.001,
    )
    assert result == "ok"
    assert calls == 3


async def test_exhausts_attempts_and_raises() -> None:
    calls = 0

    async def fn() -> str:
        nonlocal calls
        calls += 1
        raise _RetryableError("always fails")

    with pytest.raises(_RetryableError):
        await call_with_retry(
            fn,
            is_retryable=lambda exc: isinstance(exc, _RetryableError),
            max_attempts=3,
            base_delay=0.001,
        )
    assert calls == 3


async def test_non_retryable_error_fails_fast() -> None:
    calls = 0

    async def fn() -> str:
        nonlocal calls
        calls += 1
        raise _FatalError("not retryable")

    with pytest.raises(_FatalError):
        await call_with_retry(
            fn,
            is_retryable=lambda exc: isinstance(exc, _RetryableError),
            max_attempts=5,
            base_delay=0.001,
        )
    assert calls == 1
