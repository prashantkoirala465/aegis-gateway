import asyncio
import uuid

from redis.asyncio import Redis

from aegis_gateway.services.rate_limiter import (
    acquire_concurrency_slot,
    check_and_reserve_budget,
    check_token_bucket,
    register_rate_limit_scripts,
    release_concurrency_slot,
)


async def test_token_bucket_allows_up_to_capacity_then_denies(
    redis_client: Redis, unique_key: str
) -> None:
    script, _ = register_rate_limit_scripts(redis_client)
    key = f"test:bucket:{unique_key}"

    for _ in range(3):
        result = await check_token_bucket(
            script, key=key, capacity=3, refill_per_second=0.001, cost=1
        )
        assert result.allowed

    denied = await check_token_bucket(script, key=key, capacity=3, refill_per_second=0.001, cost=1)
    assert not denied.allowed


async def test_token_bucket_refills_over_time(redis_client: Redis, unique_key: str) -> None:
    script, _ = register_rate_limit_scripts(redis_client)
    key = f"test:bucket:{unique_key}"

    async def _check() -> bool:
        result = await check_token_bucket(script, key=key, capacity=2, refill_per_second=20, cost=1)
        return result.allowed

    assert await _check()
    assert await _check()
    assert not await _check()

    await asyncio.sleep(0.1)  # refill_per_second=20 -> ~2 tokens back after 100ms

    assert await _check()


async def test_token_bucket_request_larger_than_capacity_always_denied(
    redis_client: Redis, unique_key: str
) -> None:
    script, _ = register_rate_limit_scripts(redis_client)
    key = f"test:bucket:{unique_key}"

    result = await check_token_bucket(script, key=key, capacity=10, refill_per_second=5, cost=50)
    assert not result.allowed


async def test_budget_allows_under_limit_then_denies_over(
    redis_client: Redis, unique_key: str
) -> None:
    _, script = register_rate_limit_scripts(redis_client)
    key = f"test:budget:{unique_key}"

    first = await check_and_reserve_budget(script, key=key, increment=0.6, limit=1.0)
    assert first.allowed
    assert first.remaining == 0.6

    second = await check_and_reserve_budget(script, key=key, increment=0.5, limit=1.0)
    assert not second.allowed
    # denied call does not consume budget — remaining reflects the prior successful call
    assert second.remaining == 0.6

    third = await check_and_reserve_budget(script, key=key, increment=0.4, limit=1.0)
    assert third.allowed


async def test_concurrency_slot_denies_past_limit_and_release_frees_it(
    redis_client: Redis,
) -> None:
    tenant_id = uuid.uuid4()

    assert await acquire_concurrency_slot(redis_client, tenant_id=tenant_id, limit=2)
    assert await acquire_concurrency_slot(redis_client, tenant_id=tenant_id, limit=2)
    assert not await acquire_concurrency_slot(redis_client, tenant_id=tenant_id, limit=2)

    await release_concurrency_slot(redis_client, tenant_id=tenant_id)
    assert await acquire_concurrency_slot(redis_client, tenant_id=tenant_id, limit=2)

    # cleanup so this key doesn't linger for the test's 5-minute safety-net TTL
    await release_concurrency_slot(redis_client, tenant_id=tenant_id)
    await release_concurrency_slot(redis_client, tenant_id=tenant_id)
