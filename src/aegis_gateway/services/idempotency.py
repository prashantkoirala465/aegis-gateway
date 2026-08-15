import uuid

from redis.asyncio import Redis

LOCK_TTL_SECONDS = 60
REPLAY_CACHE_TTL_SECONDS = 24 * 60 * 60


def _lock_key(tenant_id: uuid.UUID, idempotency_key: str) -> str:
    return f"idempotency:{tenant_id}:{idempotency_key}:lock"


def _response_key(tenant_id: uuid.UUID, idempotency_key: str) -> str:
    return f"idempotency:{tenant_id}:{idempotency_key}:response"


async def get_cached_response(
    redis: Redis, tenant_id: uuid.UUID, idempotency_key: str
) -> str | None:
    value: str | None = await redis.get(_response_key(tenant_id, idempotency_key))
    return value


async def try_acquire_lock(redis: Redis, tenant_id: uuid.UUID, idempotency_key: str) -> bool:
    """True if this request may proceed. False means another request with the same
    idempotency key is already in flight for this tenant — the caller should reject
    with 409 rather than risk double-executing (and double-billing) the same request."""
    acquired = await redis.set(
        _lock_key(tenant_id, idempotency_key), "1", nx=True, ex=LOCK_TTL_SECONDS
    )
    return bool(acquired)


async def store_response(
    redis: Redis, tenant_id: uuid.UUID, idempotency_key: str, response_json: str
) -> None:
    await redis.set(
        _response_key(tenant_id, idempotency_key), response_json, ex=REPLAY_CACHE_TTL_SECONDS
    )


async def release_lock(redis: Redis, tenant_id: uuid.UUID, idempotency_key: str) -> None:
    await redis.delete(_lock_key(tenant_id, idempotency_key))
