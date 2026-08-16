from redis.asyncio import Redis

from aegis_gateway.schemas.chat import ChatCompletionResponse, Usage
from aegis_gateway.services.cache import get_cached_completion, store_cached_completion


def _response() -> ChatCompletionResponse:
    return ChatCompletionResponse(
        id="chatcmpl-test",
        created=0,
        model="gpt-test",
        choices=[{"index": 0, "message": {"role": "assistant", "content": "hi there"}}],
        usage=Usage(prompt_tokens=1, completion_tokens=2, total_tokens=3),
    )


async def test_cache_miss_returns_none(redis_client: Redis, unique_key: str) -> None:
    result = await get_cached_completion(redis_client, f"test:cache:{unique_key}")
    assert result is None


async def test_store_then_get_round_trips(redis_client: Redis, unique_key: str) -> None:
    key = f"test:cache:{unique_key}"
    response = _response()

    await store_cached_completion(redis_client, key, response, ttl_seconds=60)
    cached = await get_cached_completion(redis_client, key)

    assert cached is not None
    assert cached.id == response.id
    assert cached.choices == response.choices
    assert cached.usage is not None
    assert cached.usage.total_tokens == 3


async def test_stored_entry_expires(redis_client: Redis, unique_key: str) -> None:
    key = f"test:cache:{unique_key}"
    await store_cached_completion(redis_client, key, _response(), ttl_seconds=60)
    ttl = await redis_client.ttl(key)
    assert 0 < ttl <= 60
