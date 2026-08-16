import hashlib
import json
import uuid

from redis.asyncio import Redis

from aegis_gateway.schemas.chat import ChatCompletionRequest, ChatCompletionResponse


def compute_cache_key(tenant_id: uuid.UUID, body: ChatCompletionRequest) -> str:
    """Exact-match only: two requests hash the same iff every field that could affect
    the output is identical (model, messages, temperature, etc. — everything except
    `stream`, which changes transport, not content). A repeated identical request at
    temperature > 0 will replay the same cached answer rather than generating a fresh
    one — an accepted tradeoff of exact-match caching, not a bug; see README.

    Tenant-scoped by construction: the key embeds tenant_id, so no cache entry is ever
    reachable across tenants even if two tenants send byte-identical requests.
    """
    payload = body.model_dump(exclude={"stream"}, exclude_none=True)
    canonical = json.dumps(payload, sort_keys=True, separators=(",", ":"))
    digest = hashlib.sha256(canonical.encode()).hexdigest()
    return f"cache:completion:{tenant_id}:{digest}"


async def get_cached_completion(redis: Redis, key: str) -> ChatCompletionResponse | None:
    raw = await redis.get(key)
    if raw is None:
        return None
    return ChatCompletionResponse.model_validate_json(raw)


async def store_cached_completion(
    redis: Redis, key: str, response: ChatCompletionResponse, *, ttl_seconds: int
) -> None:
    await redis.set(key, response.model_dump_json(), ex=ttl_seconds)
