import uuid
from dataclasses import dataclass
from datetime import UTC, datetime

from redis.asyncio import Redis
from redis.commands.core import AsyncScript

from aegis_gateway.schemas.auth import TenantContext
from aegis_gateway.services.pricing import estimate_prompt_cost_usd

# Token bucket, continuous refill (not fixed-window — avoids the burst-at-the-
# boundary problem where a fixed window lets 2x the limit through across a window
# edge). Runs as one atomic Lua script because "read remaining tokens, then decide
# whether to consume" is a check-then-act race if split across two round trips —
# two concurrent requests could both read "1 token left" and both proceed. Uses
# Redis's own TIME command rather than a client-supplied timestamp so correctness
# doesn't depend on clock sync across app instances.
_TOKEN_BUCKET_LUA = """
local bucket_key = KEYS[1]
local capacity = tonumber(ARGV[1])
local refill_per_second = tonumber(ARGV[2])
local requested = tonumber(ARGV[3])
local ttl_seconds = tonumber(ARGV[4])

local bucket = redis.call('HMGET', bucket_key, 'tokens', 'updated_at')
local tokens = tonumber(bucket[1])
local updated_at = tonumber(bucket[2])

local time_result = redis.call('TIME')
local now = tonumber(time_result[1]) + (tonumber(time_result[2]) / 1000000)

if tokens == nil then
    tokens = capacity
    updated_at = now
end

local elapsed = math.max(0, now - updated_at)
tokens = math.min(capacity, tokens + elapsed * refill_per_second)

local allowed = 0
if tokens >= requested then
    tokens = tokens - requested
    allowed = 1
end

redis.call('HMSET', bucket_key, 'tokens', tostring(tokens), 'updated_at', tostring(now))
redis.call('EXPIRE', bucket_key, ttl_seconds)

return {allowed, tostring(tokens)}
"""

# Same check-then-act problem applies to the budget guardrail: two concurrent requests
# reading "current spend" before either writes back could both pass a check that,
# combined, exceeds the cap. One atomic script closes that gap.
_BUDGET_LUA = """
local budget_key = KEYS[1]
local increment = tonumber(ARGV[1])
local limit = tonumber(ARGV[2])
local ttl_seconds = tonumber(ARGV[3])

local current = tonumber(redis.call('GET', budget_key) or '0')
local new_value = current + increment

if new_value > limit then
    return {0, tostring(current)}
end

redis.call('SET', budget_key, tostring(new_value), 'EX', ttl_seconds)
return {1, tostring(new_value)}
"""

_BUCKET_KEY_TTL_SECONDS = 3600  # generously longer than any refill window we use
_BUDGET_KEY_TTL_SECONDS = 40 * 24 * 3600  # comfortably longer than a month


@dataclass(frozen=True)
class LimitResult:
    allowed: bool
    remaining: float


def register_rate_limit_scripts(redis: Redis) -> tuple[AsyncScript, AsyncScript]:
    """Compiles and caches both Lua scripts on the Redis connection once, at startup
    — EVALSHA under the hood, so steady-state calls don't re-upload script source."""
    return redis.register_script(_TOKEN_BUCKET_LUA), redis.register_script(_BUDGET_LUA)


async def check_token_bucket(
    script: AsyncScript,
    *,
    key: str,
    capacity: float,
    refill_per_second: float,
    cost: float,
) -> LimitResult:
    allowed, remaining = await script(
        keys=[key], args=[capacity, refill_per_second, cost, _BUCKET_KEY_TTL_SECONDS]
    )
    return LimitResult(allowed=bool(int(allowed)), remaining=float(remaining))


async def check_and_reserve_budget(
    script: AsyncScript, *, key: str, increment: float, limit: float
) -> LimitResult:
    allowed, spend = await script(keys=[key], args=[increment, limit, _BUDGET_KEY_TTL_SECONDS])
    return LimitResult(allowed=bool(int(allowed)), remaining=float(spend))


def rpm_bucket_key(tenant_id: uuid.UUID) -> str:
    return f"ratelimit:rpm:{tenant_id}"


def tpm_bucket_key(tenant_id: uuid.UUID) -> str:
    return f"ratelimit:tpm:{tenant_id}"


def budget_key(tenant_id: uuid.UUID, year_month: str) -> str:
    return f"budget:{tenant_id}:{year_month}"


def concurrency_key(tenant_id: uuid.UUID) -> str:
    return f"concurrency:{tenant_id}"


_CONCURRENCY_KEY_TTL_SECONDS = 300  # safety net if a release is ever missed (crash)


async def acquire_concurrency_slot(redis: Redis, *, tenant_id: uuid.UUID, limit: int) -> bool:
    """Plain INCR/DECR, not Lua: unlike the bucket/budget checks, a momentary overshoot
    here (two racing requests both incrementing before either checks the limit) just
    means the concurrency cap is soft by a handful of requests under a burst — not a
    correctness bug worth a script for, unlike double-spending budget or rate-limit
    tokens."""
    key = concurrency_key(tenant_id)
    current = await redis.incr(key)
    if current == 1:
        await redis.expire(key, _CONCURRENCY_KEY_TTL_SECONDS)
    if current > limit:
        await redis.decr(key)
        return False
    return True


async def release_concurrency_slot(redis: Redis, *, tenant_id: uuid.UUID) -> None:
    await redis.decr(concurrency_key(tenant_id))


class RateLimitExceeded(Exception):
    def __init__(self, *, code: str, message: str, retry_after_seconds: int | None = None) -> None:
        self.code = code
        self.retry_after_seconds = retry_after_seconds
        super().__init__(message)


async def enforce_request_limits(
    *,
    redis: Redis,
    token_bucket_script: AsyncScript,
    budget_script: AsyncScript,
    tenant: TenantContext,
    provider_name: str,
    model: str,
    prompt_tokens: int,
) -> None:
    """Checked in cheapest-first order: RPM (a single HGET-equivalent) before TPM
    before the budget script, so an obviously-abusive request rate gets rejected
    before spending a second Redis round trip on finer-grained checks. Concurrency is
    deliberately not checked here — it has to be held for the full request/stream
    duration, not just verified once, so the caller acquires/releases it separately
    around the actual provider call.
    """
    rpm = await check_token_bucket(
        token_bucket_script,
        key=rpm_bucket_key(tenant.tenant_id),
        capacity=tenant.rate_limit_rpm,
        refill_per_second=tenant.rate_limit_rpm / 60,
        cost=1,
    )
    if not rpm.allowed:
        raise RateLimitExceeded(
            code="rate_limit_exceeded",
            message=f"Request rate limit exceeded ({tenant.rate_limit_rpm} requests/min).",
            retry_after_seconds=1,
        )

    tpm = await check_token_bucket(
        token_bucket_script,
        key=tpm_bucket_key(tenant.tenant_id),
        capacity=tenant.rate_limit_tpm,
        refill_per_second=tenant.rate_limit_tpm / 60,
        cost=prompt_tokens,
    )
    if not tpm.allowed:
        raise RateLimitExceeded(
            code="token_limit_exceeded",
            message=f"Token rate limit exceeded ({tenant.rate_limit_tpm} tokens/min).",
            retry_after_seconds=1,
        )

    estimated_cost = estimate_prompt_cost_usd(
        model=model, prompt_tokens=prompt_tokens, provider_name=provider_name
    )
    if estimated_cost > 0:
        month = datetime.now(UTC).strftime("%Y-%m")
        budget = await check_and_reserve_budget(
            budget_script,
            key=budget_key(tenant.tenant_id, month),
            increment=estimated_cost,
            limit=float(tenant.monthly_budget_usd),
        )
        if not budget.allowed:
            raise RateLimitExceeded(
                code="budget_exceeded",
                message=(
                    f"Monthly budget of ${tenant.monthly_budget_usd} exceeded for this tenant."
                ),
            )
