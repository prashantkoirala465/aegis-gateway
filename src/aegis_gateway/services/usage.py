import uuid
from decimal import Decimal

from sqlalchemy.ext.asyncio import AsyncSession

from aegis_gateway.db.models import UsageRecord
from aegis_gateway.db.session import set_rls_context
from aegis_gateway.services.pricing import calculate_cost_usd


async def record_usage(
    session: AsyncSession,
    *,
    tenant_id: uuid.UUID,
    api_key_id: str,
    provider_name: str,
    model: str,
    prompt_tokens: int,
    completion_tokens: int,
    cache_hit: bool,
    correlation_id: str | None,
) -> None:
    """Explicit tenant-scoped RLS context (bypass=False) — not relying on whatever
    the session's ambient context happens to be by this point in the request (audit
    writes upstream force bypass=True internally; see write_audit_event). Unlike
    audit_log, this genuinely is one tenant's data, so it's written under that
    tenant's normal RLS policy rather than a system-level bypass.
    """
    await set_rls_context(session, tenant_id=tenant_id, bypass=False)
    cost_usd = calculate_cost_usd(
        model=model,
        prompt_tokens=prompt_tokens,
        completion_tokens=completion_tokens,
        provider_name=provider_name,
    )
    session.add(
        UsageRecord(
            tenant_id=tenant_id,
            api_key_id=api_key_id,
            provider=provider_name,
            model=model,
            prompt_tokens=prompt_tokens,
            completion_tokens=completion_tokens,
            total_tokens=prompt_tokens + completion_tokens,
            cost_usd=Decimal(str(round(cost_usd, 6))),
            cache_hit=cache_hit,
            correlation_id=correlation_id,
        )
    )
    await session.commit()
