import uuid

from fastapi import FastAPI
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from aegis_gateway.db.models import Tenant, UsageRecord
from aegis_gateway.db.session import set_rls_context
from aegis_gateway.services.usage import record_usage


async def _seed_tenant(owner_session: AsyncSession) -> uuid.UUID:
    tenant = Tenant(name=f"usage-test-tenant-{uuid.uuid4().hex[:8]}")
    owner_session.add(tenant)
    await owner_session.commit()
    return tenant.id


async def test_record_usage_writes_correct_row(app: FastAPI, owner_session: AsyncSession) -> None:
    tenant_id = await _seed_tenant(owner_session)

    async with app.state.sessionmaker() as session:
        await record_usage(
            session,
            tenant_id=tenant_id,
            api_key_id="abcdef0123456789",
            provider_name="openai",
            model="gpt-4o",
            prompt_tokens=1000,
            completion_tokens=500,
            cache_hit=False,
            correlation_id="corr-1",
        )

    await set_rls_context(owner_session, tenant_id=None, bypass=True)
    result = await owner_session.execute(
        select(UsageRecord).where(UsageRecord.tenant_id == tenant_id)
    )
    record = result.scalar_one()
    assert record.provider == "openai"
    assert record.model == "gpt-4o"
    assert record.prompt_tokens == 1000
    assert record.completion_tokens == 500
    assert record.total_tokens == 1500
    assert record.cost_usd > 0
    assert record.cache_hit is False
    assert record.correlation_id == "corr-1"


async def test_record_usage_cache_hit_and_ollama_is_free(
    app: FastAPI, owner_session: AsyncSession
) -> None:
    tenant_id = await _seed_tenant(owner_session)

    async with app.state.sessionmaker() as session:
        await record_usage(
            session,
            tenant_id=tenant_id,
            api_key_id="x" * 16,
            provider_name="ollama",
            model="llama3.1",
            prompt_tokens=10,
            completion_tokens=5,
            cache_hit=True,
            correlation_id=None,
        )

    await set_rls_context(owner_session, tenant_id=None, bypass=True)
    result = await owner_session.execute(
        select(UsageRecord).where(UsageRecord.tenant_id == tenant_id)
    )
    record = result.scalar_one()
    assert record.cache_hit is True
    assert record.cost_usd == 0


async def test_usage_records_are_tenant_isolated(app: FastAPI, owner_session: AsyncSession) -> None:
    tenant_a = await _seed_tenant(owner_session)
    tenant_b = await _seed_tenant(owner_session)

    async with app.state.sessionmaker() as session:
        await record_usage(
            session,
            tenant_id=tenant_a,
            api_key_id="a" * 16,
            provider_name="openai",
            model="gpt-4o",
            prompt_tokens=1,
            completion_tokens=1,
            cache_hit=False,
            correlation_id=None,
        )

    async with app.state.sessionmaker() as session:
        await set_rls_context(session, tenant_id=tenant_b, bypass=False)
        result = await session.execute(select(UsageRecord))
        rows = result.scalars().all()

    assert rows == []  # tenant B's own session can't see tenant A's usage record
