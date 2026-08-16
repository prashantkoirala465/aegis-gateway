import uuid
from datetime import UTC, datetime, timedelta
from decimal import Decimal

from fastapi import FastAPI
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from aegis_gateway.db.models import AuditLog, Tenant, UsageRecord, UsageRollup
from aegis_gateway.db.session import set_rls_context
from aegis_gateway.workers.tasks import _rollup_period, budget_threshold_scan


async def _seed_tenant(owner_session: AsyncSession, **overrides: object) -> Tenant:
    tenant = Tenant(name=f"worker-test-tenant-{uuid.uuid4().hex[:8]}", **overrides)
    owner_session.add(tenant)
    await owner_session.flush()
    return tenant


def _unique_period_start(tenant_id: uuid.UUID) -> datetime:
    """A rollup window derived from the tenant's own (random) UUID rather than a
    fixed literal date. Fixed dates collide across test runs against the persistent
    local Postgres volume (docker compose down without -v keeps data between
    sessions) — a *different* tenant's leftover usage_records from a prior run can
    land in the same hardcoded window and inflate `_rollup_period`'s tenant count.
    Tying the window to this test's own tenant_id makes every run's window unique."""
    offset_minutes = tenant_id.int % (365 * 24 * 60)
    return datetime(2020, 1, 1, tzinfo=UTC) + timedelta(minutes=offset_minutes)


def _usage_record(
    *, tenant_id: uuid.UUID, created_at: datetime, cost_usd: Decimal, cache_hit: bool = False
) -> UsageRecord:
    return UsageRecord(
        tenant_id=tenant_id,
        api_key_id="a" * 16,
        provider="openai",
        model="gpt-4o",
        prompt_tokens=100,
        completion_tokens=50,
        total_tokens=150,
        cost_usd=cost_usd,
        cache_hit=cache_hit,
        created_at=created_at,
    )


async def test_rollup_period_aggregates_usage_records(
    app: FastAPI, owner_session: AsyncSession
) -> None:
    tenant = await _seed_tenant(owner_session)
    period_start = _unique_period_start(tenant.id)
    period_end = period_start + timedelta(hours=1)

    owner_session.add_all(
        [
            _usage_record(
                tenant_id=tenant.id,
                created_at=period_start + timedelta(minutes=5),
                cost_usd=Decimal("1.50"),
            ),
            _usage_record(
                tenant_id=tenant.id,
                created_at=period_start + timedelta(minutes=30),
                cost_usd=Decimal("2.50"),
                cache_hit=True,
            ),
        ]
    )
    await owner_session.commit()

    count = await _rollup_period(
        app.state.sessionmaker,
        period_type="hourly",
        period_start=period_start,
        period_end=period_end,
    )
    assert count == 1

    await set_rls_context(owner_session, tenant_id=None, bypass=True)
    result = await owner_session.execute(
        select(UsageRollup).where(UsageRollup.tenant_id == tenant.id)
    )
    rollup = result.scalar_one()
    assert rollup.request_count == 2
    assert rollup.cache_hit_count == 1
    assert rollup.total_tokens == 300
    assert rollup.cost_usd == Decimal("4.00")


async def test_rollup_period_upsert_is_idempotent_on_rerun(
    app: FastAPI, owner_session: AsyncSession
) -> None:
    tenant = await _seed_tenant(owner_session)
    period_start = _unique_period_start(tenant.id)
    period_end = period_start + timedelta(hours=1)

    owner_session.add(
        _usage_record(
            tenant_id=tenant.id,
            created_at=period_start + timedelta(minutes=1),
            cost_usd=Decimal("1.00"),
        )
    )
    await owner_session.commit()

    for _ in range(2):
        await _rollup_period(
            app.state.sessionmaker,
            period_type="hourly",
            period_start=period_start,
            period_end=period_end,
        )

    await set_rls_context(owner_session, tenant_id=None, bypass=True)
    result = await owner_session.execute(
        select(UsageRollup).where(UsageRollup.tenant_id == tenant.id)
    )
    rollups = result.scalars().all()
    assert len(rollups) == 1  # rerun updated the row rather than duplicating it
    assert rollups[0].cost_usd == Decimal("1.00")


async def test_rollup_period_excludes_records_outside_window(
    app: FastAPI, owner_session: AsyncSession
) -> None:
    tenant = await _seed_tenant(owner_session)
    period_start = _unique_period_start(tenant.id)
    period_end = period_start + timedelta(hours=1)

    owner_session.add_all(
        [
            _usage_record(
                tenant_id=tenant.id,
                created_at=period_start - timedelta(minutes=1),
                cost_usd=Decimal("1.00"),
            ),
            _usage_record(tenant_id=tenant.id, created_at=period_end, cost_usd=Decimal("1.00")),
        ]
    )
    await owner_session.commit()

    count = await _rollup_period(
        app.state.sessionmaker,
        period_type="hourly",
        period_start=period_start,
        period_end=period_end,
    )
    assert count == 0


async def test_budget_threshold_scan_writes_audit_event_once(
    app: FastAPI, owner_session: AsyncSession
) -> None:
    tenant = await _seed_tenant(owner_session, monthly_budget_usd=Decimal("10.00"))
    await owner_session.commit()

    month_start = datetime.now(UTC).replace(day=1, hour=0, minute=0, second=0, microsecond=0)
    owner_session.add(
        _usage_record(
            tenant_id=tenant.id,
            created_at=month_start + timedelta(hours=1),
            cost_usd=Decimal("9.00"),
        )
    )
    await owner_session.commit()

    ctx = {"sessionmaker": app.state.sessionmaker, "redis": app.state.redis}
    await budget_threshold_scan(ctx)
    await budget_threshold_scan(ctx)  # rerun within the same month must not duplicate

    await set_rls_context(owner_session, tenant_id=None, bypass=True)
    result = await owner_session.execute(
        select(AuditLog).where(
            AuditLog.tenant_id == tenant.id, AuditLog.event_type == "budget.threshold_reached"
        )
    )
    events = result.scalars().all()
    assert len(events) == 1, [(e.detail, e.created_at, e.correlation_id) for e in events]
    assert events[0].detail["threshold"] == 0.8


async def test_budget_threshold_scan_skips_tenant_with_zero_budget(
    app: FastAPI, owner_session: AsyncSession
) -> None:
    tenant = await _seed_tenant(owner_session, monthly_budget_usd=Decimal("0.00"))
    await owner_session.commit()

    ctx = {"sessionmaker": app.state.sessionmaker, "redis": app.state.redis}
    await budget_threshold_scan(ctx)  # must not raise (would divide by zero if unguarded)

    await set_rls_context(owner_session, tenant_id=None, bypass=True)
    result = await owner_session.execute(select(AuditLog).where(AuditLog.tenant_id == tenant.id))
    assert result.scalars().all() == []
