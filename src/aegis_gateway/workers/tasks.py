from datetime import UTC, datetime, timedelta
from decimal import Decimal
from typing import Any

from redis.asyncio import Redis
from sqlalchemy import Integer, cast, func, select
from sqlalchemy.dialects.postgresql import insert as pg_insert
from sqlalchemy.ext.asyncio import async_sessionmaker

from aegis_gateway.core.config import get_settings
from aegis_gateway.core.logging import get_logger
from aegis_gateway.db.models import Tenant, UsageRecord, UsageRollup
from aegis_gateway.db.session import build_engine, build_sessionmaker, set_rls_context
from aegis_gateway.services.audit import write_audit_event

logger = get_logger(__name__)

# Alert once per tenant per threshold per month, not once per scan interval — a
# tenant sitting at 95% spend for a week shouldn't get an audit row every 15 minutes.
BUDGET_ALERT_THRESHOLDS = (0.8, 1.0)
_BUDGET_ALERT_MARKER_TTL_SECONDS = 40 * 24 * 3600  # comfortably longer than a month


async def startup(ctx: dict[str, Any]) -> None:
    """arq worker process is separate from the FastAPI app — it doesn't share
    app.state, so it builds its own engine/sessionmaker/redis here, mirroring
    main.py's lifespan. `ctx` is arq's convention for per-worker shared state,
    threaded into every job function."""
    settings = get_settings()
    engine = build_engine(settings)
    ctx["engine"] = engine
    ctx["sessionmaker"] = build_sessionmaker(engine)
    ctx["redis"] = Redis.from_url(settings.redis_url, decode_responses=True)
    logger.info("worker.startup.complete")


async def shutdown(ctx: dict[str, Any]) -> None:
    await ctx["redis"].aclose()
    await ctx["engine"].dispose()
    logger.info("worker.shutdown.complete")


async def _rollup_period(
    sessionmaker: async_sessionmaker[Any],
    *,
    period_type: str,
    period_start: datetime,
    period_end: datetime,
) -> int:
    """Aggregates usage_records in [period_start, period_end) into one usage_rollups
    row per tenant, upserting on (tenant_id, period_type, period_start) so re-running
    the same period (a retried job, a manual backfill) updates the row instead of
    duplicating it. Runs as a system job across every tenant, hence RLS bypass —
    this isn't a request on behalf of any one tenant.
    """
    async with sessionmaker() as session:
        await set_rls_context(session, tenant_id=None, bypass=True)
        result = await session.execute(
            select(
                UsageRecord.tenant_id,
                func.count().label("request_count"),
                func.sum(cast(UsageRecord.cache_hit, Integer)).label("cache_hit_count"),
                func.sum(UsageRecord.prompt_tokens).label("prompt_tokens"),
                func.sum(UsageRecord.completion_tokens).label("completion_tokens"),
                func.sum(UsageRecord.total_tokens).label("total_tokens"),
                func.sum(UsageRecord.cost_usd).label("cost_usd"),
            )
            .where(UsageRecord.created_at >= period_start, UsageRecord.created_at < period_end)
            .group_by(UsageRecord.tenant_id)
        )
        rows = result.all()

        for row in rows:
            stmt = pg_insert(UsageRollup).values(
                tenant_id=row.tenant_id,
                period_type=period_type,
                period_start=period_start,
                request_count=row.request_count,
                cache_hit_count=row.cache_hit_count,
                prompt_tokens=row.prompt_tokens,
                completion_tokens=row.completion_tokens,
                total_tokens=row.total_tokens,
                cost_usd=row.cost_usd,
            )
            stmt = stmt.on_conflict_do_update(
                index_elements=["tenant_id", "period_type", "period_start"],
                set_={
                    "request_count": stmt.excluded.request_count,
                    "cache_hit_count": stmt.excluded.cache_hit_count,
                    "prompt_tokens": stmt.excluded.prompt_tokens,
                    "completion_tokens": stmt.excluded.completion_tokens,
                    "total_tokens": stmt.excluded.total_tokens,
                    "cost_usd": stmt.excluded.cost_usd,
                },
            )
            await session.execute(stmt)
        await session.commit()

    return len(rows)


async def hourly_usage_rollup(ctx: dict[str, Any]) -> None:
    period_start = (datetime.now(UTC) - timedelta(hours=1)).replace(
        minute=0, second=0, microsecond=0
    )
    period_end = period_start + timedelta(hours=1)
    tenants = await _rollup_period(
        ctx["sessionmaker"], period_type="hourly", period_start=period_start, period_end=period_end
    )
    logger.info(
        "usage_rollup.hourly.complete", period_start=period_start.isoformat(), tenants=tenants
    )


async def daily_usage_rollup(ctx: dict[str, Any]) -> None:
    period_start = (datetime.now(UTC) - timedelta(days=1)).replace(
        hour=0, minute=0, second=0, microsecond=0
    )
    period_end = period_start + timedelta(days=1)
    tenants = await _rollup_period(
        ctx["sessionmaker"], period_type="daily", period_start=period_start, period_end=period_end
    )
    logger.info(
        "usage_rollup.daily.complete", period_start=period_start.isoformat(), tenants=tenants
    )


async def budget_threshold_scan(ctx: dict[str, Any]) -> None:
    """Scans month-to-date spend (from the exact usage_records table, not the Redis
    guardrail's approximate counter — see services/rate_limiter.py) against each
    active tenant's budget, writing a "budget.threshold_reached" audit event the
    first time a tenant crosses 80% or 100%. A Redis marker (not another DB table)
    dedupes repeat alerts for the same tenant/month/threshold — cheap and self-
    expiring, no cleanup job needed.
    """
    sessionmaker = ctx["sessionmaker"]
    redis: Redis = ctx["redis"]
    now = datetime.now(UTC)
    month_key = now.strftime("%Y-%m")
    month_start = now.replace(day=1, hour=0, minute=0, second=0, microsecond=0)

    checked = 0
    async with sessionmaker() as session:
        await set_rls_context(session, tenant_id=None, bypass=True)
        tenants = (
            (await session.execute(select(Tenant).where(Tenant.is_active.is_(True))))
            .scalars()
            .all()
        )

        for tenant in tenants:
            checked += 1
            if tenant.monthly_budget_usd <= 0:
                continue

            spend_result = await session.execute(
                select(func.coalesce(func.sum(UsageRecord.cost_usd), 0)).where(
                    UsageRecord.tenant_id == tenant.id, UsageRecord.created_at >= month_start
                )
            )
            spend = Decimal(spend_result.scalar_one())
            ratio = float(spend / tenant.monthly_budget_usd)

            for threshold in BUDGET_ALERT_THRESHOLDS:
                if ratio < threshold:
                    continue
                marker_key = f"budget_alert:{tenant.id}:{month_key}:{threshold}"
                first_time = await redis.set(
                    marker_key, "1", nx=True, ex=_BUDGET_ALERT_MARKER_TTL_SECONDS
                )
                if not first_time:
                    continue
                await write_audit_event(
                    session,
                    tenant_id=tenant.id,
                    event_type="budget.threshold_reached",
                    correlation_id=None,
                    detail={
                        "threshold": threshold,
                        "spend_usd": str(spend),
                        "budget_usd": str(tenant.monthly_budget_usd),
                    },
                )

    logger.info("budget_threshold_scan.complete", tenants_checked=checked)
