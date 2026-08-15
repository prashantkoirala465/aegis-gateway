import uuid
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager

from sqlalchemy import text
from sqlalchemy.ext.asyncio import (
    AsyncEngine,
    AsyncSession,
    async_sessionmaker,
    create_async_engine,
)

from aegis_gateway.core.config import Settings


def build_engine(settings: Settings) -> AsyncEngine:
    """Single pooled asyncpg engine for the process lifetime.

    pool_size/max_overflow are deliberately modest defaults for a single-instance
    deployment; a multi-replica deployment should sit this behind pgbouncer in
    transaction-pooling mode rather than scaling pool_size per-replica.
    """
    return create_async_engine(
        settings.database_url,
        pool_size=10,
        max_overflow=5,
        pool_pre_ping=True,
        echo=False,
    )


def build_sessionmaker(engine: AsyncEngine) -> async_sessionmaker[AsyncSession]:
    return async_sessionmaker(engine, expire_on_commit=False, autoflush=False)


@asynccontextmanager
async def session_scope(
    sessionmaker: async_sessionmaker[AsyncSession],
) -> AsyncIterator[AsyncSession]:
    """Transactional scope: commits on clean exit, rolls back on exception."""
    async with sessionmaker() as session:
        try:
            yield session
            await session.commit()
        except Exception:
            await session.rollback()
            raise


async def set_rls_context(
    session: AsyncSession, *, tenant_id: uuid.UUID | None, bypass: bool = False
) -> None:
    """Sets the Postgres session GUCs the RLS policies in migration 0001 key off of.

    Uses set_config() (a regular function call, bindable) rather than `SET LOCAL`
    (a utility statement that can't take driver-level bind parameters). `is_local=true`
    scopes the setting to the current transaction, so it never leaks across pooled
    connections reused for a different request/tenant.

    bypass=True is for the narrow pre-auth window where we must look up an api_keys row
    by key_id before we know which tenant it belongs to (see middleware/auth.py) — it is
    downgraded to bypass=False, tenant_id=<resolved tenant> immediately after that lookup
    so the rest of the request runs under normal tenant isolation.
    """
    await session.execute(
        text("SELECT set_config('aegis.tenant_id', :tenant_id, true)"),
        {"tenant_id": str(tenant_id) if tenant_id else ""},
    )
    await session.execute(
        text("SELECT set_config('aegis.bypass_rls', :bypass, true)"),
        {"bypass": "on" if bypass else "off"},
    )
