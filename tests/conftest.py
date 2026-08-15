from collections.abc import AsyncIterator

import pytest
from httpx import ASGITransport, AsyncClient
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine

from aegis_gateway.core.config import get_settings
from aegis_gateway.main import create_app


@pytest.fixture
async def client() -> AsyncIterator[AsyncClient]:
    app = create_app()
    async with app.router.lifespan_context(app):
        transport = ASGITransport(app=app)
        async with AsyncClient(transport=transport, base_url="http://test") as ac:
            yield ac


@pytest.fixture
async def owner_session() -> AsyncIterator[AsyncSession]:
    """Table-owner DB session for test setup/teardown (bypasses RLS by design —
    tests need to seed rows across tenants without fighting the isolation they're
    meant to enforce for the *application* role)."""
    settings = get_settings()
    engine = create_async_engine(settings.migration_database_url)
    session_factory = async_sessionmaker(bind=engine, expire_on_commit=False)
    async with session_factory() as session:
        yield session
    await engine.dispose()
