import uuid
from collections.abc import AsyncIterator

import pytest
from fastapi import FastAPI
from httpx import ASGITransport, AsyncClient
from redis.asyncio import Redis
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine

from aegis_gateway.core.config import get_settings
from aegis_gateway.main import create_app


@pytest.fixture
async def app() -> AsyncIterator[FastAPI]:
    app = create_app()
    async with app.router.lifespan_context(app):
        yield app


@pytest.fixture
async def client(app: FastAPI) -> AsyncIterator[AsyncClient]:
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as ac:
        yield ac


@pytest.fixture
async def redis_client() -> AsyncIterator[Redis]:
    settings = get_settings()
    client: Redis = Redis.from_url(settings.redis_url, decode_responses=True)
    yield client
    await client.aclose()


@pytest.fixture
def unique_key() -> str:
    """A random suffix for Redis keys so tests don't collide on shared state without
    needing a full FLUSHDB between them."""
    return uuid.uuid4().hex


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
