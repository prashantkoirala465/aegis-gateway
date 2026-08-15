from collections.abc import AsyncIterator

from fastapi import Request
from redis.asyncio import Redis
from sqlalchemy.ext.asyncio import AsyncSession

from aegis_gateway.core.config import Settings
from aegis_gateway.providers.registry import ProviderRegistry


async def get_db_session(request: Request) -> AsyncIterator[AsyncSession]:
    sessionmaker = request.app.state.sessionmaker
    async with sessionmaker() as session:
        yield session


def get_settings_dep(request: Request) -> Settings:
    settings: Settings = request.app.state.settings
    return settings


def get_redis(request: Request) -> Redis:
    redis: Redis = request.app.state.redis
    return redis


def get_provider_registry(request: Request) -> ProviderRegistry:
    registry: ProviderRegistry = request.app.state.providers
    return registry
