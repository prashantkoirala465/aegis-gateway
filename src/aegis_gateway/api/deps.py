from collections.abc import AsyncIterator

from fastapi import Request
from redis.asyncio import Redis
from redis.commands.core import AsyncScript
from sqlalchemy.ext.asyncio import AsyncSession

from aegis_gateway.core.config import Settings
from aegis_gateway.detectors.pii import PiiRedactor
from aegis_gateway.detectors.prompt_injection import PromptInjectionDetector
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


def get_token_bucket_script(request: Request) -> AsyncScript:
    script: AsyncScript = request.app.state.token_bucket_script
    return script


def get_budget_script(request: Request) -> AsyncScript:
    script: AsyncScript = request.app.state.budget_script
    return script


def get_pii_redactor(request: Request) -> PiiRedactor:
    redactor: PiiRedactor = request.app.state.pii_redactor
    return redactor


def get_injection_detector(request: Request) -> PromptInjectionDetector:
    detector: PromptInjectionDetector = request.app.state.injection_detector
    return detector
