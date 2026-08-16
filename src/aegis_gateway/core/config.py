from functools import lru_cache
from typing import Literal

from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    """Central application configuration, loaded from environment / .env.

    Secrets (pepper, JWT secret, provider API keys) live here via env vars only —
    never hardcoded, never committed. See .env.example for the full contract.
    """

    model_config = SettingsConfigDict(env_file=".env", env_file_encoding="utf-8", extra="ignore")

    environment: Literal["development", "test", "production"] = "development"
    log_level: str = "INFO"

    database_url: str = Field(
        default="postgresql+asyncpg://aegis_app:aegis_app@localhost:5432/aegis_gateway",
        description="Runtime app connection. Non-superuser role so RLS policies are "
        "actually enforced (superusers bypass RLS unconditionally).",
    )
    migration_database_url: str = Field(
        default="postgresql+asyncpg://aegis:aegis@localhost:5432/aegis_gateway",
        description="Table-owner connection used only by Alembic — needs DDL and "
        "CREATE ROLE privileges that the runtime aegis_app role deliberately lacks.",
    )
    redis_url: str = Field(default="redis://localhost:6379/0")

    api_key_pepper: str = Field(default="changeme-generate-a-real-32-byte-hex-secret")
    jwt_secret: str = Field(default="changeme-generate-a-real-32-byte-hex-secret")
    jwt_algorithm: str = "HS256"
    jwt_expire_minutes: int = 60

    openai_api_key: str = ""
    anthropic_api_key: str = ""
    ollama_base_url: str = "http://localhost:11434"

    provider_timeout_seconds: float = 30.0
    provider_max_attempts: int = 3
    provider_max_connections: int = 100
    provider_max_keepalive_connections: int = 20
    circuit_breaker_failure_threshold: int = 5
    circuit_breaker_recovery_seconds: float = 30.0

    cache_ttl_seconds: int = 300

    @property
    def is_production(self) -> bool:
        return self.environment == "production"


@lru_cache
def get_settings() -> Settings:
    return Settings()
