from redis.asyncio import ConnectionPool, Redis

from aegis_gateway.core.config import Settings


def build_redis_pool(settings: Settings) -> ConnectionPool:
    return ConnectionPool.from_url(settings.redis_url, decode_responses=True)


def build_redis_client(pool: ConnectionPool) -> Redis:
    return Redis(connection_pool=pool)
