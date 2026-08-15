import uuid

from httpx import AsyncClient
from sqlalchemy.ext.asyncio import AsyncSession

from aegis_gateway.core.config import get_settings
from aegis_gateway.core.security import generate_api_key, hash_api_key_secret
from aegis_gateway.db.models import ApiKey, Tenant


async def _seed_tenant_and_key(session: AsyncSession) -> str:
    settings = get_settings()
    tenant = Tenant(name=f"test-tenant-{uuid.uuid4().hex[:8]}")
    session.add(tenant)
    await session.flush()

    full_key, key_id, secret_part = generate_api_key()
    session.add(
        ApiKey(
            tenant_id=tenant.id,
            key_id=key_id,
            hashed_secret=hash_api_key_secret(secret_part, settings.api_key_pepper),
            name="test-key",
        )
    )
    await session.commit()
    return full_key


async def test_ping_rejects_missing_key(client: AsyncClient) -> None:
    response = await client.get("/v1/ping")
    assert response.status_code == 401
    assert response.json()["error"]["code"] == "invalid_api_key"


async def test_ping_rejects_invalid_key(client: AsyncClient) -> None:
    response = await client.get(
        "/v1/ping", headers={"Authorization": "Bearer agk_live_deadbeef.notreal"}
    )
    assert response.status_code == 401


async def test_ping_accepts_valid_key(client: AsyncClient, owner_session: AsyncSession) -> None:
    full_key = await _seed_tenant_and_key(owner_session)

    response = await client.get("/v1/ping", headers={"Authorization": f"Bearer {full_key}"})
    assert response.status_code == 200
    assert response.json()["status"] == "ok"


async def test_ping_rejects_revoked_key(client: AsyncClient, owner_session: AsyncSession) -> None:
    full_key = await _seed_tenant_and_key(owner_session)
    key_id, _ = full_key.removeprefix("agk_live_").split(".", 1)

    from datetime import UTC, datetime

    from sqlalchemy import select

    result = await owner_session.execute(select(ApiKey).where(ApiKey.key_id == key_id))
    api_key = result.scalar_one()
    api_key.revoked_at = datetime.now(UTC)
    await owner_session.commit()

    response = await client.get("/v1/ping", headers={"Authorization": f"Bearer {full_key}"})
    assert response.status_code == 401
