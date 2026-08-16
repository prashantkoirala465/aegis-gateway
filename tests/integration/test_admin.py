import uuid
from datetime import UTC, datetime
from decimal import Decimal

from httpx import AsyncClient
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from aegis_gateway.core.config import get_settings
from aegis_gateway.core.security import (
    create_admin_jwt,
    generate_api_key,
    hash_api_key_secret,
    hash_password,
)
from aegis_gateway.db.models import AdminUser, ApiKey, AuditLog, Tenant, UsageRecord, UsageRollup
from aegis_gateway.db.session import set_rls_context


async def _seed_admin(
    owner_session: AsyncSession,
    *,
    password: str = "correct-horse-battery",  # noqa: S107
) -> AdminUser:
    admin = AdminUser(
        email=f"admin-{uuid.uuid4().hex[:8]}@example.com",
        hashed_password=hash_password(password),
        is_superuser=True,
    )
    owner_session.add(admin)
    await owner_session.commit()
    return admin


def _admin_token(admin: AdminUser) -> str:
    settings = get_settings()
    return create_admin_jwt(
        subject=str(admin.id),
        secret=settings.jwt_secret,
        algorithm=settings.jwt_algorithm,
        expire_minutes=60,
    )


async def _seed_tenant(owner_session: AsyncSession, **overrides: object) -> Tenant:
    tenant = Tenant(name=f"admin-test-tenant-{uuid.uuid4().hex[:8]}", **overrides)
    owner_session.add(tenant)
    await owner_session.commit()
    return tenant


async def _admin_headers(owner_session: AsyncSession) -> dict[str, str]:
    admin = await _seed_admin(owner_session)
    return {"Authorization": f"Bearer {_admin_token(admin)}"}


# --- auth ---------------------------------------------------------------------


async def test_admin_endpoint_rejects_missing_token(client: AsyncClient) -> None:
    response = await client.get("/admin/tenants")
    assert response.status_code == 401


async def test_admin_endpoint_rejects_malformed_token(client: AsyncClient) -> None:
    response = await client.get(
        "/admin/tenants", headers={"Authorization": "Bearer not-a-real-jwt"}
    )
    assert response.status_code == 401


async def test_admin_endpoint_rejects_tenant_api_key(
    client: AsyncClient, owner_session: AsyncSession
) -> None:
    """A leaked tenant API key must never grant admin access — separate auth
    surfaces entirely (see middleware/admin_auth.py)."""
    settings = get_settings()
    tenant = await _seed_tenant(owner_session)
    full_key, key_id, secret_part = generate_api_key()
    owner_session.add(
        ApiKey(
            tenant_id=tenant.id,
            key_id=key_id,
            hashed_secret=hash_api_key_secret(secret_part, settings.api_key_pepper),
            name="k",
        )
    )
    await owner_session.commit()

    response = await client.get("/admin/tenants", headers={"Authorization": f"Bearer {full_key}"})
    assert response.status_code == 401


async def test_admin_login_success(client: AsyncClient, owner_session: AsyncSession) -> None:
    admin = await _seed_admin(owner_session, password="my-real-password")
    response = await client.post(
        "/admin/login", json={"email": admin.email, "password": "my-real-password"}
    )
    assert response.status_code == 200
    assert response.json()["token_type"] == "bearer"


async def test_admin_login_failure_writes_audit_event(
    client: AsyncClient, owner_session: AsyncSession
) -> None:
    admin = await _seed_admin(owner_session, password="my-real-password")
    response = await client.post(
        "/admin/login", json={"email": admin.email, "password": "wrong-password"}
    )
    assert response.status_code == 401

    await set_rls_context(owner_session, tenant_id=None, bypass=True)
    result = await owner_session.execute(
        select(AuditLog)
        .where(AuditLog.event_type == "admin.login_failure")
        .order_by(AuditLog.created_at.desc())
        .limit(1)
    )
    event = result.scalar_one()
    assert event.detail["email"] == admin.email


# --- tenant CRUD ----------------------------------------------------------------


async def test_create_tenant(client: AsyncClient, owner_session: AsyncSession) -> None:
    headers = await _admin_headers(owner_session)
    response = await client.post(
        "/admin/tenants",
        headers=headers,
        json={"name": f"new-tenant-{uuid.uuid4().hex[:8]}", "monthly_budget_usd": "50.00"},
    )
    assert response.status_code == 201
    body = response.json()
    assert body["monthly_budget_usd"] == "50.00"
    assert body["is_active"] is True

    await set_rls_context(owner_session, tenant_id=None, bypass=True)
    events = (
        (
            await owner_session.execute(
                select(AuditLog).where(
                    AuditLog.tenant_id == uuid.UUID(body["id"]),
                    AuditLog.event_type == "admin.tenant_created",
                )
            )
        )
        .scalars()
        .all()
    )
    assert len(events) == 1


async def test_get_tenant_not_found(client: AsyncClient, owner_session: AsyncSession) -> None:
    headers = await _admin_headers(owner_session)
    response = await client.get(f"/admin/tenants/{uuid.uuid4()}", headers=headers)
    assert response.status_code == 404


async def test_list_tenants_includes_created_tenant(
    client: AsyncClient, owner_session: AsyncSession
) -> None:
    headers = await _admin_headers(owner_session)
    tenant = await _seed_tenant(owner_session)

    response = await client.get("/admin/tenants?limit=200", headers=headers)
    assert response.status_code == 200
    ids = {row["id"] for row in response.json()}
    assert str(tenant.id) in ids


async def test_update_tenant_policy_toggle(
    client: AsyncClient, owner_session: AsyncSession
) -> None:
    headers = await _admin_headers(owner_session)
    tenant = await _seed_tenant(owner_session)

    response = await client.patch(
        f"/admin/tenants/{tenant.id}",
        headers=headers,
        json={"pii_redaction_enabled": False, "injection_detection_mode": "log"},
    )
    assert response.status_code == 200
    body = response.json()
    assert body["pii_redaction_enabled"] is False
    assert body["injection_detection_mode"] == "log"
    # untouched fields keep their prior values — PATCH, not PUT
    assert body["rate_limit_rpm"] == tenant.rate_limit_rpm

    await owner_session.refresh(tenant)
    assert tenant.pii_redaction_enabled is False


async def test_update_tenant_rejects_unknown_field(
    client: AsyncClient, owner_session: AsyncSession
) -> None:
    headers = await _admin_headers(owner_session)
    tenant = await _seed_tenant(owner_session)

    response = await client.patch(
        f"/admin/tenants/{tenant.id}", headers=headers, json={"rate_limit_rmp": 10}
    )
    assert response.status_code == 422


async def test_update_tenant_not_found(client: AsyncClient, owner_session: AsyncSession) -> None:
    headers = await _admin_headers(owner_session)
    response = await client.patch(
        f"/admin/tenants/{uuid.uuid4()}", headers=headers, json={"is_active": False}
    )
    assert response.status_code == 404


# --- API keys ---------------------------------------------------------------------


async def test_create_and_list_api_key(client: AsyncClient, owner_session: AsyncSession) -> None:
    headers = await _admin_headers(owner_session)
    tenant = await _seed_tenant(owner_session)

    create_response = await client.post(
        f"/admin/tenants/{tenant.id}/api-keys", headers=headers, json={"name": "ci key"}
    )
    assert create_response.status_code == 201
    created = create_response.json()
    assert created["api_key"].startswith("agk_live_")
    assert "hashed_secret" not in created

    list_response = await client.get(f"/admin/tenants/{tenant.id}/api-keys", headers=headers)
    assert list_response.status_code == 200
    keys = list_response.json()
    assert len(keys) == 1
    assert keys[0]["key_id"] == created["key_id"]
    assert "api_key" not in keys[0]


async def test_revoke_api_key(client: AsyncClient, owner_session: AsyncSession) -> None:
    headers = await _admin_headers(owner_session)
    tenant = await _seed_tenant(owner_session)
    created = (
        await client.post(
            f"/admin/tenants/{tenant.id}/api-keys", headers=headers, json={"name": "k"}
        )
    ).json()

    revoke_response = await client.delete(
        f"/admin/tenants/{tenant.id}/api-keys/{created['key_id']}", headers=headers
    )
    assert revoke_response.status_code == 204

    list_response = await client.get(f"/admin/tenants/{tenant.id}/api-keys", headers=headers)
    assert list_response.json()[0]["revoked_at"] is not None

    # revoking again is a no-op, not an error, and doesn't write a second audit event
    second_revoke = await client.delete(
        f"/admin/tenants/{tenant.id}/api-keys/{created['key_id']}", headers=headers
    )
    assert second_revoke.status_code == 204

    await set_rls_context(owner_session, tenant_id=None, bypass=True)
    events = (
        (
            await owner_session.execute(
                select(AuditLog).where(
                    AuditLog.tenant_id == tenant.id, AuditLog.event_type == "admin.api_key_revoked"
                )
            )
        )
        .scalars()
        .all()
    )
    assert len(events) == 1


async def test_revoke_unknown_api_key_returns_404(
    client: AsyncClient, owner_session: AsyncSession
) -> None:
    headers = await _admin_headers(owner_session)
    tenant = await _seed_tenant(owner_session)
    response = await client.delete(
        f"/admin/tenants/{tenant.id}/api-keys/doesnotexist12345", headers=headers
    )
    assert response.status_code == 404


# --- usage + audit queries ---------------------------------------------------------


async def test_list_usage_records(client: AsyncClient, owner_session: AsyncSession) -> None:
    headers = await _admin_headers(owner_session)
    tenant = await _seed_tenant(owner_session)
    owner_session.add(
        UsageRecord(
            tenant_id=tenant.id,
            api_key_id="a" * 16,
            provider="openai",
            model="gpt-4o",
            prompt_tokens=10,
            completion_tokens=5,
            total_tokens=15,
            cost_usd=Decimal("0.001"),
            cache_hit=False,
        )
    )
    await owner_session.commit()

    response = await client.get(f"/admin/tenants/{tenant.id}/usage/records", headers=headers)
    assert response.status_code == 200
    records = response.json()
    assert len(records) == 1
    assert records[0]["model"] == "gpt-4o"


async def test_list_usage_rollups_filters_by_period_type(
    client: AsyncClient, owner_session: AsyncSession
) -> None:
    headers = await _admin_headers(owner_session)
    tenant = await _seed_tenant(owner_session)
    owner_session.add_all(
        [
            UsageRollup(
                tenant_id=tenant.id,
                period_type="daily",
                period_start=datetime(2026, 1, 1, tzinfo=UTC),
                request_count=3,
                cache_hit_count=1,
                prompt_tokens=30,
                completion_tokens=15,
                total_tokens=45,
                cost_usd=Decimal("0.05"),
            ),
            UsageRollup(
                tenant_id=tenant.id,
                period_type="hourly",
                period_start=datetime(2026, 1, 1, 5, tzinfo=UTC),
                request_count=1,
                cache_hit_count=0,
                prompt_tokens=10,
                completion_tokens=5,
                total_tokens=15,
                cost_usd=Decimal("0.01"),
            ),
        ]
    )
    await owner_session.commit()

    response = await client.get(
        f"/admin/tenants/{tenant.id}/usage/rollups?period_type=daily", headers=headers
    )
    assert response.status_code == 200
    rollups = response.json()
    assert len(rollups) == 1
    assert rollups[0]["period_type"] == "daily"
    assert rollups[0]["request_count"] == 3


async def test_tenant_audit_log_filters_by_event_type(
    client: AsyncClient, owner_session: AsyncSession
) -> None:
    headers = await _admin_headers(owner_session)
    tenant = await _seed_tenant(owner_session)

    await client.patch(
        f"/admin/tenants/{tenant.id}", headers=headers, json={"cache_enabled": False}
    )

    response = await client.get(
        f"/admin/tenants/{tenant.id}/audit-log?event_type=admin.tenant_updated", headers=headers
    )
    assert response.status_code == 200
    events = response.json()
    assert len(events) == 1
    assert events[0]["event_type"] == "admin.tenant_updated"


async def test_system_audit_log_includes_null_tenant_events(
    client: AsyncClient, owner_session: AsyncSession
) -> None:
    headers = await _admin_headers(owner_session)
    # a failed login writes a tenant_id=None audit event (see test above)
    await client.post("/admin/login", json={"email": "nonexistent@example.com", "password": "x"})

    response = await client.get(
        "/admin/audit-log?event_type=admin.login_failure&limit=1", headers=headers
    )
    assert response.status_code == 200
    events = response.json()
    assert len(events) == 1
    assert events[0]["tenant_id"] is None
