import uuid
from datetime import UTC, datetime
from decimal import Decimal
from typing import Any, Literal

from fastapi import APIRouter, Depends, HTTPException, Query, Request
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from starlette.responses import Response

from aegis_gateway.api.deps import get_db_session, get_settings_dep
from aegis_gateway.core.config import Settings
from aegis_gateway.core.security import (
    create_admin_jwt,
    generate_api_key,
    hash_api_key_secret,
    verify_password,
)
from aegis_gateway.db.models import AdminUser, ApiKey, AuditLog, Tenant, UsageRecord, UsageRollup
from aegis_gateway.db.session import set_rls_context
from aegis_gateway.middleware.admin_auth import get_current_admin
from aegis_gateway.schemas.admin import (
    AdminContext,
    ApiKeyCreatedResponse,
    ApiKeyCreateRequest,
    ApiKeyResponse,
    AuditLogResponse,
    TenantCreateRequest,
    TenantResponse,
    TenantUpdateRequest,
    UsageRecordResponse,
    UsageRollupResponse,
)
from aegis_gateway.schemas.auth import AdminLoginRequest, TokenResponse
from aegis_gateway.schemas.errors import UnauthorizedError
from aegis_gateway.services.audit import write_audit_event

router = APIRouter(prefix="/admin", tags=["admin"])


def _correlation_id(request: Request) -> str | None:
    return getattr(request.state, "correlation_id", None)


def _json_safe(value: dict[str, Any]) -> dict[str, Any]:
    """audit_log.detail is JSONB — Decimal isn't natively JSON-serializable, so
    stringify anything that isn't already a JSON-safe type before logging it."""
    return {k: (str(v) if isinstance(v, Decimal) else v) for k, v in value.items()}


@router.post("/login", response_model=TokenResponse)
async def login(
    payload: AdminLoginRequest,
    request: Request,
    session: AsyncSession = Depends(get_db_session),
    settings: Settings = Depends(get_settings_dep),
) -> TokenResponse:
    """Admin JWT login. There is deliberately no public /admin/register endpoint —
    admin accounts are provisioned only via scripts/seed.py, run with owner DB
    credentials out-of-band, so this API surface can never self-provision admins."""
    # admin_users has no RLS policy, but every query still runs through the same
    # session-scoped GUCs; bypass=True here is a no-op for this table and kept only
    # for consistency with the rest of the request lifecycle.
    await set_rls_context(session, tenant_id=None, bypass=True)
    result = await session.execute(select(AdminUser).where(AdminUser.email == payload.email))
    admin = result.scalar_one_or_none()

    if admin is None or not verify_password(payload.password, admin.hashed_password):
        await write_audit_event(
            session,
            tenant_id=None,
            event_type="admin.login_failure",
            correlation_id=_correlation_id(request),
            detail={"email": payload.email},
        )
        raise UnauthorizedError("Invalid email or password.")

    token = create_admin_jwt(
        subject=str(admin.id),
        secret=settings.jwt_secret,
        algorithm=settings.jwt_algorithm,
        expire_minutes=settings.jwt_expire_minutes,
    )
    return TokenResponse(access_token=token, expires_in_minutes=settings.jwt_expire_minutes)


@router.post("/tenants", response_model=TenantResponse, status_code=201)
async def create_tenant(
    payload: TenantCreateRequest,
    request: Request,
    admin: AdminContext = Depends(get_current_admin),
    session: AsyncSession = Depends(get_db_session),
) -> Tenant:
    await set_rls_context(session, tenant_id=None, bypass=True)
    tenant = Tenant(**payload.model_dump())
    session.add(tenant)
    await session.flush()
    await write_audit_event(
        session,
        tenant_id=tenant.id,
        event_type="admin.tenant_created",
        correlation_id=_correlation_id(request),
        detail=_json_safe({"admin_id": str(admin.admin_id), "name": tenant.name}),
    )
    return tenant


@router.get("/tenants", response_model=list[TenantResponse])
async def list_tenants(
    admin: AdminContext = Depends(get_current_admin),
    session: AsyncSession = Depends(get_db_session),
    limit: int = Query(default=50, ge=1, le=200),
    offset: int = Query(default=0, ge=0),
) -> list[Tenant]:
    await set_rls_context(session, tenant_id=None, bypass=True)
    result = await session.execute(
        select(Tenant).order_by(Tenant.created_at.desc()).limit(limit).offset(offset)
    )
    return list(result.scalars().all())


@router.get("/tenants/{tenant_id}", response_model=TenantResponse)
async def get_tenant(
    tenant_id: uuid.UUID,
    admin: AdminContext = Depends(get_current_admin),
    session: AsyncSession = Depends(get_db_session),
) -> Tenant:
    await set_rls_context(session, tenant_id=None, bypass=True)
    tenant = await session.get(Tenant, tenant_id)
    if tenant is None:
        raise HTTPException(status_code=404, detail="Tenant not found.")
    return tenant


@router.patch("/tenants/{tenant_id}", response_model=TenantResponse)
async def update_tenant(
    tenant_id: uuid.UUID,
    payload: TenantUpdateRequest,
    request: Request,
    admin: AdminContext = Depends(get_current_admin),
    session: AsyncSession = Depends(get_db_session),
) -> Tenant:
    """The per-tenant policy toggle endpoint: rate limits, budget, PII/injection
    settings, cache — anything on the Tenant row — in one place, PATCH semantics."""
    await set_rls_context(session, tenant_id=None, bypass=True)
    tenant = await session.get(Tenant, tenant_id)
    if tenant is None:
        raise HTTPException(status_code=404, detail="Tenant not found.")

    changes = payload.model_dump(exclude_unset=True)
    for field, value in changes.items():
        setattr(tenant, field, value)

    await write_audit_event(
        session,
        tenant_id=tenant.id,
        event_type="admin.tenant_updated",
        correlation_id=_correlation_id(request),
        detail=_json_safe({"admin_id": str(admin.admin_id), "changes": changes}),
    )
    return tenant


@router.post("/tenants/{tenant_id}/api-keys", response_model=ApiKeyCreatedResponse, status_code=201)
async def create_api_key(
    tenant_id: uuid.UUID,
    payload: ApiKeyCreateRequest,
    request: Request,
    admin: AdminContext = Depends(get_current_admin),
    session: AsyncSession = Depends(get_db_session),
    settings: Settings = Depends(get_settings_dep),
) -> ApiKeyCreatedResponse:
    await set_rls_context(session, tenant_id=None, bypass=True)
    tenant = await session.get(Tenant, tenant_id)
    if tenant is None:
        raise HTTPException(status_code=404, detail="Tenant not found.")

    full_key, key_id, secret_part = generate_api_key()
    api_key = ApiKey(
        tenant_id=tenant.id,
        key_id=key_id,
        hashed_secret=hash_api_key_secret(secret_part, settings.api_key_pepper),
        name=payload.name,
    )
    session.add(api_key)
    await session.flush()
    await session.refresh(api_key)  # populate the server-generated created_at

    await write_audit_event(
        session,
        tenant_id=tenant.id,
        event_type="admin.api_key_issued",
        correlation_id=_correlation_id(request),
        detail={"admin_id": str(admin.admin_id), "key_id": key_id, "name": payload.name},
    )

    return ApiKeyCreatedResponse(
        key_id=api_key.key_id,
        name=api_key.name,
        created_at=api_key.created_at,
        revoked_at=api_key.revoked_at,
        last_used_at=api_key.last_used_at,
        api_key=full_key,
    )


@router.get("/tenants/{tenant_id}/api-keys", response_model=list[ApiKeyResponse])
async def list_api_keys(
    tenant_id: uuid.UUID,
    admin: AdminContext = Depends(get_current_admin),
    session: AsyncSession = Depends(get_db_session),
) -> list[ApiKey]:
    await set_rls_context(session, tenant_id=None, bypass=True)
    result = await session.execute(
        select(ApiKey).where(ApiKey.tenant_id == tenant_id).order_by(ApiKey.created_at.desc())
    )
    return list(result.scalars().all())


@router.delete("/tenants/{tenant_id}/api-keys/{key_id}", status_code=204)
async def revoke_api_key(
    tenant_id: uuid.UUID,
    key_id: str,
    request: Request,
    admin: AdminContext = Depends(get_current_admin),
    session: AsyncSession = Depends(get_db_session),
) -> Response:
    await set_rls_context(session, tenant_id=None, bypass=True)
    result = await session.execute(
        select(ApiKey).where(ApiKey.tenant_id == tenant_id, ApiKey.key_id == key_id)
    )
    api_key = result.scalar_one_or_none()
    if api_key is None:
        raise HTTPException(status_code=404, detail="API key not found.")

    if api_key.revoked_at is None:
        api_key.revoked_at = datetime.now(UTC)
        await write_audit_event(
            session,
            tenant_id=tenant_id,
            event_type="admin.api_key_revoked",
            correlation_id=_correlation_id(request),
            detail={"admin_id": str(admin.admin_id), "key_id": key_id},
        )
    return Response(status_code=204)


@router.get("/tenants/{tenant_id}/usage/records", response_model=list[UsageRecordResponse])
async def list_usage_records(
    tenant_id: uuid.UUID,
    admin: AdminContext = Depends(get_current_admin),
    session: AsyncSession = Depends(get_db_session),
    limit: int = Query(default=50, ge=1, le=200),
    offset: int = Query(default=0, ge=0),
) -> list[UsageRecord]:
    await set_rls_context(session, tenant_id=None, bypass=True)
    result = await session.execute(
        select(UsageRecord)
        .where(UsageRecord.tenant_id == tenant_id)
        .order_by(UsageRecord.created_at.desc())
        .limit(limit)
        .offset(offset)
    )
    return list(result.scalars().all())


@router.get("/tenants/{tenant_id}/usage/rollups", response_model=list[UsageRollupResponse])
async def list_usage_rollups(
    tenant_id: uuid.UUID,
    admin: AdminContext = Depends(get_current_admin),
    session: AsyncSession = Depends(get_db_session),
    period_type: Literal["hourly", "daily"] = Query(default="daily"),
    limit: int = Query(default=30, ge=1, le=200),
) -> list[UsageRollup]:
    await set_rls_context(session, tenant_id=None, bypass=True)
    result = await session.execute(
        select(UsageRollup)
        .where(UsageRollup.tenant_id == tenant_id, UsageRollup.period_type == period_type)
        .order_by(UsageRollup.period_start.desc())
        .limit(limit)
    )
    return list(result.scalars().all())


@router.get("/tenants/{tenant_id}/audit-log", response_model=list[AuditLogResponse])
async def list_tenant_audit_log(
    tenant_id: uuid.UUID,
    admin: AdminContext = Depends(get_current_admin),
    session: AsyncSession = Depends(get_db_session),
    event_type: str | None = Query(default=None),
    limit: int = Query(default=50, ge=1, le=200),
) -> list[AuditLog]:
    await set_rls_context(session, tenant_id=None, bypass=True)
    stmt = select(AuditLog).where(AuditLog.tenant_id == tenant_id)
    if event_type:
        stmt = stmt.where(AuditLog.event_type == event_type)
    stmt = stmt.order_by(AuditLog.created_at.desc()).limit(limit)
    result = await session.execute(stmt)
    return list(result.scalars().all())


@router.get("/audit-log", response_model=list[AuditLogResponse])
async def list_audit_log(
    admin: AdminContext = Depends(get_current_admin),
    session: AsyncSession = Depends(get_db_session),
    tenant_id: uuid.UUID | None = Query(default=None),
    event_type: str | None = Query(default=None),
    limit: int = Query(default=50, ge=1, le=200),
) -> list[AuditLog]:
    """System-wide view — includes events with tenant_id IS NULL (auth failures
    before a tenant could be resolved, admin actions not scoped to one tenant)."""
    await set_rls_context(session, tenant_id=None, bypass=True)
    stmt = select(AuditLog)
    if tenant_id is not None:
        stmt = stmt.where(AuditLog.tenant_id == tenant_id)
    if event_type:
        stmt = stmt.where(AuditLog.event_type == event_type)
    stmt = stmt.order_by(AuditLog.created_at.desc()).limit(limit)
    result = await session.execute(stmt)
    return list(result.scalars().all())
