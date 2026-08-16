from datetime import UTC, datetime

from fastapi import Depends, Request
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from aegis_gateway.api.deps import get_db_session, get_settings_dep
from aegis_gateway.core.config import Settings
from aegis_gateway.core.security import parse_api_key, verify_api_key_secret
from aegis_gateway.db.models import ApiKey, Tenant
from aegis_gateway.db.session import set_rls_context
from aegis_gateway.schemas.auth import TenantContext
from aegis_gateway.schemas.errors import UnauthorizedError
from aegis_gateway.services.audit import write_audit_event


async def get_current_tenant(
    request: Request,
    session: AsyncSession = Depends(get_db_session),
    settings: Settings = Depends(get_settings_dep),
) -> TenantContext:
    """API-key auth dependency for the tenant-facing proxy surface (/v1/*).

    Two-phase RLS handling: we must look up an api_keys row by key_id before we know
    which tenant it belongs to, so that single lookup runs with bypass_rls=true (a
    narrow, deliberate exception — see db.session.set_rls_context docstring). The
    moment the tenant is resolved we downgrade to bypass_rls=false, tenant_id=<tenant>
    for the rest of the request, so every later query is properly isolated.

    Every failure path writes a synchronous audit event before raising — auth
    failures are exactly the kind of security-critical event that must never be
    silently dropped by a queue (see services/audit.py).
    """
    correlation_id = getattr(request.state, "correlation_id", None)

    auth_header = request.headers.get("authorization", "")
    if not auth_header.lower().startswith("bearer "):
        await write_audit_event(
            session,
            tenant_id=None,
            event_type="auth.failure",
            correlation_id=correlation_id,
            detail={"reason": "missing_bearer_token"},
        )
        raise UnauthorizedError("Missing bearer token.")

    presented_key = auth_header.split(" ", 1)[1].strip()
    parsed = parse_api_key(presented_key)
    if parsed is None:
        await write_audit_event(
            session,
            tenant_id=None,
            event_type="auth.failure",
            correlation_id=correlation_id,
            detail={"reason": "malformed_api_key"},
        )
        raise UnauthorizedError("Malformed API key.")
    key_id, secret_part = parsed

    await set_rls_context(session, tenant_id=None, bypass=True)
    result = await session.execute(select(ApiKey).where(ApiKey.key_id == key_id))
    api_key = result.scalar_one_or_none()

    if api_key is None:
        await write_audit_event(
            session,
            tenant_id=None,
            event_type="auth.failure",
            correlation_id=correlation_id,
            detail={"reason": "key_not_found", "key_id": key_id},
        )
        raise UnauthorizedError()
    if api_key.revoked_at is not None:
        await write_audit_event(
            session,
            tenant_id=api_key.tenant_id,
            event_type="auth.failure",
            correlation_id=correlation_id,
            detail={"reason": "key_revoked", "key_id": key_id},
        )
        raise UnauthorizedError()
    if not verify_api_key_secret(secret_part, settings.api_key_pepper, api_key.hashed_secret):
        await write_audit_event(
            session,
            tenant_id=api_key.tenant_id,
            event_type="auth.failure",
            correlation_id=correlation_id,
            detail={"reason": "invalid_secret", "key_id": key_id},
        )
        raise UnauthorizedError()

    await set_rls_context(session, tenant_id=api_key.tenant_id, bypass=False)
    tenant = await session.get(Tenant, api_key.tenant_id)
    if tenant is None or not tenant.is_active:
        await write_audit_event(
            session,
            tenant_id=api_key.tenant_id,
            event_type="auth.failure",
            correlation_id=correlation_id,
            detail={"reason": "tenant_inactive", "key_id": key_id},
        )
        raise UnauthorizedError("Tenant is inactive.")

    api_key.last_used_at = datetime.now(UTC)
    await session.commit()

    return TenantContext(
        tenant_id=tenant.id,
        tenant_name=tenant.name,
        api_key_id=api_key.key_id,
        monthly_budget_usd=tenant.monthly_budget_usd,
        rate_limit_rpm=tenant.rate_limit_rpm,
        rate_limit_tpm=tenant.rate_limit_tpm,
        max_concurrent_requests=tenant.max_concurrent_requests,
        pii_redaction_enabled=tenant.pii_redaction_enabled,
        injection_detection_enabled=tenant.injection_detection_enabled,
        injection_detection_threshold=tenant.injection_detection_threshold,
        injection_detection_mode=tenant.injection_detection_mode,
        cache_enabled=tenant.cache_enabled,
    )
