import uuid

from fastapi import Depends, HTTPException, Request
from sqlalchemy.ext.asyncio import AsyncSession

from aegis_gateway.api.deps import get_db_session, get_settings_dep
from aegis_gateway.core.config import Settings
from aegis_gateway.core.security import decode_admin_jwt
from aegis_gateway.db.models import AdminUser
from aegis_gateway.db.session import set_rls_context
from aegis_gateway.schemas.admin import AdminContext


async def get_current_admin(
    request: Request,
    session: AsyncSession = Depends(get_db_session),
    settings: Settings = Depends(get_settings_dep),
) -> AdminContext:
    """JWT auth for the /admin/* control-plane surface — entirely separate from the
    tenant-facing HMAC API-key auth (middleware/auth.py). No code path derives one
    from the other: a leaked tenant API key never grants admin access, and an admin
    JWT is never accepted on the /v1/* proxy surface.

    Plain {"detail": ...} error bodies here, not the OpenAI-shaped errors used on
    /v1/* — this surface was never meant to look like an OpenAI-compatible API to a
    client SDK.
    """
    auth_header = request.headers.get("authorization", "")
    if not auth_header.lower().startswith("bearer "):
        raise HTTPException(status_code=401, detail="Missing bearer token.")

    token = auth_header.split(" ", 1)[1].strip()
    payload = decode_admin_jwt(token, secret=settings.jwt_secret, algorithm=settings.jwt_algorithm)
    if payload is None:
        raise HTTPException(status_code=401, detail="Invalid or expired admin token.")

    try:
        admin_id = uuid.UUID(payload["sub"])
    except (KeyError, ValueError) as exc:
        raise HTTPException(status_code=401, detail="Malformed admin token.") from exc

    await set_rls_context(session, tenant_id=None, bypass=True)
    admin = await session.get(AdminUser, admin_id)
    if admin is None:
        raise HTTPException(status_code=401, detail="Admin account no longer exists.")

    return AdminContext(admin_id=admin.id, email=admin.email, is_superuser=admin.is_superuser)
