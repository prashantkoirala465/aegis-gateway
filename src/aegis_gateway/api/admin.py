from fastapi import APIRouter, Depends
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from aegis_gateway.api.deps import get_db_session, get_settings_dep
from aegis_gateway.core.config import Settings
from aegis_gateway.core.security import create_admin_jwt, verify_password
from aegis_gateway.db.models import AdminUser
from aegis_gateway.db.session import set_rls_context
from aegis_gateway.schemas.auth import AdminLoginRequest, TokenResponse
from aegis_gateway.schemas.errors import UnauthorizedError

router = APIRouter(prefix="/admin", tags=["admin"])


@router.post("/login", response_model=TokenResponse)
async def login(
    payload: AdminLoginRequest,
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
        raise UnauthorizedError("Invalid email or password.")

    token = create_admin_jwt(
        subject=str(admin.id),
        secret=settings.jwt_secret,
        algorithm=settings.jwt_algorithm,
        expire_minutes=settings.jwt_expire_minutes,
    )
    return TokenResponse(access_token=token, expires_in_minutes=settings.jwt_expire_minutes)
