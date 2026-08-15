import uuid

from pydantic import BaseModel, EmailStr


class TenantContext(BaseModel):
    """Attached to request.state after successful API-key auth (middleware/auth.py)."""

    tenant_id: uuid.UUID
    tenant_name: str
    api_key_id: str


class AdminLoginRequest(BaseModel):
    email: EmailStr
    password: str


class TokenResponse(BaseModel):
    access_token: str
    token_type: str = "bearer"  # noqa: S105 - OAuth2 token-type field, not a secret
    expires_in_minutes: int
