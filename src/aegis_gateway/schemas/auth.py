import uuid
from decimal import Decimal
from typing import Literal

from pydantic import BaseModel, EmailStr


class TenantContext(BaseModel):
    """Attached to request.state after successful API-key auth (middleware/auth.py).
    Carries the tenant's rate-limit/budget/security-policy config straight from the
    Tenant row already fetched during auth, so downstream dependencies don't need a
    second DB query."""

    tenant_id: uuid.UUID
    tenant_name: str
    api_key_id: str
    monthly_budget_usd: Decimal
    rate_limit_rpm: int
    rate_limit_tpm: int
    max_concurrent_requests: int
    pii_redaction_enabled: bool
    injection_detection_enabled: bool
    injection_detection_threshold: float
    injection_detection_mode: Literal["block", "log"]


class AdminLoginRequest(BaseModel):
    email: EmailStr
    password: str


class TokenResponse(BaseModel):
    access_token: str
    token_type: str = "bearer"  # noqa: S105 - OAuth2 token-type field, not a secret
    expires_in_minutes: int
