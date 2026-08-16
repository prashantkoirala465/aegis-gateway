import uuid
from datetime import datetime
from decimal import Decimal
from typing import Literal

from pydantic import BaseModel, ConfigDict


class AdminContext(BaseModel):
    """Attached to request.state after successful admin JWT auth (middleware/
    admin_auth.py) — entirely separate from the tenant-facing TenantContext
    (middleware/auth.py). No code path derives one from the other."""

    admin_id: uuid.UUID
    email: str
    is_superuser: bool


class TenantCreateRequest(BaseModel):
    name: str
    monthly_budget_usd: Decimal = Decimal("100.00")
    rate_limit_rpm: int = 60
    rate_limit_tpm: int = 100_000
    max_concurrent_requests: int = 5
    pii_redaction_enabled: bool = True
    injection_detection_enabled: bool = True
    injection_detection_threshold: float = 0.75
    injection_detection_mode: Literal["block", "log"] = "block"
    cache_enabled: bool = True


class TenantUpdateRequest(BaseModel):
    """Every field optional — PATCH semantics via model_dump(exclude_unset=True), so
    only fields the caller actually supplied are changed. `extra="forbid"` catches a
    typo'd field name (e.g. `rate_limit_rmp`) as a 422 instead of silently no-op'ing."""

    model_config = ConfigDict(extra="forbid")

    name: str | None = None
    monthly_budget_usd: Decimal | None = None
    rate_limit_rpm: int | None = None
    rate_limit_tpm: int | None = None
    max_concurrent_requests: int | None = None
    pii_redaction_enabled: bool | None = None
    injection_detection_enabled: bool | None = None
    injection_detection_threshold: float | None = None
    injection_detection_mode: Literal["block", "log"] | None = None
    cache_enabled: bool | None = None
    is_active: bool | None = None


class TenantResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    name: str
    monthly_budget_usd: Decimal
    rate_limit_rpm: int
    rate_limit_tpm: int
    max_concurrent_requests: int
    pii_redaction_enabled: bool
    injection_detection_enabled: bool
    injection_detection_threshold: float
    injection_detection_mode: str
    cache_enabled: bool
    is_active: bool
    created_at: datetime


class ApiKeyCreateRequest(BaseModel):
    name: str


class ApiKeyResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    key_id: str
    name: str
    created_at: datetime
    revoked_at: datetime | None
    last_used_at: datetime | None


class ApiKeyCreatedResponse(ApiKeyResponse):
    api_key: str  # shown once — never recoverable after this response, see core/security.py


class UsageRecordResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    provider: str
    model: str
    prompt_tokens: int
    completion_tokens: int
    total_tokens: int
    cost_usd: Decimal
    cache_hit: bool
    correlation_id: str | None
    created_at: datetime


class UsageRollupResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    period_type: str
    period_start: datetime
    request_count: int
    cache_hit_count: int
    prompt_tokens: int
    completion_tokens: int
    total_tokens: int
    cost_usd: Decimal


class AuditLogResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    tenant_id: uuid.UUID | None
    event_type: str
    correlation_id: str | None
    detail: dict[str, object]
    created_at: datetime
