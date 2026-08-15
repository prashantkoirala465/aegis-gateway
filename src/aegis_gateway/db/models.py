import uuid
from datetime import datetime
from decimal import Decimal

from sqlalchemy import ARRAY, DateTime, ForeignKey, Numeric, String, func
from sqlalchemy.dialects.postgresql import JSONB, UUID
from sqlalchemy.orm import Mapped, mapped_column, relationship

from aegis_gateway.db.base import Base


class Tenant(Base):
    __tablename__ = "tenants"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    name: Mapped[str] = mapped_column(String(255), unique=True, index=True)
    monthly_budget_usd: Mapped[Decimal] = mapped_column(Numeric(10, 2), default=Decimal("100.00"))
    rate_limit_rpm: Mapped[int] = mapped_column(default=60)
    rate_limit_tpm: Mapped[int] = mapped_column(default=100_000)
    max_concurrent_requests: Mapped[int] = mapped_column(default=5)
    pii_redaction_enabled: Mapped[bool] = mapped_column(default=True)
    injection_detection_enabled: Mapped[bool] = mapped_column(default=True)
    injection_detection_threshold: Mapped[float] = mapped_column(default=0.75)
    injection_detection_mode: Mapped[str] = mapped_column(String(16), default="block")
    is_active: Mapped[bool] = mapped_column(default=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())

    api_keys: Mapped[list["ApiKey"]] = relationship(back_populates="tenant")


class ApiKey(Base):
    """RLS-protected: see alembic/versions/0001_initial.py for the tenant_isolation
    policy on this table. Only `key_id` (an indexable, non-secret prefix) and the
    HMAC digest `hashed_secret` are stored — never the raw key. See core/security.py."""

    __tablename__ = "api_keys"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    tenant_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("tenants.id", ondelete="CASCADE"), index=True
    )
    key_id: Mapped[str] = mapped_column(String(16), unique=True, index=True)
    hashed_secret: Mapped[str] = mapped_column(String(64))
    name: Mapped[str] = mapped_column(String(255))
    scopes: Mapped[list[str]] = mapped_column(ARRAY(String), default=list)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())
    revoked_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), default=None)
    last_used_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), default=None)

    tenant: Mapped["Tenant"] = relationship(back_populates="api_keys")


class AdminUser(Base):
    """Not tenant-scoped, no RLS. Admin passwords use argon2id (see core/security.py)
    — deliberately distinct from the API-key HMAC scheme, because these are low-entropy
    human secrets where argon2's slow, salted hashing defends against offline guessing."""

    __tablename__ = "admin_users"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    email: Mapped[str] = mapped_column(String(255), unique=True, index=True)
    hashed_password: Mapped[str] = mapped_column(String(255))
    is_superuser: Mapped[bool] = mapped_column(default=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())


class AuditLog(Base):
    """RLS-protected: see alembic/versions/0001_initial.py. tenant_id is nullable for
    system/admin-level events, which are only visible in an RLS-bypass (admin) context.
    `detail` must never contain raw prompts/PII — callers redact before writing (Phase 4)."""

    __tablename__ = "audit_log"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    tenant_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True), ForeignKey("tenants.id", ondelete="SET NULL"), index=True
    )
    event_type: Mapped[str] = mapped_column(String(64), index=True)
    correlation_id: Mapped[str | None] = mapped_column(String(64))
    detail: Mapped[dict[str, object]] = mapped_column(JSONB, default=dict)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())
