"""add per-tenant response-cache toggle

Revision ID: 0004
Revises: 0003
Create Date: 2026-08-30

Same fixed-typed-setting pattern as the rest of the tenants row. Some
tenants may want zero response reuse (compliance, or just always-fresh
output) — this is the escape hatch. TTL is a single global Settings
value (cache_ttl_seconds), not per-tenant: there's no strong case for
varying it per tenant, and every extra per-tenant knob is one more
thing to explain and get wrong.
"""

from collections.abc import Sequence

import sqlalchemy as sa

from alembic import op

revision: str = "0004"
down_revision: str | None = "0003"
branch_labels: Sequence[str] | None = None
depends_on: Sequence[str] | None = None


def upgrade() -> None:
    op.add_column(
        "tenants",
        sa.Column("cache_enabled", sa.Boolean(), nullable=False, server_default=sa.true()),
    )


def downgrade() -> None:
    op.drop_column("tenants", "cache_enabled")
