"""add usage_records and usage_rollups

Revision ID: 0005
Revises: 0004
Create Date: 2026-09-06

usage_records is the exact, durable per-request record (see
services/usage.py) — RLS-protected and written under the request's own
tenant context, same tenant_isolation pattern as api_keys/audit_log
from migration 0001. usage_rollups is populated only by the arq
worker (workers/tasks.py) aggregating usage_records into hourly/daily
buckets; RLS-protected too, but only ever written under bypass since
it's a cross-tenant system job, not a per-tenant request.
"""

from collections.abc import Sequence

import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

from alembic import op

revision: str = "0005"
down_revision: str | None = "0004"
branch_labels: Sequence[str] | None = None
depends_on: Sequence[str] | None = None

APP_ROLE = "aegis_app"


def upgrade() -> None:
    op.create_table(
        "usage_records",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column(
            "tenant_id",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("tenants.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column("api_key_id", sa.String(16), nullable=False),
        sa.Column("provider", sa.String(32), nullable=False),
        sa.Column("model", sa.String(128), nullable=False),
        sa.Column("prompt_tokens", sa.Integer(), nullable=False),
        sa.Column("completion_tokens", sa.Integer(), nullable=False),
        sa.Column("total_tokens", sa.Integer(), nullable=False),
        sa.Column("cost_usd", sa.Numeric(12, 6), nullable=False),
        sa.Column("cache_hit", sa.Boolean(), nullable=False, server_default=sa.false()),
        sa.Column("correlation_id", sa.String(64), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
    )
    op.create_index("ix_usage_records_tenant_id", "usage_records", ["tenant_id"])
    op.create_index("ix_usage_records_tenant_created", "usage_records", ["tenant_id", "created_at"])

    op.create_table(
        "usage_rollups",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column(
            "tenant_id",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("tenants.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column("period_type", sa.String(8), nullable=False),
        sa.Column("period_start", sa.DateTime(timezone=True), nullable=False),
        sa.Column("request_count", sa.Integer(), nullable=False),
        sa.Column("cache_hit_count", sa.Integer(), nullable=False),
        sa.Column("prompt_tokens", sa.Integer(), nullable=False),
        sa.Column("completion_tokens", sa.Integer(), nullable=False),
        sa.Column("total_tokens", sa.Integer(), nullable=False),
        sa.Column("cost_usd", sa.Numeric(12, 6), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
        sa.CheckConstraint(
            "period_type IN ('hourly', 'daily')", name="ck_usage_rollups_period_type"
        ),
        sa.UniqueConstraint(
            "tenant_id", "period_type", "period_start", name="uq_usage_rollups_period"
        ),
    )
    op.create_index("ix_usage_rollups_tenant_id", "usage_rollups", ["tenant_id"])
    op.create_index("ix_usage_rollups_period_start", "usage_rollups", ["period_start"])

    op.execute(f"GRANT SELECT, INSERT ON usage_records TO {APP_ROLE};")
    op.execute(f"GRANT SELECT, INSERT, UPDATE ON usage_rollups TO {APP_ROLE};")

    for table in ("usage_records", "usage_rollups"):
        op.execute(f"ALTER TABLE {table} ENABLE ROW LEVEL SECURITY;")
        op.execute(
            f"""
            CREATE POLICY tenant_isolation ON {table}
            USING (
                current_setting('aegis.bypass_rls', true) = 'on'
                OR tenant_id::text = current_setting('aegis.tenant_id', true)
            )
            WITH CHECK (
                current_setting('aegis.bypass_rls', true) = 'on'
                OR tenant_id::text = current_setting('aegis.tenant_id', true)
            );
            """
        )


def downgrade() -> None:
    for table in ("usage_records", "usage_rollups"):
        op.execute(f"DROP POLICY IF EXISTS tenant_isolation ON {table};")
        op.execute(f"ALTER TABLE {table} DISABLE ROW LEVEL SECURITY;")

    op.execute(f"REVOKE ALL ON usage_rollups FROM {APP_ROLE};")
    op.execute(f"REVOKE ALL ON usage_records FROM {APP_ROLE};")

    op.drop_table("usage_rollups")
    op.drop_table("usage_records")
