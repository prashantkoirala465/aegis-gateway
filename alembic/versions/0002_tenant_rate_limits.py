"""add per-tenant rate-limit columns

Revision ID: 0002
Revises: 0001
Create Date: 2026-08-22

Per-tenant RPM/TPM/concurrency limits, enforced in Redis (see
services/rate_limiter.py) but configured here in Postgres alongside
monthly_budget_usd — same pattern, same table, one place to look. No
admin API to edit these yet (that's Phase 8); for now they're set at
tenant-creation time via scripts/seed.py or a direct UPDATE.
"""

from collections.abc import Sequence

import sqlalchemy as sa

from alembic import op

revision: str = "0002"
down_revision: str | None = "0001"
branch_labels: Sequence[str] | None = None
depends_on: Sequence[str] | None = None


def upgrade() -> None:
    op.add_column(
        "tenants",
        sa.Column("rate_limit_rpm", sa.Integer(), nullable=False, server_default="60"),
    )
    op.add_column(
        "tenants",
        sa.Column("rate_limit_tpm", sa.Integer(), nullable=False, server_default="100000"),
    )
    op.add_column(
        "tenants",
        sa.Column("max_concurrent_requests", sa.Integer(), nullable=False, server_default="5"),
    )


def downgrade() -> None:
    op.drop_column("tenants", "max_concurrent_requests")
    op.drop_column("tenants", "rate_limit_tpm")
    op.drop_column("tenants", "rate_limit_rpm")
