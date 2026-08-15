"""add per-tenant PII/prompt-injection policy columns

Revision ID: 0003
Revises: 0002
Create Date: 2026-08-23

Same "fixed typed setting, not a rules engine" pattern as rate limits
(0002): a tenant can turn PII redaction on/off, tune the prompt-
injection score threshold, and choose whether a flagged request is
blocked outright or just logged. See services/audit.py and
detectors/ for how these get used.
"""

from collections.abc import Sequence

import sqlalchemy as sa

from alembic import op

revision: str = "0003"
down_revision: str | None = "0002"
branch_labels: Sequence[str] | None = None
depends_on: Sequence[str] | None = None


def upgrade() -> None:
    op.add_column(
        "tenants",
        sa.Column("pii_redaction_enabled", sa.Boolean(), nullable=False, server_default=sa.true()),
    )
    op.add_column(
        "tenants",
        sa.Column(
            "injection_detection_enabled", sa.Boolean(), nullable=False, server_default=sa.true()
        ),
    )
    op.add_column(
        "tenants",
        sa.Column(
            "injection_detection_threshold",
            sa.Float(),
            nullable=False,
            server_default="0.75",
        ),
    )
    op.add_column(
        "tenants",
        sa.Column(
            "injection_detection_mode", sa.String(16), nullable=False, server_default="block"
        ),
    )
    op.create_check_constraint(
        "ck_tenants_injection_detection_mode",
        "tenants",
        "injection_detection_mode IN ('block', 'log')",
    )


def downgrade() -> None:
    op.drop_constraint("ck_tenants_injection_detection_mode", "tenants", type_="check")
    op.drop_column("tenants", "injection_detection_mode")
    op.drop_column("tenants", "injection_detection_threshold")
    op.drop_column("tenants", "injection_detection_enabled")
    op.drop_column("tenants", "pii_redaction_enabled")
