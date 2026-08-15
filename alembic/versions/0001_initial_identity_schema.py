"""initial identity schema: tenants, api_keys, admin_users, audit_log + RLS

Revision ID: 0001
Revises:
Create Date: 2026-08-15

Creates the Phase 1 schema and a non-superuser `aegis_app` role that the running
application connects as (see Settings.database_url vs migration_database_url).
Row-Level Security is enabled on the two tenant-scoped tables (api_keys, audit_log)
with a policy keyed off session GUCs `aegis.tenant_id` / `aegis.bypass_rls`, set per
request via db.session.set_rls_context(). This only takes effect because aegis_app is
NOSUPERUSER/NOBYPASSRLS — a superuser connection silently ignores RLS entirely, which
is exactly why migrations run as the separate `aegis` owner role instead.
"""

from collections.abc import Sequence

import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

from alembic import op

revision: str = "0001"
down_revision: str | None = None
branch_labels: Sequence[str] | None = None
depends_on: Sequence[str] | None = None

APP_ROLE = "aegis_app"
# Local-dev-only credential, matching the aegis/aegis convention already in
# docker-compose.yml / .env.example. Never used outside local docker-compose.
APP_ROLE_PASSWORD = "aegis_app"  # noqa: S105


def upgrade() -> None:
    op.create_table(
        "tenants",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column("name", sa.String(255), nullable=False, unique=True),
        sa.Column("monthly_budget_usd", sa.Numeric(10, 2), nullable=False, server_default="100.00"),
        sa.Column("is_active", sa.Boolean, nullable=False, server_default=sa.true()),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
    )
    op.create_index("ix_tenants_name", "tenants", ["name"])

    op.create_table(
        "api_keys",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column(
            "tenant_id",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("tenants.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column("key_id", sa.String(16), nullable=False, unique=True),
        sa.Column("hashed_secret", sa.String(64), nullable=False),
        sa.Column("name", sa.String(255), nullable=False),
        sa.Column("scopes", postgresql.ARRAY(sa.String), nullable=False, server_default="{}"),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
        sa.Column("revoked_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("last_used_at", sa.DateTime(timezone=True), nullable=True),
    )
    op.create_index("ix_api_keys_tenant_id", "api_keys", ["tenant_id"])
    op.create_index("ix_api_keys_key_id", "api_keys", ["key_id"], unique=True)

    op.create_table(
        "admin_users",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column("email", sa.String(255), nullable=False, unique=True),
        sa.Column("hashed_password", sa.String(255), nullable=False),
        sa.Column("is_superuser", sa.Boolean, nullable=False, server_default=sa.false()),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
    )
    op.create_index("ix_admin_users_email", "admin_users", ["email"], unique=True)

    op.create_table(
        "audit_log",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column(
            "tenant_id",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("tenants.id", ondelete="SET NULL"),
            nullable=True,
        ),
        sa.Column("event_type", sa.String(64), nullable=False),
        sa.Column("correlation_id", sa.String(64), nullable=True),
        sa.Column("detail", postgresql.JSONB, nullable=False, server_default="{}"),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
    )
    op.create_index("ix_audit_log_tenant_id", "audit_log", ["tenant_id"])
    op.create_index("ix_audit_log_event_type", "audit_log", ["event_type"])

    # --- Non-superuser runtime role -----------------------------------------------
    op.execute(
        f"""
        DO $$
        BEGIN
            IF NOT EXISTS (SELECT FROM pg_roles WHERE rolname = '{APP_ROLE}') THEN
                CREATE ROLE {APP_ROLE} LOGIN PASSWORD '{APP_ROLE_PASSWORD}'
                    NOSUPERUSER NOCREATEDB NOCREATEROLE NOBYPASSRLS;
            END IF;
        END
        $$;
        """
    )
    op.execute(
        f"""
        DO $$
        BEGIN
            EXECUTE format('GRANT CONNECT ON DATABASE %I TO {APP_ROLE}', current_database());
        END
        $$;
        """
    )
    op.execute(f"GRANT USAGE ON SCHEMA public TO {APP_ROLE};")
    op.execute(f"GRANT SELECT, INSERT, UPDATE ON tenants TO {APP_ROLE};")
    op.execute(f"GRANT SELECT, INSERT, UPDATE ON api_keys TO {APP_ROLE};")
    op.execute(f"GRANT SELECT, UPDATE ON admin_users TO {APP_ROLE};")
    op.execute(f"GRANT SELECT, INSERT ON audit_log TO {APP_ROLE};")

    # --- Row-Level Security: tenant isolation as defense-in-depth ------------------
    # Bypass branch (aegis.bypass_rls = 'on') is used narrowly: once, at auth time, to
    # look up an api_keys row by key_id before the tenant is known (see
    # db.session.set_rls_context docstring), and by admin-authenticated request paths
    # that legitimately need cross-tenant visibility.
    #
    # Compares tenant_id::text rather than casting the GUC to ::uuid: Postgres does
    # NOT guarantee left-to-right short-circuit evaluation of OR, so when bypass_rls
    # is 'on' and aegis.tenant_id is unset (empty string), the ::uuid cast branch can
    # still be evaluated and raise "invalid input syntax for type uuid" even though
    # the bypass branch alone would satisfy the policy. Text comparison never throws.
    for table in ("api_keys", "audit_log"):
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
    for table in ("api_keys", "audit_log"):
        op.execute(f"DROP POLICY IF EXISTS tenant_isolation ON {table};")
        op.execute(f"ALTER TABLE {table} DISABLE ROW LEVEL SECURITY;")

    op.execute(f"REVOKE ALL ON audit_log FROM {APP_ROLE};")
    op.execute(f"REVOKE ALL ON admin_users FROM {APP_ROLE};")
    op.execute(f"REVOKE ALL ON api_keys FROM {APP_ROLE};")
    op.execute(f"REVOKE ALL ON tenants FROM {APP_ROLE};")
    op.execute(f"REVOKE USAGE ON SCHEMA public FROM {APP_ROLE};")
    op.execute(
        f"""
        DO $$
        BEGIN
            EXECUTE format('REVOKE CONNECT ON DATABASE %I FROM {APP_ROLE}', current_database());
        END
        $$;
        """
    )
    op.execute(f"DROP ROLE IF EXISTS {APP_ROLE};")

    op.drop_table("audit_log")
    op.drop_table("admin_users")
    op.drop_table("api_keys")
    op.drop_table("tenants")
