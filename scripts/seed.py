"""Bootstrap script: creates one tenant, one API key, and one admin user.

Deliberately the ONLY way to provision an admin account — there is no public
/admin/register endpoint (see api/admin.py) — so this must be run out-of-band with
the table-owner DB role, not the restricted runtime aegis_app role.

Usage:
    uv run python scripts/seed.py --tenant-name "Demo Tenant" \
        --admin-email admin@example.com --admin-password "change-me-now"

Prints the full API key exactly once — it is never recoverable after this, only its
HMAC digest is stored (see core/security.py).
"""

import argparse
import asyncio

from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine

from aegis_gateway.core.config import get_settings
from aegis_gateway.core.security import generate_api_key, hash_api_key_secret, hash_password
from aegis_gateway.db.models import AdminUser, ApiKey, Tenant


async def seed(tenant_name: str, admin_email: str, admin_password: str) -> None:
    settings = get_settings()
    engine = create_async_engine(settings.migration_database_url)
    async_session_factory = async_sessionmaker(bind=engine, expire_on_commit=False)

    async with async_session_factory() as session:
        tenant = Tenant(name=tenant_name)
        session.add(tenant)
        await session.flush()

        full_key, key_id, secret_part = generate_api_key()
        api_key = ApiKey(
            tenant_id=tenant.id,
            key_id=key_id,
            hashed_secret=hash_api_key_secret(secret_part, settings.api_key_pepper),
            name="seed-default-key",
        )
        session.add(api_key)

        admin = AdminUser(
            email=admin_email,
            hashed_password=hash_password(admin_password),
            is_superuser=True,
        )
        session.add(admin)

        await session.commit()

    await engine.dispose()

    print("Seed complete.\n")
    print(f"  Tenant:    {tenant_name} ({tenant.id})")
    print(f"  Admin:     {admin_email}")
    print(f"  API key:   {full_key}   <-- shown once, store it now\n")
    print("Try it: curl -H 'Authorization: Bearer " + full_key + "' localhost:8000/v1/ping")


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--tenant-name", required=True)
    parser.add_argument("--admin-email", required=True)
    parser.add_argument("--admin-password", required=True)
    args = parser.parse_args()
    asyncio.run(seed(args.tenant_name, args.admin_email, args.admin_password))


if __name__ == "__main__":
    main()
