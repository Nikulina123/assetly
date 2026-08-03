import os
import asyncpg
import pytest_asyncio

TEST_DATABASE_URL = os.environ.get(
    "TEST_DATABASE_URL",
    "postgresql://webiz_app@localhost:5432/webiz_checkin_test",
)

ADMIN_TEST_DATABASE_URL = os.environ.get(
    "ADMIN_TEST_DATABASE_URL",
    "postgresql://admin@localhost:5432/webiz_checkin_test",
)


@pytest_asyncio.fixture
async def db_pool():
    # Truncate via a separate admin connection: webiz_app intentionally has no
    # TRUNCATE grant in production (TRUNCATE bypasses RLS entirely), so test
    # cleanup can't go through the same role the app itself uses.
    admin_conn = await asyncpg.connect(ADMIN_TEST_DATABASE_URL)
    await admin_conn.execute("TRUNCATE device_checkins, devices, companies, admins CASCADE;")
    await admin_conn.close()

    pool = await asyncpg.create_pool(TEST_DATABASE_URL)
    yield pool
    await pool.close()


@pytest_asyncio.fixture
async def company(db_pool):
    """Inserts one company with a known plaintext key, returns (company_id, api_key)."""
    from app.auth import generate_api_key, hash_api_key

    api_key = generate_api_key()
    key_hash = hash_api_key(api_key)
    async with db_pool.acquire() as conn:
        row = await conn.fetchrow(
            "INSERT INTO companies (name, api_key_hash, api_key_prefix) "
            "VALUES ($1, $2, $3) RETURNING id",
            "Test Co", key_hash, api_key[:8],
        )
    return str(row["id"]), api_key


@pytest_asyncio.fixture
async def admin(db_pool):
    """Inserts one admin with a known plaintext password, returns (admin_id, email, password).

    Inserted via a separate admin-role connection (like the db_pool truncate
    step above): webiz_app intentionally only has SELECT on admins (see
    migrations/002_admin_auth.sql) since admin accounts are seeded via
    scripts/seed_admin.py run as the `admin` superuser, not through the app.
    """
    from app.admin_auth import hash_password

    email = "admin@example.com"
    password = "correct-horse-battery-staple"
    admin_conn = await asyncpg.connect(ADMIN_TEST_DATABASE_URL)
    try:
        row = await admin_conn.fetchrow(
            "INSERT INTO admins (email, password_hash) VALUES ($1, $2) RETURNING id",
            email, hash_password(password),
        )
    finally:
        await admin_conn.close()
    return str(row["id"]), email, password
