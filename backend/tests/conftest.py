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
