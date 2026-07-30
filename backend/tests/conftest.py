import os
import asyncpg
import pytest_asyncio

TEST_DATABASE_URL = os.environ.get(
    "TEST_DATABASE_URL",
    "postgresql://webiz_app@localhost:5432/webiz_checkin_test",
)


@pytest_asyncio.fixture
async def db_pool():
    pool = await asyncpg.create_pool(TEST_DATABASE_URL)
    async with pool.acquire() as conn:
        await conn.execute("TRUNCATE device_checkins, devices, companies CASCADE;")
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
