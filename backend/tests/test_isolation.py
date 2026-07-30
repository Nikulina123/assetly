import uuid

import pytest
import pytest_asyncio
from httpx import ASGITransport, AsyncClient

import app.db as db_module
from app.main import app

pytestmark = pytest.mark.asyncio


@pytest_asyncio.fixture(autouse=True)
async def _reset_app_pool():
    # app.db caches a module-level asyncpg pool bound to whichever event loop
    # created it. pytest-asyncio gives each test its own event loop, so a pool
    # left over from a previous test breaks (or hangs) on reuse. Close it after
    # every test so the next one lazily creates a fresh pool on its own loop.
    yield
    await db_module.close_pool()


async def _client():
    transport = ASGITransport(app=app)
    return AsyncClient(transport=transport, base_url="http://test")


async def _checkin(client, api_key, serial_number):
    payload = {
        "checkin_id": str(uuid.uuid4()),
        "timestamp": "2026-07-30T10:00:00",
        "first_name": "A",
        "last_name": "B",
        "email": "a@example.com",
        "project": "Webiz ERP",
        "serial_number": serial_number,
        "hostname": "host-1",
        "brand": "Apple",
        "model": "MacBook Pro",
        "os": "macOS 14.4.1",
    }
    return await client.post(
        "/api/v1/inventory/checkin",
        json=payload,
        headers={"Authorization": f"Bearer {api_key}"},
    )


async def test_company_a_query_never_returns_company_b_rows(db_pool, company):
    from app.auth import generate_api_key, hash_api_key

    company_a_id, company_a_key = company

    api_key_b = generate_api_key()
    async with db_pool.acquire() as conn:
        row = await conn.fetchrow(
            "INSERT INTO companies (name, api_key_hash, api_key_prefix) "
            "VALUES ($1, $2, $3) RETURNING id",
            "Company B", hash_api_key(api_key_b), api_key_b[:8],
        )
    company_b_id = str(row["id"])

    async with await _client() as client:
        resp_a = await _checkin(client, company_a_key, "SN-A-001")
        resp_b = await _checkin(client, api_key_b, "SN-B-001")
    assert resp_a.status_code == 200
    assert resp_b.status_code == 200

    async with db_pool.acquire() as conn:
        # is_local=true only holds for the duration of an explicit transaction;
        # wrap both statements in one so the RLS setting is still in effect
        # when the SELECT runs.
        async with conn.transaction():
            await conn.execute(
                "SELECT set_config('app.company_id', $1, true)", company_a_id
            )
            rows = await conn.fetch("SELECT serial_number FROM device_checkins")

    serials = {r["serial_number"] for r in rows}
    assert serials == {"SN-A-001"}
    assert "SN-B-001" not in serials
