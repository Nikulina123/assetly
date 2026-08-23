import httpx
import pytest
import pytest_asyncio

import app.db as db_module
from app.main import app


@pytest_asyncio.fixture(autouse=True)
async def _reset_app_pool():
    # app.db caches a module-level asyncpg pool bound to whichever event loop
    # created it. pytest-asyncio gives each test its own event loop, so a pool
    # left over from a previous test breaks (or hangs) on reuse. Close it after
    # every test so the next one lazily creates a fresh pool on its own loop.
    # Same pattern as tests/test_checkin.py.
    yield
    await db_module.close_pool()


def _payload(serial: str) -> dict:
    return {
        "checkin_id": "22222222-2222-2222-2222-222222222222",
        "timestamp": "2026-08-20T10:00:00Z",
        "first_name": "Ann",
        "last_name": "Lee",
        "email": "ann@example.com",
        "serial_number": serial,
        "hostname": "host-1",
        "brand": "Apple",
        "model": "MacBook Pro",
        "os": "macOS 15.0",
    }


@pytest.mark.asyncio
async def test_checkin_accepts_matching_serial(db_pool, enrolled_device):
    credential, serial = enrolled_device
    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
        resp = await client.post(
            "/api/v1/inventory/checkin",
            json=_payload(serial),
            headers={"Authorization": f"Bearer {credential}"},
        )
    assert resp.status_code == 200


@pytest.mark.asyncio
async def test_checkin_rejects_mismatched_serial(db_pool, enrolled_device):
    """The core of M-1: without this, one compromised endpoint can overwrite
    the inventory record of every other machine in the tenant."""
    credential, _serial = enrolled_device
    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
        resp = await client.post(
            "/api/v1/inventory/checkin",
            json=_payload("SOMEONE-ELSES-SERIAL"),
            headers={"Authorization": f"Bearer {credential}"},
        )
    assert resp.status_code == 409
    assert "serial" in resp.json()["detail"].lower()


@pytest.mark.asyncio
async def test_mismatched_serial_writes_nothing(db_pool, company, enrolled_device):
    company_id, _api_key = company
    credential, _serial = enrolled_device
    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
        await client.post(
            "/api/v1/inventory/checkin",
            json=_payload("SOMEONE-ELSES-SERIAL"),
            headers={"Authorization": f"Bearer {credential}"},
        )
    async with db_pool.acquire() as conn:
        # RLS on devices requires app.company_id to be set on the connection
        # (see the identical note in tests/test_checkin.py) -- a virgin
        # connection would fail with "unrecognized configuration parameter"
        # before RLS even gets a chance to filter.
        await conn.execute("SELECT set_config('app.company_id', $1, false)", company_id)
        count = await conn.fetchval(
            "SELECT count(*) FROM devices WHERE serial_number = $1",
            "SOMEONE-ELSES-SERIAL",
        )
    assert count == 0


@pytest.mark.asyncio
async def test_legacy_company_key_is_exempt(db_pool, company):
    """A company key is not issued for a serial, so there is nothing to bind
    against. Forcing binding here would take the unconverted fleet dark."""
    _company_id, api_key = company
    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
        resp = await client.post(
            "/api/v1/inventory/checkin",
            json=_payload("ANY-SERIAL"),
            headers={"Authorization": f"Bearer {api_key}"},
        )
    assert resp.status_code == 200
