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
    yield
    await db_module.close_pool()


@pytest.mark.asyncio
async def test_login_is_rate_limited_per_ip(db_pool, admin):
    """Eleven wrong passwords from one address: the eleventh must be refused
    outright rather than merely answered with 'invalid password'."""
    _admin_id, email, _password = admin
    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
        statuses = []
        for _ in range(11):
            resp = await client.post(
                "/admin/login",
                data={"email": email, "password": "wrong"},
                headers={"x-forwarded-for": "203.0.113.9"},
            )
            statuses.append(resp.status_code)
    assert statuses[-1] == 429
    assert statuses[0] == 200  # the login form, re-rendered with an error


@pytest.mark.asyncio
async def test_enroll_is_rate_limited_per_ip(db_pool):
    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
        last = None
        for _ in range(31):
            last = await client.post(
                "/api/v1/enroll",
                json={"serial_number": "S1"},
                headers={
                    "Authorization": "Bearer as_enroll_bogus",
                    "x-forwarded-for": "203.0.113.10",
                },
            )
    assert last.status_code == 429


@pytest.mark.asyncio
async def test_checkin_is_rate_limited_per_credential(db_pool, enrolled_device):
    credential, serial = enrolled_device
    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
        last = None
        for _ in range(61):
            last = await client.get(
                "/api/v1/inventory/config",
                headers={"Authorization": f"Bearer {credential}"},
            )
    assert last.status_code == 429
    assert "Retry-After" in last.headers
