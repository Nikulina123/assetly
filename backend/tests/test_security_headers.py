import pytest
import pytest_asyncio
from httpx import ASGITransport, AsyncClient

import app.db as db_module
from app.main import app

pytestmark = pytest.mark.asyncio


@pytest_asyncio.fixture(autouse=True)
async def _reset_app_pool():
    yield
    await db_module.close_pool()


async def _client():
    transport = ASGITransport(app=app)
    return AsyncClient(transport=transport, base_url="http://test")


async def test_login_page_sets_baseline_security_headers():
    async with await _client() as client:
        resp = await client.get("/admin/login")
    assert resp.status_code == 200
    assert resp.headers["x-content-type-options"] == "nosniff"
    assert resp.headers["x-frame-options"] == "DENY"
    assert resp.headers["referrer-policy"] == "strict-origin-when-cross-origin"


async def test_hsts_absent_when_session_cookie_not_secure(monkeypatch):
    monkeypatch.setattr("app.middleware.SESSION_COOKIE_SECURE", False)
    async with await _client() as client:
        resp = await client.get("/admin/login")
    assert "strict-transport-security" not in resp.headers


async def test_hsts_present_when_session_cookie_secure(monkeypatch):
    monkeypatch.setattr("app.middleware.SESSION_COOKIE_SECURE", True)
    async with await _client() as client:
        resp = await client.get("/admin/login")
    assert resp.headers["strict-transport-security"] == "max-age=31536000; includeSubDomains"
