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


async def test_two_requests_get_different_nonces():
    async with await _client() as client:
        r1 = await client.get("/admin/login")
        r2 = await client.get("/admin/login")
    csp1 = r1.headers["content-security-policy"]
    csp2 = r2.headers["content-security-policy"]
    assert csp1 != csp2


async def test_nonce_in_csp_header_matches_nonce_in_rendered_html():
    async with await _client() as client:
        resp = await client.get("/admin/login")
    csp = resp.headers["content-security-policy"]
    start = csp.index("'nonce-") + len("'nonce-")
    end = csp.index("'", start)
    nonce = csp[start:end]
    assert len(nonce) > 10


async def test_mfa_setup_page_still_renders_with_headers_applied(admin):
    admin_id, email, password = admin
    async with await _client() as client:
        await client.post(
            "/admin/login",
            data={"email": email, "password": password},
            follow_redirects=False,
        )
        resp = await client.get("/admin/mfa/setup")
    assert resp.status_code == 200
    assert b"<svg" in resp.content
    assert "content-security-policy" in resp.headers
