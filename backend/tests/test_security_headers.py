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


async def test_nonce_in_csp_header_matches_nonce_in_rendered_html(
    scoped_admin, login_as, enrolled_device
):
    _admin_id, _email, _password, _secret, company_id = scoped_admin
    credential, serial = enrolled_device
    # portal_computers.html only renders the inline <script> (and its nonce)
    # when the devices table is non-empty, so a real check-in has to land
    # first -- enrolling a device alone only creates a device_credentials
    # row, not a devices row (that's written by the checkin endpoint).
    async with await _client() as client:
        checkin_resp = await client.post(
            "/api/v1/inventory/checkin",
            json={
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
            },
            headers={"Authorization": f"Bearer {credential}"},
        )
        assert checkin_resp.status_code == 200
        await login_as(client, scoped_admin)
        resp = await client.get(f"/admin/companies/{company_id}/computers")
    assert resp.status_code == 200
    csp = resp.headers["content-security-policy"]
    start = csp.index("'nonce-") + len("'nonce-")
    end = csp.index("'", start)
    nonce = csp[start:end]
    assert len(nonce) > 10
    body = resp.content.decode()
    assert f'nonce="{nonce}"' in body
    assert "<script" in body


async def test_csp_header_contains_expected_directives():
    async with await _client() as client:
        resp = await client.get("/admin/login")
    csp = resp.headers["content-security-policy"]
    for directive in (
        "default-src",
        "script-src",
        "style-src",
        "img-src",
        "object-src",
        "base-uri",
        "frame-ancestors",
    ):
        assert directive in csp


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
