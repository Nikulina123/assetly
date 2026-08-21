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


async def test_login_page_loads():
    async with await _client() as client:
        resp = await client.get("/admin/login")
    assert resp.status_code == 200
    assert b"Log in" in resp.content or b"Login" in resp.content


async def test_login_with_correct_credentials_redirects_to_companies(admin):
    _, email, password = admin
    async with await _client() as client:
        resp = await client.post(
            "/admin/login",
            data={"email": email, "password": password},
            follow_redirects=False,
        )
    assert resp.status_code == 303
    assert resp.headers["location"] == "/admin/companies"
    assert "session" in resp.cookies


async def test_login_with_wrong_password_shows_error(admin):
    _, email, _ = admin
    async with await _client() as client:
        resp = await client.post(
            "/admin/login", data={"email": email, "password": "wrong"}
        )
    assert resp.status_code == 200
    assert b"Invalid email or password" in resp.content


async def test_accessing_companies_without_session_redirects_to_login():
    async with await _client() as client:
        resp = await client.get("/admin/companies", follow_redirects=False)
    assert resp.status_code == 303
    assert resp.headers["location"] == "/admin/login"


async def test_login_rotates_session(admin):
    """A pre-login session must not survive authentication. Without
    session.clear(), an attacker who can fixate the victim's session cookie
    before login still holds a valid cookie after it."""
    _, email, password = admin
    async with await _client() as client:
        # Touch the login form first so a session cookie exists pre-auth.
        await client.get("/admin/login")
        before = client.cookies.get("session")

        resp = await client.post(
            "/admin/login", data={"email": email, "password": password}
        )
        assert resp.status_code == 303
        after = client.cookies.get("session")

    assert after is not None
    assert after != before
