import json
from base64 import b64decode, b64encode

import itsdangerous
import pytest
import pytest_asyncio
from httpx import ASGITransport, AsyncClient

import app.db as db_module
from app.config import SESSION_SECRET_KEY
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


async def test_login_with_correct_credentials_redirects_to_mfa_setup(admin):
    """An admin with no MFA enrolled yet -- true of every admin that exists
    today, since enrollment ships in this same change -- lands on setup, not
    straight into the console. A correct password alone no longer reaches
    anything: see test_admin_mfa_routes.py for the enrolled-admin path."""
    _, email, password = admin
    async with await _client() as client:
        resp = await client.post(
            "/admin/login",
            data={"email": email, "password": password},
            follow_redirects=False,
        )
    assert resp.status_code == 303
    assert resp.headers["location"] == "/admin/mfa/setup"
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


def _sign_session(payload: dict) -> str:
    """Build a session cookie value the same way Starlette's SessionMiddleware
    does: base64-encode the JSON payload, then sign it with itsdangerous'
    TimestampSigner keyed on the app's SESSION_SECRET_KEY."""
    signer = itsdangerous.TimestampSigner(str(SESSION_SECRET_KEY))
    data = b64encode(json.dumps(payload).encode("utf-8"))
    return signer.sign(data).decode("utf-8")


def _unsign_session(cookie_value: str) -> dict:
    signer = itsdangerous.TimestampSigner(str(SESSION_SECRET_KEY))
    data = signer.unsign(cookie_value.encode("utf-8"))
    return json.loads(b64decode(data))


async def test_login_rotates_session(admin):
    """A pre-login session must not survive authentication. Without
    session.clear(), an attacker who can fixate the victim's session cookie
    (e.g. plant a csrf_token before the victim logs in) still finds that
    planted value in the session after login.

    Login now only reaches the PENDING state (no admin_id -- see
    test_admin_mfa_routes.py for the full two-stage flow and the final
    rotation at /admin/mfa/verify), but the rotation property itself must
    still hold at this first step: the planted value must not survive.
    """
    _, email, password = admin
    planted_cookie = _sign_session({"csrf_token": "attacker-planted-value"})

    async with await _client() as client:
        # Fixate the session cookie before login, as an attacker would.
        resp = await client.post(
            "/admin/login",
            data={"email": email, "password": password},
            headers={"Cookie": f"session={planted_cookie}"},
        )
        assert resp.status_code == 303
        after = client.cookies.get("session")

    assert after is not None
    session_data = _unsign_session(after)
    assert session_data.get("pending_admin_id") is not None
    assert session_data.get("csrf_token") != "attacker-planted-value"
