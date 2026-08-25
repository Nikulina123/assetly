"""Least privilege on the admin tier (H-2b).

`support` exists so that routine work -- looking things up, answering a
customer question -- does not require the credential that can rotate a
company's API key or mint an enrollment token for any tenant.
"""
import json
from base64 import b64decode

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


def _session_csrf(client) -> str:
    signer = itsdangerous.TimestampSigner(str(SESSION_SECRET_KEY))
    session = json.loads(b64decode(signer.unsign(client.cookies["session"].encode())))
    return session["csrf_token"]


READ_ROUTES = ["/admin/companies"]

# Every state-changing route, plus the three installer downloads (they are
# POSTs and they MINT ENROLLMENT TOKENS, which is exactly the capability
# `support` must not have) and /admin/diagnostics (a GET, but it discloses
# server filesystem paths).
def _write_routes(company_id, token_id, serial):
    return [
        ("POST", "/admin/companies"),
        ("POST", f"/admin/companies/{company_id}/rotate-key"),
        ("POST", f"/admin/companies/{company_id}/revoke"),
        ("POST", f"/admin/companies/{company_id}/notification-email"),
        ("POST", f"/admin/companies/{company_id}/schedule"),
        ("POST", f"/admin/companies/{company_id}/appearance"),
        ("POST", f"/admin/companies/{company_id}/fields/hardware"),
        ("POST", f"/admin/companies/{company_id}/fields/custom"),
        ("POST", f"/admin/companies/{company_id}/fields/custom/somekey/remove"),
        ("POST", f"/admin/companies/{company_id}/tokens/{token_id}/revoke"),
        ("POST", f"/admin/companies/{company_id}/devices/{serial}/revoke"),
        ("POST", f"/admin/companies/{company_id}/download/macos"),
        ("POST", f"/admin/companies/{company_id}/download/linux"),
        ("POST", f"/admin/companies/{company_id}/download/windows"),
        ("GET", "/admin/diagnostics"),
    ]


async def test_support_admin_can_read(support_admin, company, login_as):
    async with await _client() as client:
        await login_as(client, support_admin)
        for path in READ_ROUTES:
            resp = await client.get(path)
            assert resp.status_code == 200, f"{path} -> {resp.status_code}"


async def test_support_admin_is_refused_every_privileged_route(
    support_admin, company, login_as
):
    """403 must come from the dependency, not from a missing form field -- so
    a 422 here is a FAILURE: it means the request got past authorisation and
    was only stopped by validation."""
    company_id, _api_key = company
    async with await _client() as client:
        await login_as(client, support_admin)
        await client.get("/admin/companies")
        session_csrf = _session_csrf(client)
        for method, path in _write_routes(company_id, "00000000-0000-0000-0000-000000000000", "S1"):
            if method == "GET":
                resp = await client.get(path)
            else:
                resp = await client.post(path, data={"csrf_token": session_csrf})
            assert resp.status_code == 403, f"{method} {path} -> {resp.status_code}"


async def test_full_admin_is_not_refused(enrolled_admin, company, login_as):
    """The mirror of the test above: proves the 403s are about the role and not
    about something else being broken for everyone."""
    company_id, _api_key = company
    async with await _client() as client:
        await login_as(client, enrolled_admin)
        resp = await client.get("/admin/diagnostics")
    assert resp.status_code == 200


async def test_a_role_change_takes_effect_on_the_next_request(
    db_pool, enrolled_admin, login_as
):
    """Role is read per request, so demotion does not wait for cookie expiry."""
    import asyncpg
    from tests.conftest import ADMIN_TEST_DATABASE_URL

    admin_id, _email, _password, _secret = enrolled_admin
    async with await _client() as client:
        await login_as(client, enrolled_admin)
        assert (await client.get("/admin/diagnostics")).status_code == 200
        conn = await asyncpg.connect(ADMIN_TEST_DATABASE_URL)
        try:
            await conn.execute("UPDATE admins SET role = 'support' WHERE id = $1", admin_id)
        finally:
            await conn.close()
        assert (await client.get("/admin/diagnostics")).status_code == 403


async def test_a_deleted_admin_cookie_authenticates_nobody(db_pool, enrolled_admin, login_as):
    import asyncpg
    from tests.conftest import ADMIN_TEST_DATABASE_URL

    admin_id, _email, _password, _secret = enrolled_admin
    async with await _client() as client:
        await login_as(client, enrolled_admin)
        conn = await asyncpg.connect(ADMIN_TEST_DATABASE_URL)
        try:
            await conn.execute("DELETE FROM admin_recovery_codes WHERE admin_id = $1", admin_id)
            await conn.execute("DELETE FROM admins WHERE id = $1", admin_id)
        finally:
            await conn.close()
        resp = await client.get("/admin/companies", follow_redirects=False)
    assert resp.status_code == 303
    assert resp.headers["location"] == "/admin/login"
