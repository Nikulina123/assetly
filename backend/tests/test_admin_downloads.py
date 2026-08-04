import re

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


async def _logged_in_client(email, password):
    client = await _client()
    await client.post("/admin/login", data={"email": email, "password": password})
    return client


async def _get_csrf_token(client, company_id):
    resp = await client.get(f"/admin/companies/{company_id}")
    return resp.text.split('name="csrf_token" value="')[1].split('"')[0]


async def test_download_macos_requires_login(company):
    company_id, _ = company
    async with await _client() as client:
        resp = await client.post(
            f"/admin/companies/{company_id}/download/macos",
            data={"csrf_token": "irrelevant"},
            follow_redirects=False,
        )
    assert resp.status_code == 303


async def test_download_macos_rotates_key_and_embeds_new_one(admin, company, db_pool):
    from app.auth import resolve_company_id

    _, email, password = admin
    company_id, old_api_key = company
    client = await _logged_in_client(email, password)
    try:
        csrf_token = await _get_csrf_token(client, company_id)
        resp = await client.post(
            f"/admin/companies/{company_id}/download/macos",
            data={"csrf_token": csrf_token},
        )
    finally:
        await client.aclose()
    assert resp.status_code == 200
    assert "attachment" in resp.headers.get("content-disposition", "")
    body = resp.text
    assert "APPS_SCRIPT_URL" not in body
    assert 'CHECKIN_API_URL="https://api.example.com/api/v1/inventory/checkin"' in body

    match = re.search(r'COMPANY_API_KEY="(wz_live_[a-f0-9]+)"', body)
    assert match is not None, "no COMPANY_API_KEY found in downloaded script"
    new_api_key = match.group(1)
    assert new_api_key != old_api_key

    old_resolved = await resolve_company_id(db_pool, old_api_key)
    assert old_resolved is None
    new_resolved = await resolve_company_id(db_pool, new_api_key)
    assert new_resolved == company_id


async def test_download_linux_contains_a_fresh_key(admin, company):
    _, email, password = admin
    company_id, old_api_key = company
    client = await _logged_in_client(email, password)
    try:
        csrf_token = await _get_csrf_token(client, company_id)
        resp = await client.post(
            f"/admin/companies/{company_id}/download/linux",
            data={"csrf_token": csrf_token},
        )
    finally:
        await client.aclose()
    assert resp.status_code == 200
    body = resp.text
    assert "APPS_SCRIPT_URL" not in body
    match = re.search(r'COMPANY_API_KEY="(wz_live_[a-f0-9]+)"', body)
    assert match is not None
    assert match.group(1) != old_api_key


async def test_download_blocked_for_revoked_company(admin, company, db_pool):
    _, email, password = admin
    company_id, _ = company
    client = await _logged_in_client(email, password)
    try:
        # Fetch the CSRF token BEFORE revoking, so this test isolates "is the
        # download blocked for a revoked company" from any side effect of
        # revocation on CSRF/detail-page rendering.
        csrf_token = await _get_csrf_token(client, company_id)

        async with db_pool.acquire() as conn:
            await conn.execute("UPDATE companies SET revoked_at = NOW() WHERE id = $1", company_id)

        resp = await client.post(
            f"/admin/companies/{company_id}/download/macos",
            data={"csrf_token": csrf_token},
        )
    finally:
        await client.aclose()
    assert resp.status_code == 404


async def test_download_without_csrf_token_is_rejected(admin, company):
    _, email, password = admin
    company_id, _ = company
    client = await _logged_in_client(email, password)
    try:
        resp = await client.post(f"/admin/companies/{company_id}/download/macos", data={})
    finally:
        await client.aclose()
    assert resp.status_code == 422
