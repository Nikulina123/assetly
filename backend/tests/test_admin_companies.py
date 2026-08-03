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


async def test_companies_list_requires_login():
    async with await _client() as client:
        resp = await client.get("/admin/companies", follow_redirects=False)
    assert resp.status_code == 303


async def test_companies_list_shows_existing_companies(admin, company):
    _, email, password = admin
    _, _ = company
    client = await _logged_in_client(email, password)
    try:
        resp = await client.get("/admin/companies")
    finally:
        await client.aclose()
    assert resp.status_code == 200
    assert b"Test Co" in resp.content


async def test_create_company_shows_new_api_key_once(admin, db_pool):
    _, email, password = admin
    client = await _logged_in_client(email, password)
    try:
        get_resp = await client.get("/admin/companies")
        csrf_token = get_resp.text.split('name="csrf_token" value="')[1].split('"')[0]

        resp = await client.post(
            "/admin/companies",
            data={"name": "New Co", "csrf_token": csrf_token},
        )
    finally:
        await client.aclose()
    assert resp.status_code == 200
    assert b"New Co" in resp.content
    assert b"wz_live_" in resp.content

    async with db_pool.acquire() as conn:
        row = await conn.fetchrow("SELECT id FROM companies WHERE name = 'New Co'")
    assert row is not None


async def test_create_company_without_csrf_token_is_rejected(admin):
    _, email, password = admin
    client = await _logged_in_client(email, password)
    try:
        resp = await client.post("/admin/companies", data={"name": "No CSRF Co"})
    finally:
        await client.aclose()
    assert resp.status_code == 422  # FastAPI rejects the missing required Form field


async def test_company_detail_shows_company_info(admin, company):
    _, email, password = admin
    company_id, _ = company
    client = await _logged_in_client(email, password)
    try:
        resp = await client.get(f"/admin/companies/{company_id}")
    finally:
        await client.aclose()
    assert resp.status_code == 200
    assert b"Test Co" in resp.content


async def test_company_detail_404_for_unknown_id(admin):
    _, email, password = admin
    client = await _logged_in_client(email, password)
    try:
        resp = await client.get("/admin/companies/00000000-0000-0000-0000-000000000000")
    finally:
        await client.aclose()
    assert resp.status_code == 404


async def test_rotate_key_invalidates_old_key_and_activates_new(admin, company, db_pool):
    from app.auth import resolve_company_id

    _, email, password = admin
    company_id, old_api_key = company
    client = await _logged_in_client(email, password)
    try:
        get_resp = await client.get(f"/admin/companies/{company_id}")
        csrf_token = get_resp.text.split('name="csrf_token" value="')[1].split('"')[0]

        resp = await client.post(
            f"/admin/companies/{company_id}/rotate-key",
            data={"csrf_token": csrf_token},
        )
    finally:
        await client.aclose()
    assert resp.status_code == 200
    assert b"wz_live_" in resp.content

    old_resolved = await resolve_company_id(db_pool, old_api_key)
    assert old_resolved is None

    new_api_key = resp.text.split("<code>")[1].split("</code>")[0]
    new_resolved = await resolve_company_id(db_pool, new_api_key)
    assert new_resolved == company_id


async def test_revoke_company_stops_key_from_resolving(admin, company, db_pool):
    from app.auth import resolve_company_id

    _, email, password = admin
    company_id, api_key = company
    client = await _logged_in_client(email, password)
    try:
        get_resp = await client.get(f"/admin/companies/{company_id}")
        csrf_token = get_resp.text.split('name="csrf_token" value="')[1].split('"')[0]

        resp = await client.post(
            f"/admin/companies/{company_id}/revoke",
            data={"csrf_token": csrf_token},
        )
    finally:
        await client.aclose()
    assert resp.status_code == 200
    assert b"Revoked" in resp.content

    resolved = await resolve_company_id(db_pool, api_key)
    assert resolved is None


async def test_revoke_is_idempotent(admin, company):
    _, email, password = admin
    company_id, _ = company
    client = await _logged_in_client(email, password)
    try:
        get_resp = await client.get(f"/admin/companies/{company_id}")
        csrf_token = get_resp.text.split('name="csrf_token" value="')[1].split('"')[0]

        first = await client.post(
            f"/admin/companies/{company_id}/revoke", data={"csrf_token": csrf_token}
        )
        second = await client.post(
            f"/admin/companies/{company_id}/revoke", data={"csrf_token": csrf_token}
        )
    finally:
        await client.aclose()
    assert first.status_code == 200
    assert second.status_code == 200
