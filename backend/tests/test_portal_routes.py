import uuid

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


async def _login(client, email, password):
    return await client.post("/admin/login", data={"email": email, "password": password})


async def _submit(client, api_key, serial_number, hostname):
    return await client.post(
        "/api/v1/inventory/checkin",
        json={
            "checkin_id": str(uuid.uuid4()),
            "timestamp": "2026-07-30T10:00:00",
            "first_name": "A", "last_name": "B", "email": "a@example.com",
            "department": "Engineering",
            "serial_number": serial_number, "hostname": hostname,
            "brand": "Apple", "model": "MacBook Pro", "os": "macOS 14.4.1",
        },
        headers={"Authorization": f"Bearer {api_key}"},
    )


async def _second_company(db_pool, name="Other Co"):
    from app.auth import generate_api_key, hash_api_key
    api_key = generate_api_key()
    async with db_pool.acquire() as conn:
        row = await conn.fetchrow(
            "INSERT INTO companies (name, api_key_hash, api_key_prefix) "
            "VALUES ($1, $2, $3) RETURNING id",
            name, hash_api_key(api_key), api_key[:8],
        )
    return str(row["id"]), api_key


async def test_dashboard_requires_login(db_pool, company):
    company_id, _ = company
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        resp = await client.get(f"/admin/companies/{company_id}/dashboard")
    assert resp.status_code in (303, 307)
    assert "/admin/login" in resp.headers["location"]


async def test_unknown_company_is_404(db_pool, admin):
    _, email, password = admin
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test", follow_redirects=True) as client:
        await _login(client, email, password)
        resp = await client.get(f"/admin/companies/{uuid.uuid4()}/dashboard")
    assert resp.status_code == 404


@pytest.mark.xfail(reason="portal templates land in Task 13", strict=True)
async def test_dashboard_renders_for_admin(db_pool, company, admin):
    company_id, api_key = company
    _, email, password = admin
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test", follow_redirects=True) as client:
        await _submit(client, api_key, "SN-001", "host-1")
        await _login(client, email, password)
        resp = await client.get(f"/admin/companies/{company_id}/dashboard")
    assert resp.status_code == 200
    assert "Total Devices" in resp.text


@pytest.mark.xfail(reason="portal templates land in Task 13", strict=True)
async def test_computers_page_does_not_leak_other_company_devices(db_pool, company, admin):
    """RLS must scope every portal read to the company in the URL. This is the
    first place a path segment picks a tenant, so a regression here is a
    cross-tenant data leak, not a rendering bug."""
    company_a_id, key_a = company
    company_b_id, key_b = await _second_company(db_pool)
    _, email, password = admin
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test", follow_redirects=True) as client:
        await _submit(client, key_a, "SN-AAA", "alpha-host")
        await _submit(client, key_b, "SN-BBB", "bravo-host")
        await _login(client, email, password)
        resp = await client.get(f"/admin/companies/{company_a_id}/computers")
    assert resp.status_code == 200
    assert "alpha-host" in resp.text
    assert "bravo-host" not in resp.text
    assert "SN-BBB" not in resp.text


@pytest.mark.xfail(reason="portal templates land in Task 13", strict=True)
async def test_device_detail_renders(db_pool, company, admin):
    company_id, api_key = company
    _, email, password = admin
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test", follow_redirects=True) as client:
        await _submit(client, api_key, "SN-001", "host-1")
        await _login(client, email, password)
        resp = await client.get(f"/admin/companies/{company_id}/computers/SN-001")
    assert resp.status_code == 200
    assert "SN-001" in resp.text


async def test_device_detail_unknown_serial_is_404(db_pool, company, admin):
    company_id, _ = company
    _, email, password = admin
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test", follow_redirects=True) as client:
        await _login(client, email, password)
        resp = await client.get(f"/admin/companies/{company_id}/computers/NOPE")
    assert resp.status_code == 404
