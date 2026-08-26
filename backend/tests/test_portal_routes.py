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


async def test_unknown_company_is_404(db_pool, login_as, enrolled_admin):
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test", follow_redirects=True) as client:
        await login_as(client, enrolled_admin)
        resp = await client.get(f"/admin/companies/{uuid.uuid4()}/dashboard")
    assert resp.status_code == 404


async def test_dashboard_renders_for_admin(db_pool, company, login_as, enrolled_admin):
    company_id, api_key = company
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test", follow_redirects=True) as client:
        await _submit(client, api_key, "SN-001", "host-1")
        await login_as(client, enrolled_admin)
        resp = await client.get(f"/admin/companies/{company_id}/dashboard")
    assert resp.status_code == 200
    assert "Total Devices" in resp.text


async def test_dashboard_online_label_reflects_the_configured_interval(db_pool, company, login_as, enrolled_admin):
    """The "Online" count is proportional to this company's interval (see
    device_status.py), so its caption must name that interval. It read
    "checked in within 6 months" for every company, which is actively wrong
    for anyone who changed the setting -- a 24-hour count under a 6-month label.
    """
    company_id, api_key = company
    async with db_pool.acquire() as conn:
        await conn.execute(
            "UPDATE companies SET checkin_interval_seconds = $2, "
            "cancel_retry_seconds = $3 WHERE id = $1",
            uuid.UUID(company_id), 604800, 3600,   # 1 week
        )
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test", follow_redirects=True) as client:
        await _submit(client, api_key, "SN-001", "host-1")
        await login_as(client, enrolled_admin)
        resp = await client.get(f"/admin/companies/{company_id}/dashboard")
    assert resp.status_code == 200
    assert "checked in within 1 week" in resp.text
    assert "6 months" not in resp.text


async def test_computers_page_does_not_leak_other_company_devices(db_pool, company, login_as, enrolled_admin):
    """RLS must scope every portal read to the company in the URL. This is the
    first place a path segment picks a tenant, so a regression here is a
    cross-tenant data leak, not a rendering bug."""
    company_a_id, key_a = company
    company_b_id, key_b = await _second_company(db_pool)
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test", follow_redirects=True) as client:
        await _submit(client, key_a, "SN-AAA", "alpha-host")
        await _submit(client, key_b, "SN-BBB", "bravo-host")
        await login_as(client, enrolled_admin)
        resp = await client.get(f"/admin/companies/{company_a_id}/computers")
    assert resp.status_code == 200
    assert "alpha-host" in resp.text
    assert "bravo-host" not in resp.text
    assert "SN-BBB" not in resp.text


async def test_device_detail_renders(db_pool, company, login_as, enrolled_admin):
    company_id, api_key = company
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test", follow_redirects=True) as client:
        await _submit(client, api_key, "SN-001", "host-1")
        await login_as(client, enrolled_admin)
        resp = await client.get(f"/admin/companies/{company_id}/computers/SN-001")
    assert resp.status_code == 200
    assert "SN-001" in resp.text


async def test_device_detail_unknown_serial_is_404(db_pool, company, login_as, enrolled_admin):
    company_id, _ = company
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test", follow_redirects=True) as client:
        await login_as(client, enrolled_admin)
        resp = await client.get(f"/admin/companies/{company_id}/computers/NOPE")
    assert resp.status_code == 404


async def test_dashboard_renders_empty_state_for_company_with_no_devices(db_pool, company, login_as, enrolled_admin):
    """Guards the by_os division-by-zero path in portal_dashboard.html: a
    company with zero devices must render the empty state, not crash computing
    a percentage width from stats['total'] == 0."""
    company_id, _ = company
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test", follow_redirects=True) as client:
        await login_as(client, enrolled_admin)
        resp = await client.get(f"/admin/companies/{company_id}/dashboard")
    assert resp.status_code == 200
    assert "Total Devices" in resp.text
    assert "No devices yet" in resp.text


async def test_device_pages_render_with_missing_optional_fields(db_pool, company, login_as, enrolled_admin):
    """cpu, ram, storage, ip_address, department, and agent_version are all
    optional on CheckinRequest. Submitting without them must not raise in
    either the Computers list or the device detail template (both use
    `or '—'` guards and a conditional strftime for None values)."""
    company_id, api_key = company
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test", follow_redirects=True) as client:
        resp = await client.post(
            "/api/v1/inventory/checkin",
            json={
                "checkin_id": str(uuid.uuid4()),
                "timestamp": "2026-07-30T10:00:00",
                "first_name": "A", "last_name": "B", "email": "a@example.com",
                "serial_number": "SN-BARE", "hostname": "bare-host",
                "brand": "Apple", "model": "MacBook Pro", "os": "macOS 14.4.1",
            },
            headers={"Authorization": f"Bearer {api_key}"},
        )
        assert resp.status_code == 200
        await login_as(client, enrolled_admin)
        computers_resp = await client.get(f"/admin/companies/{company_id}/computers")
        device_resp = await client.get(f"/admin/companies/{company_id}/computers/SN-BARE")
    assert computers_resp.status_code == 200
    assert device_resp.status_code == 200
    assert "SN-BARE" in device_resp.text


async def test_device_detail_finds_preexisting_unnormalised_credential(db_pool, company, login_as, enrolled_admin):
    """A device_credentials row written before serials were casefolded at
    enrollment (simulated here by inserting directly with real-world casing)
    must still be found by device_detail's credential lookup -- otherwise the
    portal shows "no active credential" and hides the revoke control for a
    credential that is still live."""
    from app.auth import generate_api_key, hash_api_key

    company_id, api_key = company
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test", follow_redirects=True) as client:
        await _submit(client, api_key, "ABC-123", "raw-host")
        plaintext = generate_api_key()
        async with db_pool.acquire() as conn:
            await conn.execute(
                "INSERT INTO device_credentials "
                "(company_id, credential_hash, serial_number, hostname) "
                "VALUES ($1, $2, $3, $4)",
                company_id, hash_api_key(plaintext), "ABC-123", "raw-host",
            )
        from tests.test_enrollment import _run_migration_015
        await _run_migration_015(db_pool)
        await login_as(client, enrolled_admin)
        resp = await client.get(f"/admin/companies/{company_id}/computers/ABC-123")
    assert resp.status_code == 200
    assert "No enrollment credential on file" not in resp.text
    assert "/revoke" in resp.text


async def test_scoped_admin_gets_404_on_another_companys_portal_pages(
    db_pool, company, login_as, scoped_admin
):
    """The most valuable finding in Task 6: before per-company scoping was
    threaded through portal.py's _shell, any admin -- including one scoped to
    a single tenant -- could read another tenant's dashboard, device
    inventory, and check-in history simply by putting that tenant's
    company_id in the URL. scoped_admin is scoped to `company` (see the
    fixture), so `other_id` here is genuinely out of its scope."""
    other_id, other_key = await _second_company(db_pool, name="Other Co")
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test", follow_redirects=True) as client:
        await _submit(client, other_key, "OTHER-SN-1", "other-host")
        await login_as(client, scoped_admin)
        dashboard_resp = await client.get(f"/admin/companies/{other_id}/dashboard")
        computers_resp = await client.get(f"/admin/companies/{other_id}/computers")
        device_resp = await client.get(f"/admin/companies/{other_id}/computers/OTHER-SN-1")
    assert dashboard_resp.status_code == 404
    assert computers_resp.status_code == 404
    assert device_resp.status_code == 404


async def test_global_admin_still_gets_200_on_the_same_portal_pages(
    db_pool, company, login_as, enrolled_admin
):
    """The mirror of the test above: proves the 404s are about scope and not
    about something else being broken for everyone -- a route typo or a
    dropped dependency here would show up as a failure instead of a false
    pass."""
    company_id, api_key = company
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test", follow_redirects=True) as client:
        await _submit(client, api_key, "SN-GLOBAL-1", "global-host")
        await login_as(client, enrolled_admin)
        dashboard_resp = await client.get(f"/admin/companies/{company_id}/dashboard")
        computers_resp = await client.get(f"/admin/companies/{company_id}/computers")
        device_resp = await client.get(f"/admin/companies/{company_id}/computers/SN-GLOBAL-1")
    assert dashboard_resp.status_code == 200
    assert computers_resp.status_code == 200
    assert device_resp.status_code == 200
