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


async def _logged_in_client(login_as, admin_tuple):
    client = await _client()
    await login_as(client, admin_tuple)
    return client


async def test_companies_list_requires_login():
    async with await _client() as client:
        resp = await client.get("/admin/companies", follow_redirects=False)
    assert resp.status_code == 303


async def test_companies_list_shows_existing_companies(login_as, enrolled_admin, company):
    _, _ = company
    client = await _logged_in_client(login_as, enrolled_admin)
    try:
        resp = await client.get("/admin/companies")
    finally:
        await client.aclose()
    assert resp.status_code == 200
    assert b"Test Co" in resp.content


async def test_create_company_shows_new_api_key_once(login_as, enrolled_admin, db_pool):
    client = await _logged_in_client(login_as, enrolled_admin)
    try:
        get_resp = await client.get("/admin/companies")
        csrf_token = get_resp.text.split('name="csrf_token" value="')[1].split('"')[0]

        resp = await client.post(
            "/admin/companies",
            data={
                "name": "New Co",
                "notification_email": "owner@newco.example",
                "csrf_token": csrf_token,
            },
        )
    finally:
        await client.aclose()
    assert resp.status_code == 200
    assert b"New Co" in resp.content
    assert b"as_live_" in resp.content

    async with db_pool.acquire() as conn:
        row = await conn.fetchrow("SELECT id FROM companies WHERE name = 'New Co'")
    assert row is not None


async def test_create_company_without_csrf_token_is_rejected(login_as, enrolled_admin):
    client = await _logged_in_client(login_as, enrolled_admin)
    try:
        resp = await client.post("/admin/companies", data={"name": "No CSRF Co"})
    finally:
        await client.aclose()
    assert resp.status_code == 422  # FastAPI rejects the missing required Form field


async def test_company_detail_shows_company_info(login_as, enrolled_admin, company):
    company_id, _ = company
    client = await _logged_in_client(login_as, enrolled_admin)
    try:
        resp = await client.get(f"/admin/companies/{company_id}")
    finally:
        await client.aclose()
    assert resp.status_code == 200
    assert b"Test Co" in resp.content


async def test_company_detail_404_for_unknown_id(login_as, enrolled_admin):
    client = await _logged_in_client(login_as, enrolled_admin)
    try:
        resp = await client.get("/admin/companies/00000000-0000-0000-0000-000000000000")
    finally:
        await client.aclose()
    assert resp.status_code == 404


async def test_rotate_key_invalidates_old_key_and_activates_new(login_as, enrolled_admin, company, db_pool):
    from app.auth import resolve_company_id

    company_id, old_api_key = company
    client = await _logged_in_client(login_as, enrolled_admin)
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
    assert b"as_live_" in resp.content

    old_resolved = await resolve_company_id(db_pool, old_api_key)
    assert old_resolved is None

    new_api_key = resp.text.split("<code>")[1].split("</code>")[0]
    new_resolved = await resolve_company_id(db_pool, new_api_key)
    assert new_resolved == company_id


async def test_revoke_company_stops_key_from_resolving(login_as, enrolled_admin, company, db_pool):
    from app.auth import resolve_company_id

    company_id, api_key = company
    client = await _logged_in_client(login_as, enrolled_admin)
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


async def test_revoke_is_idempotent(login_as, enrolled_admin, company):
    company_id, _ = company
    client = await _logged_in_client(login_as, enrolled_admin)
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


async def test_create_company_requires_notification_email(login_as, enrolled_admin):
    client = await _logged_in_client(login_as, enrolled_admin)
    try:
        get_resp = await client.get("/admin/companies")
        csrf_token = get_resp.text.split('name="csrf_token" value="')[1].split('"')[0]

        resp = await client.post(
            "/admin/companies",
            data={"csrf_token": csrf_token, "name": "No Email Co"},
        )
    finally:
        await client.aclose()
    assert resp.status_code == 422  # FastAPI's own Form(...) validation


async def test_create_company_stores_notification_email(login_as, enrolled_admin, db_pool):
    client = await _logged_in_client(login_as, enrolled_admin)
    try:
        get_resp = await client.get("/admin/companies")
        csrf_token = get_resp.text.split('name="csrf_token" value="')[1].split('"')[0]

        resp = await client.post(
            "/admin/companies",
            data={
                "csrf_token": csrf_token,
                "name": "Notify Co",
                "notification_email": "owner@notifyco.example",
            },
        )
    finally:
        await client.aclose()
    assert resp.status_code == 200

    async with db_pool.acquire() as conn:
        row = await conn.fetchrow(
            "SELECT notification_email FROM companies WHERE name = 'Notify Co'"
        )
    assert row["notification_email"] == "owner@notifyco.example"


async def test_update_notification_email(login_as, enrolled_admin, company, db_pool):
    company_id, _ = company
    client = await _logged_in_client(login_as, enrolled_admin)
    try:
        get_resp = await client.get(f"/admin/companies/{company_id}")
        csrf_token = get_resp.text.split('name="csrf_token" value="')[1].split('"')[0]

        resp = await client.post(
            f"/admin/companies/{company_id}/notification-email",
            data={"csrf_token": csrf_token, "notification_email": "new-owner@example.com"},
        )
    finally:
        await client.aclose()
    assert resp.status_code == 303

    async with db_pool.acquire() as conn:
        row = await conn.fetchrow(
            "SELECT notification_email FROM companies WHERE id = $1", company_id
        )
    assert row["notification_email"] == "new-owner@example.com"


async def test_company_detail_shows_legacy_conversion(login_as, enrolled_admin, company):
    company_id, api_key = company
    client = await _logged_in_client(login_as, enrolled_admin)
    try:
        # One legacy check-in via the shared company key, so the card has
        # something non-zero to show.
        await client.post(
            "/api/v1/inventory/checkin",
            json={
                "checkin_id": "11111111-1111-1111-1111-111111111111",
                "timestamp": "2026-07-30T10:00:00",
                "first_name": "Nino", "last_name": "Nikoladze",
                "email": "nino@example.com", "department": "Engineering",
                "serial_number": "LEGACY-SN-9", "hostname": "host-9",
                "brand": "Apple", "model": "MacBook Pro", "ram": "16 GB",
                "os": "macOS 14.4.1",
            },
            headers={"Authorization": f"Bearer {api_key}"},
        )
        resp = await client.get(f"/admin/companies/{company_id}")
    finally:
        await client.aclose()
    assert resp.status_code == 200
    assert "LEGACY-SN-9" in resp.text


async def test_companies_list_shows_conversion_summary(login_as, enrolled_admin, company):
    company_id, api_key = company
    client = await _logged_in_client(login_as, enrolled_admin)
    try:
        await client.post(
            "/api/v1/inventory/checkin",
            json={
                "checkin_id": "22222222-2222-2222-2222-222222222222",
                "timestamp": "2026-07-30T10:00:00",
                "first_name": "Nino", "last_name": "Nikoladze",
                "email": "nino@example.com", "department": "Engineering",
                "serial_number": "LEGACY-SN-8", "hostname": "host-8",
                "brand": "Apple", "model": "MacBook Pro", "ram": "16 GB",
                "os": "macOS 14.4.1",
            },
            headers={"Authorization": f"Bearer {api_key}"},
        )
        resp = await client.get("/admin/companies")
    finally:
        await client.aclose()
    assert resp.status_code == 200
    # 0 converted / 1 total for this company.
    assert "0 / 1" in resp.text


async def test_saving_a_setting_confirms_it_on_the_next_page(login_as, enrolled_admin, company):
    """Every settings form redirects back to a page that looked identical
    whether the write landed or not. The redirect now carries a ?saved= slug
    that the page turns into a confirmation banner."""
    company_id, _ = company
    client = await _logged_in_client(login_as, enrolled_admin)
    try:
        get_resp = await client.get(f"/admin/companies/{company_id}")
        csrf_token = get_resp.text.split('name="csrf_token" value="')[1].split('"')[0]
        # Nothing has been saved yet, so nothing should be claimed.
        assert b"Notification email updated." not in get_resp.content

        resp = await client.post(
            f"/admin/companies/{company_id}/notification-email",
            data={"csrf_token": csrf_token, "notification_email": "ops@example.com"},
        )
        assert resp.status_code == 303
        assert resp.headers["location"].endswith("?saved=email")

        followed = await client.get(resp.headers["location"])
    finally:
        await client.aclose()
    assert followed.status_code == 200
    assert b"Notification email updated." in followed.content


async def test_unknown_saved_slug_renders_no_banner(login_as, enrolled_admin, company):
    """?saved= is looked up in a fixed table, so a hand-edited query string
    can only ever produce one of our own strings -- or nothing at all."""
    company_id, _ = company
    client = await _logged_in_client(login_as, enrolled_admin)
    try:
        resp = await client.get(
            f"/admin/companies/{company_id}",
            params={"saved": "<img src=x onerror=alert(1)>"},
        )
    finally:
        await client.aclose()
    assert resp.status_code == 200
    assert b"onerror" not in resp.content
    assert b"banner-success" not in resp.content


async def test_removing_a_custom_field_takes_two_clicks(login_as, enrolled_admin, company):
    """The Remove control used to delete on a single click. It is now a link
    to a confirm step; only the second click POSTs."""
    company_id, _ = company
    client = await _logged_in_client(login_as, enrolled_admin)
    try:
        get_resp = await client.get(f"/admin/companies/{company_id}")
        csrf_token = get_resp.text.split('name="csrf_token" value="')[1].split('"')[0]
        await client.post(
            f"/admin/companies/{company_id}/fields/custom",
            data={"csrf_token": csrf_token, "label": "Asset tag"},
        )

        listed = await client.get(f"/admin/companies/{company_id}")
        # First click is a GET link, not a form submission.
        assert b"?removing=asset_tag" in listed.content

        confirming = await client.get(
            f"/admin/companies/{company_id}", params={"removing": "asset_tag"}
        )
        assert b"Yes, remove" in confirming.content
        assert b"Remove this field?" in confirming.content

        # The field survives merely being asked about.
        still_there = await client.get(f"/admin/companies/{company_id}")
        assert b"Asset tag" in still_there.content
    finally:
        await client.aclose()
