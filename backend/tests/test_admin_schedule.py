"""Admin-facing check-in schedule editing. Mirrors test_admin_fields.py's
client/CSRF pattern exactly."""
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


async def _csrf(client, company_id):
    resp = await client.get(f"/admin/companies/{company_id}")
    return resp.text.split('name="csrf_token" value="')[1].split('"')[0]


async def test_settings_page_shows_schedule_card(admin, company):
    _, email, password = admin
    company_id, _ = company
    client = await _logged_in_client(email, password)
    try:
        resp = await client.get(f"/admin/companies/{company_id}")
    finally:
        await client.aclose()
    assert resp.status_code == 200
    assert b"Check-in schedule" in resp.content
    # The default company must read back as today's behaviour.
    assert b"6 months" in resp.content


async def test_preset_interval_persists(admin, company, db_pool):
    from app.schedule import resolve_schedule

    _, email, password = admin
    company_id, _ = company
    client = await _logged_in_client(email, password)
    try:
        token = await _csrf(client, company_id)
        resp = await client.post(
            f"/admin/companies/{company_id}/schedule",
            data={
                "csrf_token": token,
                "interval_preset": "43200",
                "cancel_retry_seconds": "3600",
            },
            follow_redirects=False,
        )
    finally:
        await client.aclose()
    assert resp.status_code in (200, 303)
    schedule = await resolve_schedule(db_pool, company_id)
    assert schedule["checkin_interval_seconds"] == 43200
    assert schedule["cancel_retry_seconds"] == 3600


async def test_custom_interval_persists(admin, company, db_pool):
    from app.schedule import resolve_schedule

    _, email, password = admin
    company_id, _ = company
    client = await _logged_in_client(email, password)
    try:
        token = await _csrf(client, company_id)
        await client.post(
            f"/admin/companies/{company_id}/schedule",
            data={
                "csrf_token": token,
                "interval_preset": "custom",
                "custom_count": "5",
                "custom_unit": "days",
                "cancel_retry_seconds": "14400",
            },
            follow_redirects=False,
        )
    finally:
        await client.aclose()
    schedule = await resolve_schedule(db_pool, company_id)
    assert schedule["checkin_interval_seconds"] == 432000


async def test_interval_below_floor_is_rejected(admin, company, db_pool):
    """Rejected at the app layer with a readable message -- the DB CHECK
    constraint must never be what reports a user error."""
    from app.schedule import resolve_schedule

    _, email, password = admin
    company_id, _ = company
    client = await _logged_in_client(email, password)
    try:
        token = await _csrf(client, company_id)
        resp = await client.post(
            f"/admin/companies/{company_id}/schedule",
            data={
                "csrf_token": token,
                "interval_preset": "custom",
                "custom_count": "30",
                "custom_unit": "minutes",
                "cancel_retry_seconds": "3600",
            },
            follow_redirects=False,
        )
    finally:
        await client.aclose()
    assert resp.status_code == 200
    assert b"at least 1 hour" in resp.content or b"Unknown unit" in resp.content
    schedule = await resolve_schedule(db_pool, company_id)
    assert schedule["checkin_interval_seconds"] == 15552000  # unchanged


async def test_retry_longer_than_interval_is_rejected(admin, company, db_pool):
    from app.schedule import resolve_schedule

    _, email, password = admin
    company_id, _ = company
    client = await _logged_in_client(email, password)
    try:
        token = await _csrf(client, company_id)
        resp = await client.post(
            f"/admin/companies/{company_id}/schedule",
            data={
                "csrf_token": token,
                "interval_preset": "43200",          # 12 h
                "cancel_retry_seconds": "86400",     # 24 h -- outlasts the cycle
            },
            follow_redirects=False,
        )
    finally:
        await client.aclose()
    assert resp.status_code == 200
    assert b"cannot be longer than" in resp.content
    schedule = await resolve_schedule(db_pool, company_id)
    assert schedule["checkin_interval_seconds"] == 15552000  # unchanged


async def test_schedule_post_requires_csrf(admin, company):
    _, email, password = admin
    company_id, _ = company
    client = await _logged_in_client(email, password)
    try:
        resp = await client.post(
            f"/admin/companies/{company_id}/schedule",
            data={
                "csrf_token": "wrong-token",
                "interval_preset": "43200",
                "cancel_retry_seconds": "3600",
            },
            follow_redirects=False,
        )
    finally:
        await client.aclose()
    assert resp.status_code == 403
