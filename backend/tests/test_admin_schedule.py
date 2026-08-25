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


async def _logged_in_client(login_as, admin_tuple):
    client = await _client()
    await login_as(client, admin_tuple)
    return client


async def _csrf(client, company_id):
    resp = await client.get(f"/admin/companies/{company_id}")
    return resp.text.split('name="csrf_token" value="')[1].split('"')[0]


async def test_settings_page_shows_schedule_card(login_as, enrolled_admin, company):
    company_id, _ = company
    client = await _logged_in_client(login_as, enrolled_admin)
    try:
        resp = await client.get(f"/admin/companies/{company_id}")
    finally:
        await client.aclose()
    assert resp.status_code == 200
    assert b"Check-in schedule" in resp.content
    # The default company must read back as today's behaviour. Assert the
    # SUMMARY sentence, not the bare "6 months": that string is also a PRESETS
    # option label, so matching it alone passed even when schedule_summary was
    # empty or missing from the context entirely.
    assert b"prompted every 6 months" in resp.content


async def test_preset_interval_persists(login_as, enrolled_admin, company, db_pool):
    from app.schedule import resolve_schedule

    company_id, _ = company
    client = await _logged_in_client(login_as, enrolled_admin)
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
    # Strictly 303: a successful save redirects. Accepting 200 as well would
    # also accept the error re-render, which is the failure this asserts against.
    assert resp.status_code == 303
    schedule = await resolve_schedule(db_pool, company_id)
    assert schedule["checkin_interval_seconds"] == 43200
    assert schedule["cancel_retry_seconds"] == 3600


async def test_custom_interval_persists(login_as, enrolled_admin, company, db_pool):
    from app.schedule import resolve_schedule

    company_id, _ = company
    client = await _logged_in_client(login_as, enrolled_admin)
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


async def test_unknown_custom_unit_is_rejected(login_as, enrolled_admin, company, db_pool):
    """A unit outside UNIT_SECONDS is its own branch of parse_interval.

    This case used to stand in for the floor check, which it never reached:
    "minutes" raises on the unknown-unit branch first, and an `or b"Unknown
    unit"` in the assertion hid that. The two are separate tests now.
    """
    from app.schedule import resolve_schedule

    company_id, _ = company
    client = await _logged_in_client(login_as, enrolled_admin)
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
    assert b"Unknown unit" in resp.content
    schedule = await resolve_schedule(db_pool, company_id)
    assert schedule["checkin_interval_seconds"] == 15552000  # unchanged


async def test_interval_below_floor_is_rejected(login_as, enrolled_admin, company, db_pool):
    """Rejected at the app layer with a readable message -- the DB CHECK
    constraint must never be what reports a user error.

    Posted as a preset value rather than a custom count/unit: the floor is
    unreachable through parse_interval (its smallest unit is hours and count
    must be >= 1), so a forged preset is the only way into validate_schedule's
    floor check.
    """
    from app.schedule import resolve_schedule

    company_id, _ = company
    client = await _logged_in_client(login_as, enrolled_admin)
    try:
        token = await _csrf(client, company_id)
        resp = await client.post(
            f"/admin/companies/{company_id}/schedule",
            data={
                "csrf_token": token,
                "interval_preset": "60",          # 1 minute -- below the floor
                "cancel_retry_seconds": "3600",
            },
            follow_redirects=False,
        )
    finally:
        await client.aclose()
    assert resp.status_code == 200
    assert b"Interval must be at least 1 hour" in resp.content
    schedule = await resolve_schedule(db_pool, company_id)
    assert schedule["checkin_interval_seconds"] == 15552000  # unchanged


async def test_over_cap_custom_interval_is_reported_as_a_form_error(login_as, enrolled_admin, company, db_pool):
    """A value past int4 made asyncpg raise DataError -- not a ValueError --
    so it escaped update_schedule's handler as an unhandled 500. It must come
    back as an ordinary readable form error instead."""
    from app.schedule import resolve_schedule

    company_id, _ = company
    client = await _logged_in_client(login_as, enrolled_admin)
    try:
        token = await _csrf(client, company_id)
        resp = await client.post(
            f"/admin/companies/{company_id}/schedule",
            data={
                "csrf_token": token,
                "interval_preset": "custom",
                "custom_count": "100000",       # 100000 years, far past int4
                "custom_unit": "years",
                "cancel_retry_seconds": "3600",
            },
            follow_redirects=False,
        )
    finally:
        await client.aclose()
    assert resp.status_code == 200
    assert b"Interval cannot be longer than 5 years" in resp.content
    schedule = await resolve_schedule(db_pool, company_id)
    assert schedule["checkin_interval_seconds"] == 15552000  # unchanged


async def test_custom_interval_is_preselected_when_the_form_reloads(login_as, enrolled_admin, company):
    """The bug this pins is data loss, not cosmetics.

    With no option carrying `selected`, the browser selects the first one
    ("12 hours"), so an admin who reopened Settings to change only the retry
    silently overwrote their custom interval on save.
    """
    company_id, _ = company
    client = await _logged_in_client(login_as, enrolled_admin)
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
        resp = await client.get(f"/admin/companies/{company_id}")
    finally:
        await client.aclose()

    assert resp.status_code == 200
    assert b'value="custom" selected' in resp.content
    # And the custom row is pre-filled by decomposing 432000 back to 5 / days,
    # so re-saving reproduces the stored interval rather than blanking it.
    assert b'name="custom_count" value="5"' in resp.content
    assert b'<option value="days" selected>days</option>' in resp.content
    # No preset may claim selection at the same time.
    assert b'value="43200" selected' not in resp.content


async def test_preset_interval_leaves_custom_unselected(login_as, enrolled_admin, company):
    """The other half of the same invariant: exactly one selected option."""
    company_id, _ = company
    client = await _logged_in_client(login_as, enrolled_admin)
    try:
        token = await _csrf(client, company_id)
        await client.post(
            f"/admin/companies/{company_id}/schedule",
            data={
                "csrf_token": token,
                "interval_preset": "43200",
                "cancel_retry_seconds": "3600",
            },
            follow_redirects=False,
        )
        resp = await client.get(f"/admin/companies/{company_id}")
    finally:
        await client.aclose()

    assert resp.status_code == 200
    assert b'value="43200" selected' in resp.content
    assert b'value="custom" selected' not in resp.content


async def test_retry_longer_than_interval_is_rejected(login_as, enrolled_admin, company, db_pool):
    from app.schedule import resolve_schedule

    company_id, _ = company
    client = await _logged_in_client(login_as, enrolled_admin)
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


async def test_schedule_post_requires_csrf(login_as, enrolled_admin, company):
    company_id, _ = company
    client = await _logged_in_client(login_as, enrolled_admin)
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
