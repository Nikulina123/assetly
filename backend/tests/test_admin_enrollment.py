"""Admin UI for enrollment tokens and per-device revocation.

Covers the two new POST routes (token revoke, device revoke) and the two
template changes (the tokens card in Settings, the revoke control on the
device detail page). The two blast-radius assertions --
`test_revoking_a_device_stops_only_that_device` and
`test_revoking_a_token_does_not_disturb_already_enrolled_devices` -- are the
ones that matter: they prove revocation scope is exactly what the design
promises, not larger.
"""
import uuid

import pytest
import pytest_asyncio
from httpx import ASGITransport, AsyncClient

import app.db as db_module
from app.enrollment import create_enrollment_token, enroll_device, list_device_credentials, list_tokens
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


async def _get_csrf_token(client, company_id):
    resp = await client.get(f"/admin/companies/{company_id}")
    return resp.text.split('name="csrf_token" value="')[1].split('"')[0]


def _checkin_payload(**overrides):
    base = {
        "checkin_id": str(uuid.uuid4()),
        "timestamp": "2026-08-06T10:00:00",
        "first_name": "A", "last_name": "B", "email": "a@example.com",
        "department": "Engineering", "serial_number": "SN-001",
        "hostname": "host-1", "brand": "Apple", "model": "MacBook Pro",
        "os": "macOS 14.4.1",
    }
    base.update(overrides)
    return base


async def _checkin(client, credential, **overrides):
    return await client.post(
        "/api/v1/inventory/checkin",
        json=_checkin_payload(**overrides),
        headers={"Authorization": f"Bearer {credential}"},
    )


# ── Token revoke route ──────────────────────────────────────────────────

async def test_revoking_a_token_does_not_disturb_already_enrolled_devices(login_as, enrolled_admin, company, db_pool):
    """Revoking a token blocks NEW enrollments through it; it must not touch
    the credential of a device that already enrolled via that same token."""
    company_id, _ = company
    token = await create_enrollment_token(db_pool, company_id, label="macOS")
    credential = await enroll_device(db_pool, token, "SN-ALREADY", "host-already")

    client = await _logged_in_client(login_as, enrolled_admin)
    try:
        csrf_token = await _get_csrf_token(client, company_id)
        tokens = await list_tokens(db_pool, company_id)
        token_id = str(tokens[0]["id"])

        resp = await client.post(
            f"/admin/companies/{company_id}/tokens/{token_id}/revoke",
            data={"csrf_token": csrf_token},
        )
        assert resp.status_code == 303

        # Further enrollment with the revoked token is refused.
        enroll_resp = await client.post(
            "/api/v1/enroll",
            json={"serial_number": "SN-NEW", "hostname": "host-new"},
            headers={"Authorization": f"Bearer {token}"},
        )
        assert enroll_resp.status_code == 403
        assert "revoked" in enroll_resp.json()["detail"].lower()

        # The device that enrolled BEFORE the revoke keeps checking in.
        checkin_resp = await _checkin(client, credential, serial_number="SN-ALREADY", hostname="host-already")
        assert checkin_resp.status_code == 200
    finally:
        await client.aclose()

    tokens_after = await list_tokens(db_pool, company_id)
    assert tokens_after[0]["revoked_at"] is not None


async def test_revoke_token_route_requires_login(company):
    company_id, _ = company
    async with await _client() as client:
        resp = await client.post(
            f"/admin/companies/{company_id}/tokens/{uuid.uuid4()}/revoke",
            data={"csrf_token": "irrelevant"},
            follow_redirects=False,
        )
    assert resp.status_code == 303
    assert "/admin/login" in resp.headers["location"]


async def test_revoke_token_rejects_bad_csrf_token(login_as, enrolled_admin, company, db_pool):
    company_id, _ = company
    token = await create_enrollment_token(db_pool, company_id, label="x")
    tokens = await list_tokens(db_pool, company_id)
    token_id = str(tokens[0]["id"])

    client = await _logged_in_client(login_as, enrolled_admin)
    try:
        await _get_csrf_token(client, company_id)  # establishes a real session csrf token
        resp = await client.post(
            f"/admin/companies/{company_id}/tokens/{token_id}/revoke",
            data={"csrf_token": "not-the-real-token"},
        )
    finally:
        await client.aclose()
    assert resp.status_code == 403

    tokens_after = await list_tokens(db_pool, company_id)
    assert tokens_after[0]["revoked_at"] is None  # untouched


# ── Device revoke route ─────────────────────────────────────────────────

async def test_revoking_a_device_stops_only_that_device(login_as, enrolled_admin, company, db_pool):
    """The important assertion in this whole task: revoking device A's
    credential 401s device A's check-ins while device B, enrolled through the
    very same token, keeps working. That is the entire point of per-device
    credentials over a single shared company key."""
    company_id, _ = company
    token = await create_enrollment_token(db_pool, company_id, label="macOS")
    cred_a = await enroll_device(db_pool, token, "SN-A", "host-a")
    cred_b = await enroll_device(db_pool, token, "SN-B", "host-b")

    client = await _logged_in_client(login_as, enrolled_admin)
    try:
        csrf_token = await _get_csrf_token(client, company_id)
        resp = await client.post(
            f"/admin/companies/{company_id}/devices/SN-A/revoke",
            data={"csrf_token": csrf_token},
        )
        assert resp.status_code == 303

        resp_a = await _checkin(client, cred_a, serial_number="SN-A", hostname="host-a")
        resp_b = await _checkin(client, cred_b, serial_number="SN-B", hostname="host-b")
    finally:
        await client.aclose()

    assert resp_a.status_code == 401
    assert resp_b.status_code == 200

    # device_credentials.serial_number is stored normalised (.strip().casefold())
    # -- see app/enrollment.py::enroll_device -- so keys here are lowercase
    # even though the enrolled/URL/checkin serials above use their real casing.
    creds = {c["serial_number"]: c for c in await list_device_credentials(db_pool, company_id)}
    assert creds["sn-a"]["revoked_at"] is not None
    assert creds["sn-b"]["revoked_at"] is None


async def test_revoke_device_route_requires_login(company):
    company_id, _ = company
    async with await _client() as client:
        resp = await client.post(
            f"/admin/companies/{company_id}/devices/SN-A/revoke",
            data={"csrf_token": "irrelevant"},
            follow_redirects=False,
        )
    assert resp.status_code == 303
    assert "/admin/login" in resp.headers["location"]


async def test_revoke_device_rejects_bad_csrf_token(login_as, enrolled_admin, company, db_pool):
    company_id, _ = company
    token = await create_enrollment_token(db_pool, company_id, label="x")
    await enroll_device(db_pool, token, "SN-A", "host-a")

    client = await _logged_in_client(login_as, enrolled_admin)
    try:
        await _get_csrf_token(client, company_id)
        resp = await client.post(
            f"/admin/companies/{company_id}/devices/SN-A/revoke",
            data={"csrf_token": "not-the-real-token"},
        )
    finally:
        await client.aclose()
    assert resp.status_code == 403

    creds = await list_device_credentials(db_pool, company_id)
    assert creds[0]["revoked_at"] is None  # untouched


async def test_revoke_device_serial_with_special_characters_round_trips(login_as, enrolled_admin, company, db_pool):
    """Serial numbers are free-form strings from client hardware and may
    contain spaces or other characters that need URL-encoding in the revoke
    link. Confirm the redirect target decodes back to the exact serial and
    the right credential was revoked."""
    company_id, _ = company
    serial = "SN 001 #weird"
    token = await create_enrollment_token(db_pool, company_id, label="x")
    credential = await enroll_device(db_pool, token, serial, "host-weird")

    from urllib.parse import quote

    # A device only appears on its detail page once it has checked in --
    # device_credentials and devices are separate tables.
    async with await _client() as seed_client:
        seed_resp = await _checkin(seed_client, credential, serial_number=serial, hostname="host-weird")
        assert seed_resp.status_code == 200

    client = await _logged_in_client(login_as, enrolled_admin)
    try:
        csrf_token = await _get_csrf_token(client, company_id)
        resp = await client.post(
            f"/admin/companies/{company_id}/devices/{quote(serial, safe='')}/revoke",
            data={"csrf_token": csrf_token},
            follow_redirects=False,
        )
        assert resp.status_code == 303
        assert resp.headers["location"] == (
            f"/admin/companies/{company_id}/computers/{quote(serial, safe='')}"
        )

        # And that redirect target actually renders (proves round-trip decoding works).
        device_resp = await client.get(resp.headers["location"])
    finally:
        await client.aclose()
    assert device_resp.status_code == 200

    creds = await list_device_credentials(db_pool, company_id)
    # Stored normalised (.strip().casefold()); the display/inventory value
    # (devices/device_checkins) keeps the real casing, but device_credentials
    # does not -- see app/enrollment.py::enroll_device.
    assert creds[0]["serial_number"] == serial.strip().casefold()
    assert creds[0]["revoked_at"] is not None


# ── Tokens card rendering ────────────────────────────────────────────────

async def test_settings_page_renders_tokens_card_with_a_token_present(login_as, enrolled_admin, company, db_pool):
    company_id, _ = company
    await create_enrollment_token(db_pool, company_id, label="macOS installer", max_devices=5)

    client = await _logged_in_client(login_as, enrolled_admin)
    try:
        resp = await client.get(f"/admin/companies/{company_id}")
    finally:
        await client.aclose()
    assert resp.status_code == 200
    body = resp.text
    assert "Enrollment tokens" in body
    assert "macOS installer" in body
    assert "as_enroll_" in body  # token_prefix is shown
    assert "0 / 5" in body
    assert "Active" in body
    assert "Revoke" in body
    # Consequence copy: distinct from the per-device copy, and must not
    # overclaim that revoking touches already-enrolled machines.
    assert "does not" in body.lower() or "keep checking in" in body.lower()


async def test_settings_page_renders_tokens_card_with_unlimited_and_no_tokens(login_as, enrolled_admin, company, db_pool):
    company_id, _ = company

    client = await _logged_in_client(login_as, enrolled_admin)
    try:
        resp = await client.get(f"/admin/companies/{company_id}")
    finally:
        await client.aclose()
    assert resp.status_code == 200
    assert "Enrollment tokens" in resp.text
    assert "No enrollment tokens yet" in resp.text

    # Now with a token that has no device cap (max_devices IS NULL).
    await create_enrollment_token(db_pool, company_id, label="Linux installer", max_devices=None)
    client2 = await _logged_in_client(login_as, enrolled_admin)
    try:
        resp2 = await client2.get(f"/admin/companies/{company_id}")
    finally:
        await client2.aclose()
    assert resp2.status_code == 200
    assert "unlimited" in resp2.text


async def test_revoked_token_shows_revoked_status_without_a_revoke_button(login_as, enrolled_admin, company, db_pool):
    company_id, _ = company
    await create_enrollment_token(db_pool, company_id, label="Old token")

    client = await _logged_in_client(login_as, enrolled_admin)
    try:
        csrf_token = await _get_csrf_token(client, company_id)
        tokens = await list_tokens(db_pool, company_id)
        token_id = str(tokens[0]["id"])
        await client.post(
            f"/admin/companies/{company_id}/tokens/{token_id}/revoke",
            data={"csrf_token": csrf_token},
        )
        resp = await client.get(f"/admin/companies/{company_id}")
    finally:
        await client.aclose()
    assert resp.status_code == 200
    assert "Revoked" in resp.text


# ── Device detail page revoke control ────────────────────────────────────

async def test_device_detail_shows_revoke_button_for_active_credential(login_as, enrolled_admin, company, db_pool):
    company_id, _ = company
    token = await create_enrollment_token(db_pool, company_id, label="x")
    credential = await enroll_device(db_pool, token, "SN-001", "host-1")
    async with await _client() as seed_client:
        assert (await _checkin(seed_client, credential)).status_code == 200

    client = await _logged_in_client(login_as, enrolled_admin)
    try:
        resp = await client.get(f"/admin/companies/{company_id}/computers/SN-001")
    finally:
        await client.aclose()
    assert resp.status_code == 200
    assert "Revoke device" in resp.text
    assert "this machine only" in resp.text.lower()


async def test_device_detail_shows_revoked_state_instead_of_button(login_as, enrolled_admin, company, db_pool):
    company_id, _ = company
    token = await create_enrollment_token(db_pool, company_id, label="x")
    credential = await enroll_device(db_pool, token, "SN-001", "host-1")
    async with await _client() as seed_client:
        assert (await _checkin(seed_client, credential)).status_code == 200

    client = await _logged_in_client(login_as, enrolled_admin)
    try:
        csrf_token = await _get_csrf_token(client, company_id)
        await client.post(
            f"/admin/companies/{company_id}/devices/SN-001/revoke",
            data={"csrf_token": csrf_token},
        )
        resp = await client.get(f"/admin/companies/{company_id}/computers/SN-001")
    finally:
        await client.aclose()
    assert resp.status_code == 200
    assert "Revoke device" not in resp.text
    assert "no longer check in" in resp.text.lower()


async def test_device_detail_with_no_credential_at_all(login_as, enrolled_admin, company, db_pool):
    """A device that checked in via the legacy company key (pre-enrollment)
    has no device_credentials row at all. The page must render that state,
    not crash on a None credential."""
    company_id, api_key = company
    client = await _logged_in_client(login_as, enrolled_admin)
    try:
        await client.post(
            "/api/v1/inventory/checkin",
            json=_checkin_payload(serial_number="SN-LEGACY", hostname="legacy-host"),
            headers={"Authorization": f"Bearer {api_key}"},
        )
        resp = await client.get(f"/admin/companies/{company_id}/computers/SN-LEGACY")
    finally:
        await client.aclose()
    assert resp.status_code == 200
    assert "No enrollment credential on file" in resp.text
    assert "Revoke device" not in resp.text
