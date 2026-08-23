import uuid

import pytest
import pytest_asyncio
from httpx import ASGITransport, AsyncClient

import app.db as db_module
from app.main import app

pytestmark = pytest.mark.asyncio


@pytest_asyncio.fixture(autouse=True)
async def _reset_app_pool():
    # app.db caches a module-level asyncpg pool bound to whichever event loop
    # created it. pytest-asyncio gives each test its own event loop, so a pool
    # left over from a previous test breaks (or hangs) on reuse. Close it after
    # every test so the next one lazily creates a fresh pool on its own loop.
    yield
    await db_module.close_pool()


def _payload(**overrides):
    base = {
        "checkin_id": str(uuid.uuid4()),
        "timestamp": "2026-07-30T10:00:00",
        "first_name": "Nino",
        "last_name": "Nikoladze",
        "email": "nino@example.com",
        "department": "Engineering",
        "serial_number": "SN-001",
        "hostname": "nino-macbook",
        "brand": "Apple",
        "model": "MacBook Pro",
        "cpu": "Apple M3",
        "ram": "16 GB",
        "storage": "512 GB",
        "ip_address": "10.0.0.5",
        "os": "macOS 14.4.1",
        "agent_version": "2.0",
    }
    base.update(overrides)
    return base


async def _client():
    transport = ASGITransport(app=app)
    return AsyncClient(transport=transport, base_url="http://test")


async def test_checkin_without_auth_header_is_rejected():
    async with await _client() as client:
        resp = await client.post("/api/v1/inventory/checkin", json=_payload())
    assert resp.status_code == 401


async def test_checkin_with_unknown_key_is_rejected():
    async with await _client() as client:
        resp = await client.post(
            "/api/v1/inventory/checkin",
            json=_payload(),
            headers={"Authorization": "Bearer as_live_unknown"},
        )
    assert resp.status_code == 401


async def test_checkin_with_valid_key_persists_row(db_pool, company):
    company_id, api_key = company
    checkin_id = str(uuid.uuid4())
    async with await _client() as client:
        resp = await client.post(
            "/api/v1/inventory/checkin",
            json=_payload(checkin_id=checkin_id),
            headers={"Authorization": f"Bearer {api_key}"},
        )
    assert resp.status_code == 200
    body = resp.json()
    assert body["status"] == "ok"
    assert body["id"] == checkin_id

    async with db_pool.acquire() as conn:
        # RLS on device_checkins requires app.company_id to be set on the
        # connection: current_setting() raises "unrecognized configuration
        # parameter" on a virgin connection instead of denying rows, so a
        # plain SELECT would fail even before RLS gets a chance to filter.
        await conn.execute("SELECT set_config('app.company_id', $1, false)", company_id)
        row = await conn.fetchrow(
            "SELECT * FROM device_checkins WHERE checkin_id = $1", checkin_id
        )
    assert row is not None
    assert str(row["company_id"]) == company_id
    assert row["platform"] == "macos"
    assert row["os_version"] == "14.4.1"


async def test_checkin_duplicate_checkin_id_returns_409(db_pool, company):
    _, api_key = company
    checkin_id = str(uuid.uuid4())
    async with await _client() as client:
        first = await client.post(
            "/api/v1/inventory/checkin",
            json=_payload(checkin_id=checkin_id),
            headers={"Authorization": f"Bearer {api_key}"},
        )
        second = await client.post(
            "/api/v1/inventory/checkin",
            json=_payload(checkin_id=checkin_id),
            headers={"Authorization": f"Bearer {api_key}"},
        )
    assert first.status_code == 200
    assert second.status_code == 409
    assert second.json()["status"] == "duplicate"


async def test_checkin_missing_required_field_returns_422(company):
    _, api_key = company
    payload = _payload()
    del payload["serial_number"]
    async with await _client() as client:
        resp = await client.post(
            "/api/v1/inventory/checkin",
            json=payload,
            headers={"Authorization": f"Bearer {api_key}"},
        )
    assert resp.status_code == 422


async def test_checkin_stores_custom_fields(db_pool, company):
    company_id, api_key = company
    checkin_id = str(uuid.uuid4())
    async with await _client() as client:
        resp = await client.post(
            "/api/v1/inventory/checkin",
            json=_payload(checkin_id=checkin_id, custom_fields={"department": "Engineering"}),
            headers={"Authorization": f"Bearer {api_key}"},
        )
    assert resp.status_code == 200

    async with db_pool.acquire() as conn:
        await conn.execute("SELECT set_config('app.company_id', $1, false)", company_id)
        row = await conn.fetchrow(
            "SELECT custom_fields FROM device_checkins WHERE checkin_id = $1", checkin_id
        )
    import json as json_module
    assert json_module.loads(row["custom_fields"]) == {"department": "Engineering"}


async def test_checkin_without_custom_fields_defaults_to_empty(db_pool, company):
    company_id, api_key = company
    checkin_id = str(uuid.uuid4())
    async with await _client() as client:
        resp = await client.post(
            "/api/v1/inventory/checkin",
            json=_payload(checkin_id=checkin_id),
            headers={"Authorization": f"Bearer {api_key}"},
        )
    assert resp.status_code == 200

    async with db_pool.acquire() as conn:
        await conn.execute("SELECT set_config('app.company_id', $1, false)", company_id)
        row = await conn.fetchrow(
            "SELECT custom_fields FROM device_checkins WHERE checkin_id = $1", checkin_id
        )
    import json as json_module
    assert json_module.loads(row["custom_fields"]) == {}


async def test_checkin_rejects_non_string_custom_field_value(company):
    _, api_key = company
    async with await _client() as client:
        resp = await client.post(
            "/api/v1/inventory/checkin",
            json=_payload(custom_fields={"department": 123}),
            headers={"Authorization": f"Bearer {api_key}"},
        )
    assert resp.status_code == 422


async def test_checkin_succeeds_without_department(db_pool, company):
    """department is toggleable per company (app/field_config.py); a company with
    it disabled must still be able to check in successfully."""
    company_id, api_key = company
    checkin_id = str(uuid.uuid4())
    payload = _payload(checkin_id=checkin_id)
    del payload["department"]
    async with await _client() as client:
        resp = await client.post(
            "/api/v1/inventory/checkin",
            json=payload,
            headers={"Authorization": f"Bearer {api_key}"},
        )
    assert resp.status_code == 200

    async with db_pool.acquire() as conn:
        await conn.execute("SELECT set_config('app.company_id', $1, false)", company_id)
        row = await conn.fetchrow(
            "SELECT department FROM device_checkins WHERE checkin_id = $1", checkin_id
        )
    assert row["department"] is None


async def test_checkin_succeeds_without_optional_hardware_fields(db_pool, company):
    """A regression guard for the same shape of bug that once bit the
    timestamp field: omitting a toggleable hardware field must not 422."""
    company_id, api_key = company
    checkin_id = str(uuid.uuid4())
    payload = _payload(checkin_id=checkin_id)
    for key in ("cpu", "ram", "storage", "ip_address"):
        del payload[key]
    async with await _client() as client:
        resp = await client.post(
            "/api/v1/inventory/checkin",
            json=payload,
            headers={"Authorization": f"Bearer {api_key}"},
        )
    assert resp.status_code == 200

    async with db_pool.acquire() as conn:
        await conn.execute("SELECT set_config('app.company_id', $1, false)", company_id)
        row = await conn.fetchrow(
            "SELECT cpu, ram, storage, ip_address FROM device_checkins WHERE checkin_id = $1",
            checkin_id,
        )
    assert row["cpu"] is None
    assert row["ram"] is None
    assert row["storage"] is None
    assert row["ip_address"] is None


async def test_checkin_success_triggers_notification(db_pool, company, monkeypatch):
    import app.routers.checkin as checkin_module

    calls = []

    def fake_notify(*args):
        calls.append(args)

    company_id, api_key = company
    async with db_pool.acquire() as conn:
        await conn.execute("SELECT set_config('app.company_id', $1, false)", company_id)
        await conn.execute(
            "UPDATE companies SET notification_email = $1 WHERE id = $2",
            "owner@example.com", company_id,
        )

    # Patch AFTER the client is created but before the request -- the
    # autouse conftest fixture already patched this once; this test
    # overrides it again with a recording stub for this test only.
    monkeypatch.setattr(checkin_module, "notify_checkin_success", fake_notify)
    async with await _client() as client:
        resp = await client.post(
            "/api/v1/inventory/checkin",
            json=_payload(checkin_id=str(uuid.uuid4())),
            headers={"Authorization": f"Bearer {api_key}"},
        )
    assert resp.status_code == 200
    assert len(calls) == 1
    to_email, hostname, full_name, department, custom_fields = calls[0]
    assert to_email == "owner@example.com"
    assert hostname == "nino-macbook"


async def test_checkin_auth_failure_triggers_notification(monkeypatch):
    import app.routers.checkin as checkin_module

    calls = []

    async def fake_record(pool, key_prefix, ip_address):
        calls.append(key_prefix)

    async def fake_digest(pool):
        return None

    monkeypatch.setattr(checkin_module, "record_auth_failure", fake_record)
    monkeypatch.setattr(checkin_module, "maybe_send_auth_failure_digest", fake_digest)
    async with await _client() as client:
        resp = await client.post(
            "/api/v1/inventory/checkin",
            json=_payload(),
            headers={"Authorization": "Bearer as_live_doesnotexist"},
        )
    assert resp.status_code == 401
    assert len(calls) == 1
    assert calls[0].startswith("as_live_")


async def test_device_credential_checkin_updates_last_used(db_pool, company):
    """last_used_at is what makes the Agents page's 'last ping' real rather
    than inferred from check-in history."""
    from app.enrollment import create_enrollment_token, enroll_device, list_device_credentials
    company_id, _ = company
    token = await create_enrollment_token(db_pool, company_id, label="x")
    cred = await enroll_device(db_pool, token, "SN-001", "host-1")
    async with await _client() as client:
        resp = await client.post(
            "/api/v1/inventory/checkin",
            json=_payload(serial_number="SN-001"),
            headers={"Authorization": f"Bearer {cred}"},
        )
    assert resp.status_code == 200
    creds = await list_device_credentials(db_pool, company_id)
    assert creds[0]["last_used_at"] is not None


async def test_allow_legacy_company_key_checkin_flag_gates_legacy_path(
    db_pool, company, monkeypatch
):
    """Proves ALLOW_LEGACY_COMPANY_KEY_CHECKIN actually gates: with it off, a
    company-key check-in must be rejected while an enrolled device's own
    credential keeps working -- switching the flag off retires the legacy
    path without breaking machines that have already migrated.

    Patches app.auth's own copy of the flag (not app.config's): auth.py does
    `from app.config import ALLOW_LEGACY_COMPANY_KEY_CHECKIN`, which binds a
    separate name in app.auth's namespace at import time, so that's the
    reference resolve_credential actually reads. Same pattern documented in
    tests/conftest.py for notify_checkin_success/notify_auth_failure."""
    import app.auth
    from app.enrollment import create_enrollment_token, enroll_device

    company_id, api_key = company
    token = await create_enrollment_token(db_pool, company_id, label="x")
    cred = await enroll_device(db_pool, token, "SN-001", "host-1")

    monkeypatch.setattr(app.auth, "ALLOW_LEGACY_COMPANY_KEY_CHECKIN", False)

    async with await _client() as client:
        legacy_resp = await client.post(
            "/api/v1/inventory/checkin",
            json=_payload(checkin_id=str(uuid.uuid4())),
            headers={"Authorization": f"Bearer {api_key}"},
        )
        device_resp = await client.post(
            "/api/v1/inventory/checkin",
            json=_payload(checkin_id=str(uuid.uuid4()), serial_number="SN-001"),
            headers={"Authorization": f"Bearer {cred}"},
        )
    assert legacy_resp.status_code == 401
    assert device_resp.status_code == 200


async def test_config_includes_schedule_defaults(company):
    """Additive to the existing user_fields/hardware_fields response -- an
    agent that has not self-updated ignores the new key entirely."""
    _, api_key = company
    async with await _client() as client:
        resp = await client.get(
            "/api/v1/inventory/config",
            headers={"Authorization": f"Bearer {api_key}"},
        )
    assert resp.status_code == 200
    body = resp.json()
    assert body["schedule"] == {
        "checkin_interval_seconds": 15552000,
        "cancel_retry_seconds": 86400,
    }
    # The pre-existing keys must survive untouched.
    assert "user_fields" in body
    assert "hardware_fields" in body


async def test_config_reflects_configured_schedule(db_pool, company):
    import uuid as uuid_module

    company_id, api_key = company
    async with db_pool.acquire() as conn:
        await conn.execute(
            "UPDATE companies SET checkin_interval_seconds = $2, "
            "cancel_retry_seconds = $3 WHERE id = $1",
            uuid_module.UUID(company_id), 43200, 3600,
        )
    async with await _client() as client:
        resp = await client.get(
            "/api/v1/inventory/config",
            headers={"Authorization": f"Bearer {api_key}"},
        )
    assert resp.json()["schedule"]["checkin_interval_seconds"] == 43200
    assert resp.json()["schedule"]["cancel_retry_seconds"] == 3600
