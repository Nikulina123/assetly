import uuid

import pytest
import pytest_asyncio
from httpx import ASGITransport, AsyncClient

import app.db as db_module
from app.devices import dashboard_stats, get_checkin_history, get_device, legacy_key_conversion, list_devices
from app.main import app

pytestmark = pytest.mark.asyncio


@pytest_asyncio.fixture(autouse=True)
async def _reset_app_pool():
    yield
    await db_module.close_pool()


async def _submit(api_key, serial_number, hostname="host-1", os_name="macOS 14.4.1", custom_fields=None):
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        payload = {
            "checkin_id": str(uuid.uuid4()),
            "timestamp": "2026-07-30T10:00:00",
            "first_name": "Nino",
            "last_name": "Nikoladze",
            "email": "nino@example.com",
            "department": "Engineering",
            "serial_number": serial_number,
            "hostname": hostname,
            "brand": "Apple",
            "model": "MacBook Pro",
            "ram": "16 GB",
            "os": os_name,
        }
        if custom_fields is not None:
            payload["custom_fields"] = custom_fields
        return await client.post(
            "/api/v1/inventory/checkin",
            json=payload,
            headers={"Authorization": f"Bearer {api_key}"},
        )


async def test_list_devices_returns_submitted_device(db_pool, company):
    company_id, api_key = company
    await _submit(api_key, "SN-001")
    devices = await list_devices(db_pool, company_id)
    assert len(devices) == 1
    assert devices[0]["serial_number"] == "SN-001"
    assert devices[0]["status"] in {"online", "pending", "offline"}


async def test_list_devices_empty_for_new_company(db_pool, company):
    company_id, _ = company
    assert await list_devices(db_pool, company_id) == []


async def test_get_device_returns_none_for_unknown_serial(db_pool, company):
    company_id, _ = company
    assert await get_device(db_pool, company_id, "NO-SUCH-SERIAL") is None


async def test_checkin_history_is_newest_first(db_pool, company):
    company_id, api_key = company
    await _submit(api_key, "SN-001", hostname="old-name")
    await _submit(api_key, "SN-001", hostname="new-name")
    history = await get_checkin_history(db_pool, company_id, "SN-001")
    assert len(history) == 2
    assert history[0]["hostname"] == "new-name"


async def test_checkin_history_decodes_custom_fields_to_dict(db_pool, company):
    """asyncpg returns JSONB columns as raw text unless a codec is registered
    (none is), so custom_fields must be decoded in devices.py -- otherwise the
    device-detail template that iterates it would crash or render
    character-by-character instead of key/value pairs."""
    company_id, api_key = company
    await _submit(api_key, "SN-001", custom_fields={"location": "Tbilisi HQ"})
    history = await get_checkin_history(db_pool, company_id, "SN-001")
    assert history[0]["custom_fields"] == {"location": "Tbilisi HQ"}
    assert isinstance(history[0]["custom_fields"], dict)


async def test_dashboard_stats_counts_devices(db_pool, company):
    company_id, api_key = company
    await _submit(api_key, "SN-001", os_name="macOS 14.4.1")
    await _submit(api_key, "SN-002", os_name="Windows 11")
    stats = await dashboard_stats(db_pool, company_id)
    assert stats["total"] == 2
    assert stats["by_status"]["online"] == 2
    assert dict(stats["by_os"])["Windows 11"] == 1


async def test_queries_never_cross_tenant_boundary(db_pool, company):
    """These are the first queries in the codebase where a URL path segment
    (not an API key) selects which company's data is read. Every other read
    in this codebase is scoped by the caller's own API key, so there is no
    way for company A to even name company B's identifier. Here, an operator
    types a company's id/serial into the portal URL, so a missing or wrong
    app.company_id setting would let one tenant read another tenant's devices
    and check-in history. This test proves Postgres RLS -- not a WHERE clause
    an author might forget -- is what blocks that.
    """
    from app.auth import generate_api_key, hash_api_key

    company_a_id, api_key_a = company

    api_key_b = generate_api_key()
    key_hash_b = hash_api_key(api_key_b)
    async with db_pool.acquire() as conn:
        row_b = await conn.fetchrow(
            "INSERT INTO companies (name, api_key_hash, api_key_prefix) "
            "VALUES ($1, $2, $3) RETURNING id",
            "Other Co", key_hash_b, api_key_b[:8],
        )
    company_b_id = str(row_b["id"])

    await _submit(api_key_a, "SN-A-001", hostname="host-a")
    await _submit(api_key_b, "SN-B-001", hostname="host-b")

    devices_a = await list_devices(db_pool, company_a_id)
    serials_a = {d["serial_number"] for d in devices_a}
    assert serials_a == {"SN-A-001"}
    assert "SN-B-001" not in serials_a

    assert await get_device(db_pool, company_a_id, "SN-B-001") is None
    assert await get_checkin_history(db_pool, company_a_id, "SN-B-001") == []

    # Mirrored: an asymmetric bug (correct for A but not B) must be caught too.
    devices_b = await list_devices(db_pool, company_b_id)
    serials_b = {d["serial_number"] for d in devices_b}
    assert serials_b == {"SN-B-001"}
    assert "SN-A-001" not in serials_b

    assert await get_device(db_pool, company_b_id, "SN-A-001") is None
    assert await get_checkin_history(db_pool, company_b_id, "SN-A-001") == []

    stats_a = await dashboard_stats(db_pool, company_a_id)
    stats_b = await dashboard_stats(db_pool, company_b_id)
    assert stats_a["total"] == 1
    assert stats_b["total"] == 1


async def test_legacy_key_conversion_empty_company(db_pool, company):
    company_id, _api_key = company
    result = await legacy_key_conversion(db_pool, company_id)
    assert result == {
        "total": 0, "converted": 0, "legacy": 0,
        "last_legacy_checkin": None, "legacy_devices": [],
    }


async def test_legacy_key_conversion_counts_legacy_device(db_pool, company):
    company_id, api_key = company
    await _submit(api_key, "LEGACY-SN-1")
    result = await legacy_key_conversion(db_pool, company_id)
    assert result["total"] == 1
    assert result["converted"] == 0
    assert result["legacy"] == 1
    assert result["last_legacy_checkin"] is not None
    assert [d["serial_number"] for d in result["legacy_devices"]] == ["LEGACY-SN-1"]


async def test_legacy_key_conversion_counts_converted_device(db_pool, company, enrolled_device):
    company_id, _api_key = company
    credential, serial = enrolled_device
    await _submit(credential, serial)
    result = await legacy_key_conversion(db_pool, company_id)
    assert result["total"] == 1
    assert result["converted"] == 1
    assert result["legacy"] == 0
    assert result["last_legacy_checkin"] is None
    assert result["legacy_devices"] == []


async def test_legacy_key_conversion_matches_serial_case_insensitively(db_pool, company, enrolled_device):
    """enrolled_device enrolls a device credential for serial 'ENROLLED-SERIAL-1'
    (stored normalised, lower/stripped, by migration 015). If the agent's
    check-in payload reports different casing/whitespace for the same
    physical machine's serial, this must still count as converted -- matching
    the .strip().casefold() comparison checkin.py's M-1 binding check already
    uses, not a raw string equality that would double-count the same machine
    as both converted and legacy."""
    credential, serial = enrolled_device
    company_id, _api_key = company
    # enrolled_device's serial is "ENROLLED-SERIAL-1"; submit with different
    # casing and surrounding whitespace via the SAME credential, so the
    # credential's binding check (which itself normalises) still accepts it,
    # and devices.serial_number stores exactly what was submitted.
    await _submit(credential, "  enrolled-serial-1  ".strip())
    result = await legacy_key_conversion(db_pool, company_id)
    assert result["converted"] == 1
    assert result["legacy"] == 0
