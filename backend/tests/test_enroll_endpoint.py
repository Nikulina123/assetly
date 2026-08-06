import uuid

import pytest
import pytest_asyncio
from httpx import ASGITransport, AsyncClient

import app.db as db_module
from app.enrollment import create_enrollment_token
from app.main import app

pytestmark = pytest.mark.asyncio


@pytest_asyncio.fixture(autouse=True)
async def _reset_app_pool():
    yield
    await db_module.close_pool()


async def _client():
    return AsyncClient(transport=ASGITransport(app=app), base_url="http://test")


async def _enroll(client, bearer, serial="SN-001", hostname="host-1"):
    return await client.post(
        "/api/v1/enroll",
        json={"serial_number": serial, "hostname": hostname},
        headers={"Authorization": f"Bearer {bearer}"},
    )


async def test_enroll_with_token_returns_credential(db_pool, company):
    company_id, _ = company
    token = await create_enrollment_token(db_pool, company_id, label="macOS")
    async with await _client() as client:
        resp = await _enroll(client, token)
    assert resp.status_code == 200
    assert resp.json()["credential"].startswith("as_dev_")


async def test_enroll_with_company_key_self_migrates(db_pool, company):
    """A deployed agent holding only the legacy company key must be able to
    migrate itself without anyone visiting the machine."""
    _, api_key = company
    async with await _client() as client:
        resp = await _enroll(client, api_key)
    assert resp.status_code == 200
    assert resp.json()["credential"].startswith("as_dev_")


async def test_enroll_with_unknown_bearer_is_401(db_pool, company):
    async with await _client() as client:
        resp = await _enroll(client, "as_enroll_nope")
    assert resp.status_code == 401


async def test_enroll_without_auth_header_is_401(db_pool, company):
    async with await _client() as client:
        resp = await client.post("/api/v1/enroll", json={"serial_number": "SN-001"})
    assert resp.status_code == 401


async def test_expired_token_is_403_with_reason(db_pool, company):
    import datetime
    company_id, _ = company
    token = await create_enrollment_token(
        db_pool, company_id, label="old",
        expires_at=datetime.datetime.now(datetime.timezone.utc) - datetime.timedelta(days=1),
    )
    async with await _client() as client:
        resp = await _enroll(client, token)
    assert resp.status_code == 403
    assert "expired" in resp.json()["detail"].lower()


async def test_enrolled_credential_authenticates_a_checkin(db_pool, company):
    company_id, _ = company
    token = await create_enrollment_token(db_pool, company_id, label="macOS")
    async with await _client() as client:
        cred = (await _enroll(client, token)).json()["credential"]
        resp = await client.post(
            "/api/v1/inventory/checkin",
            json={
                "checkin_id": str(uuid.uuid4()),
                "timestamp": "2026-08-06T10:00:00",
                "first_name": "A", "last_name": "B", "email": "a@example.com",
                "department": "Engineering", "serial_number": "SN-001",
                "hostname": "host-1", "brand": "Apple", "model": "MacBook Pro",
                "os": "macOS 14.4.1",
            },
            headers={"Authorization": f"Bearer {cred}"},
        )
    assert resp.status_code == 200


async def test_token_from_company_a_cannot_enroll_into_company_b(db_pool, company):
    """Tenant isolation: the token carries the company claim, so a token must
    only ever produce credentials belonging to its own company."""
    from app.auth import generate_api_key, hash_api_key
    from app.enrollment import list_device_credentials
    company_a_id, _ = company
    async with db_pool.acquire() as conn:
        key_b = generate_api_key()
        row = await conn.fetchrow(
            "INSERT INTO companies (name, api_key_hash, api_key_prefix) "
            "VALUES ($1, $2, $3) RETURNING id",
            "Other Co", hash_api_key(key_b), key_b[:8],
        )
    company_b_id = str(row["id"])
    token_a = await create_enrollment_token(db_pool, company_a_id, label="A")
    async with await _client() as client:
        await _enroll(client, token_a, serial="SN-AAA")
    assert len(await list_device_credentials(db_pool, company_a_id)) == 1
    assert await list_device_credentials(db_pool, company_b_id) == []
