import datetime

import pytest
import pytest_asyncio

import app.db as db_module
from app.enrollment import (
    EnrollmentError,
    create_enrollment_token,
    enroll_device,
    list_tokens,
    revoke_device_credential,
    revoke_token,
)

pytestmark = pytest.mark.asyncio


@pytest_asyncio.fixture(autouse=True)
async def _reset_app_pool():
    yield
    await db_module.close_pool()


async def test_create_token_returns_plaintext_once(db_pool, company):
    company_id, _ = company
    token = await create_enrollment_token(db_pool, company_id, label="macOS")
    assert token.startswith("as_enroll_")
    rows = await list_tokens(db_pool, company_id)
    assert len(rows) == 1
    assert rows[0]["label"] == "macOS"
    assert token not in str(dict(rows[0]))  # plaintext is never stored


async def test_enroll_issues_device_credential(db_pool, company):
    company_id, _ = company
    token = await create_enrollment_token(db_pool, company_id, label="macOS")
    cred = await enroll_device(db_pool, token, "SN-001", "host-1")
    assert cred.startswith("as_dev_")


async def test_reenrolling_same_serial_replaces_not_duplicates(db_pool, company):
    """Re-running an installer on an enrolled machine must not inflate the
    device count, and must not consume another slot against max_devices."""
    company_id, _ = company
    token = await create_enrollment_token(db_pool, company_id, label="macOS")
    first = await enroll_device(db_pool, token, "SN-001", "host-1")
    second = await enroll_device(db_pool, token, "SN-001", "host-1")
    assert first != second
    tokens = await list_tokens(db_pool, company_id)
    assert tokens[0]["used_count"] == 1


async def test_expired_token_is_rejected(db_pool, company):
    company_id, _ = company
    token = await create_enrollment_token(
        db_pool, company_id, label="old",
        expires_at=datetime.datetime.now(datetime.timezone.utc) - datetime.timedelta(days=1),
    )
    with pytest.raises(EnrollmentError) as exc:
        await enroll_device(db_pool, token, "SN-001", "host-1")
    assert "expired" in str(exc.value).lower()


async def test_revoked_token_is_rejected(db_pool, company):
    company_id, _ = company
    token = await create_enrollment_token(db_pool, company_id, label="x")
    rows = await list_tokens(db_pool, company_id)
    await revoke_token(db_pool, company_id, str(rows[0]["id"]))
    with pytest.raises(EnrollmentError) as exc:
        await enroll_device(db_pool, token, "SN-001", "host-1")
    assert "revoked" in str(exc.value).lower()


async def test_max_devices_cap_is_enforced(db_pool, company):
    company_id, _ = company
    token = await create_enrollment_token(db_pool, company_id, label="x", max_devices=1)
    await enroll_device(db_pool, token, "SN-001", "host-1")
    with pytest.raises(EnrollmentError) as exc:
        await enroll_device(db_pool, token, "SN-002", "host-2")
    assert "limit" in str(exc.value).lower()


async def test_unknown_token_is_rejected(db_pool, company):
    with pytest.raises(EnrollmentError):
        await enroll_device(db_pool, "as_enroll_nope", "SN-001", "host-1")


async def test_revoked_device_credential_stops_resolving(db_pool, company):
    from app.auth import resolve_credential
    company_id, _ = company
    token = await create_enrollment_token(db_pool, company_id, label="x")
    cred = await enroll_device(db_pool, token, "SN-001", "host-1")
    assert await resolve_credential(db_pool, cred) is not None
    await revoke_device_credential(db_pool, company_id, "SN-001")
    assert await resolve_credential(db_pool, cred) is None
