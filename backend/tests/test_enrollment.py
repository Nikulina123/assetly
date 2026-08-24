import datetime
import uuid

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


async def _insert_raw_credential(db_pool, company_id, serial_number, *, enrolled_at=None):
    """Inserts a device_credentials row directly, bypassing enroll_device's
    normalisation, to simulate a row written before serials were casefolded
    at enrollment. Returns (plaintext_credential, row_id)."""
    from app.auth import generate_api_key, hash_api_key

    plaintext = generate_api_key()
    async with db_pool.acquire() as conn:
        row = await conn.fetchrow(
            "INSERT INTO device_credentials "
            "(company_id, credential_hash, serial_number, hostname, enrolled_at) "
            "VALUES ($1, $2, $3, $4, COALESCE($5, NOW())) RETURNING id",
            company_id, hash_api_key(plaintext), serial_number, "host-raw", enrolled_at,
        )
    return plaintext, str(row["id"])


async def _run_migration_015(db_pool):
    """Runs migration 015's actual SQL against the current fixture data. The
    db_pool fixture truncates device_credentials before every test, so any
    real migration run against the shared test database (done once, earlier
    in the suite's history) has no bearing on rows a test inserts itself --
    each test that wants pre-existing un-normalised rows treated as already
    migrated has to apply the migration to its own fixture data."""
    import pathlib

    migration_sql = (
        pathlib.Path(__file__).parent.parent
        / "migrations" / "015_normalise_credential_serials.sql"
    ).read_text()
    async with db_pool.acquire() as conn:
        await conn.execute(migration_sql)


async def test_revoke_matches_preexisting_unnormalised_serial(db_pool, company):
    """Migration 015 normalises rows at rest, but this test proves the
    application-level fix too: revoke_device_credential must find and revoke
    a row inserted with un-normalised casing (simulating data written before
    the normalise-on-write change existed), using the machine's real casing
    as the lookup key -- not silently affect zero rows."""
    from app.auth import resolve_credential

    company_id, _ = company
    cred, row_id = await _insert_raw_credential(db_pool, company_id, "ABC-123")
    assert await resolve_credential(db_pool, cred) is not None
    await _run_migration_015(db_pool)

    await revoke_device_credential(db_pool, company_id, "ABC-123")

    async with db_pool.acquire() as conn:
        revoked_at = await conn.fetchval(
            "SELECT revoked_at FROM device_credentials WHERE id = $1", uuid.UUID(row_id)
        )
    assert revoked_at is not None
    assert await resolve_credential(db_pool, cred) is None


async def test_migration_015_resolves_case_collision_keeping_newest(db_pool, company):
    """Simulates two pre-existing rows for the same machine that differ only
    in serial casing (e.g. two independent enrollments before normalise-at-
    write existed). Runs migration 015's actual SQL against this fixture data
    and asserts it collapses the pair to a single active, normalised
    credential -- the more-recently-enrolled one -- while revoking (not
    deleting) the loser so the audit trail survives."""
    company_id, _ = company
    older_cred, older_id = await _insert_raw_credential(
        db_pool, company_id, "ABC-123",
        enrolled_at=datetime.datetime(2026, 1, 1, tzinfo=datetime.timezone.utc),
    )
    newer_cred, newer_id = await _insert_raw_credential(
        db_pool, company_id, "abc-123",
        enrolled_at=datetime.datetime(2026, 6, 1, tzinfo=datetime.timezone.utc),
    )

    await _run_migration_015(db_pool)

    async with db_pool.acquire() as conn:
        rows = await conn.fetch(
            "SELECT id, serial_number, revoked_at FROM device_credentials "
            "WHERE company_id = $1 ORDER BY enrolled_at",
            company_id,
        )

    assert len(rows) == 2
    by_id = {str(r["id"]): r for r in rows}

    # Exactly one row is active; it is the newer one, and it holds the clean
    # normalised serial (this is what revoke_device_credential and
    # device_detail will actually look up).
    active = [r for r in rows if r["revoked_at"] is None]
    revoked = [r for r in rows if r["revoked_at"] is not None]
    assert len(active) == 1
    assert len(revoked) == 1
    assert str(active[0]["id"]) == newer_id
    assert active[0]["serial_number"] == "abc-123"

    # The loser is revoked and can no longer collide with the winner under
    # UNIQUE (company_id, serial_number) -- it's tagged rather than deleted,
    # so the fact it once existed as 'abc-123' is still visible.
    assert str(revoked[0]["id"]) == older_id
    assert revoked[0]["serial_number"].startswith("abc-123~superseded-")
