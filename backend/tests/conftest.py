import os

import asyncpg
import pytest
import pytest_asyncio

TEST_DATABASE_URL = os.environ.get(
    "TEST_DATABASE_URL",
    "postgresql://assetly@localhost:5432/webiz_checkin_test",
)

ADMIN_TEST_DATABASE_URL = os.environ.get(
    "ADMIN_TEST_DATABASE_URL",
    "postgresql://admin@localhost:5432/webiz_checkin_test",
)


@pytest.fixture(autouse=True)
def _stub_checkin_notifications(monkeypatch):
    """Prevents every test in the suite from triggering a real Sendly send
    via the checkin endpoint's background-task notifications, once Task 3
    wires them in. Patches app.routers.checkin's OWN imported names (not
    app.notifications' originals) -- checkin.py does `from app.notifications
    import notify_checkin_success, notify_auth_failure`, which binds a
    separate reference in checkin.py's namespace at import time, so that's
    the reference that must be patched for checkin.py's call sites to see
    the stub. This is the exact same pattern already used for WINDOWS_EXE_PATH
    in test_admin_downloads.py (patching the consumer module's copy of an
    imported name, not the defining module's).

    Individual tests that want to verify notification behavior re-patch
    these same two names with their own recording stub via monkeypatch,
    which simply overrides this default for that one test."""
    import app.routers.checkin as checkin_module
    monkeypatch.setattr(checkin_module, "notify_checkin_success", lambda *a, **kw: None)

    async def _noop(*args, **kwargs):
        return None

    monkeypatch.setattr(checkin_module, "record_auth_failure", _noop)
    monkeypatch.setattr(checkin_module, "maybe_send_auth_failure_digest", _noop)


@pytest_asyncio.fixture
async def db_pool():
    # Truncate via a separate admin connection: assetly intentionally has no
    # TRUNCATE grant in production (TRUNCATE bypasses RLS entirely), so test
    # cleanup can't go through the same role the app itself uses.
    admin_conn = await asyncpg.connect(ADMIN_TEST_DATABASE_URL)
    await admin_conn.execute(
        "TRUNCATE device_checkins, devices, companies, admins, company_fields, "
        "enrollment_tokens, device_credentials, rate_limit_hits, "
        "auth_failure_events CASCADE;"
    )
    await admin_conn.execute(
        "UPDATE notification_state SET last_digest_sent_at = NULL, "
        "digests_sent_today = 0, digest_day = NULL"
    )
    await admin_conn.close()

    pool = await asyncpg.create_pool(TEST_DATABASE_URL)
    yield pool
    await pool.close()


@pytest_asyncio.fixture
async def company(db_pool):
    """Inserts one company with a known plaintext key, returns (company_id, api_key)."""
    from app.auth import generate_api_key, hash_api_key

    api_key = generate_api_key()
    key_hash = hash_api_key(api_key)
    async with db_pool.acquire() as conn:
        row = await conn.fetchrow(
            "INSERT INTO companies (name, api_key_hash, api_key_prefix) "
            "VALUES ($1, $2, $3) RETURNING id",
            "Test Co", key_hash, api_key[:8],
        )
    return str(row["id"]), api_key


@pytest_asyncio.fixture
async def enrolled_device(db_pool, company):
    """Enrolls one device via a real enrollment token, returning the plaintext
    credential and the serial it was enrolled for."""
    from app.enrollment import create_enrollment_token, enroll_device

    company_id, _api_key = company
    token = await create_enrollment_token(
        db_pool, company_id, label="test", max_devices=5
    )
    serial = "ENROLLED-SERIAL-1"
    credential = await enroll_device(db_pool, token, serial, "host-1")
    return credential, serial


@pytest_asyncio.fixture
async def admin(db_pool):
    """Inserts one admin with a known plaintext password, returns (admin_id, email, password).

    Inserted via a separate admin-role connection (like the db_pool truncate
    step above): assetly intentionally only has SELECT on admins (see
    migrations/002_admin_auth.sql) since admin accounts are seeded via
    scripts/seed_admin.py run as the `admin` superuser, not through the app.
    """
    from app.admin_auth import hash_password

    email = "admin@example.com"
    password = "correct-horse-battery-staple"
    admin_conn = await asyncpg.connect(ADMIN_TEST_DATABASE_URL)
    try:
        row = await admin_conn.fetchrow(
            "INSERT INTO admins (email, password_hash) VALUES ($1, $2) RETURNING id",
            email, hash_password(password),
        )
    finally:
        await admin_conn.close()
    return str(row["id"]), email, password
