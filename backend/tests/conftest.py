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
    import notify_checkin_success, record_auth_failure, maybe_send_auth_failure_digest`,
    which binds a separate reference in checkin.py's namespace at import
    time, so that's
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
        "auth_failure_events, admin_recovery_codes, audit_log CASCADE;"
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


@pytest_asyncio.fixture
async def enrolled_admin(db_pool, admin):
    """An admin with MFA already enrolled. Returns (admin_id, email, password, secret)."""
    from app import mfa

    admin_id, email, password = admin
    secret = mfa.generate_secret()
    async with db_pool.acquire() as conn:
        await conn.execute(
            "UPDATE admins SET mfa_secret = $1, mfa_enrolled_at = NOW() WHERE id = $2",
            mfa.encrypt_secret(secret), admin_id,
        )
    return admin_id, email, password, secret


@pytest_asyncio.fixture
async def support_admin(db_pool):
    """A read-only admin, MFA already enrolled. Returns (admin_id, email, password, secret).

    Inserted through the `admin` superuser connection: the app role has no
    grant to write `role`, which is the point of the column-level grant in 016.
    """
    from app.admin_auth import hash_password
    from app import mfa

    email = "support@example.com"
    password = "support-horse-battery-staple"
    secret = mfa.generate_secret()
    admin_conn = await asyncpg.connect(ADMIN_TEST_DATABASE_URL)
    try:
        row = await admin_conn.fetchrow(
            "INSERT INTO admins (email, password_hash, role, mfa_secret, mfa_enrolled_at) "
            "VALUES ($1, $2, 'support', $3, NOW()) RETURNING id",
            email, hash_password(password), mfa.encrypt_secret(secret),
        )
    finally:
        await admin_conn.close()
    return str(row["id"]), email, password, secret


@pytest_asyncio.fixture
async def scoped_admin(db_pool, company):
    """A full admin scoped to one company. Returns (admin_id, email, password, secret, company_id)."""
    from app.admin_auth import hash_password
    from app import mfa

    company_id, _api_key = company
    email = "scoped@example.com"
    password = "scoped-horse-battery-staple"
    secret = mfa.generate_secret()
    admin_conn = await asyncpg.connect(ADMIN_TEST_DATABASE_URL)
    try:
        row = await admin_conn.fetchrow(
            "INSERT INTO admins (email, password_hash, company_id, mfa_secret, mfa_enrolled_at) "
            "VALUES ($1, $2, $3, $4, NOW()) RETURNING id",
            email, hash_password(password), company_id, mfa.encrypt_secret(secret),
        )
    finally:
        await admin_conn.close()
    return str(row["id"]), email, password, secret, company_id
