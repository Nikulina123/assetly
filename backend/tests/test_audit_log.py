"""Audit logging of privileged admin actions (H-4).

The transaction property is the one that matters and the one that is easy to
get subtly wrong: the audit row must live or die with the mutation it
describes. A log that records attempts that did not happen is as useless in an
incident as one that misses changes that did.
"""
import json

import asyncpg
import pytest
import pytest_asyncio
from base64 import b64decode
from httpx import ASGITransport, AsyncClient
import itsdangerous

import app.db as db_module
from app.config import SESSION_SECRET_KEY
from app.main import app

pytestmark = pytest.mark.asyncio


@pytest_asyncio.fixture(autouse=True)
async def _reset_app_pool():
    yield
    await db_module.close_pool()


async def _client():
    transport = ASGITransport(app=app)
    return AsyncClient(transport=transport, base_url="http://test")


def _unsign_session(cookie_value: str) -> dict:
    signer = itsdangerous.TimestampSigner(str(SESSION_SECRET_KEY))
    return json.loads(b64decode(signer.unsign(cookie_value.encode())))


async def _audit_rows(db_pool, action=None):
    async with db_pool.acquire() as conn:
        if action:
            return await conn.fetch(
                "SELECT * FROM audit_log WHERE action = $1 ORDER BY id", action
            )
        return await conn.fetch("SELECT * FROM audit_log ORDER BY id")


async def test_audited_writes_one_row_on_success(db_pool, admin):
    from app.audit import audited

    admin_id, _email, _password = admin

    class _Req:
        headers = {"user-agent": "pytest-agent"}
        client = type("C", (), {"host": "203.0.113.9"})()

    async with audited(db_pool, _Req(), admin_id, "test.action",
                       target_id="abc", metadata={"k": "v"}) as scope:
        await scope.conn.execute("SELECT 1")

    rows = await _audit_rows(db_pool, "test.action")
    assert len(rows) == 1
    assert str(rows[0]["actor_admin_id"]) == admin_id
    assert rows[0]["target_id"] == "abc"
    assert rows[0]["user_agent"] == "pytest-agent"
    assert json.loads(rows[0]["metadata"])["k"] == "v"


async def test_a_failing_mutation_writes_no_audit_row(db_pool, admin):
    """The transaction claim, tested directly. If the audit insert is outside
    the mutation's transaction, this test records an action that never
    happened."""
    from app.audit import audited

    admin_id, _email, _password = admin

    class _Req:
        headers = {}
        client = type("C", (), {"host": "203.0.113.9"})()

    with pytest.raises(RuntimeError):
        async with audited(db_pool, _Req(), admin_id, "test.explodes") as scope:
            await scope.conn.execute(
                "INSERT INTO companies (name, api_key_hash, api_key_prefix) "
                "VALUES ('Doomed', 'h', 'p')"
            )
            raise RuntimeError("mutation failed")

    assert await _audit_rows(db_pool, "test.explodes") == []
    async with db_pool.acquire() as conn:
        leaked = await conn.fetchval("SELECT COUNT(*) FROM companies WHERE name = 'Doomed'")
    assert leaked == 0, "the mutation must roll back too"


async def test_a_failing_audit_insert_rolls_the_mutation_back(db_pool, admin):
    """The other direction of the atomicity claim. The previous test shows an
    exception in the block writes no row; this one shows a failure in the
    INSERT ITSELF (action is NOT NULL, so action=None forces it) takes a
    SUCCESSFUL mutation down with it. A two-connection implementation -- run
    the block's mutation in its own transaction, then write the audit row
    separately afterwards -- passes the other test but fails this one: the
    mutation would already have committed by the time the audit insert blows
    up."""
    admin_id, _email, _password = admin

    class _Req:
        headers = {}
        client = type("C", (), {"host": "203.0.113.9"})()

    from app.audit import audited

    with pytest.raises(asyncpg.NotNullViolationError):
        async with audited(db_pool, _Req(), admin_id, None) as scope:
            await scope.conn.execute(
                "INSERT INTO companies (name, api_key_hash, api_key_prefix) "
                "VALUES ('Doomed', 'h', 'p')"
            )
    async with db_pool.acquire() as conn:
        leaked = await conn.fetchval(
            "SELECT COUNT(*) FROM companies WHERE name = 'Doomed'"
        )
    assert leaked == 0, "a failed audit insert must roll back the mutation too"


async def test_an_oversized_metadata_value_is_bounded_not_rejected(db_pool, admin):
    """admin.login.failed puts an unauthenticated, un-length-checked email
    straight into metadata, and audit_log is append-only (no UPDATE/DELETE
    for the app role), so the app can never prune an oversized row after the
    fact. A huge value must be truncated, not merely accepted -- and must
    still come out as valid JSON, not a slice through the middle of it."""
    from app.audit import audited

    admin_id, _email, _password = admin

    class _Req:
        headers = {}
        client = type("C", (), {"host": "203.0.113.9"})()

    huge = "x" * 50_000
    async with audited(
        db_pool, _Req(), admin_id, "test.oversized", metadata={"email": huge}
    ) as scope:
        await scope.conn.execute("SELECT 1")

    rows = await _audit_rows(db_pool, "test.oversized")
    assert len(rows) == 1
    raw = rows[0]["metadata"]
    assert len(raw) < 5000, "metadata JSON must be bounded, not stored unbounded"
    parsed = json.loads(raw)  # must still be valid JSON, not a truncated fragment
    assert "email" not in parsed or len(parsed["email"]) < len(huge)


async def test_metadata_can_be_enriched_inside_the_block(db_pool, admin):
    from app.audit import audited

    admin_id, _email, _password = admin

    class _Req:
        headers = {}
        client = type("C", (), {"host": "203.0.113.9"})()

    async with audited(db_pool, _Req(), admin_id, "test.enriched") as scope:
        scope.metadata["rows_matched"] = 3

    rows = await _audit_rows(db_pool, "test.enriched")
    assert json.loads(rows[0]["metadata"])["rows_matched"] == 3


# --- authentication events ---

async def test_successful_login_is_audited(db_pool, enrolled_admin, login_as):
    admin_id, _email, _password, _secret = enrolled_admin
    async with await _client() as client:
        await login_as(client, enrolled_admin)
    rows = await _audit_rows(db_pool, "admin.login.succeeded")
    assert len(rows) == 1
    assert str(rows[0]["actor_admin_id"]) == admin_id
    assert json.loads(rows[0]["metadata"])["method"] == "totp"


async def test_failed_login_is_audited_with_the_attempted_email(db_pool, admin):
    """Recorded in clear, deliberately -- unlike the rate-limit buckets, which
    are hashed. This table's job is answering 'who was targeted, from where'
    during an incident, and a hash cannot answer it."""
    _admin_id, email, _password = admin
    async with await _client() as client:
        await client.post("/admin/login", data={"email": email, "password": "wrong"})
    rows = await _audit_rows(db_pool, "admin.login.failed")
    assert len(rows) == 1
    assert rows[0]["actor_admin_id"] is None
    assert json.loads(rows[0]["metadata"])["email"] == email


async def test_a_failed_login_for_an_unknown_email_is_audited(db_pool):
    async with await _client() as client:
        await client.post(
            "/admin/login", data={"email": "nobody@example.com", "password": "x"}
        )
    assert len(await _audit_rows(db_pool, "admin.login.failed")) == 1


async def test_a_failed_mfa_code_is_audited(db_pool, enrolled_admin):
    _admin_id, email, password, _secret = enrolled_admin
    async with await _client() as client:
        await client.post("/admin/login", data={"email": email, "password": password})
        await client.get("/admin/mfa/verify")
        csrf = _unsign_session(client.cookies["session"])["csrf_token"]
        await client.post("/admin/mfa/verify", data={"code": "000000", "csrf_token": csrf})
    assert len(await _audit_rows(db_pool, "admin.mfa.failed")) == 1


async def test_enrollment_is_audited(db_pool, admin):
    import pyotp
    admin_id, email, password = admin
    async with await _client() as client:
        await client.post("/admin/login", data={"email": email, "password": password})
        await client.get("/admin/mfa/setup")
        session = _unsign_session(client.cookies["session"])
        await client.post(
            "/admin/mfa/setup",
            data={"code": pyotp.TOTP(session["pending_secret"]).now(),
                  "csrf_token": session["csrf_token"]},
        )
    assert len(await _audit_rows(db_pool, "admin.mfa.enrolled")) == 1


async def test_recovery_code_login_is_audited(db_pool, admin):
    """Deleting the `admin.mfa.recovery_code_used` call site should fail a
    test -- this is that test. Drives a real recovery-code login (the same
    pattern as test_a_recovery_code_completes_login_once in
    test_admin_mfa_routes.py) and asserts the event was recorded, not just
    that login succeeded."""
    from app.admin_auth import replace_recovery_codes
    from app import mfa as mfa_module

    admin_id, email, password = admin
    codes = mfa_module.generate_recovery_codes()
    async with db_pool.acquire() as conn:
        await conn.execute(
            "UPDATE admins SET mfa_secret = $1, mfa_enrolled_at = NOW() WHERE id = $2",
            mfa_module.encrypt_secret(mfa_module.generate_secret()), admin_id,
        )
        await replace_recovery_codes(conn, admin_id, codes)

    async with await _client() as client:
        await client.post("/admin/login", data={"email": email, "password": password})
        await client.get("/admin/mfa/verify")
        csrf = _unsign_session(client.cookies["session"])["csrf_token"]
        resp = await client.post(
            "/admin/mfa/verify",
            data={"code": codes[0], "csrf_token": csrf},
            follow_redirects=False,
        )
    assert resp.status_code == 303

    used_rows = await _audit_rows(db_pool, "admin.mfa.recovery_code_used")
    assert len(used_rows) == 1
    assert str(used_rows[0]["actor_admin_id"]) == admin_id

    succeeded_rows = await _audit_rows(db_pool, "admin.login.succeeded")
    assert len(succeeded_rows) == 1
    assert json.loads(succeeded_rows[0]["metadata"])["method"] == "recovery"


async def test_diagnostics_view_is_audited(db_pool, enrolled_admin, login_as):
    """Deleting the `admin.diagnostics_viewed` call site should fail a test --
    this is that test."""
    admin_id, *_ = enrolled_admin
    async with await _client() as client:
        await login_as(client, enrolled_admin)
        resp = await client.get("/admin/diagnostics")
    assert resp.status_code == 200
    rows = await _audit_rows(db_pool, "admin.diagnostics_viewed")
    assert len(rows) == 1
    assert str(rows[0]["actor_admin_id"]) == admin_id


async def test_logout_is_audited(db_pool, enrolled_admin, login_as):
    # POST /admin/logout currently takes no CSRF token (confirmed against the
    # route signature), so no token is needed here regardless. Separately,
    # login_as *does* GET /admin/mfa/verify, which mints a csrf_token into the
    # session -- but mfa_verify_submit calls request.session.clear() at the
    # point it grants the session, which wipes that token back out. That is
    # why none survives login_as, not any absence of a form-rendering GET.
    async with await _client() as client:
        await login_as(client, enrolled_admin)
        await client.post("/admin/logout")
    assert len(await _audit_rows(db_pool, "admin.logout")) == 1


async def test_no_audit_metadata_contains_secret_material(db_pool, admin):
    """Greeping for key names like "secret" or "password" would pass even if
    a handler logged the actual secret VALUE under an innocuous key (e.g.
    {"code": "123456"}) -- exactly the realistic mistake here, since the
    submitted TOTP code, the enrollment secret, and the recovery code are all
    plain strings a careless metadata={"code": code} would leak. So this
    drives every handler that ever touches secret material and asserts the
    LITERAL VALUES are absent from every row, not just banned key names."""
    import pyotp
    from app.admin_auth import replace_recovery_codes
    from app import mfa as mfa_module

    admin_id, email, password = admin

    # Enroll (captures the TOTP secret) and use MFA setup with a WRONG code
    # first so a code value is on the table too.
    secret_holder = {}
    async with await _client() as client:
        await client.post("/admin/login", data={"email": email, "password": password})
        await client.get("/admin/mfa/setup")
        session = _unsign_session(client.cookies["session"])
        pending_secret = session["pending_secret"]
        secret_holder["secret"] = pending_secret
        await client.post(
            "/admin/mfa/setup",
            data={"code": pyotp.TOTP(pending_secret).now(),
                  "csrf_token": session["csrf_token"]},
        )

    # Failed MFA code against the now-enrolled admin.
    wrong_code = "000000"
    async with await _client() as client:
        await client.post("/admin/login", data={"email": email, "password": password})
        await client.get("/admin/mfa/verify")
        csrf = _unsign_session(client.cookies["session"])["csrf_token"]
        await client.post(
            "/admin/mfa/verify", data={"code": wrong_code, "csrf_token": csrf}
        )

    # Recovery-code login.
    codes = mfa_module.generate_recovery_codes()
    async with db_pool.acquire() as conn:
        await replace_recovery_codes(conn, admin_id, codes)
    recovery_code = codes[0]
    async with await _client() as client:
        await client.post("/admin/login", data={"email": email, "password": password})
        await client.get("/admin/mfa/verify")
        csrf = _unsign_session(client.cookies["session"])["csrf_token"]
        await client.post(
            "/admin/mfa/verify",
            data={"code": recovery_code, "csrf_token": csrf},
        )

    rows = await _audit_rows(db_pool)
    assert rows
    banned_literals = {
        "password": password,
        "totp secret": secret_holder["secret"],
        "wrong mfa code": wrong_code,
        "recovery code": recovery_code,
    }
    for row in rows:
        blob = row["metadata"] or ""
        for label, value in banned_literals.items():
            assert value not in blob, (
                f"{row['action']} metadata contains the {label} value {value!r}"
            )
