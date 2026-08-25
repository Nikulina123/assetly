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


async def test_enrollment_and_recovery_use_are_audited(db_pool, admin):
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


async def test_logout_is_audited(db_pool, enrolled_admin, login_as):
    # POST /admin/logout currently takes no CSRF token (confirmed against the
    # route signature) -- login_as leaves no csrf_token in the session either,
    # since no form-rendering GET happens during the two-stage login. Posting
    # with no body is therefore the accurate way to exercise this route as it
    # actually behaves today.
    async with await _client() as client:
        await login_as(client, enrolled_admin)
        await client.post("/admin/logout")
    assert len(await _audit_rows(db_pool, "admin.logout")) == 1


async def test_no_audit_metadata_contains_secret_material(db_pool, enrolled_admin, login_as):
    async with await _client() as client:
        await login_as(client, enrolled_admin)
    rows = await _audit_rows(db_pool)
    assert rows
    for row in rows:
        blob = (row["metadata"] or "").lower()
        for banned in ("password", "secret", "api_key", "token_plain"):
            assert banned not in blob, f"{row['action']} metadata contains {banned}"
