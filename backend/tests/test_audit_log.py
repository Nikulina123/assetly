"""Audit logging of privileged admin actions (H-4).

The transaction property is the one that matters and the one that is easy to
get subtly wrong: the audit row must live or die with the mutation it
describes. A log that records attempts that did not happen is as useless in an
incident as one that misses changes that did.
"""
import json
import uuid as uuid_module

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


async def test_every_privileged_mutation_is_audited(db_pool, enrolled_admin, company, login_as):
    """One row per action, with the actor and the tenant it touched. Drives
    each route for real rather than asserting on the source, so a route that
    stops calling audited() fails here."""
    admin_id, _email, _password, _secret = enrolled_admin
    company_id, _api_key = company

    async with await _client() as client:
        await login_as(client, enrolled_admin)
        resp = await client.get(f"/admin/companies/{company_id}")
        csrf = resp.text.split('name="csrf_token" value="')[1].split('"')[0]

        await client.post(f"/admin/companies/{company_id}/rotate-key",
                          data={"csrf_token": csrf})
        await client.post(f"/admin/companies/{company_id}/notification-email",
                          data={"csrf_token": csrf, "notification_email": "a@b.com"})
        await client.post(f"/admin/companies/{company_id}/download/linux",
                          data={"csrf_token": csrf, "device_count": 5})
        await client.post(f"/admin/companies/{company_id}/schedule",
                          data={"csrf_token": csrf, "interval_preset": "86400",
                                "cancel_retry_seconds": "3600"})
        await client.post(f"/admin/companies/{company_id}/appearance",
                          data={"csrf_token": csrf, "heading": "Whose laptop is this?"})
        await client.post(f"/admin/companies/{company_id}/fields/hardware",
                          data={"csrf_token": csrf, "cpu": "on"})
        await client.post(f"/admin/companies/{company_id}/fields/custom",
                          data={"csrf_token": csrf, "label": "Cost Center"})
        await client.post(f"/admin/companies/{company_id}/fields/custom/cost_center/remove",
                          data={"csrf_token": csrf})

        from app.enrollment import create_enrollment_token
        await create_enrollment_token(db_pool, company_id, label="pre-existing")
        async with db_pool.acquire() as conn:
            row = await conn.fetchrow(
                "SELECT id FROM enrollment_tokens WHERE company_id = $1 "
                "ORDER BY created_at DESC LIMIT 1", uuid_module.UUID(company_id),
            )
        token_id = str(row["id"])
        await client.post(f"/admin/companies/{company_id}/tokens/{token_id}/revoke",
                          data={"csrf_token": csrf})

        from app.enrollment import enroll_device
        token = await create_enrollment_token(db_pool, company_id, label="device source")
        await enroll_device(db_pool, token, "AUDIT-SERIAL-1", "host-1")
        await client.post(f"/admin/companies/{company_id}/devices/AUDIT-SERIAL-1/revoke",
                          data={"csrf_token": csrf})

        await client.post(f"/admin/companies/{company_id}/revoke",
                          data={"csrf_token": csrf})

    for action in (
        "company.api_key_rotated", "company.notification_email_updated",
        "installer.downloaded", "enrollment_token.created",
        "company.schedule_updated",
        "company.appearance_updated", "company.fields.hardware_updated",
        "company.fields.custom_added", "company.fields.custom_removed",
        "enrollment_token.revoked", "device_credential.revoked",
        "company.revoked",
    ):
        rows = await _audit_rows(db_pool, action)
        assert len(rows) == 1, f"{action}: {len(rows)} rows"
        assert str(rows[0]["actor_admin_id"]) == admin_id
        assert str(rows[0]["target_company_id"]) == company_id

    # The device revoked above WAS enrolled, so the count must be a real 1 --
    # the other end of the signal from
    # test_device_revoke_records_actual_rows_matched, which pins the 0 case.
    # Together they rule out a hardcoded constant at either value.
    revoked = await _audit_rows(db_pool, "device_credential.revoked")
    assert json.loads(revoked[0]["metadata"])["rows_matched"] == 1


async def test_a_tokens_created_and_revoked_rows_share_one_target_id(
    db_pool, enrolled_admin, company, login_as
):
    """The token lifecycle has to be queryable from either end. An
    investigator holding an `enrollment_token.revoked` row must be able to ask
    "when was this token minted, by whom, with what max_devices?" -- which
    only works if both rows carry the same target_id. They used to carry
    different key spaces (row uuid vs token prefix), so no join existed."""
    company_id, _api_key = company
    async with await _client() as client:
        await login_as(client, enrolled_admin)
        resp = await client.get(f"/admin/companies/{company_id}")
        csrf = resp.text.split('name="csrf_token" value="')[1].split('"')[0]
        await client.post(f"/admin/companies/{company_id}/download/linux",
                          data={"csrf_token": csrf, "device_count": 5})

        created = await _audit_rows(db_pool, "enrollment_token.created")
        assert len(created) == 1
        token_id = created[0]["target_id"]

        # The id in the audit row must be the real enrollment_tokens row id --
        # i.e. the value the revoke route is reached with.
        await client.post(f"/admin/companies/{company_id}/tokens/{token_id}/revoke",
                          data={"csrf_token": csrf})

    revoked = await _audit_rows(db_pool, "enrollment_token.revoked")
    assert len(revoked) == 1
    assert revoked[0]["target_id"] == token_id, (
        "created and revoked must share a target_id or the lifecycle cannot be joined"
    )
    async with db_pool.acquire() as conn:
        row = await conn.fetchrow(
            "SELECT revoked_at FROM enrollment_tokens WHERE id = $1",
            uuid_module.UUID(token_id),
        )
    assert row is not None, "the audited target_id must be a real enrollment_tokens id"
    assert row["revoked_at"] is not None


async def test_company_created_is_audited(db_pool, enrolled_admin, login_as):
    """company.created is issued by a global admin creating a new tenant --
    driven separately from the parametrised set above because it needs no
    pre-existing company and its target is the NEW company's id."""
    admin_id, _email, _password, _secret = enrolled_admin
    # enrolled_admin is inserted with no company_id, which is already NULL --
    # i.e. already a global admin (see admin_auth.AdminContext.is_global) --
    # so no extra setup is needed here.
    async with await _client() as client:
        await login_as(client, enrolled_admin)
        resp = await client.get("/admin/companies")
        csrf = resp.text.split('name="csrf_token" value="')[1].split('"')[0]
        await client.post("/admin/companies", data={
            "csrf_token": csrf, "name": "Brand New Co",
            "notification_email": "new@co.example",
        })

    rows = await _audit_rows(db_pool, "company.created")
    assert len(rows) == 1
    assert str(rows[0]["actor_admin_id"]) == admin_id
    assert json.loads(rows[0]["metadata"])["name"] == "Brand New Co"


async def test_a_rotate_key_audit_records_the_prefix_not_the_key(db_pool, enrolled_admin, company, login_as):
    """The audit trail must be readable by a support engineer without handing
    them a live credential."""
    _admin_id, _email, _password, _secret = enrolled_admin
    company_id, _api_key = company
    async with await _client() as client:
        await login_as(client, enrolled_admin)
        resp = await client.get(f"/admin/companies/{company_id}")
        csrf = resp.text.split('name="csrf_token" value="')[1].split('"')[0]
        await client.post(f"/admin/companies/{company_id}/rotate-key",
                          data={"csrf_token": csrf})
    rows = await _audit_rows(db_pool, "company.api_key_rotated")
    metadata = json.loads(rows[0]["metadata"])
    assert "key_prefix" in metadata
    assert len(metadata["key_prefix"]) <= 8


async def test_installer_download_records_the_platform(db_pool, enrolled_admin, company, login_as):
    _admin_id, _email, _password, _secret = enrolled_admin
    company_id, _api_key = company
    async with await _client() as client:
        await login_as(client, enrolled_admin)
        resp = await client.get(f"/admin/companies/{company_id}")
        csrf = resp.text.split('name="csrf_token" value="')[1].split('"')[0]
        await client.post(f"/admin/companies/{company_id}/download/linux",
                          data={"csrf_token": csrf, "device_count": 5})
    rows = await _audit_rows(db_pool, "installer.downloaded")
    assert json.loads(rows[0]["metadata"])["platform"] == "linux"


async def test_device_revoke_records_actual_rows_matched(db_pool, enrolled_admin, company, login_as):
    """The exact signal that would have caught a Revoke button matching zero
    rows while reporting success: revoking a serial that was never enrolled
    must record rows_matched == 0, not a hardcoded 1."""
    company_id, _api_key = company
    async with await _client() as client:
        await login_as(client, enrolled_admin)
        resp = await client.get(f"/admin/companies/{company_id}")
        csrf = resp.text.split('name="csrf_token" value="')[1].split('"')[0]
        await client.post(f"/admin/companies/{company_id}/devices/NEVER-ENROLLED/revoke",
                          data={"csrf_token": csrf})
    rows = await _audit_rows(db_pool, "device_credential.revoked")
    assert len(rows) == 1
    assert json.loads(rows[0]["metadata"])["rows_matched"] == 0


@pytest.mark.parametrize(
    "path,action,form,column,old_value,new_value",
    [
        ("schedule", "company.schedule_updated",
         {"interval_preset": "604800", "cancel_retry_seconds": "3600"},
         "checkin_interval_seconds", 86400, 604800),
        ("notification-email", "company.notification_email_updated",
         {"notification_email": "changed@example.com"},
         "notification_email", "original@example.com", "changed@example.com"),
    ],
)
async def test_a_failing_audit_insert_rolls_a_real_route_back(
    db_pool, enrolled_admin, company, login_as, monkeypatch,
    path, action, form, column, old_value, new_value,
):
    """THE test that pins `conn=scope.conn` at every route call site.

    test_a_failing_audit_insert_rolls_the_mutation_back proves audited() is
    atomic when the caller uses scope.conn. It cannot notice a ROUTE that
    stopped doing so: drop `conn=scope.conn` from set_schedule(...) and the
    UPDATE runs on a second pooled connection in its own transaction, the
    audit row still commits, and every row-counting test stays green while
    atomicity is silently gone (and, on the production 2-connection pool, one
    concurrent request from starvation).

    So this drives a REAL privileged route with the audit insert forced to
    fail, and asserts the column still holds its OLD value. That can only
    pass if the mutation shared the audit row's transaction -- which can only
    happen if the route passed scope.conn down to its helper.
    """
    company_id, _api_key = company
    async with db_pool.acquire() as conn:
        await conn.execute(
            "UPDATE companies SET checkin_interval_seconds = 86400, "
            "cancel_retry_seconds = 3600, notification_email = 'original@example.com' "
            "WHERE id = $1",
            uuid_module.UUID(company_id),
        )

    import app.audit as audit_module

    real_insert = audit_module._insert

    async def _exploding_insert(conn, actor, written_action, *args, **kwargs):
        # Only the route's own action blows up -- the login rows written on
        # the way in must still succeed or the request never gets this far.
        if written_action == action:
            raise RuntimeError("audit insert failed")
        return await real_insert(conn, actor, written_action, *args, **kwargs)

    monkeypatch.setattr(audit_module, "_insert", _exploding_insert)

    async with await _client() as client:
        await login_as(client, enrolled_admin)
        resp = await client.get(f"/admin/companies/{company_id}")
        csrf = resp.text.split('name="csrf_token" value="')[1].split('"')[0]
        with pytest.raises(RuntimeError):
            await client.post(
                f"/admin/companies/{company_id}/{path}",
                data={"csrf_token": csrf, **form},
            )

    async with db_pool.acquire() as conn:
        stored = await conn.fetchval(
            f"SELECT {column} FROM companies WHERE id = $1",
            uuid_module.UUID(company_id),
        )
    assert stored != new_value, (
        f"{path}: the mutation committed even though its audit row failed -- "
        f"the route is not running its mutation on scope.conn"
    )
    assert stored == old_value

    assert await _audit_rows(db_pool, action) == []


async def test_second_connection_inside_audited_block_does_not_share_fate(db_pool, admin):
    """Pins the pitfall the brief warns about: acquiring a SECOND connection
    inside an `audited()` block runs the mutation in a different transaction,
    so it does NOT roll back with the audit row. This documents the failure
    mode a future editor of these routes must not reintroduce -- if this test
    ever starts failing because someone "fixed" audited() to share the
    connection automatically, that's fine; it means the trap plugged itself.
    But as long as `audited()` hands out one connection and a caller can still
    reach for a second one, this is the behavior to expect from doing so."""
    from app.audit import audited

    admin_id, _email, _password = admin

    class _Req:
        headers = {}
        client = type("C", (), {"host": "203.0.113.9"})()

    with pytest.raises(RuntimeError):
        async with audited(db_pool, _Req(), admin_id, "test.second_connection") as scope:
            # The trap: a SECOND connection, acquired independently of
            # scope.conn, running its own transaction that commits before the
            # audited() block ever gets to the audit INSERT.
            async with db_pool.acquire() as other_conn:
                async with other_conn.transaction():
                    await other_conn.execute(
                        "INSERT INTO companies (name, api_key_hash, api_key_prefix) "
                        "VALUES ('LeakedBySecondConn', 'h', 'p')"
                    )
            # scope.conn's own transaction now fails, simulating the audit
            # insert (or anything else in the real mutation) blowing up.
            raise RuntimeError("mutation failed after the second connection committed")

    async with db_pool.acquire() as conn:
        leaked = await conn.fetchval(
            "SELECT COUNT(*) FROM companies WHERE name = 'LeakedBySecondConn'"
        )
    # This is the bug the pitfall describes: the second connection's insert
    # survives even though the audited() block "failed" and wrote no audit
    # row -- exactly the split-fate outcome atomicity is supposed to prevent.
    assert leaked == 1, (
        "a second connection acquired inside audited() commits independently "
        "of the block's own transaction -- this is why routes must never "
        "acquire one"
    )
    assert await _audit_rows(db_pool, "test.second_connection") == []


async def test_no_audit_metadata_contains_secret_material(db_pool, admin, company):
    """Greeping for key names like "secret" or "password" would pass even if
    a handler logged the actual secret VALUE under an innocuous key (e.g.
    {"code": "123456"}) -- exactly the realistic mistake here, since the
    submitted TOTP code, the enrollment secret, and the recovery code are all
    plain strings a careless metadata={"code": code} would leak. So this
    drives every handler that ever touches secret material and asserts the
    LITERAL VALUES are absent from every row, not just banned key names.

    The privileged mutations are driven too, not just the auth flows: the
    download routes record `token_prefix: token[:18]` and rotate-key records
    `key_prefix: api_key[:8]`, both deliberate slices one careless edit away
    from recording the whole live credential -- into a table the application
    role cannot prune (INSERT/SELECT only, no UPDATE or DELETE).

    target_id is checked alongside metadata for the same reason: it is a
    separate column that the download routes also write a token-derived value
    into, so checking only metadata would miss a leak there entirely."""
    import re
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

    # Privileged mutations that handle live credentials: a key rotation and an
    # installer download (which mints an enrollment token).
    company_id, _api_key = company
    async with await _client() as client:
        await client.post("/admin/login", data={"email": email, "password": password})
        await client.get("/admin/mfa/verify")
        csrf = _unsign_session(client.cookies["session"])["csrf_token"]
        await client.post(
            "/admin/mfa/verify",
            data={"code": pyotp.TOTP(secret_holder["secret"]).now(), "csrf_token": csrf},
        )
        resp = await client.get(f"/admin/companies/{company_id}")
        csrf = resp.text.split('name="csrf_token" value="')[1].split('"')[0]

        rotated = await client.post(
            f"/admin/companies/{company_id}/rotate-key", data={"csrf_token": csrf}
        )
        rotated_key = re.search(r"as_live_[0-9a-f]{64}", rotated.text).group(0)

        downloaded = await client.post(
            f"/admin/companies/{company_id}/download/linux",
            data={"csrf_token": csrf, "device_count": 5},
        )
        enrollment_token = re.search(r"as_enroll_[0-9a-f]{64}", downloaded.text).group(0)

    rows = await _audit_rows(db_pool)
    assert rows
    banned_literals = {
        "password": password,
        "totp secret": secret_holder["secret"],
        "wrong mfa code": wrong_code,
        "recovery code": recovery_code,
        "rotated api key": rotated_key,
        "enrollment token": enrollment_token,
    }
    for row in rows:
        # target_id as well as metadata: both are columns a handler writes
        # credential-derived values into.
        for column in ("metadata", "target_id"):
            blob = row[column] or ""
            for label, value in banned_literals.items():
                assert value not in blob, (
                    f"{row['action']} {column} contains the {label} value {value!r}"
                )


# --- /admin/audit: the read-only viewer (H-4) -------------------------------
#
# NOTE ON CSRF: the brief's own draft of these tests read the csrf_token by
# unsigning the session cookie immediately after login_as(). That does not
# work -- the MFA-verify route clears the session before writing admin_id
# (session-fixation hardening), so no csrf_token key survives into the
# authenticated session until something mints one. Following the pattern
# Task 8 already established (test_a_failing_audit_insert_rolls_a_real_route_back
# and the credential-literal sweep above): GET an authenticated page and
# scrape the token out of the rendered form.


async def test_audit_viewer_lists_recent_actions(db_pool, enrolled_admin, company, login_as):
    _admin_id, email, _password, _secret = enrolled_admin
    company_id, _api_key = company
    async with await _client() as client:
        await login_as(client, enrolled_admin)
        detail = await client.get(f"/admin/companies/{company_id}")
        csrf = detail.text.split('name="csrf_token" value="')[1].split('"')[0]
        await client.post(f"/admin/companies/{company_id}/rotate-key", data={"csrf_token": csrf})
        resp = await client.get("/admin/audit")
    assert resp.status_code == 200
    assert b"company.api_key_rotated" in resp.content
    assert email.encode() in resp.content, "the actor must be resolvable to an email"


async def test_audit_viewer_is_refused_to_support_admins(support_admin, login_as):
    async with await _client() as client:
        await login_as(client, support_admin)
        resp = await client.get("/admin/audit")
    assert resp.status_code == 403


async def test_audit_viewer_filters_by_action(db_pool, enrolled_admin, company, login_as):
    _admin_id, _email, _password, _secret = enrolled_admin
    company_id, _api_key = company
    async with await _client() as client:
        await login_as(client, enrolled_admin)
        detail = await client.get(f"/admin/companies/{company_id}")
        csrf = detail.text.split('name="csrf_token" value="')[1].split('"')[0]
        await client.post(f"/admin/companies/{company_id}/rotate-key", data={"csrf_token": csrf})
        resp = await client.get("/admin/audit?action=company.api_key_rotated")
    assert b"company.api_key_rotated" in resp.content
    # Scoped to the table body, not the whole page: the filter <select> is
    # legitimately populated with every distinct action name this admin can
    # filter by (including admin.login.succeeded, produced by login_as()
    # itself above), so the interesting assertion is that the ROWS are
    # filtered, not that the string never appears anywhere on the page.
    body = resp.text.split("<tbody>")[1].split("</tbody>")[0]
    assert "admin.login.succeeded" not in body


async def test_audit_viewer_survives_a_deleted_actor(db_pool, enrolled_admin, login_as):
    """The log outlives the accounts it describes -- there is deliberately no
    foreign key. The viewer must render such a row, not 500 on it."""
    import asyncpg
    from tests.conftest import ADMIN_TEST_DATABASE_URL

    _admin_id, _email, _password, _secret = enrolled_admin
    async with await _client() as client:
        await login_as(client, enrolled_admin)
        conn = await asyncpg.connect(ADMIN_TEST_DATABASE_URL)
        try:
            await conn.execute(
                "INSERT INTO audit_log (actor_admin_id, action) "
                "VALUES ('00000000-0000-0000-0000-000000000000', 'ghost.action')"
            )
        finally:
            await conn.close()
        resp = await client.get("/admin/audit")
    assert resp.status_code == 200
    assert b"ghost.action" in resp.content


async def test_audit_viewer_scopes_a_scoped_admin_to_their_own_company(
    db_pool, scoped_admin, company, login_as
):
    """A scoped full admin must never see another tenant's audit history, nor
    another admin's actor-level events (logins)."""
    admin_id, _email, _password, _secret, own_company_id = scoped_admin

    async with db_pool.acquire() as conn:
        other_company_id = await conn.fetchval(
            "INSERT INTO companies (name, api_key_hash, api_key_prefix) "
            "VALUES ('Other Co', 'x', 'x') RETURNING id"
        )
        await conn.execute(
            "INSERT INTO audit_log (target_company_id, action) VALUES ($1, 'company.api_key_rotated')",
            other_company_id,
        )
        await conn.execute(
            "INSERT INTO audit_log (target_company_id, action) VALUES ($1, 'company.api_key_rotated')",
            own_company_id,
        )
        # An actor-level event (a login) with no target_company_id -- this is
        # the admin's OWN login, but it carries no tenant scope at all, and
        # the viewer must not show it to a scoped admin either.
        await conn.execute(
            "INSERT INTO audit_log (actor_admin_id, action) VALUES ($1, 'admin.login.succeeded')",
            admin_id,
        )

    async with await _client() as client:
        await login_as(client, scoped_admin)
        resp = await client.get("/admin/audit")
    assert resp.status_code == 200
    assert str(own_company_id).encode() in resp.content
    assert str(other_company_id).encode() not in resp.content
    assert b"admin.login.succeeded" not in resp.content, (
        "a scoped admin must not see actor-level events with no tenant scope"
    )
