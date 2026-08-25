"""Two-stage admin login.

The property under test throughout: a correct password alone reaches nothing.
Before this change, `POST /admin/login` with the right password handed over a
console that can rotate any company's API key and mint enrollment tokens for
any tenant.
"""
import asyncio
import json
import time
from base64 import b64decode, b64encode

import itsdangerous
import pyotp
import pytest
import pytest_asyncio
from httpx import ASGITransport, AsyncClient

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


def _sign_session(payload: dict) -> str:
    """Build a session cookie the way Starlette's SessionMiddleware does:
    base64-encode the JSON payload, then sign with itsdangerous' TimestampSigner
    keyed on the app's SESSION_SECRET_KEY."""
    signer = itsdangerous.TimestampSigner(str(SESSION_SECRET_KEY))
    return signer.sign(b64encode(json.dumps(payload).encode())).decode()


def _unsign_session(cookie_value: str) -> dict:
    signer = itsdangerous.TimestampSigner(str(SESSION_SECRET_KEY))
    return json.loads(b64decode(signer.unsign(cookie_value.encode())))


async def test_correct_password_alone_does_not_grant_a_session(enrolled_admin):
    """The core of H-2."""
    _admin_id, email, password, _secret = enrolled_admin
    async with await _client() as client:
        resp = await client.post(
            "/admin/login",
            data={"email": email, "password": password},
            follow_redirects=False,
        )
    assert resp.status_code == 303
    assert resp.headers["location"] == "/admin/mfa/verify"
    session = _unsign_session(resp.cookies["session"])
    assert "admin_id" not in session
    assert session["pending_admin_id"]


async def test_a_pending_session_cannot_reach_an_admin_route(enrolled_admin):
    admin_id, _email, _password, _secret = enrolled_admin
    cookie = _sign_session({"pending_admin_id": admin_id, "pending_at": int(time.time())})
    async with await _client() as client:
        client.cookies.set("session", cookie)
        resp = await client.get("/admin/companies", follow_redirects=False)
    assert resp.status_code == 303
    assert resp.headers["location"] == "/admin/login"


async def test_an_expired_pending_session_is_refused(enrolled_admin):
    admin_id, _email, _password, secret = enrolled_admin
    stale = int(time.time()) - 3600
    cookie = _sign_session({"pending_admin_id": admin_id, "pending_at": stale,
                            "csrf_token": "t"})
    async with await _client() as client:
        client.cookies.set("session", cookie)
        resp = await client.post(
            "/admin/mfa/verify",
            data={"code": pyotp.TOTP(secret).now(), "csrf_token": "t"},
            follow_redirects=False,
        )
    assert resp.status_code == 303
    assert resp.headers["location"] == "/admin/login"


async def test_correct_totp_completes_login(enrolled_admin):
    _admin_id, email, password, secret = enrolled_admin
    async with await _client() as client:
        await client.post("/admin/login", data={"email": email, "password": password})
        verify_page = await client.get("/admin/mfa/verify")
        csrf = _unsign_session(client.cookies["session"])["csrf_token"]
        assert verify_page.status_code == 200
        resp = await client.post(
            "/admin/mfa/verify",
            data={"code": pyotp.TOTP(secret).now(), "csrf_token": csrf},
            follow_redirects=False,
        )
    assert resp.status_code == 303
    assert resp.headers["location"] == "/admin/companies"
    session = _unsign_session(resp.cookies["session"])
    assert session["admin_id"]
    assert "pending_admin_id" not in session


async def test_wrong_totp_does_not_grant_a_session(enrolled_admin):
    _admin_id, email, password, _secret = enrolled_admin
    async with await _client() as client:
        await client.post("/admin/login", data={"email": email, "password": password})
        await client.get("/admin/mfa/verify")
        csrf = _unsign_session(client.cookies["session"])["csrf_token"]
        resp = await client.post(
            "/admin/mfa/verify", data={"code": "000000", "csrf_token": csrf}
        )
        assert resp.status_code == 200
        assert b"Invalid code" in resp.content
        after = await client.get("/admin/companies", follow_redirects=False)
    assert after.status_code == 303


async def test_verify_completes_session_rotation(enrolled_admin):
    """The session-fixation fix must survive the move to two stages: the
    session id that ends up authenticated must not be one an attacker could
    have planted before the password was checked."""
    _admin_id, email, password, secret = enrolled_admin
    planted = _sign_session({"attacker_key": "planted"})
    async with await _client() as client:
        # domain="test.local" matches how Python's http.cookiejar records the
        # server's own Set-Cookie for a bare hostname (it appends ".local" for
        # domain-matching purposes per RFC 2965) -- without it, the
        # manually-planted cookie and the server's response cookie land as two
        # distinct jar entries under the same name and httpx's
        # Cookies.__getitem__ raises CookieConflict on the second request.
        # This is an httpx/cookiejar quirk of the test client, not a property
        # of the app under test.
        client.cookies.set("session", planted, domain="test.local")
        await client.post("/admin/login", data={"email": email, "password": password})
        await client.get("/admin/mfa/verify")
        csrf = _unsign_session(client.cookies["session"])["csrf_token"]
        resp = await client.post(
            "/admin/mfa/verify",
            data={"code": pyotp.TOTP(secret).now(), "csrf_token": csrf},
            follow_redirects=False,
        )
    session = _unsign_session(resp.cookies["session"])
    assert "attacker_key" not in session
    assert session["admin_id"]


async def test_verify_requires_csrf(enrolled_admin):
    _admin_id, email, password, secret = enrolled_admin
    async with await _client() as client:
        await client.post("/admin/login", data={"email": email, "password": password})
        await client.get("/admin/mfa/verify")
        resp = await client.post(
            "/admin/mfa/verify",
            data={"code": pyotp.TOTP(secret).now(), "csrf_token": "wrong"},
        )
    assert resp.status_code == 403


# --- enrollment (the rollout path for every admin that exists today) ---

async def test_an_unenrolled_admin_is_sent_to_setup(admin):
    _admin_id, email, password = admin
    async with await _client() as client:
        resp = await client.post(
            "/admin/login",
            data={"email": email, "password": password},
            follow_redirects=False,
        )
    assert resp.status_code == 303
    assert resp.headers["location"] == "/admin/mfa/setup"


async def test_setup_page_shows_a_scannable_qr_and_the_manual_key(admin):
    _admin_id, email, password = admin
    async with await _client() as client:
        await client.post("/admin/login", data={"email": email, "password": password})
        resp = await client.get("/admin/mfa/setup")
    assert resp.status_code == 200
    assert b"<svg" in resp.content
    secret = _unsign_session(resp.cookies["session"])["pending_secret"]
    assert secret.encode() in resp.content, "the manual-entry key must be shown too"


async def test_completing_setup_enrolls_shows_ten_codes_and_logs_in(db_pool, admin):
    admin_id, email, password = admin
    async with await _client() as client:
        await client.post("/admin/login", data={"email": email, "password": password})
        await client.get("/admin/mfa/setup")
        session = _unsign_session(client.cookies["session"])
        resp = await client.post(
            "/admin/mfa/setup",
            data={"code": pyotp.TOTP(session["pending_secret"]).now(),
                  "csrf_token": session["csrf_token"]},
        )
    assert resp.status_code == 200
    body = resp.content.decode()
    async with db_pool.acquire() as conn:
        stored = await conn.fetchval("SELECT mfa_secret FROM admins WHERE id = $1", admin_id)
        codes = await conn.fetchval(
            "SELECT COUNT(*) FROM admin_recovery_codes WHERE admin_id = $1", admin_id
        )
    assert stored is not None
    assert stored != session["pending_secret"], "the raw seed must not be stored"
    assert codes == 10
    assert sum(1 for line in body.splitlines() if "-" in line and "recovery-code" in line) >= 10 \
        or body.count("recovery-code") >= 10
    assert _unsign_session(client.cookies["session"])["admin_id"] == admin_id


async def test_a_wrong_code_at_setup_enrolls_nothing(db_pool, admin):
    """Half-enrollment -- a secret written without codes, or vice versa -- must
    be impossible."""
    admin_id, email, password = admin
    async with await _client() as client:
        await client.post("/admin/login", data={"email": email, "password": password})
        await client.get("/admin/mfa/setup")
        session = _unsign_session(client.cookies["session"])
        resp = await client.post(
            "/admin/mfa/setup",
            data={"code": "000000", "csrf_token": session["csrf_token"]},
        )
    assert resp.status_code == 200
    async with db_pool.acquire() as conn:
        stored = await conn.fetchval("SELECT mfa_secret FROM admins WHERE id = $1", admin_id)
        codes = await conn.fetchval(
            "SELECT COUNT(*) FROM admin_recovery_codes WHERE admin_id = $1", admin_id
        )
    assert stored is None
    assert codes == 0


async def test_an_enrolled_admin_cannot_reset_their_secret_via_setup(enrolled_admin):
    """Otherwise /admin/mfa/setup is an MFA bypass: anyone with the password
    re-enrolls their own authenticator and walks in."""
    _admin_id, email, password, _secret = enrolled_admin
    async with await _client() as client:
        await client.post("/admin/login", data={"email": email, "password": password})
        resp = await client.get("/admin/mfa/setup", follow_redirects=False)
    assert resp.status_code == 303
    assert resp.headers["location"] == "/admin/mfa/verify"


# --- recovery codes ---

async def test_a_recovery_code_completes_login_once(db_pool, admin):
    admin_id, email, password = admin
    from app.admin_auth import replace_recovery_codes
    from app import mfa as mfa_module

    codes = mfa_module.generate_recovery_codes()
    async with db_pool.acquire() as conn:
        await conn.execute(
            "UPDATE admins SET mfa_secret = $1, mfa_enrolled_at = NOW() WHERE id = $2",
            mfa_module.encrypt_secret(mfa_module.generate_secret()), admin_id,
        )
        await replace_recovery_codes(conn, admin_id, codes)

    async def attempt(code):
        async with await _client() as client:
            await client.post("/admin/login", data={"email": email, "password": password})
            await client.get("/admin/mfa/verify")
            csrf = _unsign_session(client.cookies["session"])["csrf_token"]
            return await client.post(
                "/admin/mfa/verify",
                data={"code": code, "csrf_token": csrf},
                follow_redirects=False,
            )

    first = await attempt(codes[0])
    assert first.status_code == 303
    assert first.headers["location"] == "/admin/companies"

    second = await attempt(codes[0])
    assert second.status_code == 200, "a used recovery code must not work twice"


# --- rate limiting ---

async def test_mfa_verification_is_rate_limited(enrolled_admin):
    _admin_id, email, password, _secret = enrolled_admin
    async with await _client() as client:
        await client.post("/admin/login", data={"email": email, "password": password})
        await client.get("/admin/mfa/verify")
        csrf = _unsign_session(client.cookies["session"])["csrf_token"]
        codes = [
            (await client.post("/admin/mfa/verify",
                               data={"code": "000000", "csrf_token": csrf})).status_code
            for _ in range(7)
        ]
    assert 429 in codes, f"no 429 in {codes}"


async def test_restarting_the_login_does_not_reset_the_mfa_limit(enrolled_admin):
    """The bypass this bucket exists to prevent. Keyed on the admin id, so a
    fresh session -- new cookie, new CSRF token -- is the same bucket.

    Each attempt is pinned to a DISTINCT source IP so that the per-IP bucket
    can never be what produces the 429: with every request on its own address,
    and RATE_LIMIT_MFA_IP far looser than RATE_LIMIT_MFA anyway, the only
    counter that accumulates across these seven attempts is the admin-id one.
    Without this the test passes even with the admin-id bucket deleted, since
    a single ASGI client shares one client_ip and would trip the IP bucket at
    the same iteration -- proving nothing about the property it is named for.

    client_ip() takes the LAST x-forwarded-for entry (the only one a client
    cannot forge through a real proxy), so a single-entry header per request
    is what actually selects the bucket here.
    """
    _admin_id, email, password, secret = enrolled_admin

    # This test's whole premise is that all 7 attempts land in the SAME fixed
    # window (RATE_LIMIT_MFA's 900-second bucket, from _window_start in
    # app/rate_limit.py). If the window boundary falls between attempt 5 and
    # attempt 6, the admin-id counter resets mid-burst and 6/7 come back 200
    # instead of 429 -- a real flake (~1-in-450 runs at this test's ~2s
    # runtime), not a bug in the rate limiter. Rather than freezing the clock
    # (no freezegun dependency here) or retrying on failure (which could just
    # as easily mask a real regression), wait out a near-boundary window
    # before starting the burst so the whole sequence always lands in one
    # window.
    import datetime as _datetime
    from app.rate_limit import _window_start

    _WINDOW_SECONDS = 900
    _SAFETY_MARGIN_SECONDS = 15  # generous vs. this test's ~2s of bcrypt work
    now = _datetime.datetime.now(_datetime.timezone.utc)
    window_start = _window_start(_WINDOW_SECONDS, now)
    remaining = _WINDOW_SECONDS - (now - window_start).total_seconds()
    if remaining < _SAFETY_MARGIN_SECONDS:
        await asyncio.sleep(remaining + 0.5)

    async def burn_one(source_ip):
        async with await _client() as client:
            headers = {"x-forwarded-for": source_ip}
            await client.post(
                "/admin/login",
                data={"email": email, "password": password},
                headers=headers,
            )
            await client.get("/admin/mfa/verify", headers=headers)
            csrf = _unsign_session(client.cookies["session"])["csrf_token"]
            return await client.post(
                "/admin/mfa/verify",
                data={"code": "000000", "csrf_token": csrf},
                headers=headers,
            )

    statuses = [(await burn_one(f"10.0.0.{i}")).status_code for i in range(7)]
    assert 429 in statuses, (
        f"restarting the login reset the counter -- statuses {statuses}"
    )


# --- /admin/mfa/recovery-codes: self-service regeneration ------------------
#
# NOTE ON CSRF: as above, the session's csrf_token does not survive
# login_as() -- MFA verification clears the session before writing admin_id.
# GET the recovery-codes page first (a page every logged-in admin, support
# included, can reach) and scrape the token from its rendered form.


async def test_recovery_codes_page_shows_the_remaining_count(db_pool, enrolled_admin, login_as):
    from app.admin_auth import replace_recovery_codes
    from app import mfa as mfa_module

    admin_id, _email, _password, _secret = enrolled_admin
    codes = mfa_module.generate_recovery_codes()
    async with db_pool.acquire() as conn:
        await replace_recovery_codes(conn, admin_id, codes)
    async with await _client() as client:
        await login_as(client, enrolled_admin)
        resp = await client.get("/admin/mfa/recovery-codes")
    assert resp.status_code == 200
    assert b"10" in resp.content
    for code in codes:
        assert code.encode() not in resp.content, "codes are shown once, at generation, only"


async def test_support_admin_can_reach_the_recovery_codes_page(support_admin, login_as):
    """These are the admin's OWN credentials, not a privileged action against
    a tenant, so support (read-only for tenant data) must not be blocked."""
    async with await _client() as client:
        await login_as(client, support_admin)
        resp = await client.get("/admin/mfa/recovery-codes")
    assert resp.status_code == 200


async def test_regenerating_replaces_the_old_set(db_pool, enrolled_admin, login_as):
    """An old printout must stop working the moment a new set is issued."""
    from app.admin_auth import consume_recovery_code, replace_recovery_codes
    from app import mfa as mfa_module

    admin_id, _email, _password, _secret = enrolled_admin
    old = mfa_module.generate_recovery_codes()
    async with db_pool.acquire() as conn:
        await replace_recovery_codes(conn, admin_id, old)
    async with await _client() as client:
        await login_as(client, enrolled_admin)
        page = await client.get("/admin/mfa/recovery-codes")
        csrf = page.text.split('name="csrf_token" value="')[1].split('"')[0]
        resp = await client.post(
            "/admin/mfa/recovery-codes", data={"csrf_token": csrf}
        )
    assert resp.status_code == 200
    assert resp.content.count(b"recovery-code") >= 10
    async with db_pool.acquire() as conn:
        assert await consume_recovery_code(conn, admin_id, old[0]) is False, (
            "a code from the replaced set must no longer authenticate"
        )


async def test_regeneration_requires_csrf_and_a_real_session(enrolled_admin, login_as):
    async with await _client() as client:
        anon = await client.post("/admin/mfa/recovery-codes", data={"csrf_token": "x"},
                                 follow_redirects=False)
        assert anon.status_code == 303
        await login_as(client, enrolled_admin)
        page = await client.get("/admin/mfa/recovery-codes")
        assert page.status_code == 200
        bad = await client.post("/admin/mfa/recovery-codes", data={"csrf_token": "wrong"})
    assert bad.status_code == 403


async def test_regeneration_is_audited(db_pool, enrolled_admin, login_as):
    async with await _client() as client:
        await login_as(client, enrolled_admin)
        page = await client.get("/admin/mfa/recovery-codes")
        csrf = page.text.split('name="csrf_token" value="')[1].split('"')[0]
        await client.post("/admin/mfa/recovery-codes", data={"csrf_token": csrf})
    async with db_pool.acquire() as conn:
        rows = await conn.fetch(
            "SELECT * FROM audit_log WHERE action = 'admin.mfa.recovery_codes_regenerated'"
        )
    assert len(rows) == 1


async def test_a_failing_audit_insert_rolls_regeneration_back(
    db_pool, enrolled_admin, login_as, monkeypatch
):
    """Pins `conn=scope.conn` at this route's call site (see
    test_a_failing_audit_insert_rolls_a_real_route_back in test_audit_log.py
    for the full rationale). Force the audit insert to fail and prove the old
    recovery-code set survives -- that can only happen if replace_recovery_codes
    ran on scope.conn, sharing the audit row's transaction."""
    from app.admin_auth import consume_recovery_code, replace_recovery_codes
    from app import mfa as mfa_module

    admin_id, _email, _password, _secret = enrolled_admin
    old = mfa_module.generate_recovery_codes()
    async with db_pool.acquire() as conn:
        await replace_recovery_codes(conn, admin_id, old)

    import app.audit as audit_module

    real_insert = audit_module._insert

    async def _exploding_insert(conn, actor, written_action, *args, **kwargs):
        if written_action == "admin.mfa.recovery_codes_regenerated":
            raise RuntimeError("audit insert failed")
        return await real_insert(conn, actor, written_action, *args, **kwargs)

    monkeypatch.setattr(audit_module, "_insert", _exploding_insert)

    async with await _client() as client:
        await login_as(client, enrolled_admin)
        page = await client.get("/admin/mfa/recovery-codes")
        csrf = page.text.split('name="csrf_token" value="')[1].split('"')[0]
        with pytest.raises(RuntimeError):
            await client.post("/admin/mfa/recovery-codes", data={"csrf_token": csrf})

    async with db_pool.acquire() as conn:
        assert await consume_recovery_code(conn, admin_id, old[0]) is True, (
            "the old set must still be live -- regeneration is not atomic with its audit row"
        )
