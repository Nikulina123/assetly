import datetime
import hashlib
import json
import re
import time
import uuid
from pathlib import Path
from urllib.parse import quote

from fastapi import APIRouter, Depends, Form, HTTPException, Request
from fastapi.responses import RedirectResponse, Response
from fastapi.templating import Jinja2Templates

from app.admin_auth import (
    AdminContext,
    load_admin_context,
    get_mfa_secret,
    set_mfa_secret,
    replace_recovery_codes,
    consume_recovery_code,
    resolve_admin,
)
from app.audit import audited, record_audit
from app import mfa
from app.auth import generate_api_key, hash_api_key
from app.config import (
    CHECKIN_API_URL_FOR_DOWNLOAD,
    INSTALLER_TOKEN_DAY_CHOICES,
    INSTALLER_TOKEN_DAYS,
    MACOS_PKG_IDENTIFIER,
    MACOS_PKG_VERSION,
    PENDING_LOGIN_MAX_AGE_SECONDS,
    RATE_LIMIT_LOGIN,
    RATE_LIMIT_MFA,
    RATE_LIMIT_MFA_IP,
    REPO_ROOT,
    WINDOWS_EXE_PATH,
)
from app.db import get_pool
from app.rate_limit import client_ip, enforce_rate_limit, hashed_bucket
from app.enrollment import (
    create_enrollment_token,
    list_tokens,
    revoke_device_credential,
    revoke_token,
)
from app.agent_ui import (
    DEFAULT_AGENT_UI,
    resolve_agent_ui_for_admin,
    set_agent_ui,
)
from app.field_config import (
    add_custom_field,
    remove_custom_field,
    resolve_field_settings_for_admin,
    set_department_config,
    set_hardware_field_enabled,
)
from app.macos_pkg import build_flat_package
from app.schedule import (
    MAX_INTERVAL_SECONDS,
    PRESETS,
    RETRY_PRESETS,
    UNIT_SECONDS,
    format_interval,
    parse_interval,
    resolve_schedule,
    set_schedule,
    validate_schedule,
)

router = APIRouter(prefix="/admin")
templates = Jinja2Templates(directory=str(Path(__file__).resolve().parent.parent / "templates"))


class NotAuthenticated(Exception):
    pass


class PendingLoginRequired(Exception):
    """Raised when a pending-login route is reached without a live pending
    session. Handled like NotAuthenticated: bounce to /admin/login."""


async def require_admin(request: Request) -> AdminContext:
    """Identity comes from the signed cookie; role and scope come from the
    database on every request.

    That one indexed primary-key lookup is what makes a demotion, a scope
    change, or a deleted account take effect immediately rather than at cookie
    expiry -- and it means an already-issued cookie is no longer authoritative
    for anything but which admin it names. That is a partial answer to M-3
    (no server-side session revocation), which otherwise remains open.
    """
    admin_id = request.session.get("admin_id")
    if not admin_id:
        raise NotAuthenticated()
    ctx = await load_admin_context(await get_pool(), admin_id)
    if ctx is None:
        request.session.clear()
        raise NotAuthenticated()
    return ctx


async def require_full_admin(admin: AdminContext = Depends(require_admin)) -> AdminContext:
    """Read-only `support` admins are refused. Applied to every state-changing
    route, to the three installer downloads (they mint enrollment tokens), and
    to /admin/diagnostics (it discloses server filesystem paths).

    The templates also hide these controls, but THIS is the enforcement -- a
    hidden button is not an authorisation control, it is a nicety."""
    if not admin.is_full_admin:
        raise HTTPException(status_code=403, detail="Insufficient privileges")
    return admin


async def require_global_admin(admin: AdminContext = Depends(require_full_admin)) -> AdminContext:
    """For routes that make no sense scoped -- creating a company a scoped
    admin would then be unable to see."""
    if not admin.is_global:
        raise HTTPException(status_code=403, detail="Insufficient privileges")
    return admin


def _pending_admin_id(request: Request) -> str:
    """The admin whose password has been verified but whose second factor has
    not. This is NOT a logged-in session: it carries no admin_id, so
    require_admin refuses it exactly like an anonymous request.

    Expiry is checked here against a timestamp inside the session rather than
    being left to the cookie's own max_age, because the cookie's lifetime is
    the full 8-hour admin session -- leaving a half-authenticated state lying
    around that long would turn "attacker got the password" into an 8-hour
    window to also get the code.
    """
    admin_id = request.session.get("pending_admin_id")
    started = request.session.get("pending_at", 0)
    if not admin_id:
        raise PendingLoginRequired()
    if int(time.time()) - int(started) > PENDING_LOGIN_MAX_AGE_SECONDS:
        request.session.clear()
        raise PendingLoginRequired()
    return admin_id


def _new_csrf_token(request: Request) -> str:
    if "csrf_token" not in request.session:
        request.session["csrf_token"] = uuid.uuid4().hex
    return request.session["csrf_token"]


def _check_csrf(request: Request, csrf_token: str) -> None:
    expected = request.session.get("csrf_token")
    if not expected or csrf_token != expected:
        raise HTTPException(status_code=403, detail="Invalid CSRF token")


async def _all_companies(pool, admin: AdminContext):
    """A scoped admin's list is filtered in SQL rather than in the template --
    the template is presentation, and a value that never leaves the database
    cannot leak through a context that some other view forgets to filter."""
    async with pool.acquire() as conn:
        if admin.is_global:
            return await conn.fetch(
                "SELECT id, name, revoked_at FROM companies ORDER BY name"
            )
        return await conn.fetch(
            "SELECT id, name, revoked_at FROM companies WHERE id = $1 ORDER BY name",
            uuid.UUID(admin.company_id),
        )


@router.get("/login")
async def login_form(request: Request):
    return templates.TemplateResponse(request, "login.html")


@router.post("/login")
async def login_submit(request: Request, email: str = Form(...), password: str = Form(...)):
    pool = await get_pool()
    # Two buckets, both enforced. Per-IP stops one host walking a password
    # list; per-account stops a distributed attempt against one known admin
    # address, which per-IP alone would not see. The email is hashed into the
    # bucket key so this table never becomes a list of admin addresses.
    limit, window = RATE_LIMIT_LOGIN
    await enforce_rate_limit(pool, f"login:ip:{client_ip(request)}", limit, window)
    await enforce_rate_limit(pool, hashed_bucket("login:email", email), limit, window)

    admin_id = await resolve_admin(pool, email, password)
    if admin_id is None:
        # Recorded in clear, deliberately -- unlike the rate-limit buckets,
        # which are hashed. This table's job is answering "who was targeted,
        # from where" during an incident, and a hash cannot answer that.
        await record_audit(
            pool, request, None, "admin.login.failed", metadata={"email": email}
        )
        return templates.TemplateResponse(
            request, "login.html", {"error": "Invalid email or password"}
        )
    # A correct password no longer grants access -- it grants the RIGHT TO
    # ATTEMPT the second factor. Clearing first is the session-fixation fix
    # (these are client-side signed cookies, so the pre-login session is
    # attacker-fixable) and it also drops any pre-auth csrf_token, so the
    # token the MFA form carries was minted after the password check.
    request.session.clear()
    request.session["pending_admin_id"] = admin_id
    request.session["pending_at"] = int(time.time())
    ctx = await load_admin_context(pool, admin_id)
    if ctx is not None and ctx.mfa_enrolled:
        return RedirectResponse("/admin/mfa/verify", status_code=303)
    return RedirectResponse("/admin/mfa/setup", status_code=303)


@router.post("/logout")
async def logout(request: Request):
    admin_id = request.session.get("admin_id")
    if admin_id:
        pool = await get_pool()
        await record_audit(pool, request, admin_id, "admin.logout")
    request.session.clear()
    return RedirectResponse("/admin/login", status_code=303)


@router.get("/mfa/setup")
async def mfa_setup_form(request: Request):
    pool = await get_pool()
    admin_id = _pending_admin_id(request)
    ctx = await load_admin_context(pool, admin_id)
    if ctx is None:
        request.session.clear()
        raise PendingLoginRequired()
    if ctx.mfa_enrolled:
        # Otherwise this route is an MFA bypass: anyone holding the password
        # could re-enroll their own authenticator and walk straight in.
        # Re-enrollment for a locked-out admin is an operator action.
        return RedirectResponse("/admin/mfa/verify", status_code=303)

    # The unconfirmed secret lives in the pending session, not in the database,
    # so a half-enrolled row -- a secret set that no authenticator actually
    # holds -- cannot exist. It is written only once a live code proves the
    # authenticator has it.
    secret = request.session.get("pending_secret")
    if not secret:
        secret = mfa.generate_secret()
        request.session["pending_secret"] = secret

    uri = mfa.provisioning_uri(secret, ctx.email)
    return templates.TemplateResponse(
        request,
        "mfa_setup.html",
        {
            "qr_svg": mfa.qr_svg(uri),
            "secret": secret,
            "csrf_token": _new_csrf_token(request),
        },
    )


@router.post("/mfa/setup")
async def mfa_setup_submit(
    request: Request, code: str = Form(...), csrf_token: str = Form(...)
):
    _check_csrf(request, csrf_token)
    pool = await get_pool()
    admin_id = _pending_admin_id(request)
    ctx = await load_admin_context(pool, admin_id)
    if ctx is None or ctx.mfa_enrolled:
        request.session.clear()
        raise PendingLoginRequired()

    secret = request.session.get("pending_secret")
    if not secret:
        # No pending secret means this POST did not follow a GET of this form
        # in the same session. Fabricating one here would render a QR for a
        # secret nothing is tracking, next to a blank manual-entry key -- an
        # unusable page that invites the admin to scan a code that can never
        # verify. Send them back to restart the flow instead.
        request.session.clear()
        raise PendingLoginRequired()

    if not mfa.verify_totp(secret, code):
        uri = mfa.provisioning_uri(secret, ctx.email)
        return templates.TemplateResponse(
            request,
            "mfa_setup.html",
            {
                "qr_svg": mfa.qr_svg(uri),
                "secret": secret,
                "csrf_token": _new_csrf_token(request),
                "error": "That code did not match. Check your device clock and try again.",
            },
        )

    codes = mfa.generate_recovery_codes()
    # One transaction: secret, codes, and the audit row land together or not
    # at all. Never put the secret or the recovery codes themselves in
    # metadata.
    async with audited(pool, request, admin_id, "admin.mfa.enrolled") as scope:
        await set_mfa_secret(scope.conn, admin_id, secret)
        await replace_recovery_codes(scope.conn, admin_id, codes)

    request.session.clear()
    request.session["admin_id"] = admin_id
    # No csrf_token in the context: this page has no form. Its only control is
    # a plain GET link to the console, and the next authenticated render mints
    # a token of its own.
    return templates.TemplateResponse(
        request, "mfa_recovery_codes.html", {"codes": codes}
    )


@router.get("/mfa/verify")
async def mfa_verify_form(request: Request):
    _pending_admin_id(request)
    return templates.TemplateResponse(
        request, "mfa_verify.html", {"csrf_token": _new_csrf_token(request)}
    )


@router.post("/mfa/verify")
async def mfa_verify_submit(
    request: Request, code: str = Form(...), csrf_token: str = Form(...)
):
    _check_csrf(request, csrf_token)
    pool = await get_pool()
    admin_id = _pending_admin_id(request)

    # Two buckets, both enforced BEFORE any comparison. A 6-digit code is a far
    # weaker secret than a password, so these are tighter than RATE_LIMIT_LOGIN.
    #
    # THE ADMIN-ID BUCKET IS THE LOAD-BEARING CONTROL. It is keyed on the admin
    # id, never on the session: abandoning the login and starting again produces
    # a new cookie and a new CSRF token but the same admin, so the counter does
    # not reset. That reset is the bypass this bucket exists to prevent -- see
    # test_restarting_the_login_does_not_reset_the_mfa_limit, which pins each
    # attempt to a distinct IP precisely so that only THIS bucket can produce
    # the 429 it asserts.
    #
    # The IP bucket is only a coarse guard against one address hammering many
    # different accounts, and is deliberately much looser (RATE_LIMIT_MFA_IP).
    # It is NOT defence in its own right: off Vercel, client_ip() falls through
    # to the last x-forwarded-for entry, which an attacker on a direct
    # connection rotates at will. Tightening it to the admin limit would buy no
    # security and would let admins behind one office NAT lock each other out.
    limit, window = RATE_LIMIT_MFA
    await enforce_rate_limit(pool, hashed_bucket("mfa:admin", admin_id), limit, window)
    ip_limit, ip_window = RATE_LIMIT_MFA_IP
    await enforce_rate_limit(pool, f"mfa:ip:{client_ip(request)}", ip_limit, ip_window)

    secret = await get_mfa_secret(pool, admin_id)
    method = None
    if secret and mfa.looks_like_totp(code):
        if mfa.verify_totp(secret, code):
            method = "totp"
    elif not mfa.looks_like_totp(code):
        async with pool.acquire() as conn:
            async with conn.transaction():
                if await consume_recovery_code(conn, admin_id, code):
                    method = "recovery"

    if method is None:
        # Never put the submitted code in metadata -- it is secret material
        # for the six-digit TOTP window it was valid in.
        await record_audit(pool, request, admin_id, "admin.mfa.failed")
        return templates.TemplateResponse(
            request, "mfa_verify.html",
            {"csrf_token": _new_csrf_token(request), "error": "Invalid code"},
        )

    if method == "recovery":
        await record_audit(pool, request, admin_id, "admin.mfa.recovery_code_used")
    await record_audit(
        pool, request, admin_id, "admin.login.succeeded", metadata={"method": method}
    )

    # Rotate at the point access is actually granted, not merely at the
    # password step.
    request.session.clear()
    request.session["admin_id"] = admin_id
    return RedirectResponse("/admin/companies", status_code=303)


@router.get("/companies")
async def companies_list(request: Request, admin: AdminContext = Depends(require_admin)):
    pool = await get_pool()
    companies = await _all_companies(pool, admin)
    return templates.TemplateResponse(
        request,
        "companies_list.html",
        {"companies": companies, "csrf_token": _new_csrf_token(request), "admin": admin},
    )


@router.post("/companies")
async def companies_create(
    request: Request,
    name: str = Form(...),
    notification_email: str = Form(...),
    csrf_token: str = Form(...),
    admin: AdminContext = Depends(require_global_admin),
):
    _check_csrf(request, csrf_token)

    api_key = generate_api_key()
    key_hash = hash_api_key(api_key)
    pool = await get_pool()
    async with pool.acquire() as conn:
        await conn.execute(
            "INSERT INTO companies (name, api_key_hash, api_key_prefix, notification_email) "
            "VALUES ($1, $2, $3, $4)",
            name, key_hash, api_key[:8], notification_email,
        )

    companies = await _all_companies(pool, admin)
    return templates.TemplateResponse(
        request,
        "companies_list.html",
        {
            "companies": companies,
            "csrf_token": _new_csrf_token(request),
            "new_api_key": api_key,
            "admin": admin,
        },
    )


async def _get_company_or_404(pool, company_id: uuid.UUID, admin: AdminContext):
    # 404 rather than 403, and checked before the lookup: a 403 (or a 404 whose
    # timing differs from a real miss) confirms the company exists, which tells
    # a scoped admin that a tenant they are not entitled to see is a customer.
    if not admin.is_global and str(company_id) != admin.company_id:
        raise HTTPException(status_code=404, detail="Company not found")
    async with pool.acquire() as conn:
        company = await conn.fetchrow(
            "SELECT id, name, api_key_prefix, revoked_at, notification_email FROM companies WHERE id = $1",
            company_id,
        )
    if company is None:
        raise HTTPException(status_code=404, detail="Company not found")
    return company


def _with_token_status(token: dict, now: datetime.datetime) -> dict:
    # Status is derived here in Python, not stored or computed in SQL, matching
    # devices.py's device_status pattern -- one definition, evaluated at render
    # time so "expired" flips the instant the clock passes expires_at.
    token = dict(token)
    if token["revoked_at"] is not None:
        token["status"] = "revoked"
    elif token["expires_at"] <= now:
        token["status"] = "expired"
    else:
        token["status"] = "active"
    return token


async def _tokens_for_display(pool, company_id: str) -> list[dict]:
    now = datetime.datetime.now(datetime.timezone.utc)
    tokens = await list_tokens(pool, company_id)
    return [_with_token_status(t, now) for t in tokens]


def _decompose_interval(seconds: int) -> tuple[str, str]:
    """Stored seconds -> the (count, unit) that would produce them.

    Largest unit first, so this reports the form an admin would have typed
    ("5 days", not "120 hours"). The order is derived from UNIT_SECONDS on each
    call rather than snapshotted at import, so it cannot go stale against the
    table it is supposed to mirror -- five items, so the sort costs nothing.

    Returns the count as a string because it is rendered straight into the
    number input's value=, and "" is how that input spells "empty".

    Nothing divides exactly only if the value did not come through
    parse_interval at all (a direct DB edit such as 3700). Rather than round --
    which would silently rewrite the admin's interval the next time they saved
    anything on this form -- the count comes back empty, so the box shows no
    number and a save has to state an interval explicitly. The summary banner
    above the form still reports the value actually in force.
    """
    for unit, size in sorted(UNIT_SECONDS.items(), key=lambda kv: -kv[1]):
        if seconds % size == 0:
            return str(seconds // size), unit
    return "", "hours"


async def _schedule_context(pool, company_id: str) -> dict:
    """Everything company_detail.html needs to render the schedule card."""
    schedule = await resolve_schedule(pool, str(company_id))
    interval = schedule["checkin_interval_seconds"]
    # Whether the stored interval is one of the dropdown's presets decides which
    # option carries `selected`. Without this the template emitted no selected
    # option at all for a custom interval, and the browser fell back to the
    # first one -- so the form silently offered to overwrite a custom interval
    # with 12 hours.
    interval_is_custom = interval not in [s for _, s in PRESETS]
    custom_count, custom_unit = (
        _decompose_interval(interval) if interval_is_custom else ("", "hours")
    )
    return {
        "schedule": schedule,
        "presets": PRESETS,
        "retry_presets": RETRY_PRESETS,
        "interval_is_custom": interval_is_custom,
        "custom_count": custom_count,
        "custom_unit": custom_unit,
        # Client-side courtesy only; parse_interval is what actually enforces
        # the cap. The count is in whichever unit is selected, so the only
        # bound valid for every unit is the one for the smallest (hours) --
        # deliberately loose, and never the thing a rejection depends on.
        "custom_count_max": MAX_INTERVAL_SECONDS // UNIT_SECONDS["hours"],
        "schedule_summary": (
            f"Employees are prompted every "
            f"{format_interval(schedule['checkin_interval_seconds'])}; "
            f"if they cancel, they are asked again after "
            f"{format_interval(schedule['cancel_retry_seconds'])}."
        ),
    }


async def _agent_ui_context(pool, company_id: uuid.UUID) -> dict:
    """Everything company_detail.html needs to render the appearance card.

    Called alongside _schedule_context at every site that renders that
    template, including the error re-renders -- a handler that skipped it would
    drop the whole card off the page as a side effect of an unrelated
    validation failure.
    """
    return {"agent_ui": await resolve_agent_ui_for_admin(pool, str(company_id))}


@router.get("/companies/{company_id}")
async def company_detail(
    request: Request, company_id: uuid.UUID, admin: AdminContext = Depends(require_admin)
):
    pool = await get_pool()
    company = await _get_company_or_404(pool, company_id, admin)
    field_settings = await resolve_field_settings_for_admin(pool, str(company_id))
    companies = await _all_companies(pool, admin)
    context = {
        "request": request,
        "companies": companies,
        "company": company,
        "csrf_token": _new_csrf_token(request),
        "field_settings": field_settings,
        "tokens": await _tokens_for_display(pool, str(company_id)),
        "nav_active": "settings",
        "admin": admin,
    }
    context.update(await _schedule_context(pool, company_id))
    context.update(await _agent_ui_context(pool, company_id))
    return templates.TemplateResponse(request, "company_detail.html", context)


@router.post("/companies/{company_id}/rotate-key")
async def rotate_key(
    request: Request,
    company_id: uuid.UUID,
    csrf_token: str = Form(...),
    admin: AdminContext = Depends(require_full_admin),
):
    _check_csrf(request, csrf_token)
    pool = await get_pool()
    await _get_company_or_404(pool, company_id, admin)

    api_key = generate_api_key()
    key_hash = hash_api_key(api_key)
    async with pool.acquire() as conn:
        company = await conn.fetchrow(
            """
            UPDATE companies SET api_key_hash = $1, api_key_prefix = $2 WHERE id = $3
            RETURNING id, name, api_key_prefix, revoked_at, notification_email
            """,
            key_hash, api_key[:8], company_id,
        )
    if company is None:
        raise HTTPException(status_code=404, detail="Company not found")

    field_settings = await resolve_field_settings_for_admin(pool, str(company_id))
    companies = await _all_companies(pool, admin)
    context = {
        "request": request,
        "companies": companies,
        "company": company,
        "csrf_token": _new_csrf_token(request),
        "new_api_key": api_key,
        "field_settings": field_settings,
        "tokens": await _tokens_for_display(pool, str(company_id)),
        "admin": admin,
    }
    context.update(await _schedule_context(pool, company_id))
    context.update(await _agent_ui_context(pool, company_id))
    return templates.TemplateResponse(request, "company_detail.html", context)


@router.post("/companies/{company_id}/revoke")
async def revoke_company(
    request: Request,
    company_id: uuid.UUID,
    csrf_token: str = Form(...),
    admin: AdminContext = Depends(require_full_admin),
):
    _check_csrf(request, csrf_token)
    pool = await get_pool()
    await _get_company_or_404(pool, company_id, admin)

    async with pool.acquire() as conn:
        company = await conn.fetchrow(
            """
            UPDATE companies SET revoked_at = NOW() WHERE id = $1 AND revoked_at IS NULL
            RETURNING id, name, api_key_prefix, revoked_at, notification_email
            """,
            company_id,
        )

    if company is None:
        # UPDATE's WHERE clause excludes already-revoked rows, so None here means
        # either "already revoked" or "doesn't exist" — disambiguate with a plain
        # lookup: 404s if truly missing, otherwise returns the existing (already-
        # revoked) row so this stays idempotent instead of erroring on a re-click.
        company = await _get_company_or_404(pool, company_id, admin)

    field_settings = await resolve_field_settings_for_admin(pool, str(company_id))
    companies = await _all_companies(pool, admin)
    context = {
        "request": request,
        "companies": companies,
        "company": company,
        "csrf_token": _new_csrf_token(request),
        "field_settings": field_settings,
        "tokens": await _tokens_for_display(pool, str(company_id)),
        "admin": admin,
    }
    context.update(await _schedule_context(pool, company_id))
    context.update(await _agent_ui_context(pool, company_id))
    return templates.TemplateResponse(request, "company_detail.html", context)


@router.post("/companies/{company_id}/notification-email")
async def update_notification_email(
    request: Request,
    company_id: uuid.UUID,
    notification_email: str = Form(...),
    csrf_token: str = Form(...),
    admin: AdminContext = Depends(require_full_admin),
):
    _check_csrf(request, csrf_token)
    pool = await get_pool()
    await _get_company_or_404(pool, company_id, admin)
    async with pool.acquire() as conn:
        await conn.execute(
            "UPDATE companies SET notification_email = $1 WHERE id = $2",
            notification_email, company_id,
        )
    return RedirectResponse(f"/admin/companies/{company_id}", status_code=303)


@router.post("/companies/{company_id}/schedule")
async def update_schedule(
    request: Request,
    company_id: uuid.UUID,
    csrf_token: str = Form(...),
    interval_preset: str = Form(...),
    cancel_retry_seconds: int = Form(...),
    # str, NOT int: the template always submits custom_count, empty when a
    # preset is selected. An `int | None` annotation would make FastAPI reject
    # that empty string with a 422 before this handler ever runs -- so every
    # ordinary preset save would fail.
    custom_count: str | None = Form(None),
    custom_unit: str | None = Form(None),
    admin: AdminContext = Depends(require_full_admin),
):
    _check_csrf(request, csrf_token)
    pool = await get_pool()
    await _get_company_or_404(pool, company_id, admin)

    try:
        if interval_preset == "custom":
            if not custom_count or not custom_unit:
                raise ValueError("Enter a number and a unit for a custom interval")
            try:
                count = int(custom_count)
            except ValueError:
                raise ValueError("Custom interval must be a whole number")
            interval = parse_interval(count, custom_unit)
        else:
            interval = int(interval_preset)
        validate_schedule(interval, cancel_retry_seconds)
    except ValueError as exc:
        # Re-render with the error rather than redirecting, so the message is
        # shown in place -- the same pattern add_custom_field_route uses. Note
        # the form comes back populated from the STORED schedule, not from the
        # rejected submission: _schedule_context re-reads the database. That is
        # the deliberate choice -- a rejected value is by definition one that
        # cannot be stored, and redisplaying it invites a second save of the
        # same bad input, while the stored values are what is still in force.
        company = await _get_company_or_404(pool, company_id, admin)
        companies = await _all_companies(pool, admin)
        field_settings = await resolve_field_settings_for_admin(pool, str(company_id))
        context = {
            "request": request,
            "company": company,
            "companies": companies,
            "field_settings": field_settings,
            "tokens": await _tokens_for_display(pool, str(company_id)),
            "csrf_token": _new_csrf_token(request),
            "nav_active": "settings",
            "schedule_error": str(exc),
            "admin": admin,
        }
        context.update(await _schedule_context(pool, company_id))
        context.update(await _agent_ui_context(pool, company_id))
        return templates.TemplateResponse(
            request, "company_detail.html", context, status_code=200
        )

    await set_schedule(pool, str(company_id), interval, cancel_retry_seconds)
    return RedirectResponse(f"/admin/companies/{company_id}", status_code=303)


@router.post("/companies/{company_id}/appearance")
async def update_agent_ui(
    request: Request,
    company_id: uuid.UUID,
    admin: AdminContext = Depends(require_full_admin),
):
    """Saves the agent window's copy and colours.

    Reads the raw form rather than declaring ~20 Form(...) parameters: the set
    of keys is DEFAULT_AGENT_UI, and restating it here would be a second list
    to keep in sync -- one that fails by silently ignoring a field rather than
    by raising.
    """
    form = await request.form()
    _check_csrf(request, str(form.get("csrf_token", "")))
    pool = await get_pool()
    await _get_company_or_404(pool, company_id, admin)

    # Absent keys mean "leave at default"; the template posts every key, so in
    # practice absence only happens for a form from an older page load.
    submitted = {key: str(form[key]) for key in DEFAULT_AGENT_UI if key in form}

    try:
        await set_agent_ui(pool, str(company_id), submitted)
    except ValueError as exc:
        # Re-render in place with the message, as update_schedule does. The
        # rejected values ARE echoed back here, unlike the schedule form: a
        # colour submission is ~20 interdependent values an admin has just
        # hand-picked, and re-reading the stored palette would throw all of
        # that away to show the failure. The card renders from `agent_ui_form`
        # when present, so the admin can fix the one bad value in place.
        company = await _get_company_or_404(pool, company_id, admin)
        companies = await _all_companies(pool, admin)
        field_settings = await resolve_field_settings_for_admin(pool, str(company_id))
        context = {
            "request": request,
            "company": company,
            "companies": companies,
            "field_settings": field_settings,
            "tokens": await _tokens_for_display(pool, str(company_id)),
            "csrf_token": _new_csrf_token(request),
            "nav_active": "settings",
            "agent_ui_error": str(exc),
            "agent_ui_form": submitted,
            "admin": admin,
        }
        context.update(await _schedule_context(pool, company_id))
        context.update(await _agent_ui_context(pool, company_id))
        return templates.TemplateResponse(
            request, "company_detail.html", context, status_code=200
        )

    return RedirectResponse(f"/admin/companies/{company_id}", status_code=303)


@router.post("/companies/{company_id}/fields/hardware")
async def update_hardware_fields(
    request: Request,
    company_id: uuid.UUID,
    csrf_token: str = Form(...),
    cpu: str | None = Form(None),
    ram: str | None = Form(None),
    storage: str | None = Form(None),
    ip_address: str | None = Form(None),
    department_enabled: str | None = Form(None),
    department_required: str | None = Form(None),
    admin: AdminContext = Depends(require_full_admin),
):
    _check_csrf(request, csrf_token)
    pool = await get_pool()
    await _get_company_or_404(pool, company_id, admin)

    company_id_str = str(company_id)
    for field_key, submitted_value in [
        ("cpu", cpu), ("ram", ram), ("storage", storage), ("ip_address", ip_address),
    ]:
        await set_hardware_field_enabled(pool, company_id_str, field_key, submitted_value is not None)

    # Check if department_options was submitted in the form. In Starlette 1.6.0, empty form fields
    # may not appear in the Form() parameters, so we check the raw form data to distinguish
    # between "not submitted" (None) and "submitted but empty" (list).
    form_data = await request.form()
    if "department_options" in form_data:
        department_options_raw = form_data["department_options"]
        options = department_options_raw.splitlines() if department_options_raw else []
    else:
        options = None

    await set_department_config(
        pool, company_id_str,
        enabled=department_enabled is not None,
        required=department_required is not None,
        options=options,
    )

    return RedirectResponse(f"/admin/companies/{company_id}", status_code=303)


@router.post("/companies/{company_id}/fields/custom")
async def add_custom_field_route(
    request: Request,
    company_id: uuid.UUID,
    label: str = Form(...),
    required: str | None = Form(None),
    csrf_token: str = Form(...),
    admin: AdminContext = Depends(require_full_admin),
):
    _check_csrf(request, csrf_token)
    pool = await get_pool()
    company = await _get_company_or_404(pool, company_id, admin)
    try:
        await add_custom_field(pool, str(company_id), label, required is not None)
    except ValueError as e:
        field_settings = await resolve_field_settings_for_admin(pool, str(company_id))
        companies = await _all_companies(pool, admin)
        context = {
            "request": request,
            "companies": companies,
            "company": company,
            "csrf_token": _new_csrf_token(request),
            "field_settings": field_settings,
            "field_error": str(e),
            "tokens": await _tokens_for_display(pool, str(company_id)),
            "admin": admin,
        }
        context.update(await _schedule_context(pool, company_id))
        context.update(await _agent_ui_context(pool, company_id))
        return templates.TemplateResponse(request, "company_detail.html", context)
    return RedirectResponse(f"/admin/companies/{company_id}", status_code=303)


@router.post("/companies/{company_id}/fields/custom/{field_key}/remove")
async def remove_custom_field_route(
    request: Request,
    company_id: uuid.UUID,
    field_key: str,
    csrf_token: str = Form(...),
    admin: AdminContext = Depends(require_full_admin),
):
    _check_csrf(request, csrf_token)
    pool = await get_pool()
    await _get_company_or_404(pool, company_id, admin)
    await remove_custom_field(pool, str(company_id), field_key)
    return RedirectResponse(f"/admin/companies/{company_id}", status_code=303)


@router.post("/companies/{company_id}/tokens/{token_id}/revoke")
async def revoke_enrollment_token(
    request: Request,
    company_id: uuid.UUID,
    token_id: uuid.UUID,
    csrf_token: str = Form(...),
    admin: AdminContext = Depends(require_full_admin),
):
    """Blocks future enrollments with this token. Devices that already
    enrolled through it keep their own credential and are untouched -- the
    token is only ever a gate for NEW enrollments, never a live credential
    itself."""
    _check_csrf(request, csrf_token)
    pool = await get_pool()
    await _get_company_or_404(pool, company_id, admin)
    await revoke_token(pool, str(company_id), str(token_id))
    return RedirectResponse(f"/admin/companies/{company_id}", status_code=303)


@router.post("/companies/{company_id}/devices/{serial_number}/revoke")
async def revoke_device(
    request: Request,
    company_id: uuid.UUID,
    serial_number: str,
    csrf_token: str = Form(...),
    admin: AdminContext = Depends(require_full_admin),
):
    """Revokes exactly one machine's credential. Every other device in the
    company -- including ones enrolled through the same token -- keeps
    checking in normally; this is a single-device action, not a fleet-wide
    one. Serial numbers are free-form strings from client hardware and may
    contain characters that need escaping in a URL, so the redirect target
    below re-encodes it (Starlette has already decoded the incoming path
    segment for us by the time `serial_number` reaches this function)."""
    _check_csrf(request, csrf_token)
    pool = await get_pool()
    await _get_company_or_404(pool, company_id, admin)
    await revoke_device_credential(pool, str(company_id), serial_number)
    return RedirectResponse(
        f"/admin/companies/{company_id}/computers/{quote(serial_number, safe='')}",
        status_code=303,
    )


async def _get_active_company_or_404(pool, company_id: uuid.UUID, admin: AdminContext):
    """Like _get_company_or_404, but also blocks revoked companies -- a
    downloadable installer whose key immediately 401s is worse than no
    download button."""
    company = await _get_company_or_404(pool, company_id, admin)
    if company["revoked_at"] is not None:
        raise HTTPException(status_code=404, detail="Company not found")
    return company


_CHECKIN_API_URL_PATTERN = r'^CHECKIN_API_URL=".*?"(\s*#.*)?$'
_ENROLLMENT_TOKEN_PATTERN = r'^ENROLLMENT_TOKEN=".*?"(\s*#.*)?$'


def _load_installer_template(filename: str) -> str:
    """Reads the installer script and confirms both substitution markers are
    present, BEFORE any token is minted -- so a missing file or a marker
    that's drifted out of sync (e.g. the script's formatting changed) can't
    leave a token minted with no valid installer to show for it."""
    text = (REPO_ROOT / filename).read_text()
    if not re.search(_CHECKIN_API_URL_PATTERN, text, flags=re.MULTILINE):
        raise RuntimeError(f"{filename}: CHECKIN_API_URL substitution marker not found")
    if not re.search(_ENROLLMENT_TOKEN_PATTERN, text, flags=re.MULTILINE):
        raise RuntimeError(f"{filename}: ENROLLMENT_TOKEN substitution marker not found")
    return text


def _render_installer_script(template_text: str, checkin_api_url: str, enrollment_token: str) -> str:
    text = re.sub(
        _CHECKIN_API_URL_PATTERN,
        f'CHECKIN_API_URL="{checkin_api_url}"',
        template_text, count=1, flags=re.MULTILINE,
    )
    text = re.sub(
        _ENROLLMENT_TOKEN_PATTERN,
        f'ENROLLMENT_TOKEN="{enrollment_token}"',
        text, count=1, flags=re.MULTILINE,
    )
    return text


@router.get("/diagnostics")
async def diagnostics(request: Request, admin: AdminContext = Depends(require_full_admin)):
    """Reports what this instance actually has on disk.

    Every file a download route reads is committed to the repository, which
    makes it tempting to assume the deployed instance holds the same bytes.
    That assumption is invisible from a checkout and has already been wrong
    twice: once because vercel.json did not bundle the directory at all, and
    once because a served executable did not match the committed one. Hashes
    are included so a served artifact can be compared with `sha256sum` against
    a local checkout without downloading anything.
    """
    pool = await get_pool()
    await record_audit(pool, request, admin, "admin.diagnostics_viewed")

    def describe(path: Path) -> dict:
        if not path.is_file():
            return {"path": str(path), "exists": False}
        data = path.read_bytes()
        return {
            "path": str(path),
            "exists": True,
            "bytes": len(data),
            "sha256": hashlib.sha256(data).hexdigest(),
        }

    static_dir = WINDOWS_EXE_PATH.parent
    return {
        "repo_root": str(REPO_ROOT),
        "checkin_api_url": CHECKIN_API_URL_FOR_DOWNLOAD,
        "windows_exe": describe(WINDOWS_EXE_PATH),
        "agent_source": describe(REPO_ROOT / "inventory_agent.py"),
        "macos_postinstall": describe(REPO_ROOT / "AssetlyAgent_macOS_postinstall.sh"),
        "linux_installer": describe(REPO_ROOT / "AssetlyAgent_Linux.sh"),
        "windows_exe_dir": (
            sorted(p.name for p in static_dir.iterdir()) if static_dir.is_dir() else None
        ),
    }


# Delimiters the Windows agent scans for at the tail of its own executable.
# Kept byte-for-byte in sync with Get-EmbeddedConfig in AssetlyAgent_Windows.ps1.
WINDOWS_CONFIG_BEGIN = b"ASSETLY-CONFIG-BEGIN:"
WINDOWS_CONFIG_END = b":ASSETLY-CONFIG-END"


def embed_windows_config(exe_bytes: bytes, config: dict) -> bytes:
    """Appends a config block to a PE image, replacing one already present.

    Replacing rather than appending keeps this idempotent: an executable that
    has already been through a download once -- someone copying a configured
    exe back over the build artifact, say -- still comes out with exactly one
    config block, and the one that belongs to the company downloading it.

    The search is anchored to the end of the file, and that is not a detail.
    The agent has to contain this marker in order to look for it, and ps2exe
    stores the script as plain text, so the compiled executable holds a copy of
    the string ~15 KB in. Searching the whole file finds *that* copy and
    truncates the binary mid-script, which shipped an unrunnable 16 KB exe to
    every Windows download until it was caught. A block this function wrote is
    always the last thing in the file; anything else is the agent's own source.
    """
    if exe_bytes.endswith(WINDOWS_CONFIG_END):
        previous_block = exe_bytes.rfind(WINDOWS_CONFIG_BEGIN)
        if previous_block != -1:
            exe_bytes = exe_bytes[:previous_block]
    return exe_bytes + WINDOWS_CONFIG_BEGIN + json.dumps(config).encode() + WINDOWS_CONFIG_END


def _installer_token_terms(device_count: int, token_days: int) -> tuple[int, datetime.datetime]:
    """Validated (max_devices, expires_at) for an installer-minted token.

    Rejects rather than clamps, matching agent_ui.py: an admin who typed 5000
    by accident should see an error, not silently receive a token that lets
    5000 machines enroll.

    The headroom exists because a device count is an estimate and a re-imaged
    machine re-enrolls under the same serial (device_credentials is UNIQUE on
    (company_id, serial_number), so that replaces rather than adds) -- but a
    genuinely new machine does not, and an installer that stops working
    mid-rollout is a support call.
    """
    if not 1 <= device_count <= 10000:
        raise HTTPException(status_code=400, detail="Device count must be between 1 and 10000")
    if token_days not in INSTALLER_TOKEN_DAY_CHOICES:
        raise HTTPException(
            status_code=400,
            detail=f"Token lifetime must be one of {INSTALLER_TOKEN_DAY_CHOICES} days",
        )
    max_devices = device_count + max(5, device_count // 10)
    expires_at = datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(days=token_days)
    return max_devices, expires_at


@router.post("/companies/{company_id}/download/macos")
async def download_macos(
    request: Request,
    company_id: uuid.UUID,
    csrf_token: str = Form(...),
    device_count: int = Form(...),
    token_days: int = Form(INSTALLER_TOKEN_DAYS),
    admin: AdminContext = Depends(require_full_admin),
):
    """Serves a double-clickable installer package rather than a shell script.

    The agent's source travels inside the package, so an install never depends
    on GitHub being reachable from the machine being set up. A missing agent
    file surfaces here, as a failed download an admin can see, instead of
    hundreds of installs each failing on their own later.
    """
    _check_csrf(request, csrf_token)
    pool = await get_pool()
    await _get_active_company_or_404(pool, company_id, admin)
    postinstall_template = _load_installer_template("AssetlyAgent_macOS_postinstall.sh")
    agent_source = (REPO_ROOT / "inventory_agent.py").read_bytes()
    max_devices, expires_at = _installer_token_terms(device_count, token_days)
    token = await create_enrollment_token(
        pool, str(company_id), label=f"macOS installer ({device_count} devices)",
        expires_at=expires_at, max_devices=max_devices,
    )
    postinstall = _render_installer_script(
        postinstall_template, CHECKIN_API_URL_FOR_DOWNLOAD, token
    )
    pkg_bytes = build_flat_package(
        identifier=MACOS_PKG_IDENTIFIER,
        version=MACOS_PKG_VERSION,
        title="Assetly Inventory Agent",
        scripts={
            "postinstall": postinstall.encode(),
            "inventory_agent.py": agent_source,
            # Source for the .app bundle's icns, which the postinstall builds
            # with sips/iconutil. Shipped rather than fetched so a machine with
            # no route to the internet at imaging time still gets the icon.
            "assetly_icon.png": (REPO_ROOT / "assetly_icon.png").read_bytes(),
        },
        component_name="AssetlyAgent.pkg",
    )
    return Response(
        content=pkg_bytes,
        media_type="application/octet-stream",
        headers={"Content-Disposition": 'attachment; filename="AssetlyAgent_macOS.pkg"'},
    )


@router.post("/companies/{company_id}/download/linux")
async def download_linux(
    request: Request,
    company_id: uuid.UUID,
    csrf_token: str = Form(...),
    device_count: int = Form(...),
    token_days: int = Form(INSTALLER_TOKEN_DAYS),
    admin: AdminContext = Depends(require_full_admin),
):
    _check_csrf(request, csrf_token)
    pool = await get_pool()
    await _get_active_company_or_404(pool, company_id, admin)
    template_text = _load_installer_template("AssetlyAgent_Linux.sh")
    max_devices, expires_at = _installer_token_terms(device_count, token_days)
    token = await create_enrollment_token(
        pool, str(company_id), label=f"Linux installer ({device_count} devices)",
        expires_at=expires_at, max_devices=max_devices,
    )
    script_text = _render_installer_script(template_text, CHECKIN_API_URL_FOR_DOWNLOAD, token)
    return Response(
        content=script_text,
        media_type="text/x-shellscript",
        headers={"Content-Disposition": 'attachment; filename="AssetlyAgent_Linux.sh"'},
    )


@router.post("/companies/{company_id}/download/windows")
async def download_windows(
    request: Request,
    company_id: uuid.UUID,
    csrf_token: str = Form(...),
    device_count: int = Form(...),
    token_days: int = Form(INSTALLER_TOKEN_DAYS),
    admin: AdminContext = Depends(require_full_admin),
):
    """Serves one self-contained .exe instead of an exe plus a config file.

    A zip asked the person deploying it to keep two files together, which is
    exactly the thing that goes wrong when an installer is emailed around or
    copied to a share. The config is appended to the executable instead: a PE
    image declares its own length, so Windows ignores trailing bytes, and the
    agent reads them back out of its own file (see Get-CheckinConfig).
    """
    _check_csrf(request, csrf_token)
    # Checked before any DB work / token minting below -- same validate-before-
    # mutate ordering as _load_installer_template for macos/linux, so a
    # missing build artifact can't leave a token minted with nothing to
    # download.
    if not WINDOWS_EXE_PATH.exists():
        raise HTTPException(
            status_code=503,
            detail="Windows agent build not yet available. Contact support.",
        )
    exe_bytes = WINDOWS_EXE_PATH.read_bytes()
    pool = await get_pool()
    await _get_active_company_or_404(pool, company_id, admin)
    max_devices, expires_at = _installer_token_terms(device_count, token_days)
    token = await create_enrollment_token(
        pool, str(company_id), label=f"Windows installer ({device_count} devices)",
        expires_at=expires_at, max_devices=max_devices,
    )

    return Response(
        content=embed_windows_config(
            exe_bytes,
            {
                "checkin_api_url": CHECKIN_API_URL_FOR_DOWNLOAD,
                "enrollment_token": token,
            },
        ),
        media_type="application/vnd.microsoft.portable-executable",
        headers={"Content-Disposition": 'attachment; filename="AssetlyAgent_Windows.exe"'},
    )
