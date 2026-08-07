import io
import json
import re
import uuid
import zipfile
from pathlib import Path

from fastapi import APIRouter, Depends, Form, HTTPException, Request
from fastapi.responses import RedirectResponse, Response
from fastapi.templating import Jinja2Templates

from app.admin_auth import resolve_admin
from app.auth import generate_api_key, hash_api_key
from app.config import CHECKIN_API_URL_FOR_DOWNLOAD, REPO_ROOT, WINDOWS_EXE_PATH
from app.db import get_pool
from app.enrollment import create_enrollment_token
from app.field_config import (
    add_custom_field,
    remove_custom_field,
    resolve_field_settings_for_admin,
    set_department_config,
    set_hardware_field_enabled,
)

router = APIRouter(prefix="/admin")
templates = Jinja2Templates(directory=str(Path(__file__).resolve().parent.parent / "templates"))


class NotAuthenticated(Exception):
    pass


async def require_admin(request: Request) -> str:
    admin_id = request.session.get("admin_id")
    if not admin_id:
        raise NotAuthenticated()
    return admin_id


def _new_csrf_token(request: Request) -> str:
    if "csrf_token" not in request.session:
        request.session["csrf_token"] = uuid.uuid4().hex
    return request.session["csrf_token"]


def _check_csrf(request: Request, csrf_token: str) -> None:
    expected = request.session.get("csrf_token")
    if not expected or csrf_token != expected:
        raise HTTPException(status_code=403, detail="Invalid CSRF token")


async def _all_companies(pool):
    async with pool.acquire() as conn:
        return await conn.fetch("SELECT id, name, revoked_at FROM companies ORDER BY name")


@router.get("/login")
async def login_form(request: Request):
    return templates.TemplateResponse("login.html", {"request": request})


@router.post("/login")
async def login_submit(request: Request, email: str = Form(...), password: str = Form(...)):
    pool = await get_pool()
    admin_id = await resolve_admin(pool, email, password)
    if admin_id is None:
        return templates.TemplateResponse(
            "login.html", {"request": request, "error": "Invalid email or password"}
        )
    request.session["admin_id"] = admin_id
    return RedirectResponse("/admin/companies", status_code=303)


@router.post("/logout")
async def logout(request: Request):
    request.session.clear()
    return RedirectResponse("/admin/login", status_code=303)


@router.get("/companies")
async def companies_list(request: Request, admin_id: str = Depends(require_admin)):
    pool = await get_pool()
    companies = await _all_companies(pool)
    return templates.TemplateResponse(
        "companies_list.html",
        {"request": request, "companies": companies, "csrf_token": _new_csrf_token(request)},
    )


@router.post("/companies")
async def companies_create(
    request: Request,
    name: str = Form(...),
    notification_email: str = Form(...),
    csrf_token: str = Form(...),
    admin_id: str = Depends(require_admin),
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

    companies = await _all_companies(pool)
    return templates.TemplateResponse(
        "companies_list.html",
        {
            "request": request,
            "companies": companies,
            "csrf_token": _new_csrf_token(request),
            "new_api_key": api_key,
        },
    )


async def _get_company_or_404(pool, company_id: uuid.UUID):
    async with pool.acquire() as conn:
        company = await conn.fetchrow(
            "SELECT id, name, api_key_prefix, revoked_at, notification_email FROM companies WHERE id = $1",
            company_id,
        )
    if company is None:
        raise HTTPException(status_code=404, detail="Company not found")
    return company


@router.get("/companies/{company_id}")
async def company_detail(
    request: Request, company_id: uuid.UUID, admin_id: str = Depends(require_admin)
):
    pool = await get_pool()
    company = await _get_company_or_404(pool, company_id)
    field_settings = await resolve_field_settings_for_admin(pool, str(company_id))
    companies = await _all_companies(pool)
    return templates.TemplateResponse(
        "company_detail.html",
        {
            "request": request,
            "companies": companies,
            "company": company,
            "csrf_token": _new_csrf_token(request),
            "field_settings": field_settings,
            "nav_active": "settings",
        },
    )


@router.post("/companies/{company_id}/rotate-key")
async def rotate_key(
    request: Request,
    company_id: uuid.UUID,
    csrf_token: str = Form(...),
    admin_id: str = Depends(require_admin),
):
    _check_csrf(request, csrf_token)
    pool = await get_pool()

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
    companies = await _all_companies(pool)
    return templates.TemplateResponse(
        "company_detail.html",
        {
            "request": request,
            "companies": companies,
            "company": company,
            "csrf_token": _new_csrf_token(request),
            "new_api_key": api_key,
            "field_settings": field_settings,
        },
    )


@router.post("/companies/{company_id}/revoke")
async def revoke_company(
    request: Request,
    company_id: uuid.UUID,
    csrf_token: str = Form(...),
    admin_id: str = Depends(require_admin),
):
    _check_csrf(request, csrf_token)
    pool = await get_pool()

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
        company = await _get_company_or_404(pool, company_id)

    field_settings = await resolve_field_settings_for_admin(pool, str(company_id))
    companies = await _all_companies(pool)
    return templates.TemplateResponse(
        "company_detail.html",
        {
            "request": request,
            "companies": companies,
            "company": company,
            "csrf_token": _new_csrf_token(request),
            "field_settings": field_settings,
        },
    )


@router.post("/companies/{company_id}/notification-email")
async def update_notification_email(
    request: Request,
    company_id: uuid.UUID,
    notification_email: str = Form(...),
    csrf_token: str = Form(...),
    admin_id: str = Depends(require_admin),
):
    _check_csrf(request, csrf_token)
    pool = await get_pool()
    await _get_company_or_404(pool, company_id)
    async with pool.acquire() as conn:
        await conn.execute(
            "UPDATE companies SET notification_email = $1 WHERE id = $2",
            notification_email, company_id,
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
    admin_id: str = Depends(require_admin),
):
    _check_csrf(request, csrf_token)
    pool = await get_pool()
    await _get_company_or_404(pool, company_id)

    company_id_str = str(company_id)
    for field_key, submitted_value in [
        ("cpu", cpu), ("ram", ram), ("storage", storage), ("ip_address", ip_address),
    ]:
        await set_hardware_field_enabled(pool, company_id_str, field_key, submitted_value is not None)
    await set_department_config(
        pool, company_id_str,
        enabled=department_enabled is not None,
        required=department_required is not None,
    )

    return RedirectResponse(f"/admin/companies/{company_id}", status_code=303)


@router.post("/companies/{company_id}/fields/custom")
async def add_custom_field_route(
    request: Request,
    company_id: uuid.UUID,
    label: str = Form(...),
    required: str | None = Form(None),
    csrf_token: str = Form(...),
    admin_id: str = Depends(require_admin),
):
    _check_csrf(request, csrf_token)
    pool = await get_pool()
    company = await _get_company_or_404(pool, company_id)
    try:
        await add_custom_field(pool, str(company_id), label, required is not None)
    except ValueError as e:
        field_settings = await resolve_field_settings_for_admin(pool, str(company_id))
        companies = await _all_companies(pool)
        return templates.TemplateResponse(
            "company_detail.html",
            {
                "request": request,
                "companies": companies,
                "company": company,
                "csrf_token": _new_csrf_token(request),
                "field_settings": field_settings,
                "field_error": str(e),
            },
        )
    return RedirectResponse(f"/admin/companies/{company_id}", status_code=303)


@router.post("/companies/{company_id}/fields/custom/{field_key}/remove")
async def remove_custom_field_route(
    request: Request,
    company_id: uuid.UUID,
    field_key: str,
    csrf_token: str = Form(...),
    admin_id: str = Depends(require_admin),
):
    _check_csrf(request, csrf_token)
    pool = await get_pool()
    await _get_company_or_404(pool, company_id)
    await remove_custom_field(pool, str(company_id), field_key)
    return RedirectResponse(f"/admin/companies/{company_id}", status_code=303)


async def _get_active_company_or_404(pool, company_id: uuid.UUID):
    """Like _get_company_or_404, but also blocks revoked companies -- a
    downloadable installer whose key immediately 401s is worse than no
    download button."""
    company = await _get_company_or_404(pool, company_id)
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


@router.post("/companies/{company_id}/download/macos")
async def download_macos(
    request: Request,
    company_id: uuid.UUID,
    csrf_token: str = Form(...),
    admin_id: str = Depends(require_admin),
):
    _check_csrf(request, csrf_token)
    pool = await get_pool()
    await _get_active_company_or_404(pool, company_id)
    template_text = _load_installer_template("AssetlyAgent_macOS.sh")
    token = await create_enrollment_token(pool, str(company_id), label="macOS installer")
    script_text = _render_installer_script(template_text, CHECKIN_API_URL_FOR_DOWNLOAD, token)
    return Response(
        content=script_text,
        media_type="text/x-shellscript",
        headers={"Content-Disposition": 'attachment; filename="AssetlyAgent_macOS.sh"'},
    )


@router.post("/companies/{company_id}/download/linux")
async def download_linux(
    request: Request,
    company_id: uuid.UUID,
    csrf_token: str = Form(...),
    admin_id: str = Depends(require_admin),
):
    _check_csrf(request, csrf_token)
    pool = await get_pool()
    await _get_active_company_or_404(pool, company_id)
    template_text = _load_installer_template("AssetlyAgent_Linux.sh")
    token = await create_enrollment_token(pool, str(company_id), label="Linux installer")
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
    admin_id: str = Depends(require_admin),
):
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
    pool = await get_pool()
    await _get_active_company_or_404(pool, company_id)
    token = await create_enrollment_token(pool, str(company_id), label="Windows installer")

    config_bytes = json.dumps({
        "checkin_api_url": CHECKIN_API_URL_FOR_DOWNLOAD,
        "enrollment_token": token,
    }).encode()

    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.write(WINDOWS_EXE_PATH, arcname="AssetlyAgent_Windows.exe")
        zf.writestr("config.json", config_bytes)

    return Response(
        content=buffer.getvalue(),
        media_type="application/zip",
        headers={"Content-Disposition": 'attachment; filename="AssetlyAgent_Windows.zip"'},
    )
