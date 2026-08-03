import uuid
from pathlib import Path

from fastapi import APIRouter, Depends, Form, HTTPException, Request
from fastapi.responses import RedirectResponse
from fastapi.templating import Jinja2Templates

from app.admin_auth import resolve_admin
from app.auth import generate_api_key, hash_api_key
from app.db import get_pool
from app.field_config import (
    add_custom_field,
    remove_custom_field,
    resolve_field_settings_for_admin,
    set_hardware_field_enabled,
    set_project_config,
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
    csrf_token: str = Form(...),
    admin_id: str = Depends(require_admin),
):
    _check_csrf(request, csrf_token)

    api_key = generate_api_key()
    key_hash = hash_api_key(api_key)
    pool = await get_pool()
    async with pool.acquire() as conn:
        await conn.execute(
            "INSERT INTO companies (name, api_key_hash, api_key_prefix) VALUES ($1, $2, $3)",
            name, key_hash, api_key[:8],
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
            "SELECT id, name, api_key_prefix, revoked_at FROM companies WHERE id = $1",
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
            RETURNING id, name, api_key_prefix, revoked_at
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
            RETURNING id, name, api_key_prefix, revoked_at
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


@router.post("/companies/{company_id}/fields/hardware")
async def update_hardware_fields(
    request: Request,
    company_id: uuid.UUID,
    csrf_token: str = Form(...),
    cpu: str | None = Form(None),
    ram: str | None = Form(None),
    storage: str | None = Form(None),
    ip_address: str | None = Form(None),
    project_enabled: str | None = Form(None),
    project_required: str | None = Form(None),
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
    await set_project_config(
        pool, company_id_str,
        enabled=project_enabled is not None,
        required=project_required is not None,
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
