import uuid
from pathlib import Path

from fastapi import APIRouter, Depends, Form, HTTPException, Request
from fastapi.responses import RedirectResponse
from fastapi.templating import Jinja2Templates

from app.admin_auth import resolve_admin
from app.auth import generate_api_key, hash_api_key
from app.db import get_pool

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
