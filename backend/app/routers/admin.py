from pathlib import Path

from fastapi import APIRouter, Depends, Form, Request
from fastapi.responses import RedirectResponse
from fastapi.templating import Jinja2Templates

from app.admin_auth import resolve_admin
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
async def companies_placeholder(admin_id: str = Depends(require_admin)):
    return {"status": "placeholder — replaced in Task 6"}
