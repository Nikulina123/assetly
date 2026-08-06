"""Read-only tenant portal screens.

Kept separate from admin.py, which already covers company CRUD, API keys, field
configuration, and downloads. No POST routes here, so no CSRF surface is added.
"""
import uuid
from pathlib import Path

from fastapi import APIRouter, Depends, HTTPException, Request
from fastapi.templating import Jinja2Templates

from app.db import get_pool
from app.devices import dashboard_stats, get_checkin_history, get_device, list_devices
from app.routers.admin import _all_companies, _get_company_or_404, _new_csrf_token, require_admin

router = APIRouter(prefix="/admin/companies")
templates = Jinja2Templates(
    directory=str(Path(__file__).resolve().parent.parent / "templates")
)


async def _shell(request: Request, company_id: uuid.UUID):
    """Context every portal screen needs: the company itself plus the sidebar's
    company switcher."""
    pool = await get_pool()
    company = await _get_company_or_404(pool, company_id)
    companies = await _all_companies(pool)
    return pool, {
        "request": request,
        "company": company,
        "companies": companies,
        "csrf_token": _new_csrf_token(request),
    }


@router.get("/{company_id}/dashboard")
async def dashboard(
    request: Request, company_id: uuid.UUID, admin_id: str = Depends(require_admin)
):
    pool, context = await _shell(request, company_id)
    context["stats"] = await dashboard_stats(pool, str(company_id))
    context["nav_active"] = "dashboard"
    return templates.TemplateResponse("portal_dashboard.html", context)


@router.get("/{company_id}/computers")
async def computers(
    request: Request, company_id: uuid.UUID, admin_id: str = Depends(require_admin)
):
    pool, context = await _shell(request, company_id)
    context["devices"] = await list_devices(pool, str(company_id))
    context["nav_active"] = "computers"
    return templates.TemplateResponse("portal_computers.html", context)


@router.get("/{company_id}/computers/{serial_number}")
async def device_detail(
    request: Request,
    company_id: uuid.UUID,
    serial_number: str,
    admin_id: str = Depends(require_admin),
):
    pool, context = await _shell(request, company_id)
    device = await get_device(pool, str(company_id), serial_number)
    if device is None:
        raise HTTPException(status_code=404, detail="Device not found")
    context["device"] = device
    context["history"] = await get_checkin_history(pool, str(company_id), serial_number)
    context["nav_active"] = "computers"
    return templates.TemplateResponse("portal_device.html", context)
