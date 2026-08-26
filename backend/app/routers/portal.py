"""Read-only tenant portal screens.

Kept separate from admin.py, which already covers company CRUD, API keys, field
configuration, and downloads. No POST routes here, so no CSRF surface is added.
"""
import uuid
from pathlib import Path

from fastapi import APIRouter, Depends, HTTPException, Request
from fastapi.templating import Jinja2Templates

from app.admin_auth import AdminContext
from app.db import get_pool
from app.devices import dashboard_stats, get_checkin_history, get_device, list_devices
from app.enrollment import list_device_credentials
from app.routers.admin import _all_companies, _get_company_or_404, _new_csrf_token, require_admin
from app.schedule import format_interval, resolve_schedule

router = APIRouter(prefix="/admin/companies")


def _csp_nonce_context(request):
    return {"csp_nonce": getattr(request.state, "csp_nonce", "")}


templates = Jinja2Templates(
    directory=str(Path(__file__).resolve().parent.parent / "templates"),
    context_processors=[_csp_nonce_context],
)


async def _shell(request: Request, company_id: uuid.UUID, admin: AdminContext):
    """Context every portal screen needs: the company itself plus the sidebar's
    company switcher."""
    pool = await get_pool()
    company = await _get_company_or_404(pool, company_id, admin)
    companies = await _all_companies(pool, admin)
    return pool, {
        "request": request,
        "company": company,
        "companies": companies,
        "csrf_token": _new_csrf_token(request),
    }


@router.get("/{company_id}/dashboard")
async def dashboard(
    request: Request, company_id: uuid.UUID, admin: AdminContext = Depends(require_admin)
):
    pool, context = await _shell(request, company_id, admin)
    context["stats"] = await dashboard_stats(pool, str(company_id))
    context["devices"] = await list_devices(pool, str(company_id))
    # The "Online" band is proportional to this company's interval (see
    # device_status.py), so the stat card's caption has to name that interval
    # rather than the 6 months that used to be hardcoded fleet-wide.
    schedule = await resolve_schedule(pool, str(company_id))
    context["checkin_interval_label"] = format_interval(
        schedule["checkin_interval_seconds"]
    )
    context["nav_active"] = "dashboard"
    return templates.TemplateResponse(request, "portal_dashboard.html", context)


@router.get("/{company_id}/computers")
async def computers(
    request: Request, company_id: uuid.UUID, admin: AdminContext = Depends(require_admin)
):
    pool, context = await _shell(request, company_id, admin)
    context["devices"] = await list_devices(pool, str(company_id))
    context["nav_active"] = "computers"
    return templates.TemplateResponse(request, "portal_computers.html", context)


@router.get("/{company_id}/computers/{serial_number}")
async def device_detail(
    request: Request,
    company_id: uuid.UUID,
    serial_number: str,
    admin: AdminContext = Depends(require_admin),
):
    pool, context = await _shell(request, company_id, admin)
    device = await get_device(pool, str(company_id), serial_number)
    if device is None:
        raise HTTPException(status_code=404, detail="Device not found")
    context["device"] = device
    context["history"] = await get_checkin_history(pool, str(company_id), serial_number)
    # No single-row lookup exists in enrollment.py (out of scope to add one for
    # this), so filter the company's credential list for this device. Fleet
    # size per company is small enough that this is fine on a page view.
    credentials = await list_device_credentials(pool, str(company_id))
    # device_credentials.serial_number is stored normalised (see
    # enroll_device in app/enrollment.py), while `serial_number` here comes
    # from the URL / devices table and keeps the machine's real casing --
    # normalise this side the same way before comparing, or an otherwise
    # active credential would look revoked/missing on this page.
    normalized_serial = serial_number.strip().casefold()
    context["credential"] = next(
        (c for c in credentials if c["serial_number"] == normalized_serial), None
    )
    context["nav_active"] = "computers"
    return templates.TemplateResponse(request, "portal_device.html", context)
