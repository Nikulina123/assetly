from pathlib import Path

from fastapi import FastAPI, HTTPException
from fastapi.exception_handlers import http_exception_handler
from fastapi.responses import RedirectResponse
from fastapi.staticfiles import StaticFiles
from starlette.middleware.sessions import SessionMiddleware

from app.config import SESSION_COOKIE_SECURE, SESSION_MAX_AGE_SECONDS, SESSION_SECRET_KEY
from app.db import get_pool
from app.middleware import SecurityHeadersMiddleware
from app.routers.admin import NotAuthenticated, PendingLoginRequired
from app.routers.admin import router as admin_router
from app.routers.agent_update import router as agent_update_router
from app.routers.checkin import router as checkin_router
from app.routers.enroll import router as enroll_router
from app.routers.portal import router as portal_router

app = FastAPI(title="Assetly Inventory Check-in API")
app.add_middleware(
    SessionMiddleware,
    secret_key=SESSION_SECRET_KEY,
    https_only=SESSION_COOKIE_SECURE,
    same_site="lax",
    max_age=SESSION_MAX_AGE_SECONDS,
)
app.add_middleware(SecurityHeadersMiddleware)
app.include_router(checkin_router)
app.include_router(enroll_router)
app.include_router(admin_router)
app.include_router(portal_router)
app.include_router(agent_update_router)
app.mount(
    "/static",
    StaticFiles(directory=str(Path(__file__).resolve().parent / "static")),
    name="static",
)


@app.get("/", include_in_schema=False)
@app.get("/admin", include_in_schema=False)
async def root():
    """Send the bare domain somewhere useful.

    Every route in this app lives under a prefix -- /admin/login,
    /admin/companies, /checkin -- so hitting https://<host>/ produced
    FastAPI's own {"detail":"Not Found"}, which reads as a broken
    deployment rather than "you wanted the portal". Same for /admin, which
    is a router prefix with no route of its own.

    Redirects to the companies list rather than to the login page: an admin
    with a live session lands where they meant to go, and one without is
    bounced to /admin/login by the NotAuthenticated handler anyway.
    """
    return RedirectResponse("/admin/companies", status_code=307)


@app.get("/healthz", include_in_schema=False)
async def healthz():
    """Liveness plus database reachability, for uptime monitoring and for
    confirming a deploy is actually serving rather than merely built.

    Deliberately queries no application table: every one of them is either
    RLS-protected (and would error without app.company_id set) or holds tenant
    data that has no business being reachable from an unauthenticated endpoint.
    SELECT 1 still proves the credentials, network path, and pooler all work.
    """
    pool = await get_pool()
    async with pool.acquire() as conn:
        await conn.fetchval("SELECT 1")
    return {"status": "ok"}


@app.exception_handler(NotAuthenticated)
async def not_authenticated_handler(request, exc):
    return RedirectResponse("/admin/login", status_code=303)


@app.exception_handler(PendingLoginRequired)
async def pending_login_required_handler(request, exc):
    return RedirectResponse("/admin/login", status_code=303)


@app.exception_handler(HTTPException)
async def http_exception_handler_with_background_tasks(request, exc):
    # FastAPI only auto-attaches a BackgroundTasks instance to the response
    # on the normal successful-return path; a dependency (e.g.
    # app.routers.checkin.get_current_company_id) that raises HTTPException
    # bypasses that entirely, so any background tasks it queued (e.g.
    # record_auth_failure and maybe_send_auth_failure_digest) would otherwise
    # be silently dropped. That
    # dependency stashes its BackgroundTasks instance on request.state
    # specifically so this handler can still run it.
    response = await http_exception_handler(request, exc)
    background_tasks = getattr(request.state, "background_tasks", None)
    if background_tasks is not None:
        response.background = background_tasks
    return response
