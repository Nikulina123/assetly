from fastapi import FastAPI, HTTPException
from fastapi.exception_handlers import http_exception_handler
from fastapi.responses import RedirectResponse
from starlette.middleware.sessions import SessionMiddleware

from app.config import SESSION_COOKIE_SECURE, SESSION_SECRET_KEY
from app.routers.admin import NotAuthenticated
from app.routers.admin import router as admin_router
from app.routers.checkin import router as checkin_router

app = FastAPI(title="Webiz Inventory Check-in API")
app.add_middleware(
    SessionMiddleware,
    secret_key=SESSION_SECRET_KEY,
    https_only=SESSION_COOKIE_SECURE,
    same_site="lax",
)
app.include_router(checkin_router)
app.include_router(admin_router)


@app.exception_handler(NotAuthenticated)
async def not_authenticated_handler(request, exc):
    return RedirectResponse("/admin/login", status_code=303)


@app.exception_handler(HTTPException)
async def http_exception_handler_with_background_tasks(request, exc):
    # FastAPI only auto-attaches a BackgroundTasks instance to the response
    # on the normal successful-return path; a dependency (e.g.
    # app.routers.checkin.get_current_company_id) that raises HTTPException
    # bypasses that entirely, so any background tasks it queued (e.g.
    # notify_auth_failure) would otherwise be silently dropped. That
    # dependency stashes its BackgroundTasks instance on request.state
    # specifically so this handler can still run it.
    response = await http_exception_handler(request, exc)
    background_tasks = getattr(request.state, "background_tasks", None)
    if background_tasks is not None:
        response.background = background_tasks
    return response
