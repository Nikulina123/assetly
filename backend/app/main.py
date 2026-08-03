from fastapi import FastAPI
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
