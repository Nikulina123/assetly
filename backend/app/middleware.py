"""ASGI (not BaseHTTPMiddleware) security-headers middleware.

Plain ASGI, not @app.middleware("http")/BaseHTTPMiddleware: main.py's
HTTPException handler stashes a BackgroundTasks instance on request.state so
background work isn't silently dropped when a dependency raises before
FastAPI's normal response path attaches one. BaseHTTPMiddleware is known to
interact badly with that pattern in some Starlette versions by wrapping the
response in a way that can drop `.background`. A raw ASGI middleware that
only inspects/patches outgoing `http.response.start` messages never touches
`response.background` at all, so it can't reintroduce that failure mode.
"""
import secrets

from app.config import SESSION_COOKIE_SECURE


def _build_csp(nonce: str) -> str:
    return (
        "default-src 'self'; "
        f"script-src 'self' 'nonce-{nonce}'; "
        "style-src 'self' 'unsafe-inline'; "
        "img-src 'self' data:; "
        "object-src 'none'; "
        "base-uri 'self'; "
        "frame-ancestors 'none'"
    )


class SecurityHeadersMiddleware:
    def __init__(self, app):
        self.app = app

    async def __call__(self, scope, receive, send):
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return

        nonce = secrets.token_urlsafe(16)
        scope.setdefault("state", {})
        scope["state"]["csp_nonce"] = nonce

        async def send_wrapper(message):
            if message["type"] == "http.response.start":
                headers = list(message.get("headers", []))
                headers.append(
                    (b"content-security-policy", _build_csp(nonce).encode())
                )
                headers.append((b"x-content-type-options", b"nosniff"))
                headers.append((b"x-frame-options", b"DENY"))
                headers.append(
                    (b"referrer-policy", b"strict-origin-when-cross-origin")
                )
                if SESSION_COOKIE_SECURE:
                    headers.append(
                        (
                            b"strict-transport-security",
                            b"max-age=31536000; includeSubDomains",
                        )
                    )
                message = {**message, "headers": headers}
            await send(message)

        await self.app(scope, receive, send_wrapper)
