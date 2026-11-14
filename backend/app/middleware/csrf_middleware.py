"""
PREVENT-X Cross-Site Request Forgery (CSRF) Middleware
Enforces CSRF protection on state-changing requests when cookie authentication is active.
"""

from starlette.middleware.base import BaseHTTPMiddleware, RequestResponseEndpoint
from starlette.requests import Request
from starlette.responses import JSONResponse, Response
from backend.app.core.config import settings
from backend.app.security.csrf import (
    CSRF_COOKIE_NAME,
    CSRF_HEADER_NAME,
    SAFE_METHODS,
)

EXEMPT_PATHS = {
    "/api/v1/auth/login",
    "/api/v1/auth/bootstrap",
}


class CSRFMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next: RequestResponseEndpoint) -> Response:
        if not settings.CSRF_PROTECTION_ENABLED:
            return await call_next(request)

        if request.method in SAFE_METHODS or request.url.path in EXEMPT_PATHS:
            return await call_next(request)

        # If client uses explicit Bearer token in Authorization header, immune to cookie CSRF
        auth_header = request.headers.get("Authorization")
        if auth_header and auth_header.startswith("Bearer "):
            return await call_next(request)

        # Check if browser cookie session is being used
        session_cookie = request.cookies.get("preventx_session")
        if not session_cookie:
            return await call_next(request)

        csrf_cookie = request.cookies.get(CSRF_COOKIE_NAME)
        csrf_header = request.headers.get(CSRF_HEADER_NAME)

        if not csrf_cookie or not csrf_header:
            return JSONResponse(
                status_code=403,
                content={"detail": {"code": "CSRF_MISSING", "message": "CSRF token missing from request"}},
            )

        import hmac
        if not hmac.compare_digest(csrf_cookie, csrf_header):
            return JSONResponse(
                status_code=403,
                content={"detail": {"code": "CSRF_INVALID", "message": "Invalid CSRF token"}},
            )

        return await call_next(request)
