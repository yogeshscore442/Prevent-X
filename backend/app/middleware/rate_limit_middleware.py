"""
PREVENT-X Global Rate Limiting Middleware
"""

from starlette.middleware.base import BaseHTTPMiddleware, RequestResponseEndpoint
from starlette.requests import Request
from starlette.responses import JSONResponse, Response
from backend.app.core.config import settings
from backend.app.security.rate_limiter import rate_limiter


class GlobalRateLimitMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next: RequestResponseEndpoint) -> Response:
        # Exempt health & readiness checks from aggressive rate limiting
        if request.url.path in ["/api/v1/health", "/api/v1/ready"]:
            return await call_next(request)

        client_ip = request.client.host if request.client else "127.0.0.1"
        limiter_key = f"global:{client_ip}"

        allowed, retry_after = rate_limiter.check_rate_limit(
            key=limiter_key,
            max_requests=settings.RATE_LIMIT_PER_MINUTE,
            window_seconds=60,
        )

        if not allowed:
            return JSONResponse(
                status_code=429,
                content={
                    "detail": {
                        "code": "RATE_LIMIT_EXCEEDED",
                        "message": f"Too many requests. Please retry in {retry_after} seconds.",
                    }
                },
                headers={"Retry-After": str(retry_after)},
            )

        return await call_next(request)
