"""
PREVENT-X Cross-Site Request Forgery (CSRF) Protection
Implements double-submit cookie / custom header verification for browser sessions.
"""

import hmac
import secrets
from fastapi import Request, HTTPException, status
from backend.app.core.config import settings

CSRF_COOKIE_NAME = "preventx_csrf_token"
CSRF_HEADER_NAME = "x-csrf-token"
SAFE_METHODS = {"GET", "HEAD", "OPTIONS", "TRACE"}


def generate_csrf_token() -> str:
    """Generates a cryptographically strong CSRF token."""
    return secrets.token_hex(32)


def verify_csrf_token(request: Request) -> None:
    """
    Verifies CSRF token for state-changing HTTP requests.
    Exempts requests utilizing Bearer authentication in the Authorization header.
    """
    if not settings.CSRF_PROTECTION_ENABLED:
        return

    if request.method in SAFE_METHODS:
        return

    auth_header = request.headers.get("Authorization")
    if auth_header and auth_header.startswith("Bearer "):
        # API client using explicit Bearer token is immune to browser ambient credential CSRF
        return

    # If cookie authentication is present, check CSRF
    session_cookie = request.cookies.get("preventx_session")
    if not session_cookie:
        return

    csrf_cookie = request.cookies.get(CSRF_COOKIE_NAME)
    csrf_header = request.headers.get(CSRF_HEADER_NAME)

    if not csrf_cookie or not csrf_header:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail={"code": "CSRF_MISSING", "message": "CSRF token missing from request"},
        )

    if not hmac.compare_digest(csrf_cookie, csrf_header):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail={"code": "CSRF_INVALID", "message": "Invalid CSRF token"},
        )

