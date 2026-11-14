"""
PREVENT-X Application Security Controls Tests
"""

from backend.app.core.config import settings
from backend.app.security.rate_limiter import rate_limiter


def test_security_headers_present(client):
    resp = client.get("/api/v1/health")
    assert resp.status_code == 200

    headers = resp.headers
    assert headers.get("X-Content-Type-Options") == "nosniff"
    assert headers.get("X-Frame-Options") == "DENY"
    assert headers.get("X-XSS-Protection") == "1; mode=block"
    assert headers.get("Referrer-Policy") == "strict-origin-when-cross-origin"
    assert "Content-Security-Policy" in headers
    assert "default-src 'self'" in headers["Content-Security-Policy"]


def test_rate_limiter_mechanism():
    test_key = "test:unit:rate_limit"
    rate_limiter.reset(test_key)

    # Allow up to 3 requests
    allowed1, _ = rate_limiter.check_rate_limit(test_key, max_requests=3, window_seconds=10)
    allowed2, _ = rate_limiter.check_rate_limit(test_key, max_requests=3, window_seconds=10)
    allowed3, _ = rate_limiter.check_rate_limit(test_key, max_requests=3, window_seconds=10)
    allowed4, retry_after = rate_limiter.check_rate_limit(test_key, max_requests=3, window_seconds=10)

    assert allowed1 is True
    assert allowed2 is True
    assert allowed3 is True
    assert allowed4 is False
    assert retry_after > 0

    rate_limiter.reset(test_key)


def test_csrf_cookie_authentication_enforcement(client, test_tenants):
    # Authenticate via login
    login_resp = client.post(
        "/api/v1/auth/login",
        json={"email": "admin@alphacorp.in", "password": "AlphaAdminPass123!"},
    )
    assert login_resp.status_code == 200

    # Extract session cookie and csrf cookie
    session_cookie = login_resp.cookies.get("preventx_session")
    csrf_cookie = login_resp.cookies.get("preventx_csrf_token")
    assert session_cookie is not None
    assert csrf_cookie is not None

    # State-changing request using ONLY session cookie without X-CSRF-Token header -> Must be rejected (403)
    client.cookies.set("preventx_session", session_cookie)
    client.cookies.set("preventx_csrf_token", csrf_cookie)

    resp_no_csrf_hdr = client.post(
        "/api/v1/assets",
        json={
            "name": "CSRF Attack Target",
            "asset_type": "DOMAIN",
            "target": "csrf.alphacorp.in",
            "environment": "PRODUCTION",
            "criticality": "LOW",
            "is_in_scope": True,
        },
    )
    assert resp_no_csrf_hdr.status_code == 403
    assert resp_no_csrf_hdr.json()["detail"]["code"] == "CSRF_MISSING"

    # Now provide the matching X-CSRF-Token header -> Must succeed
    resp_with_csrf = client.post(
        "/api/v1/assets",
        json={
            "name": "CSRF Valid Target",
            "asset_type": "DOMAIN",
            "target": "csrf.alphacorp.in",
            "environment": "PRODUCTION",
            "criticality": "LOW",
            "is_in_scope": True,
        },
        headers={"X-CSRF-Token": csrf_cookie},
    )
    assert resp_with_csrf.status_code == 201

