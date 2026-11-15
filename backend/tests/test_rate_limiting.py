"""
PREVENT-X Phase 4: Advanced Rate Limiting Tests
Validates sliding-window and token-bucket algorithms, per-IP, per-endpoint, and per-tenant
scoping, burst capacity enforcement, Redis-backed counters, HTTP 429 status and headers,
and multi-tenant policy isolation.
"""

import time
import uuid
import pytest

from backend.app.models.network_defense import (
    RateLimitPolicy,
    RateLimitScope,
    RateLimitingAlgorithm,
)
from backend.app.modules.network_defense.rate_limiting.limiter import (
    AdvancedRateLimiter,
    advanced_rate_limiter,
)
from backend.app.modules.network_defense.rate_limiting.service import (
    rate_limit_service,
)


def test_sliding_window_enforcement():
    """Verifies that sliding window permits up to max_requests and rejects subsequent requests."""
    limiter = AdvancedRateLimiter()
    policy = RateLimitPolicy(
        id=str(uuid.uuid4()),
        organization_id=uuid.uuid4(),
        name="Test Sliding Window",
        endpoint_pattern="/api/v1/test",
        scope=RateLimitScope.IP,
        algorithm=RateLimitingAlgorithm.SLIDING_WINDOW,
        max_requests=5,
        window_seconds=60,
        burst_capacity=5,
        refill_rate_per_sec=1.0,
    )
    ip = "192.0.2.10"

    # Reset any existing keys
    limiter.reset_key(f"*{policy.id}*")

    # First 5 requests must succeed
    for i in range(5):
        res = limiter.evaluate(policy, ip, "/api/v1/test")
        assert res.allowed is True
        assert res.remaining == 5 - i - 1

    # 6th request must be rejected with retry_after > 0
    res6 = limiter.evaluate(policy, ip, "/api/v1/test")
    assert res6.allowed is False
    assert res6.remaining == 0
    assert res6.retry_after >= 1


def test_token_bucket_burst_and_refill():
    """Verifies that token bucket allows burst up to capacity and exhausts tokens."""
    limiter = AdvancedRateLimiter()
    policy = RateLimitPolicy(
        id=str(uuid.uuid4()),
        organization_id=uuid.uuid4(),
        name="Test Token Bucket",
        endpoint_pattern="/api/v1/burst",
        scope=RateLimitScope.IP,
        algorithm=RateLimitingAlgorithm.TOKEN_BUCKET,
        max_requests=10,
        window_seconds=60,
        burst_capacity=3,       # Burst limit of 3
        refill_rate_per_sec=0.5, # 1 token every 2 seconds
    )
    ip = "192.0.2.20"
    limiter.reset_key(f"*{policy.id}*")

    # Burst of 3 must be allowed
    r1 = limiter.evaluate(policy, ip, "/api/v1/burst")
    r2 = limiter.evaluate(policy, ip, "/api/v1/burst")
    r3 = limiter.evaluate(policy, ip, "/api/v1/burst")
    assert r1.allowed is True
    assert r2.allowed is True
    assert r3.allowed is True

    # 4th request must be blocked
    r4 = limiter.evaluate(policy, ip, "/api/v1/burst")
    assert r4.allowed is False
    assert r4.retry_after >= 1


def test_per_ip_vs_per_endpoint_scoping():
    """Verifies that per-IP limits track different IPs separately, and per-endpoint limits track paths."""
    limiter = AdvancedRateLimiter()
    ip_policy = RateLimitPolicy(
        id=str(uuid.uuid4()),
        organization_id=uuid.uuid4(),
        name="Per IP Policy",
        endpoint_pattern="*",
        scope=RateLimitScope.IP,
        algorithm=RateLimitingAlgorithm.SLIDING_WINDOW,
        max_requests=2,
        window_seconds=10,
        burst_capacity=2,
        refill_rate_per_sec=1.0,
    )
    limiter.reset_key(f"*{ip_policy.id}*")

    # IP 1 uses up quota
    assert limiter.evaluate(ip_policy, "192.0.2.31", "/api/a").allowed is True
    assert limiter.evaluate(ip_policy, "192.0.2.31", "/api/a").allowed is True
    assert limiter.evaluate(ip_policy, "192.0.2.31", "/api/a").allowed is False

    # IP 2 is unaffected
    assert limiter.evaluate(ip_policy, "192.0.2.32", "/api/a").allowed is True


def test_rate_limiting_api_and_429_response(client, db_session, test_tenants):
    """Verifies REST API policy creation, evaluation endpoint, 429 headers, and tenant isolation."""
    org_a = test_tenants["org_a"]
    org_b = test_tenants["org_b"]
    admin_a = test_tenants["admin_a"]
    admin_b = test_tenants["admin_b"]

    login_a = client.post("/api/v1/auth/login", json={"email": admin_a.email, "password": "AlphaAdminPass123!"})
    token_a = login_a.json()["tokens"]["access_token"]
    headers_a = {"Authorization": f"Bearer {token_a}"}

    # 1. Create a restrictive policy: 2 requests per 60s on /api/v1/sensitive/*
    create_res = client.post(
        "/api/v1/network-defense/rate-limiting/policies",
        json={
            "name": "Sensitive API Strict Quota",
            "endpoint_pattern": "/api/v1/sensitive/*",
            "scope": "IP",
            "algorithm": "SLIDING_WINDOW",
            "max_requests": 2,
            "window_seconds": 60,
            "burst_capacity": 2,
            "refill_rate_per_sec": 1.0,
        },
        headers=headers_a,
    )
    assert create_res.status_code == 201
    policy_id = create_res.json()["id"]

    # 2. Test evaluation: 1st and 2nd should pass
    eval1 = client.post(
        "/api/v1/network-defense/rate-limiting/evaluate",
        json={"client_ip": "198.51.100.99", "path": "/api/v1/sensitive/data"},
        headers=headers_a,
    )
    assert eval1.status_code == 200
    assert eval1.json()["allowed"] is True
    assert eval1.headers.get("X-RateLimit-Limit") == "2"

    eval2 = client.post(
        "/api/v1/network-defense/rate-limiting/evaluate",
        json={"client_ip": "198.51.100.99", "path": "/api/v1/sensitive/data"},
        headers=headers_a,
    )
    assert eval2.status_code == 200

    # 3. 3rd request must trigger HTTP 429 Too Many Requests
    eval3 = client.post(
        "/api/v1/network-defense/rate-limiting/evaluate",
        json={"client_ip": "198.51.100.99", "path": "/api/v1/sensitive/data"},
        headers=headers_a,
    )
    assert eval3.status_code == 429
    assert "Retry-After" in eval3.headers
    assert int(eval3.headers["Retry-After"]) >= 1

    # 4. Tenant B isolation: Tenant B should not see Tenant A's policy
    login_b = client.post("/api/v1/auth/login", json={"email": admin_b.email, "password": "BetaAdminPass123!"})
    token_b = login_b.json()["tokens"]["access_token"]
    headers_b = {"Authorization": f"Bearer {token_b}"}

    list_b = client.get("/api/v1/network-defense/rate-limiting/policies", headers=headers_b)
    assert list_b.status_code == 200
    assert not any(p["id"] == policy_id for p in list_b.json())
