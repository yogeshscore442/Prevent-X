"""
Tests for PREVENT-X GeoIP Policy Engine (Phase 9)
Validates country-based access policies, CIDR exceptions, offline geolocation lookup,
advisory-only risk modifiers, and REST API tenant isolation.
"""

import uuid
import pytest
from fastapi.testclient import TestClient

from backend.app.models.network_defense import GeoIPPolicyAction
from backend.app.modules.network_defense.geoip.service import (
    GeoIPService,
    geoip_service,
)
from backend.app.schemas.network_defense import GeoIPPolicyCreate


def test_offline_ip_geolocation_resolution():
    """Verifies that IP addresses resolve accurately without external network dependencies."""
    svc = GeoIPService()

    # Public IPs
    in_code, in_name = svc.resolve_ip_location("103.21.244.1")
    assert in_code == "IN"
    assert in_name == "India"

    us_code, us_name = svc.resolve_ip_location("8.8.8.8")
    assert us_code == "US"
    assert us_name == "United States"

    kp_code, kp_name = svc.resolve_ip_location("175.45.176.10")
    assert kp_code == "KP"
    assert kp_name == "North Korea"

    # Private & Loopback IPs
    priv_code, priv_name = svc.resolve_ip_location("192.168.1.1")
    assert priv_code == "ZZ"
    assert "Private" in priv_name

    loopback_code, loopback_name = svc.resolve_ip_location("127.0.0.1")
    assert loopback_code == "ZZ"


def test_policy_evaluation_and_cidr_exceptions(db_session, test_tenants):
    """Verifies that DENY policies flag country traffic unless explicit CIDR exceptions match."""
    org_a = test_tenants["org_a"]

    # 1. Create a DENY policy for North Korea (KP) with an exception for partner IP
    policy_data = GeoIPPolicyCreate(
        country_code="KP",
        country_name="North Korea",
        action=GeoIPPolicyAction.DENY,
        exception_cidrs="175.45.176.50/32,175.45.176.128/28",
        risk_score_modifier=50.0,
    )
    policy = geoip_service.create_policy(db_session, org_a.id, policy_data)
    assert policy.id is not None
    assert policy.country_code == "KP"

    # 2. Evaluate normal IP from North Korea -> must be denied
    eval_denied = geoip_service.evaluate_ip(db_session, org_a.id, "175.45.176.10")
    assert eval_denied.is_denied is True
    assert eval_denied.country_code == "KP"
    assert eval_denied.risk_score_modifier == 50.0
    assert eval_denied.is_exception_cidr is False
    assert eval_denied.is_advisory_only is True

    # 3. Evaluate whitelisted exception IP from North Korea -> must NOT be denied
    eval_except = geoip_service.evaluate_ip(db_session, org_a.id, "175.45.176.50")
    assert eval_except.is_denied is False
    assert eval_except.is_exception_cidr is True

    # 4. Evaluate IP from allowed country (India) -> must NOT be denied
    eval_in = geoip_service.evaluate_ip(db_session, org_a.id, "103.21.244.1")
    assert eval_in.is_denied is False
    assert eval_in.risk_score_modifier == 0.0


def test_geoip_api_lifecycle(client: TestClient, db_session, test_tenants):
    """Tests the full REST API lifecycle for GeoIP policies and tenant isolation."""
    org_a = test_tenants["org_a"]
    admin_a = test_tenants["admin_a"]

    login_res = client.post(
        "/api/v1/auth/login",
        json={"email": admin_a.email, "password": "AlphaAdminPass123!"},
    )
    assert login_res.status_code == 200
    token_a = login_res.json()["tokens"]["access_token"]
    headers_a = {"Authorization": f"Bearer {token_a}"}

    # 1. Create Policy
    create_res = client.post(
        "/api/v1/network-defense/geoip/policies",
        json={
            "country_code": "RU",
            "country_name": "Russia",
            "action": "DENY",
            "exception_cidrs": "77.88.21.0/24",
            "risk_score_modifier": 35.0,
        },
        headers=headers_a,
    )
    assert create_res.status_code == 200
    policy_data = create_res.json()
    assert policy_data["country_code"] == "RU"
    policy_id = policy_data["id"]

    # 2. List Policies
    list_res = client.get("/api/v1/network-defense/geoip/policies", headers=headers_a)
    assert list_res.status_code == 200
    policies = list_res.json()
    assert len(policies) >= 1
    assert any(p["id"] == policy_id for p in policies)

    # 3. Evaluate blocked IP
    eval_res = client.post(
        "/api/v1/network-defense/geoip/evaluate",
        json={"ip_address": "77.100.50.25"},
        headers=headers_a,
    )
    assert eval_res.status_code == 200
    eval_data = eval_res.json()
    assert eval_data["country_code"] == "RU"
    assert eval_data["is_denied"] is True

    # 4. Evaluate exception IP
    eval_except_res = client.post(
        "/api/v1/network-defense/geoip/evaluate",
        json={"ip_address": "77.88.21.100"},
        headers=headers_a,
    )
    assert eval_except_res.status_code == 200
    assert eval_except_res.json()["is_denied"] is False
    assert eval_except_res.json()["is_exception_cidr"] is True

    # 5. Quick lookup endpoint
    lookup_res = client.get("/api/v1/network-defense/geoip/lookup/8.8.8.8", headers=headers_a)
    assert lookup_res.status_code == 200
    assert lookup_res.json()["country_code"] == "US"

    # 6. Delete Policy
    del_res = client.delete(f"/api/v1/network-defense/geoip/policies/{policy_id}", headers=headers_a)
    assert del_res.status_code == 200
