"""
PREVENT-X Phase 6: Advanced Attack Detection Tests
Validates detection of the 10 extended attack categories without false positives:
SSRF, XXE, SSTI, NoSQL Injection, LDAP Injection, Open Redirect,
HTTP Request Smuggling, GraphQL Abuse, Mass Assignment, and JWT Misuse.
"""

import base64
import json
import pytest

from backend.app.modules.network_defense.detection.engine import (
    advanced_attack_detection_engine,
)


def test_ssrf_detection():
    """Verifies detection of AWS/GCP metadata probes and dangerous internal protocols."""
    engine = advanced_attack_detection_engine

    # AWS metadata probe
    res1 = engine.inspect_request(
        method="GET",
        path="/api/v1/fetch",
        query_string="url=http://169.254.169.254/latest/meta-data/",
    )
    assert res1.detected is True
    assert res1.category == "SSRF"
    assert res1.cwe_id == "CWE-918"

    # Dangerous protocol (gopher://)
    res2 = engine.inspect_request(
        method="POST",
        path="/api/v1/webhook",
        body='{"target": "gopher://127.0.0.1:6379/_flushall"}',
    )
    assert res2.detected is True
    assert res2.category == "SSRF"


def test_xxe_detection():
    """Verifies detection of XML External Entity DOCTYPE injections."""
    engine = advanced_attack_detection_engine

    xml_payload = """<?xml version="1.0"?>
    <!DOCTYPE foo [
    <!ELEMENT foo ANY >
    <!ENTITY xxe SYSTEM "file:///etc/passwd" >]>
    <foo>&xxe;</foo>"""

    res = engine.inspect_request(
        method="POST",
        path="/api/v1/xml-upload",
        body=xml_payload,
        headers={"content-type": "application/xml"},
    )
    assert res.detected is True
    assert res.category == "XXE"
    assert res.cwe_id == "CWE-611"


def test_ssti_detection():
    """Verifies detection of Server-Side Template Injection syntax."""
    engine = advanced_attack_detection_engine

    # Jinja2 / Twig math probe
    res1 = engine.inspect_request(
        method="GET",
        path="/profile",
        query_string="name={{7*7}}",
    )
    assert res1.detected is True
    assert res1.category == "SSTI"

    # Java template injection
    res2 = engine.inspect_request(
        method="POST",
        path="/render",
        body='{"template": "${T(java.lang.Runtime).getRuntime().exec(\'id\')}"}',
    )
    assert res2.detected is True
    assert res2.category == "SSTI"


def test_nosql_injection_detection():
    """Verifies detection of MongoDB operator injections."""
    engine = advanced_attack_detection_engine

    res = engine.inspect_request(
        method="POST",
        path="/api/v1/login",
        body='{"username": {"$gt": ""}, "password": {"$ne": null}}',
    )
    assert res.detected is True
    assert res.category == "NOSQL_INJECTION"
    assert res.cwe_id == "CWE-943"


def test_ldap_injection_detection():
    """Verifies detection of LDAP directory filter injections."""
    engine = advanced_attack_detection_engine

    res = engine.inspect_request(
        method="GET",
        path="/users/search",
        query_string="user=admin*)(uid=*))(|(uid=*",
    )
    assert res.detected is True
    assert res.category == "LDAP_INJECTION"
    assert res.cwe_id == "CWE-90"


def test_open_redirect_detection():
    """Verifies detection of unvalidated external redirect parameters."""
    engine = advanced_attack_detection_engine

    res = engine.inspect_request(
        method="GET",
        path="/logout",
        query_string="redirect=https://evil-phishing-site.com/login",
    )
    assert res.detected is True
    assert res.category == "OPEN_REDIRECT"
    assert res.cwe_id == "CWE-601"


def test_http_request_smuggling_detection():
    """Verifies detection of conflicting Transfer-Encoding and Content-Length headers."""
    engine = advanced_attack_detection_engine

    headers = {
        "content-length": "42",
        "transfer-encoding": "chunked",
    }
    res = engine.inspect_request(
        method="POST",
        path="/api/v1/orders",
        headers=headers,
    )
    assert res.detected is True
    assert res.category == "HTTP_REQUEST_SMUGGLING"
    assert res.cwe_id == "CWE-444"


def test_graphql_abuse_detection():
    """Verifies detection of deeply nested GraphQL queries and introspection probes."""
    engine = advanced_attack_detection_engine

    # Deeply nested query (depth >= 7)
    deep_query = "{ user { posts { comments { author { profile { settings { theme } } } } } } }"
    res_deep = engine.inspect_request(
        method="POST",
        path="/graphql",
        body=deep_query,
    )
    assert res_deep.detected is True
    assert res_deep.category == "GRAPHQL_ABUSE"
    assert "depth" in res_deep.explanation.lower()

    # Introspection query
    introspect = "{ __schema { types { name } } }"
    res_intro = engine.inspect_request(
        method="POST",
        path="/api/graphql",
        body=introspect,
    )
    assert res_intro.detected is True
    assert res_intro.category == "GRAPHQL_ABUSE"


def test_mass_assignment_detection():
    """Verifies detection of administrative privilege escalation fields in mutating bodies."""
    engine = advanced_attack_detection_engine

    body = json.dumps({"username": "john_doe", "email": "john@example.com", "role": "SUPER_ADMIN"})
    res = engine.inspect_request(
        method="POST",
        path="/api/v1/users/register",
        body=body,
    )
    assert res.detected is True
    assert res.category == "MASS_ASSIGNMENT"
    assert res.cwe_id == "CWE-915"


def test_jwt_misuse_detection():
    """Verifies detection of 'alg': 'none' JWT exploit tokens."""
    engine = advanced_attack_detection_engine

    header_none = base64.b64encode(b'{"alg":"none","typ":"JWT"}').decode().rstrip("=")
    claims = base64.b64encode(b'{"sub":"12345","role":"admin"}').decode().rstrip("=")
    jwt_none = f"{header_none}.{claims}."

    res = engine.inspect_request(
        method="GET",
        path="/api/v1/admin/overview",
        headers={"authorization": f"Bearer {jwt_none}"},
    )
    assert res.detected is True
    assert res.category == "JWT_MISUSE"
    assert res.cwe_id == "CWE-347"


def test_benign_negative_cases_no_false_positives():
    """Verifies that legitimate search queries, pagination, and benign bodies pass cleanly."""
    engine = advanced_attack_detection_engine

    # Legitimate search
    r1 = engine.inspect_request(
        method="GET",
        path="/api/v1/products",
        query_string="q=laptop+accessories&page=2&limit=20&sort=price_asc",
    )
    assert r1.detected is False

    # Legitimate JSON order placement
    r2 = engine.inspect_request(
        method="POST",
        path="/api/v1/orders",
        body='{"product_id": 402, "quantity": 2, "shipping_address": "MG Road, Bengaluru"}',
    )
    assert r2.detected is False


def test_detection_api_endpoints(client, test_tenants):
    """Verifies the REST API endpoint for attack inspection and category listing."""
    admin_a = test_tenants["admin_a"]
    login_res = client.post("/api/v1/auth/login", json={"email": admin_a.email, "password": "AlphaAdminPass123!"})
    token = login_res.json()["tokens"]["access_token"]
    headers = {"Authorization": f"Bearer {token}"}

    # Inspect endpoint with an SSRF probe
    inspect_res = client.post(
        "/api/v1/network-defense/detection/inspect",
        json={
            "method": "POST",
            "path": "/api/v1/fetch",
            "query_string": "target=http://169.254.169.254/latest/",
        },
        headers=headers,
    )
    assert inspect_res.status_code == 200
    data = inspect_res.json()
    assert data["detected"] is True
    assert data["category"] == "SSRF"
    assert data["cwe_id"] == "CWE-918"

    # Category list endpoint
    cats_res = client.get("/api/v1/network-defense/detection/categories", headers=headers)
    assert cats_res.status_code == 200
    categories = cats_res.json()
    assert len(categories) == 10
    cat_keys = [c["category"] for c in categories]
    assert "SSRF" in cat_keys
    assert "JWT_MISUSE" in cat_keys
