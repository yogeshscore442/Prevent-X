"""
PREVENT-X Audit Log Integration Tests
"""

def test_audit_logs_recorded_and_retrieved(client, test_tenants):
    # 1. Login to generate an audit event
    login_a = client.post(
        "/api/v1/auth/login",
        json={"email": "admin@alphacorp.in", "password": "AlphaAdminPass123!"},
    )
    token = login_a.json()["tokens"]["access_token"]
    headers = {"Authorization": f"Bearer {token}"}

    # 2. Perform an action (create asset)
    client.post(
        "/api/v1/assets",
        json={
            "name": "Audit Test Asset",
            "asset_type": "DOMAIN",
            "target": "audit.alphacorp.in",
            "environment": "PRODUCTION",
            "criticality": "MEDIUM",
            "is_in_scope": True,
        },
        headers=headers,
    )

    # 3. Retrieve audit logs
    audit_resp = client.get("/api/v1/audit-logs", headers=headers)
    assert audit_resp.status_code == 200
    logs = audit_resp.json()
    assert logs["total"] >= 2
    actions = [item["action"] for item in logs["items"]]
    assert "AUTH_LOGIN_SUCCESS" in actions
    assert "ASSET_CREATE" in actions

    # Verify structured attributes
    for item in logs["items"]:
        assert item["status"] in ["SUCCESS", "FAILURE", "DENIED"]
        assert "created_at" in item
        assert "resource_type" in item

