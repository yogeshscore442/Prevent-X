"""
PREVENT-X Multi-Tenant Isolation Security Tests
Explicitly attempts cross-tenant access to verify that data boundaries are strictly enforced.
"""

from backend.app.models.asset import ManagedAsset


def test_cross_tenant_asset_isolation(client, test_tenants, db_session):
    org_a = test_tenants["org_a"]
    org_b = test_tenants["org_b"]

    # 1. Create asset for Org A
    asset_a = ManagedAsset(
        organization_id=org_a.id,
        name="Alpha Payment Gateway",
        asset_type="API_GATEWAY",
        target="api.alphacorp.in",
        environment="PRODUCTION",
        criticality="CRITICAL",
        is_in_scope=True,
    )
    # 2. Create asset for Org B
    asset_b = ManagedAsset(
        organization_id=org_b.id,
        name="Beta Supply Chain Portal",
        asset_type="WEB_APPLICATION",
        target="portal.betaind.in",
        environment="PRODUCTION",
        criticality="HIGH",
        is_in_scope=True,
    )
    db_session.add_all([asset_a, asset_b])
    db_session.commit()

    # Login as Admin of Org A
    login_a = client.post(
        "/api/v1/auth/login",
        json={"email": "admin@alphacorp.in", "password": "AlphaAdminPass123!"},
    )
    token_a = login_a.json()["tokens"]["access_token"]
    headers_a = {"Authorization": f"Bearer {token_a}"}

    # 3. List assets as Org A - should only see Alpha assets, NEVER Beta assets
    resp = client.get("/api/v1/assets", headers=headers_a)
    assert resp.status_code == 200
    data = resp.json()
    asset_ids = [item["id"] for item in data["items"]]
    assert str(asset_a.id) in asset_ids
    assert str(asset_b.id) not in asset_ids

    # 4. Explicit cross-tenant GET: Org A admin directly requests Org B's asset by ID
    cross_get_resp = client.get(f"/api/v1/assets/{asset_b.id}", headers=headers_a)
    assert cross_get_resp.status_code == 404  # Scoped lookup fails to find it in Org A
    assert cross_get_resp.json()["detail"]["code"] == "RESOURCE_NOT_FOUND"

    # 5. Explicit cross-tenant DELETE: Org A admin attempts to delete Org B's asset
    cross_del_resp = client.delete(f"/api/v1/assets/{asset_b.id}", headers=headers_a)
    assert cross_del_resp.status_code == 404

    # 6. Explicit cross-tenant UPDATE: Org A admin attempts to modify Org B's asset
    cross_patch_resp = client.patch(
        f"/api/v1/assets/{asset_b.id}",
        json={"name": "Hacked Asset Name"},
        headers=headers_a,
    )
    assert cross_patch_resp.status_code == 404

    # Verify Org B's asset in DB was NOT modified
    db_session.expire_all()
    check_b = db_session.query(ManagedAsset).filter(ManagedAsset.id == asset_b.id).first()
    assert check_b.name == "Beta Supply Chain Portal"


def test_cross_tenant_organization_header_spoofing(client, test_tenants):
    org_b = test_tenants["org_b"]

    # Login as Admin of Org A
    login_a = client.post(
        "/api/v1/auth/login",
        json={"email": "admin@alphacorp.in", "password": "AlphaAdminPass123!"},
    )
    token_a = login_a.json()["tokens"]["access_token"]

    # Attempt to spoof tenant context using X-Organization-Id header pointing to Org B
    spoofed_headers = {
        "Authorization": f"Bearer {token_a}",
        "X-Organization-Id": str(org_b.id),
    }

    # Should be rejected with 403 Forbidden
    resp = client.get("/api/v1/assets", headers=spoofed_headers)
    assert resp.status_code == 403
    assert resp.json()["detail"]["code"] == "TENANT_ACCESS_DENIED"


def test_cross_tenant_user_listing_isolation(client, test_tenants):
    # Login as Admin of Org A
    login_a = client.post(
        "/api/v1/auth/login",
        json={"email": "admin@alphacorp.in", "password": "AlphaAdminPass123!"},
    )
    token_a = login_a.json()["tokens"]["access_token"]

    resp = client.get("/api/v1/users", headers={"Authorization": f"Bearer {token_a}"})
    assert resp.status_code == 200
    users = resp.json()["items"]
    user_emails = [u["email"] for u in users]

    # Must contain Alpha Corp users
    assert "admin@alphacorp.in" in user_emails
    assert "analyst@alphacorp.in" in user_emails

    # Must NEVER leak Beta Industries users
    assert "admin@betaind.in" not in user_emails
    assert "viewer@betaind.in" not in user_emails

