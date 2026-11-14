"""
PREVENT-X Role-Based Access Control (RBAC) Tests
"""

def test_unauthenticated_api_access_blocked(client):
    # Unauthenticated access to protected endpoints must return 401
    resp_users = client.get("/api/v1/users")
    assert resp_users.status_code == 401

    resp_assets = client.get("/api/v1/assets")
    assert resp_assets.status_code == 401

    resp_audit = client.get("/api/v1/audit-logs")
    assert resp_audit.status_code == 401


def test_viewer_permission_denial(client, test_tenants):
    # Login as Viewer of Org B
    login_viewer = client.post(
        "/api/v1/auth/login",
        json={"email": "viewer@betaind.in", "password": "BetaViewerPass123!"},
    )
    token = login_viewer.json()["tokens"]["access_token"]
    headers = {"Authorization": f"Bearer {token}"}

    # Viewer CAN view assets (asset:read)
    resp_view = client.get("/api/v1/assets", headers=headers)
    assert resp_view.status_code == 200

    # Viewer CANNOT create an asset (lacks asset:write)
    new_asset_data = {
        "name": "Disallowed Asset",
        "asset_type": "PUBLIC_IP",
        "target": "198.51.100.1",
        "environment": "PRODUCTION",
        "criticality": "LOW",
        "is_in_scope": True,
    }
    resp_create = client.post("/api/v1/assets", json=new_asset_data, headers=headers)
    assert resp_create.status_code == 403
    assert resp_create.json()["detail"]["code"] == "INSUFFICIENT_PERMISSIONS"

    # Viewer CANNOT create a user (lacks user:write)
    new_user_data = {
        "email": "hacker@betaind.in",
        "password": "Password123!",
        "full_name": "Unauthorized User",
        "role_name": "VIEWER",
    }
    resp_create_user = client.post("/api/v1/users", json=new_user_data, headers=headers)
    assert resp_create_user.status_code == 403


def test_roles_and_permissions_endpoint(client, test_tenants):
    login_super = client.post(
        "/api/v1/auth/login",
        json={"email": "superadmin@preventx.internal", "password": "SuperSecretPass123!"},
    )
    token = login_super.json()["tokens"]["access_token"]
    headers = {"Authorization": f"Bearer {token}"}

    resp_roles = client.get("/api/v1/roles", headers=headers)
    assert resp_roles.status_code == 200
    roles = resp_roles.json()
    role_names = [r["name"] for r in roles]
    assert "SUPER_ADMIN" in role_names
    assert "ORG_ADMIN" in role_names
    assert "SECURITY_ANALYST" in role_names
    assert "VIEWER" in role_names

    resp_perms = client.get("/api/v1/roles/permissions", headers=headers)
    assert resp_perms.status_code == 200
    perms = resp_perms.json()
    assert len(perms) >= 10
