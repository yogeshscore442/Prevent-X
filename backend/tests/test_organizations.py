"""
PREVENT-X Organization Management Tests
"""

def test_organization_crud_lifecycle(client, test_tenants):
    # Login as Super Admin
    login_super = client.post(
        "/api/v1/auth/login",
        json={"email": "superadmin@preventx.internal", "password": "SuperSecretPass123!"},
    )
    token = login_super.json()["tokens"]["access_token"]
    headers = {"Authorization": f"Bearer {token}"}

    # 1. Create Organization
    create_payload = {
        "name": "Gamma Retail Ltd",
        "slug": "gamma-retail",
        "sector": "Retail E-Commerce",
        "contact_email": "security@gammaretail.in",
    }
    create_resp = client.post("/api/v1/organizations", json=create_payload, headers=headers)
    assert create_resp.status_code == 201
    org_data = create_resp.json()
    org_id = org_data["id"]
    assert org_data["name"] == "Gamma Retail Ltd"
    assert org_data["slug"] == "gamma-retail"

    # 2. Get Organization
    get_resp = client.get(f"/api/v1/organizations/{org_id}", headers=headers)
    assert get_resp.status_code == 200
    assert get_resp.json()["id"] == org_id

    # 3. Update Organization
    patch_resp = client.patch(
        f"/api/v1/organizations/{org_id}",
        json={"sector": "Omnichannel Retail"},
        headers=headers,
    )
    assert patch_resp.status_code == 200
    assert patch_resp.json()["sector"] == "Omnichannel Retail"


def test_organization_creation_rejected_for_regular_user(client, test_tenants):
    # Login as regular tenant admin (not superuser)
    login_a = client.post(
        "/api/v1/auth/login",
        json={"email": "admin@alphacorp.in", "password": "AlphaAdminPass123!"},
    )
    token = login_a.json()["tokens"]["access_token"]
    headers = {"Authorization": f"Bearer {token}"}

    # Creating a new organization requires superuser privilege
    resp = client.post(
        "/api/v1/organizations",
        json={
            "name": "Unauthorized Org Creation",
            "slug": "unauthorized-org",
            "contact_email": "admin@alphacorp.in",
        },
        headers=headers,
    )
    assert resp.status_code == 403
