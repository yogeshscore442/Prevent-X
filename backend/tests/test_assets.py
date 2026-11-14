"""
PREVENT-X Managed Asset Management Tests
"""

def test_asset_lifecycle(client, test_tenants):
    # Login as Org Admin of Org A
    login_a = client.post(
        "/api/v1/auth/login",
        json={"email": "admin@alphacorp.in", "password": "AlphaAdminPass123!"},
    )
    token = login_a.json()["tokens"]["access_token"]
    headers = {"Authorization": f"Bearer {token}"}

    # 1. Create Asset
    create_payload = {
        "name": "Alpha Customer Banking API",
        "asset_type": "API_GATEWAY",
        "target": "https://banking.alphacorp.in",
        "environment": "PRODUCTION",
        "criticality": "CRITICAL",
        "is_in_scope": True,
    }
    create_resp = client.post("/api/v1/assets", json=create_payload, headers=headers)
    assert create_resp.status_code == 201
    created_asset = create_resp.json()
    asset_id = created_asset["id"]
    assert created_asset["name"] == "Alpha Customer Banking API"
    assert created_asset["is_in_scope"] is True

    # 2. Get Asset by ID
    get_resp = client.get(f"/api/v1/assets/{asset_id}", headers=headers)
    assert get_resp.status_code == 200
    assert get_resp.json()["id"] == asset_id

    # 3. Update Asset
    update_resp = client.patch(
        f"/api/v1/assets/{asset_id}",
        json={"criticality": "HIGH", "environment": "STAGING"},
        headers=headers,
    )
    assert update_resp.status_code == 200
    updated_data = update_resp.json()
    assert updated_data["criticality"] == "HIGH"
    assert updated_data["environment"] == "STAGING"

    # 4. Delete Asset
    del_resp = client.delete(f"/api/v1/assets/{asset_id}", headers=headers)
    assert del_resp.status_code == 204

    # 5. Verify deletion
    verify_resp = client.get(f"/api/v1/assets/{asset_id}", headers=headers)
    assert verify_resp.status_code == 404


def test_asset_input_validation(client, test_tenants):
    login_a = client.post(
        "/api/v1/auth/login",
        json={"email": "admin@alphacorp.in", "password": "AlphaAdminPass123!"},
    )
    headers = {"Authorization": f"Bearer {login_a.json()['tokens']['access_token']}"}

    # Invalid asset type
    bad_payload = {
        "name": "Invalid Type Asset",
        "asset_type": "NOT_A_VALID_TYPE",
        "target": "10.0.0.1",
        "environment": "PRODUCTION",
        "criticality": "HIGH",
        "is_in_scope": True,
    }
    resp = client.post("/api/v1/assets", json=bad_payload, headers=headers)
    assert resp.status_code == 422

