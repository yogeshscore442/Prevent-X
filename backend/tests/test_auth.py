"""
PREVENT-X Authentication and Session Security Tests
"""

import pytest
from backend.app.core.config import settings
from backend.app.models.session import UserSession
from backend.app.security.passwords import hash_password, verify_password


def test_argon2id_password_hashing():
    password = "CorrectHorseBatteryStaple2026!"
    hashed = hash_password(password)

    # Must be valid Argon2id hash format
    assert hashed.startswith("$argon2id$")
    assert verify_password(password, hashed) is True
    assert verify_password("WrongPassword!", hashed) is False
    assert verify_password("", hashed) is False

    with pytest.raises(ValueError):
        hash_password("short")


def test_admin_bootstrap_endpoint(client, db_session):
    # Test valid bootstrap
    payload = {
        "bootstrap_token": settings.BOOTSTRAP_TOKEN,
        "email": "newadmin@smbenterprise.in",
        "password": "SecureAdminPassword2026!",
        "full_name": "New Enterprise Admin",
        "initial_organization_name": "New SMB Tech",
        "initial_organization_slug": "new-smb-tech",
    }
    resp = client.post("/api/v1/auth/bootstrap", json=payload)
    assert resp.status_code == 201
    data = resp.json()
    assert data["status"] == "SUCCESS"
    assert "user_id" in data
    assert "organization_id" in data

    # Test invalid bootstrap token
    bad_payload = payload.copy()
    bad_payload["bootstrap_token"] = "invalid-token-attempt"
    bad_resp = client.post("/api/v1/auth/bootstrap", json=bad_payload)
    assert bad_resp.status_code == 400


def test_user_login_success_and_session_creation(client, test_tenants, db_session):
    login_data = {
        "email": "admin@alphacorp.in",
        "password": "AlphaAdminPass123!",
    }
    resp = client.post("/api/v1/auth/login", json=login_data)
    assert resp.status_code == 200
    data = resp.json()
    assert data["message"] == "Authentication successful"
    assert "tokens" in data
    assert "access_token" in data["tokens"]
    assert data["user"]["email"] == "admin@alphacorp.in"
    assert len(data["user"]["memberships"]) >= 1

    # Verify session was recorded in database
    session_id = data["tokens"]["session_id"]
    db_session_obj = db_session.query(UserSession).filter(UserSession.id == session_id).first()
    assert db_session_obj is not None
    assert db_session_obj.is_active is True
    assert db_session_obj.revoked_at is None


def test_user_login_failure(client, test_tenants):
    # Bad password
    resp = client.post(
        "/api/v1/auth/login",
        json={"email": "admin@alphacorp.in", "password": "WrongPassword123!"},
    )
    assert resp.status_code == 401
    assert resp.json()["detail"]["code"] == "AUTHENTICATION_FAILED"

    # Nonexistent user
    resp_nonexistent = client.post(
        "/api/v1/auth/login",
        json={"email": "nobody@nowhere.com", "password": "SomePassword123!"},
    )
    assert resp_nonexistent.status_code == 401


def test_auth_me_endpoint(client, test_tenants):
    # Login to obtain token
    login_resp = client.post(
        "/api/v1/auth/login",
        json={"email": "admin@alphacorp.in", "password": "AlphaAdminPass123!"},
    )
    token = login_resp.json()["tokens"]["access_token"]

    # Request /auth/me with Bearer token
    me_resp = client.get(
        "/api/v1/auth/me",
        headers={"Authorization": f"Bearer {token}"},
    )
    assert me_resp.status_code == 200
    me_data = me_resp.json()
    assert me_data["email"] == "admin@alphacorp.in"
    assert me_data["full_name"] == "Alpha Admin"
    assert me_data["is_superuser"] is False


def test_logout_and_session_revocation(client, test_tenants, db_session):
    login_resp = client.post(
        "/api/v1/auth/login",
        json={"email": "admin@alphacorp.in", "password": "AlphaAdminPass123!"},
    )
    token = login_resp.json()["tokens"]["access_token"]
    session_id = login_resp.json()["tokens"]["session_id"]

    # Logout
    logout_resp = client.post(
        "/api/v1/auth/logout",
        headers={"Authorization": f"Bearer {token}"},
    )
    assert logout_resp.status_code == 200

    # Session in DB should now be revoked
    db_session.expire_all()
    session_obj = db_session.query(UserSession).filter(UserSession.id == session_id).first()
    assert session_obj.is_active is False
    assert session_obj.revoked_at is not None

    # Subsequent /auth/me call with same token must fail
    me_resp_after = client.get(
        "/api/v1/auth/me",
        headers={"Authorization": f"Bearer {token}"},
    )
    assert me_resp_after.status_code == 401

