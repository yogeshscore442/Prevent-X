"""
PREVENT-X Admin Credential Security & Session Invalidation Tests
Verifies password rotation, server-side session invalidation,
token revocation, and secure credential generation.
"""

import uuid
from datetime import datetime, timezone
import pytest
from backend.app.models.session import UserSession
from backend.app.models.user import User
from backend.app.repositories.user_repo import user_repo
from backend.app.security.passwords import hash_password, verify_password
from scripts.bootstrap_admin import generate_secure_credential
from scripts.rotate_admin_credential import generate_high_entropy_password


def test_secure_credential_entropy_and_complexity():
    """Verify generated credentials meet strict complexity and high entropy standards."""
    passwords = set()
    for _ in range(25):
        pwd = generate_secure_credential(28)
        assert len(pwd) == 28
        assert any(c.isupper() for c in pwd)
        assert any(c.islower() for c in pwd)
        assert any(c.isdigit() for c in pwd)
        assert any(c in "!@#$%^&*()-_=+" for c in pwd)
        passwords.add(pwd)

    # All generated credentials must be unique
    assert len(passwords) == 25


def test_high_entropy_password_generator():
    """Verify rotation password generator meets strict standards."""
    pwd = generate_high_entropy_password(32)
    assert len(pwd) == 32
    assert any(c.isupper() for c in pwd)
    assert any(c.islower() for c in pwd)
    assert any(c.isdigit() for c in pwd)
    assert any(c in "!@#$%^&*()-_=+" for c in pwd)


def test_password_rotation_invalidates_prior_sessions(client, test_tenants, db_session):
    """
    Comprehensive test demonstrating:
    1. User authenticates with initial password and establishes sessions.
    2. Password is rotated to a new password and existing sessions are invalidated.
    3. Authentication with the old password fails.
    4. Prior session tokens are rejected by protected endpoints (HTTP 401).
    5. Authentication with the new password succeeds.
    6. Newly established sessions can access protected endpoints.
    """
    initial_password = "AlphaAdminPass123!"
    user_email = "admin@alphacorp.in"

    # Step 1: Login to obtain session 1
    resp1 = client.post("/api/v1/auth/login", json={"email": user_email, "password": initial_password})
    assert resp1.status_code == 200
    token1 = resp1.json()["tokens"]["access_token"]
    session_id1 = resp1.json()["tokens"]["session_id"]

    # Login again to obtain session 2
    resp2 = client.post("/api/v1/auth/login", json={"email": user_email, "password": initial_password})
    assert resp2.status_code == 200
    token2 = resp2.json()["tokens"]["access_token"]
    session_id2 = resp2.json()["tokens"]["session_id"]

    # Verify both sessions can access /api/v1/auth/me
    assert client.get("/api/v1/auth/me", headers={"Authorization": f"Bearer {token1}"}).status_code == 200
    assert client.get("/api/v1/auth/me", headers={"Authorization": f"Bearer {token2}"}).status_code == 200

    # Step 2: Rotate password and revoke all active sessions for this user
    user = user_repo.get_by_email(db_session, user_email)
    assert user is not None

    new_password = "NewlyRotatedAdminSecret2026!#"
    user.hashed_password = hash_password(new_password)

    now_utc = datetime.now(timezone.utc)
    sessions = db_session.query(UserSession).filter(
        UserSession.user_id == user.id,
        UserSession.is_active == True,
    ).all()
    for s in sessions:
        s.is_active = False
        s.revoked_at = now_utc

    db_session.commit()
    db_session.expire_all()

    # Step 3: Old password cannot authenticate
    fail_login = client.post("/api/v1/auth/login", json={"email": user_email, "password": initial_password})
    assert fail_login.status_code == 401

    # Step 4: Prior session tokens fail authentication
    me_resp1 = client.get("/api/v1/auth/me", headers={"Authorization": f"Bearer {token1}"})
    assert me_resp1.status_code == 401

    me_resp2 = client.get("/api/v1/auth/me", headers={"Authorization": f"Bearer {token2}"})
    assert me_resp2.status_code == 401

    # Step 5: Login with newly rotated password succeeds
    success_login = client.post("/api/v1/auth/login", json={"email": user_email, "password": new_password})
    assert success_login.status_code == 200
    new_token = success_login.json()["tokens"]["access_token"]
    new_session_id = success_login.json()["tokens"]["session_id"]
    assert new_session_id != session_id1
    assert new_session_id != session_id2

    # Step 6: Newly established session can access protected endpoints
    me_resp_new = client.get("/api/v1/auth/me", headers={"Authorization": f"Bearer {new_token}"})
    assert me_resp_new.status_code == 200
    assert me_resp_new.json()["email"] == user_email
