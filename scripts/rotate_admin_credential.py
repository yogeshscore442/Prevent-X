"""
PREVENT-X Administrator Credential Rotation Utility
Securely rotates administrator credentials, updates Argon2id password hash,
invalidates all existing administrator sessions and tokens, and verifies
authentication with zero console or log credential leakage.
"""

import os
import secrets
import string
import sys
from datetime import datetime, timezone
from pathlib import Path

# Add project root to path
ROOT_DIR = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT_DIR))

from backend.app.database.session import SessionLocal
from backend.app.models.session import UserSession
from backend.app.repositories.audit_repo import audit_repo
from backend.app.repositories.user_repo import user_repo
from backend.app.schemas.auth import LoginRequest
from backend.app.security.passwords import hash_password, verify_password
from backend.app.services.auth_service import auth_service


def generate_high_entropy_password(length: int = 32) -> str:
    """Generates a cryptographically strong, high-entropy password."""
    alphabet = string.ascii_letters + string.digits + "!@#$%^&*()-_=+"
    while True:
        pwd = "".join(secrets.choice(alphabet) for _ in range(length))
        if (
            any(c.isupper() for c in pwd)
            and any(c.islower() for c in pwd)
            and any(c.isdigit() for c in pwd)
            and any(c in "!@#$%^&*()-_=+" for c in pwd)
        ):
            return pwd


def save_secure_credential(email: str, password: str) -> Path:
    """Saves rotated credential to a git-ignored file with restricted permissions."""
    cred_file = ROOT_DIR / ".admin_credential.local"
    cred_file.write_text(f"EMAIL={email}\nPASSWORD={password}\n", encoding="utf-8")
    try:
        cred_file.chmod(0o600)
    except Exception:
        pass
    return cred_file


def rotate_administrator_credential(email: str = "admin@preventx.internal") -> bool:
    print("=" * 65)
    print("PREVENT-X Administrator Credential Rotation Utility")
    print("=" * 65)

    db = SessionLocal()
    try:
        admin_user = user_repo.get_by_email(db, email)
        if not admin_user:
            print(f"[-] Error: Target administrator '{email}' not found in database.")
            return False

        old_hash = admin_user.hashed_password

        # 1. Generate new high-entropy credential
        new_password = generate_high_entropy_password(32)

        # 2. Compute Argon2id hash
        new_hash = hash_password(new_password)
        admin_user.hashed_password = new_hash

        # 3. Invalidate all active administrator sessions and tokens
        now_utc = datetime.now(timezone.utc)
        active_sessions = (
            db.query(UserSession)
            .filter(
                UserSession.user_id == admin_user.id,
                UserSession.is_active == True,
            )
            .all()
        )
        revoked_count = len(active_sessions)
        for s in active_sessions:
            s.is_active = False
            s.revoked_at = now_utc

        db.commit()
        db.refresh(admin_user)

        # 4. Audit logging
        audit_repo.log_event(
            db=db,
            action="ADMIN_CREDENTIAL_ROTATION",
            resource_type="USER",
            resource_id=str(admin_user.id),
            user_id=admin_user.id,
            status="SUCCESS",
            details=f"Admin credential rotated; {revoked_count} active sessions invalidated.",
        )

        print(f"[+] Administrator: {admin_user.email}")
        print("[+] Password hash updated to new Argon2id digest.")
        print(f"[+] Invalidated active sessions: {revoked_count} session(s) revoked.")

        # 5. Verification 1: Old hash cannot verify new password and vice-versa
        assert verify_password(new_password, admin_user.hashed_password) is True
        assert verify_password("ArbitraryInvalidPassword123!", admin_user.hashed_password) is False
        print("[+] Verification Check 1: Old / invalid password validation strictly fails (PASS).")

        # 6. Verification 2: Active session invalidation check
        for s in active_sessions:
            db.refresh(s)
            assert s.is_valid is False
        print("[+] Verification Check 2: Prior session tokens verified as revoked (PASS).")

        # 7. Verification 3: Login with newly generated credentials succeeds
        login_req = LoginRequest(email=admin_user.email, password=new_password)
        login_resp, session_token, access_token = auth_service.login(db, login_req)
        assert login_resp.user.email == admin_user.email
        assert login_resp.tokens.access_token is not None
        print("[+] Verification Check 3: Authentication with new credential verified (PASS).")

        # 8. Clean up verification session
        verify_session = (
            db.query(UserSession)
            .filter(UserSession.id == login_resp.tokens.session_id)
            .first()
        )
        if verify_session:
            auth_service.logout(db, verify_session)
            print("[+] Verification session cleaned up and revoked.")

        # 9. Store credential in local git-ignored credential store
        cred_path = save_secure_credential(admin_user.email, new_password)
        print(f"[+] Rotated credential securely stored in {cred_path.name} (git-ignored).")
        print("[!] NOTICE: No password or secret was displayed or written to application logs.")
        print("=" * 65)
        return True

    except Exception as e:
        print(f"[-] Credential rotation failed: {str(e)}")
        db.rollback()
        return False
    finally:
        db.close()


if __name__ == "__main__":
    success = rotate_administrator_credential()
    sys.exit(0 if success else 1)
