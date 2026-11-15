"""
PREVENT-X Administrator Bootstrap CLI Script
Initializes root platform administrator and tenant organization via CLI.
Enforces secure credential provisioning: avoids insecure hardcoded passwords,
generates cryptographically strong random credentials when none are provided,
and stores credentials strictly in local git-ignored stores without stdout leakage.
"""

import os
import secrets
import string
import sys
from pathlib import Path

# Add project root to path
ROOT_DIR = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT_DIR))

from backend.app.core.config import settings
from backend.app.database.session import SessionLocal
from backend.app.repositories.user_repo import user_repo
from backend.app.schemas.auth import BootstrapRequest
from backend.app.services.auth_service import auth_service


def generate_secure_credential(length: int = 24) -> str:
    """Generates a high-entropy cryptographically secure credential."""
    chars = string.ascii_letters + string.digits + "!@#$%^&*()-_=+"
    while True:
        pwd = "".join(secrets.choice(chars) for _ in range(length))
        if (
            any(c.isupper() for c in pwd)
            and any(c.islower() for c in pwd)
            and any(c.isdigit() for c in pwd)
            and any(c in "!@#$%^&*()-_=+" for c in pwd)
        ):
            return pwd


def save_local_credential(email: str, secret: str) -> Path:
    """Saves generated credential to a git-ignored local file with restricted permissions."""
    cred_file = ROOT_DIR / ".admin_credential.local"
    cred_file.write_text(f"EMAIL={email}\nPASSWORD={secret}\n", encoding="utf-8")
    try:
        cred_file.chmod(0o600)
    except Exception:
        pass
    return cred_file


def main():
    print("=" * 60)
    print("PREVENT-X Administrator Bootstrap Utility")
    print("=" * 60)

    admin_email = os.environ.get("INITIAL_ADMIN_EMAIL", "admin@preventx.internal").strip().lower()
    provided_password = os.environ.get("INITIAL_ADMIN_PASSWORD", "").strip()

    db = SessionLocal()
    try:
        # Check idempotency: if admin user already exists, exit cleanly
        existing_admin = user_repo.get_by_email(db, admin_email)
        if existing_admin:
            print(f"[+] Administrator account '{admin_email}' is already provisioned.")
            print("[+] Bootstrap check completed successfully (idempotent).")
            return

        # Secure password determination
        generated = False
        if provided_password:
            admin_password = provided_password
        else:
            admin_password = generate_secure_credential(28)
            generated = True

        req = BootstrapRequest(
            bootstrap_token=settings.BOOTSTRAP_TOKEN,
            email=admin_email,
            password=admin_password,
            full_name="Lead Security Administrator",
            initial_organization_name="Default SMB Enterprise",
            initial_organization_slug="smb-default",
        )
        res = auth_service.bootstrap_admin(db, req)
        print(f"[+] Status: {res.status}")
        print(f"[+] Message: {res.message}")
        print(f"[+] Root Admin User ID: {res.user_id}")
        print(f"[+] Initial Org ID: {res.organization_id}")
        print(f"[+] Administrator: {req.email}")

        if generated:
            cred_path = save_local_credential(admin_email, admin_password)
            print(f"[+] Secure initial credential generated and written to {cred_path.name} (git-ignored).")
            print("[!] SECURITY NOTICE: Rotate administrator credentials immediately upon first login.")
        else:
            print("[+] Configured initial administrator credential from environment variable.")

    except Exception as e:
        print(f"[-] Bootstrap error: {str(e)}")
        sys.exit(1)
    finally:
        db.close()


if __name__ == "__main__":
    main()
