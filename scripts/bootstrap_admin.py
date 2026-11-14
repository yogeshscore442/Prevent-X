"""
PREVENT-X Administrator Bootstrap CLI Script
Initializes root platform administrator and tenant organization via CLI.
"""

import sys
from pathlib import Path

# Add project root to path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from backend.app.core.config import settings
from backend.app.database.session import SessionLocal
from backend.app.schemas.auth import BootstrapRequest
from backend.app.services.auth_service import auth_service


def main():
    print("=" * 60)
    print("PREVENT-X Administrator Bootstrap Utility")
    print("=" * 60)

    db = SessionLocal()
    try:
        req = BootstrapRequest(
            bootstrap_token=settings.BOOTSTRAP_TOKEN,
            email="admin@preventx.internal",
            password="AdminPasswordSecure2026!",
            full_name="Lead Security Administrator",
            initial_organization_name="Default SMB Enterprise",
            initial_organization_slug="smb-default",
        )
        res = auth_service.bootstrap_admin(db, req)
        print(f"[+] Status: {res.status}")
        print(f"[+] Message: {res.message}")
        print(f"[+] Root Admin User ID: {res.user_id}")
        print(f"[+] Initial Org ID: {res.organization_id}")
        print("[+] Credentials: admin@preventx.internal / AdminPasswordSecure2026!")
    except Exception as e:
        print(f"[-] Bootstrap error: {str(e)}")
        sys.exit(1)
    finally:
        db.close()


if __name__ == "__main__":
    main()

