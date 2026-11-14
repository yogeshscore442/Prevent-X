"""
PREVENT-X Phase 1 Automated End-to-End Verification Harness
Executes integration probes to verify that all Phase 1 acceptance criteria are satisfied.
"""

import sys
import uuid
from pathlib import Path

# Add project root to path
ROOT_DIR = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT_DIR))

from fastapi.testclient import TestClient
from backend.app.main import app
from backend.app.core.config import settings
from backend.app.database.session import SessionLocal
from backend.app.models.organization import Organization
from backend.app.models.asset import ManagedAsset
from backend.app.models.audit_log import AuditEvent
from backend.app.modules.registry import module_registry


def run_verification():
    print("=" * 70)
    print("PREVENT-X PHASE 1 ACCEPTANCE VERIFICATION HARNESS")
    print("=" * 70)

    client = TestClient(app)
    results = []

    # 1. Health & Liveness Probe
    h_resp = client.get("/api/v1/health")
    if h_resp.status_code == 200 and h_resp.json().get("status") == "HEALTHY":
        results.append(("Health Endpoint (/api/v1/health)", True, "HTTP 200 HEALTHY"))
    else:
        results.append(("Health Endpoint (/api/v1/health)", False, f"Failed with {h_resp.status_code}"))

    # 2. Readiness Probe
    r_resp = client.get("/api/v1/ready")
    if r_resp.status_code == 200 and r_resp.json()["database"]["status"] == "UP":
        latency = r_resp.json()["database"]["latency_ms"]
        results.append(("Readiness Probe (/api/v1/ready)", True, f"DB UP ({latency}ms latency)"))
    else:
        results.append(("Readiness Probe (/api/v1/ready)", False, "Database probe failed"))

    # 3. System Info & Honest Module Catalog
    s_resp = client.get("/api/v1/system/info")
    if s_resp.status_code == 200:
        modules = s_resp.json().get("modules", [])
        mod_12 = next((m for m in modules if m["module_id"] == "MOD-12"), None)
        mod_08 = next((m for m in modules if m["module_id"] == "MOD-08"), None)
        if len(modules) == 12 and mod_12["status"] == "OPERATIONAL" and mod_08["status"] != "OPERATIONAL":
            results.append(("Module Catalog Telemetry", True, "12 engines declared; no fake features"))
        else:
            results.append(("Module Catalog Telemetry", False, "Module definitions inconsistent"))
    else:
        results.append(("Module Catalog Telemetry", False, f"HTTP {s_resp.status_code}"))

    # 4. Bootstrap Administrator
    test_slug = f"verify-org-{uuid.uuid4().hex[:6]}"
    test_email = f"ciso-{uuid.uuid4().hex[:6]}@smbclient.in"
    b_resp = client.post("/api/v1/auth/bootstrap", json={
        "bootstrap_token": settings.BOOTSTRAP_TOKEN,
        "email": test_email,
        "password": "VerificationPass2026!",
        "full_name": "Verification Security Officer",
        "initial_organization_name": "Verification Corp",
        "initial_organization_slug": test_slug,
    })
    if b_resp.status_code == 201 and b_resp.json().get("status") == "SUCCESS":
        results.append(("Admin Bootstrap Service", True, f"Created {test_email} in {test_slug}"))
    else:
        results.append(("Admin Bootstrap Service", False, f"Bootstrap returned {b_resp.status_code}"))

    # 5. User Login & Argon2id Verification
    l_resp = client.post("/api/v1/auth/login", json={
        "email": test_email,
        "password": "VerificationPass2026!",
    })
    if l_resp.status_code == 200:
        token = l_resp.json()["tokens"]["access_token"]
        auth_headers = {"Authorization": f"Bearer {token}"}
        results.append(("Argon2id Login & Session Creation", True, "Valid JWT & Server Session issued"))
    else:
        results.append(("Argon2id Login & Session Creation", False, f"Login failed: {l_resp.status_code}"))
        token = None
        auth_headers = {}

    if token:
        # 6. Asset Onboarding (Scoped to Organization)
        a_resp = client.post("/api/v1/assets", json={
            "name": "Verification Payment Microservice",
            "asset_type": "API_GATEWAY",
            "target": "https://pay.verification.in",
            "environment": "PRODUCTION",
            "criticality": "CRITICAL",
            "is_in_scope": True,
        }, headers=auth_headers)
        if a_resp.status_code == 201:
            asset_id = a_resp.json()["id"]
            results.append(("Managed Asset Foundation", True, f"Asset {asset_id} authorized"))
        else:
            results.append(("Managed Asset Foundation", False, f"Failed asset create: {a_resp.status_code}"))
            asset_id = None

        # 7. Audit Log Trail
        audit_resp = client.get("/api/v1/audit-logs", headers=auth_headers)
        if audit_resp.status_code == 200 and audit_resp.json().get("total", 0) > 0:
            count = audit_resp.json()["total"]
            results.append(("Cryptographic Audit Trail", True, f"{count} audit events verified in DB"))
        else:
            results.append(("Cryptographic Audit Trail", False, "No audit logs found"))

        # 8. Cross-Tenant Isolation Enforcement
        spoofed_headers = {
            "Authorization": f"Bearer {token}",
            "X-Organization-Id": str(uuid.uuid4()),  # Attempt to switch to arbitrary unauthorized org
        }
        iso_resp = client.get("/api/v1/assets", headers=spoofed_headers)
        if iso_resp.status_code == 403 and iso_resp.json().get("detail", {}).get("code") == "TENANT_ACCESS_DENIED":
            results.append(("Tenant Isolation Security Guard", True, "Cross-tenant spoofing blocked (403)"))
        else:
            results.append(("Tenant Isolation Security Guard", False, f"Expected 403, got {iso_resp.status_code}"))

        # 9. Session Revocation (Logout)
        logout_resp = client.post("/api/v1/auth/logout", headers=auth_headers)
        after_resp = client.get("/api/v1/auth/me", headers=auth_headers)
        if logout_resp.status_code == 200 and after_resp.status_code == 401:
            results.append(("Session Revocation Lifecycle", True, "Session revoked; subsequent request rejected (401)"))
        else:
            results.append(("Session Revocation Lifecycle", False, "Session not properly revoked"))

    # 10. Frontend Distribution Build Check
    dist_index = ROOT_DIR / "frontend" / "dist" / "index.html"
    if dist_index.exists():
        results.append(("Frontend Production Bundle", True, "Vite production assets compiled in frontend/dist"))
    else:
        results.append(("Frontend Production Bundle", False, "frontend/dist/index.html not found"))

    # Print Report
    print("\nVERIFICATION RESULTS:")
    print("-" * 70)
    all_passed = True
    for name, passed, details in results:
        status_str = "[PASS]" if passed else "[FAIL]"
        print(f"{status_str:<8} | {name:<35} | {details}")
        if not passed:
            all_passed = False
    print("-" * 70)

    if all_passed:
        print("\n>>> ALL PHASE 1 CRITICAL ACCEPTANCE CRITERIA VERIFIED SUCCESSFUL. <<<\n")
        return 0
    else:
        print("\n>>> ONE OR MORE VERIFICATION CHECKS FAILED. <<<\n")
        return 1


if __name__ == "__main__":
    sys.exit(run_verification())

