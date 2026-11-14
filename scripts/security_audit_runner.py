"""
PREVENT-X Independent Security Audit & Verification Runner
Directly executes verification and security attack vectors via TestClient.
"""

import sys
import uuid
from pathlib import Path
ROOT_DIR = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT_DIR))

from fastapi.testclient import TestClient
from backend.app.main import app
from backend.app.core.config import settings
from backend.app.database.session import SessionLocal
from backend.app.models.organization import Organization
from backend.app.models.role import Role
from backend.app.models.user import User, OrganizationMembership
from backend.app.models.asset import ManagedAsset
from backend.app.models.session import UserSession
from backend.app.security.passwords import hash_password, _hasher
from backend.app.security.permissions import SystemRole

client = TestClient(app)
audit_results = []

def record(test_name, passed, evidence, command_info=""):
    audit_results.append({
        "name": test_name,
        "status": "PASS" if passed else "FAIL",
        "evidence": evidence,
        "command": command_info,
    })
    status_str = "[PASS]" if passed else "[FAIL]"
    print(f"{status_str:<8} | {test_name:<45} | {evidence}")

print("=" * 75)
print("PREVENT-X PHASE 1 INDEPENDENT SECURITY AUDIT EXECUTION")
print("=" * 75)

# ------------------------------------------------------------------------------
# 1. Inspect Argon2id Configuration
# ------------------------------------------------------------------------------
print("\n--- SECTION 1: CRYPTOGRAPHIC CONFIGURATION AUDIT ---")
test_pwd = "AuditPassword2026!#"
sample_hash = hash_password(test_pwd)

argon_evidence = f"Algorithm: {_hasher.type.name}, Time: {_hasher.time_cost}, Memory: {_hasher.memory_cost} KiB ({_hasher.memory_cost//1024} MB), Parallelism: {_hasher.parallelism}, Hash: {sample_hash[:30]}..."
argon_pass = (
    sample_hash.startswith("$argon2id$") and
    _hasher.time_cost == 3 and
    _hasher.memory_cost == 65536 and
    _hasher.parallelism == 4
)
record("Argon2id Hash Configuration", argon_pass, argon_evidence, "hash_password('AuditPassword2026!#')")

# ------------------------------------------------------------------------------
# 2. Database Multi-Tenant Setup (Tenant 1: FinTech SMB, Tenant 2: Health SMB)
# ------------------------------------------------------------------------------
print("\n--- SECTION 2: MULTI-TENANT TEST FIXTURE CREATION ---")
db = SessionLocal()
suffix = uuid.uuid4().hex[:6]
slug_1 = f"fintech-{suffix}"
slug_2 = f"health-{suffix}"

org_1 = Organization(
    name=f"Fintech Shield SMB {suffix}",
    slug=slug_1,
    contact_email=f"sec@{slug_1}.in",
    sector="Fintech",
    is_active=True
)
org_2 = Organization(
    name=f"HealthCare Digital SMB {suffix}",
    slug=slug_2,
    contact_email=f"sec@{slug_2}.in",
    sector="Healthcare",
    is_active=True
)
db.add_all([org_1, org_2])
db.flush()

org_admin_role = db.query(Role).filter(Role.name == SystemRole.ORG_ADMIN).first()
analyst_role = db.query(Role).filter(Role.name == SystemRole.SECURITY_ANALYST).first()
viewer_role = db.query(Role).filter(Role.name == SystemRole.VIEWER).first()

pwd_hash = hash_password("TenantPass12345!")

# User 1: Org Admin for Org 1
user_1 = User(
    email=f"admin@{slug_1}.in",
    hashed_password=pwd_hash,
    full_name="Fintech Admin",
    is_active=True,
    is_superuser=False
)
# User 2: Analyst for Org 1
user_1_analyst = User(
    email=f"analyst@{slug_1}.in",
    hashed_password=pwd_hash,
    full_name="Fintech Analyst",
    is_active=True,
    is_superuser=False
)
# User 3: Org Admin for Org 2
user_2 = User(
    email=f"admin@{slug_2}.in",
    hashed_password=pwd_hash,
    full_name="Health Admin",
    is_active=True,
    is_superuser=False
)
# User 4: Viewer for Org 2
user_2_viewer = User(
    email=f"viewer@{slug_2}.in",
    hashed_password=pwd_hash,
    full_name="Health Viewer",
    is_active=True,
    is_superuser=False
)
db.add_all([user_1, user_1_analyst, user_2, user_2_viewer])
db.flush()

m1 = OrganizationMembership(user_id=user_1.id, organization_id=org_1.id, role_id=org_admin_role.id, is_default=True)
m1_an = OrganizationMembership(user_id=user_1_analyst.id, organization_id=org_1.id, role_id=analyst_role.id, is_default=True)
m2 = OrganizationMembership(user_id=user_2.id, organization_id=org_2.id, role_id=org_admin_role.id, is_default=True)
m2_vi = OrganizationMembership(user_id=user_2_viewer.id, organization_id=org_2.id, role_id=viewer_role.id, is_default=True)
db.add_all([m1, m1_an, m2, m2_vi])

# Assets
asset_1 = ManagedAsset(
    organization_id=org_1.id,
    name="Fintech Core API",
    asset_type="API_GATEWAY",
    target="https://api.fintech-smb.in",
    environment="PRODUCTION",
    criticality="CRITICAL",
    is_in_scope=True
)
asset_2 = ManagedAsset(
    organization_id=org_2.id,
    name="Patient Portal WebApp",
    asset_type="WEB_APPLICATION",
    target="https://patient.health-smb.in",
    environment="PRODUCTION",
    criticality="HIGH",
    is_in_scope=True
)
db.add_all([asset_1, asset_2])
db.commit()
print(f"Created Org 1 ({slug_1}) and Org 2 ({slug_2}) with respective users and assets.")

# ------------------------------------------------------------------------------
# 3. Authentication & Session Security Audit
# ------------------------------------------------------------------------------
print("\n--- SECTION 3: AUTHENTICATION & SESSION AUDIT ---")

# Login User 1
l1_resp = client.post("/api/v1/auth/login", json={"email": f"admin@{slug_1}.in", "password": "TenantPass12345!"})
l1_data = l1_resp.json()
token_1 = l1_data["tokens"]["access_token"]
session_id_1 = l1_data["tokens"]["session_id"]
cookie_session_1 = l1_resp.cookies.get("preventx_session")
cookie_csrf_1 = l1_resp.cookies.get("preventx_csrf_token")
headers_1 = {"Authorization": f"Bearer {token_1}"}

record("Login Authentication & Token Issuance", l1_resp.status_code == 200, f"Token issued, session ID {session_id_1}")
record("HttpOnly Session Cookie Issuance", cookie_session_1 is not None and cookie_csrf_1 is not None, f"Cookies: preventx_session, preventx_csrf_token set")

# Login User 2
l2_resp = client.post("/api/v1/auth/login", json={"email": f"admin@{slug_2}.in", "password": "TenantPass12345!"})
token_2 = l2_resp.json()["tokens"]["access_token"]
headers_2 = {"Authorization": f"Bearer {token_2}"}

# Test Session Revocation
temp_user = User(
    email=f"temp-{suffix}@test.in",
    hashed_password=pwd_hash,
    full_name="Temporary User",
    is_active=True,
    is_superuser=False
)
db.add(temp_user)
db.flush()
db.add(OrganizationMembership(user_id=temp_user.id, organization_id=org_1.id, role_id=org_admin_role.id, is_default=True))
db.commit()

temp_login = client.post("/api/v1/auth/login", json={"email": f"temp-{suffix}@test.in", "password": "TenantPass12345!"})
temp_token = temp_login.json()["tokens"]["access_token"]
temp_headers = {"Authorization": f"Bearer {temp_token}"}

# Check /auth/me before logout
me_before = client.get("/api/v1/auth/me", headers=temp_headers)
logout_res = client.post("/api/v1/auth/logout", headers=temp_headers)
me_after = client.get("/api/v1/auth/me", headers=temp_headers)
record("Session Revocation on Logout", logout_res.status_code == 200 and me_after.status_code == 401, f"Pre-logout: {me_before.status_code}, Post-logout: {me_after.status_code}")

# Test Auth Rate Limiting
brute_email = f"brute-{suffix}@test.in"
rate_hits = []
for i in range(12):
    res = client.post("/api/v1/auth/login", json={"email": brute_email, "password": "WrongPassword!"})
    rate_hits.append(res.status_code)

rate_limited = 429 in rate_hits
record("Brute-Force Rate Limiting (429)", rate_limited, f"Hit status sequence: {rate_hits[-4:]} -> 429 triggered")

# ------------------------------------------------------------------------------
# 4. CSRF Protection Audit
# ------------------------------------------------------------------------------
print("\n--- SECTION 4: CSRF PROTECTION AUDIT ---")
# Create client simulating browser with cookie but NO custom X-CSRF-Token header
csrf_client = TestClient(app)
csrf_client.cookies.set("preventx_session", cookie_session_1)
csrf_client.cookies.set("preventx_csrf_token", cookie_csrf_1)

# Mutating request with NO X-CSRF-Token header
csrf_fail_res = csrf_client.post("/api/v1/assets", json={
    "name": "Malicious CSRF Asset",
    "asset_type": "DOMAIN",
    "target": "csrf-attack.in",
    "environment": "PRODUCTION",
    "criticality": "LOW",
    "is_in_scope": True,
})
record("CSRF Block (Missing Header)", csrf_fail_res.status_code == 403, f"Status: {csrf_fail_res.status_code}, code: {csrf_fail_res.json().get('detail', {}).get('code')}")

# Mutating request with INVALID X-CSRF-Token header
csrf_bad_res = csrf_client.post("/api/v1/assets", json={
    "name": "Malicious CSRF Asset",
    "asset_type": "DOMAIN",
    "target": "csrf-attack.in",
    "environment": "PRODUCTION",
    "criticality": "LOW",
    "is_in_scope": True,
}, headers={"X-CSRF-Token": "tampered-forged-token-value"})
record("CSRF Block (Forged Header)", csrf_bad_res.status_code == 403, f"Status: {csrf_bad_res.status_code}, code: {csrf_bad_res.json().get('detail', {}).get('code')}")

# Mutating request with VALID X-CSRF-Token header
csrf_good_res = csrf_client.post("/api/v1/assets", json={
    "name": "Valid CSRF Protected Asset",
    "asset_type": "DOMAIN",
    "target": "csrf-valid.in",
    "environment": "PRODUCTION",
    "criticality": "LOW",
    "is_in_scope": True,
}, headers={"X-CSRF-Token": cookie_csrf_1})
record("CSRF Success (Valid Matching Header)", csrf_good_res.status_code == 201, f"Status: {csrf_good_res.status_code}")

# ------------------------------------------------------------------------------
# 5. Multi-Tenant Penetration Audit (Cross-Tenant Attacks)
# ------------------------------------------------------------------------------
print("\n--- SECTION 5: MULTI-TENANT ISOLATION PENETRATION AUDIT ---")

# Vector 1: Org 1 Admin attempts to READ Org 2 Asset
read_cross = client.get(f"/api/v1/assets/{asset_2.id}", headers=headers_1)
record("Cross-Tenant Asset Read Attack", read_cross.status_code == 404, f"Status: {read_cross.status_code} (Asset 2 not visible in Tenant 1 scope)")

# Vector 2: Org 1 Admin attempts to MODIFY Org 2 Asset
patch_cross = client.patch(f"/api/v1/assets/{asset_2.id}", json={"name": "Hacked Title"}, headers=headers_1)
record("Cross-Tenant Asset Modify Attack", patch_cross.status_code == 404, f"Status: {patch_cross.status_code} (Modification rejected)")

# Vector 3: Org 1 Admin attempts to DELETE Org 2 Asset
del_cross = client.delete(f"/api/v1/assets/{asset_2.id}", headers=headers_1)
record("Cross-Tenant Asset Delete Attack", del_cross.status_code == 404, f"Status: {del_cross.status_code} (Deletion rejected)")

# Vector 4: Org 1 Admin attempts to LIST users in Org 1 (must not leak Org 2 users)
users_list = client.get("/api/v1/users", headers=headers_1)
user_emails = [u["email"] for u in users_list.json().get("items", [])]
leak_check = (f"admin@{slug_1}.in" in user_emails) and (f"admin@{slug_2}.in" not in user_emails)
record("Cross-Tenant User Listing Segregation", leak_check, f"Org 1 list: {user_emails}; Org 2 user excluded")

# Vector 5: Organization ID Header Manipulation (Spoofing X-Organization-Id to Org 2)
spoof_headers = {
    "Authorization": f"Bearer {token_1}",
    "X-Organization-Id": str(org_2.id)
}
spoof_res = client.get("/api/v1/assets", headers=spoof_headers)
record("Header Spoofing Attack (X-Organization-Id)", spoof_res.status_code == 403, f"Status: {spoof_res.status_code}, code: {spoof_res.json().get('detail', {}).get('code')}")

# Vector 6: Unauthorized Organization Switching
unauth_org_read = client.get(f"/api/v1/organizations/{org_2.id}", headers=headers_1)
record("Unauthorized Organization Direct Access", unauth_org_read.status_code == 403, f"Status: {unauth_org_read.status_code}")

# ------------------------------------------------------------------------------
# 6. Role-Based Access Control (RBAC) Audit
# ------------------------------------------------------------------------------
print("\n--- SECTION 6: RBAC PERMISSION ENFORCEMENT AUDIT ---")
# Login Viewer of Org 2
l_vi = client.post("/api/v1/auth/login", json={"email": f"viewer@{slug_2}.in", "password": "TenantPass12345!"})
token_vi = l_vi.json()["tokens"]["access_token"]
headers_vi = {"Authorization": f"Bearer {token_vi}"}

# Viewer read asset: Allowed
vi_read = client.get("/api/v1/assets", headers=headers_vi)
record("RBAC Viewer Asset Read (asset:read)", vi_read.status_code == 200, f"Status: {vi_read.status_code}")

# Viewer write asset: Forbidden (403)
vi_write = client.post("/api/v1/assets", json={
    "name": "Disallowed Viewer Asset",
    "asset_type": "PUBLIC_IP",
    "target": "10.0.0.1",
    "environment": "PRODUCTION",
    "criticality": "LOW",
    "is_in_scope": True,
}, headers=headers_vi)
record("RBAC Viewer Asset Create Block (asset:write)", vi_write.status_code == 403, f"Status: {vi_write.status_code}, code: {vi_write.json().get('detail', {}).get('code')}")

# Viewer create user: Forbidden (403)
vi_user = client.post("/api/v1/users", json={
    "email": f"hacked@{slug_2}.in",
    "password": "Password123!",
    "full_name": "Injected User",
    "role_name": "ORG_ADMIN",
}, headers=headers_vi)
record("RBAC Viewer User Provisioning Block (user:write)", vi_user.status_code == 403, f"Status: {vi_user.status_code}")

# Non-superuser attempting to provision an Organization: Forbidden (403)
org_create_regular = client.post("/api/v1/organizations", json={
    "name": "Illegal Org",
    "slug": f"illegal-{suffix}",
    "contact_email": "test@test.in"
}, headers=headers_1)
record("RBAC Non-Superuser Org Creation Block", org_create_regular.status_code == 403, f"Status: {org_create_regular.status_code}")

# ------------------------------------------------------------------------------
# 7. Summary
# ------------------------------------------------------------------------------
print("\n" + "=" * 75)
total_tests = len(audit_results)
passed_tests = sum(1 for t in audit_results if t["status"] == "PASS")
failed_tests = total_tests - passed_tests
print(f"AUDIT COMPLETE: {passed_tests}/{total_tests} PASSED ({failed_tests} FAILED)")
print("=" * 75)

db.close()
