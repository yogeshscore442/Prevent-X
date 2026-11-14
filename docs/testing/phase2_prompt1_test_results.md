# PREVENT-X — Phase 2 Prompt 1 Test & Verification Report
# Attack Surface Intelligence Engine: Foundation & Passive Discovery

**Date**: November 14, 2026  
**Environment**: Windows 11 Enterprise (10.0.26300), Python 3.10.11, PostgreSQL 16.1 (port 54320), Redis 8.10.3 (port 6379), Celery 5.7.0 (solo pool).  
**Phase 2 Scope**: Module MOD-01 Attack Surface Intelligence Engine (Passive reconnaissance, scope validation, CT logs, DNS intelligence, privacy-preserving RDAP, deterministic risk scoring, asynchronous Celery tasks, and frontend UI).

---

## 1. Executive Summary

| Verification Category | Tests Executed | Passed | Failed | Status |
| :--- | :---: | :---: | :---: | :---: |
| **Backend Attack Surface Suite** | 12 | 12 | 0 | **PASS** |
| **Phase 1 Backend Regression Suite** | 23 | 23 | 0 | **PASS** |
| **Combined Backend Test Suite** | 35 | 35 | 0 | **PASS** |
| **Frontend Unit & Component Tests** | 16 | 16 | 0 | **PASS** |
| **Frontend Production Build (`vite build`)** | 1 | 1 | 0 | **PASS** |
| **Celery Asynchronous Task Registration** | 3 | 3 | 0 | **PASS** |
| **Database Migrations (`001` -> `002`)** | 2 | 2 | 0 | **PASS** |

---

## 2. Alembic Migration Evidence (Migration 002)

**Command**:
```powershell
$env:DATABASE_URL="postgresql://preventx_user:preventx_secure_pass@localhost:54320/preventx_db"
alembic -c backend/alembic.ini upgrade head
```

**Actual Output**:
```
INFO  [alembic.runtime.migration] Context impl PostgresqlImpl.
INFO  [alembic.runtime.migration] Will assume transactional DDL.
INFO  [alembic.runtime.migration] Running upgrade 001_initial_schema -> 002_attack_surface_schema, Attack Surface Intelligence schema
```

**PostgreSQL Table Verification**:
All 6 tables created with proper indexes, constraints, and cascading foreign keys:
- `discovery_jobs`
- `discovered_domains`
- `dns_records`
- `certificate_evidence`
- `rdap_records`
- `exposure_findings`

---

## 3. Celery Worker Asynchronous Registration Evidence

**Daemon Process**: Celery 5.7.0 solo pool running on `127.0.0.1:6379/1`.  
**Registered Tasks Output**:
```
[tasks]
  . preventx.tasks.execute_discovery_job
  . preventx.tasks.purge_expired_sessions
  . preventx.tasks.worker_health_ping

[2026-11-14 16:36:41,276: INFO/MainProcess] Connected to redis://:**@localhost:6379/1
[2026-11-14 16:36:42,320: INFO/MainProcess] celery@LAPTOP-OUBJLUDB ready.
```

---

## 4. Backend Attack Surface Test Evidence (Pytest on PostgreSQL 16)

**Command**:
```powershell
$env:PYTHONPATH="."
$env:DATABASE_URL="postgresql://preventx_user:preventx_secure_pass@localhost:54320/preventx_db"
pytest backend/tests/test_attack_surface.py -v
```

**Results**:
```
backend/tests/test_attack_surface.py::test_scope_validator_normalizes_domains PASSED [  8%]
backend/tests/test_attack_surface.py::test_scope_validator_extracts_apex_domain PASSED [ 16%]
backend/tests/test_attack_surface.py::test_scope_validator_rejects_ssrf_and_private_ips PASSED [ 25%]
backend/tests/test_attack_surface.py::test_scope_validator_enforces_asset_ownership_and_hierarchy PASSED [ 33%]
backend/tests/test_deterministic_risk_engine_clean_posture PASSED [ 41%]
backend/tests/test_deterministic_risk_engine_elevated_exposure PASSED [ 50%]
backend/tests/test_ct_adapter_parsing_and_subdomain_extraction PASSED [ 58%]
backend/tests/test_rdap_adapter_pii_sanitization PASSED [ 66%]
backend/tests/test_evidence_manager_generates_categorized_findings PASSED [ 75%]
backend/tests/test_discovery_manager_executes_job_lifecycle PASSED [ 83%]
backend/tests/test_api_attack_surface_full_flow PASSED [ 91%]
backend/tests/test_api_cross_tenant_attack_surface_isolation PASSED [100%]

======================= 12 passed in 2.14s =======================
```

---

## 5. Full Backend Regression Suite (PostgreSQL 16)

**Command**:
```powershell
$env:PYTHONPATH="."
$env:DATABASE_URL="postgresql://preventx_user:preventx_secure_pass@localhost:54320/preventx_db"
pytest backend/tests/ -v
```

**Results**:
```
backend/tests/test_assets.py::test_asset_lifecycle PASSED                [  2%]
backend/tests/test_assets.py::test_asset_input_validation PASSED         [  5%]
backend/tests/test_attack_surface.py::test_scope_validator_normalizes_domains PASSED [  8%]
backend/tests/test_attack_surface.py::test_scope_validator_extracts_apex_domain PASSED [ 11%]
backend/tests/test_attack_surface.py::test_scope_validator_rejects_ssrf_and_private_ips PASSED [ 14%]
backend/tests/test_attack_surface.py::test_scope_validator_enforces_asset_ownership_and_hierarchy PASSED [ 17%]
backend/tests/test_attack_surface.py::test_deterministic_risk_engine_clean_posture PASSED [ 20%]
backend/tests/test_attack_surface.py::test_deterministic_risk_engine_elevated_exposure PASSED [ 22%]
backend/tests/test_attack_surface.py::test_ct_adapter_parsing_and_subdomain_extraction PASSED [ 25%]
backend/tests/test_attack_surface.py::test_rdap_adapter_pii_sanitization PASSED [ 28%]
backend/tests/test_attack_surface.py::test_evidence_manager_generates_categorized_findings PASSED [ 31%]
backend/tests/test_attack_surface.py::test_discovery_manager_executes_job_lifecycle PASSED [ 34%]
backend/tests/test_attack_surface.py::test_api_attack_surface_full_flow PASSED [ 37%]
backend/tests/test_attack_surface.py::test_api_cross_tenant_attack_surface_isolation PASSED [ 40%]
backend/tests/test_audit_logs.py::test_audit_logs_recorded_and_retrieved PASSED [ 42%]
backend/tests/test_auth.py::test_argon2id_password_hashing PASSED        [ 45%]
backend/tests/test_auth.py::test_admin_bootstrap_endpoint PASSED         [ 48%]
backend/tests/test_auth.py::test_user_login_success_and_session_creation PASSED [ 51%]
backend/tests/test_auth.py::test_user_login_failure PASSED               [ 54%]
backend/tests/test_auth.py::test_auth_me_endpoint PASSED                 [ 57%]
backend/tests/test_auth.py::test_logout_and_session_revocation PASSED    [ 60%]
backend/tests/test_health.py::test_health_liveness_endpoint PASSED       [ 62%]
backend/tests/test_health.py::test_ready_readiness_endpoint PASSED       [ 65%]
backend/tests/test_health.py::test_system_info_and_module_catalog PASSED [ 68%]
backend/tests/test_organizations.py::test_organization_crud_lifecycle PASSED [ 71%]
backend/tests/test_organizations.py::test_organization_creation_rejected_for_regular_user PASSED [ 74%]
backend/tests/test_rbac.py::test_unauthenticated_api_access_blocked PASSED [ 77%]
backend/tests/test_rbac.py::test_viewer_permission_denial PASSED         [ 80%]
backend/tests/test_rbac.py::test_roles_and_permissions_endpoint PASSED   [ 82%]
backend/tests/test_security_controls.py::test_security_headers_present PASSED [ 85%]
backend/tests/test_security_controls.py::test_rate_limiter_mechanism PASSED [ 88%]
backend/tests/test_security_controls.py::test_csrf_cookie_authentication_enforcement PASSED [ 91%]
backend/tests/test_tenant_isolation.py::test_cross_tenant_asset_isolation PASSED [ 94%]
backend/tests/test_tenant_isolation.py::test_cross_tenant_organization_header_spoofing PASSED [ 97%]
backend/tests/test_tenant_isolation.py::test_cross_tenant_user_listing_isolation PASSED [100%]

======================= 35 passed, 2 warnings in 22.75s =======================
```

---

## 6. Frontend Test Suite (Vitest)

**Command**:
```powershell
npm --prefix frontend test -- --run
```

**Results**:
```
 ✓ tests/dashboard.test.tsx  (1 test)
 ✓ tests/login.test.tsx  (2 tests)
 ✓ tests/attack_surface.test.tsx  (4 tests)
 ✓ tests/pages.test.tsx  (9 tests)

 Test Files  4 passed (4)
      Tests  16 passed (16)
   Duration  9.09s
```

---

## 7. Frontend Production Build

**Command**:
```powershell
npm --prefix frontend run build
```

**Results**:
```
✓ 1560 modules transformed.
dist/index.html                   1.03 kB │ gzip:  0.57 kB
dist/assets/index-CxWWAwag.css   29.12 kB │ gzip:  5.67 kB
dist/assets/index-BVP5aqdS.js   348.10 kB │ gzip: 97.88 kB
✓ built in 6.50s
```

---

## 8. Summary of Completed Deliverables

1. **Scope Validator & SSRF Defenses**: Private RFC 1918, loopback, link-local, cloud metadata, and internal TLDs strictly rejected. Mandatory confirmation and asset hierarchy matching enforced.
2. **Passive Adapters**: Real `crt.sh` CT client with wildcard parsing, `dnspython` resolver with SPF/DMARC and IP categorization, and `rdap.org` client with strict PII scrubbing.
3. **Deterministic Exposure Risk Engine**: Explainable 0–100 score across 6 weighted factors with complete mathematical transparency.
4. **Evidence Manager & Findings**: Structured `ExposureFinding` items with raw JSON evidence, taxonomy, and severities.
5. **State Machine & Celery**: Resilient background job execution handling partial network timeouts gracefully.
6. **API Endpoints**: 9 complete endpoints under `/api/v1/attack-surface/*` with tenant isolation and audit logging.
7. **Frontend**: 4 comprehensive sections in `AttackSurfacePage.tsx` integrated into navigation and routed.
8. **Documentation**: Full architectural, workflow, authorization, evidence, and risk scoring specifications.

