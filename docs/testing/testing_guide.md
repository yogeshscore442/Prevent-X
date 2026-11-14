# PREVENT-X Automated Testing Guide

Automated testing is mandatory for all PREVENT-X components. No test may be skipped, mocked to give false passes, or suppressed.

---

## 1. Test Architecture & Coverage

The test suite is structured into two tiers:
1. **Backend Integration & Security Tests (`backend/tests/`)**:
   - `test_auth.py`: Verifies Argon2id password hashing, admin bootstrap, login/logout, session creation, expiration, and database revocation.
   - `test_tenant_isolation.py`: Explicitly tests cross-tenant data boundaries, cross-tenant asset reads, deletions, updates, user leakage, and header spoofing.
   - `test_rbac.py`: Tests built-in roles (`SUPER_ADMIN`, `ORG_ADMIN`, `SECURITY_ANALYST`, `VIEWER`), unauthenticated access rejection, and granular permission enforcement.
   - `test_assets.py`: Tests authorized asset onboarding, input validation, and tenant scoping.
   - `test_audit_logs.py`: Verifies that security-critical actions generate immutable audit log records with IP and user context.
   - `test_health.py`: Verifies `/health`, `/ready`, and `/system/info` module catalog statuses.
   - `test_organizations.py`: Tests tenant organization creation and authorization.
   - `test_security_controls.py`: Tests security headers, sliding-window rate limiting, and double-submit CSRF protection.

2. **Frontend Component & Unit Tests (`frontend/tests/`)**:
   - `login.test.tsx`: Tests rendering of authentication forms, credentials input, and form submission.
   - `dashboard.test.tsx`: Tests multi-tenant dashboard rendering, module availability catalog, and absence of fabricated security statistics.

---

## 2. Execution Commands

### Run Full Backend Pytest Suite:
```bash
# From workspace root
.\.venv\Scripts\python.exe -m pytest backend/tests -v
```

### Run Frontend Vitest Suite:
```bash
# From workspace root
cd frontend
npm test
```

### Run Code Quality & Linter Checks:
```bash
# Python Ruff & Mypy
.\.venv\Scripts\ruff.exe check backend
.\.venv\Scripts\mypy.exe backend/app

# Frontend TypeScript Check
cd frontend
npm run build
```
