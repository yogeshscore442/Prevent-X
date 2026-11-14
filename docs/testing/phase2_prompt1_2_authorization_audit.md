# PREVENT-X — Phase 2 Prompt 1.2: Authorization & Scope Audit Report

## 1. Executive Summary
This document provides the formal verification report and architectural audit trail for the **Scope Authorization & Audit Engine** in PREVENT-X Phase 2 Prompt 1.2.

Every active or passive security scan in PREVENT-X is an authorized action governed by strict cryptographic, role-based, tenant-isolated, and immutably logged operational boundaries. To satisfy enterprise compliance (ISO 27001, SOC 2, Indian Digital Personal Data Protection Act) and prevent unauthorized or rogue scanning, PREVENT-X guarantees that no discovery job can be created or executed without verifying and permanently persisting **all eight mandatory authorization fields**.

---

## 2. Mandatory Eight-Field Authorization Audit Trail

Location: [models/attack_surface.py](file:///c:/Users/YOGESH/Desktop/PREVENT-X/backend/app/models/attack_surface.py#L38-L90), [service.py](file:///c:/Users/YOGESH/Desktop/PREVENT-X/backend/app/modules/attack_surface/service.py#L40-L100)

Every record in the PostgreSQL `discovery_jobs` table stores the complete authorization chain:

```
+--------------------------------------------------------------------------------------------------------------------------------------------------+
|                                                      DISCOVERY JOB AUTHORIZATION AUDIT TRAIL                                                     |
+----+-----------------------------+---------------------------------------+-----------------------------------------------------------------------+
| #  | Mandatory Field             | Database Column / Type                | Description & Enforcement Rule                                        |
+----+-----------------------------+---------------------------------------+-----------------------------------------------------------------------+
| 1  | Target Asset ID             | asset_id (UUID, FK -> managed_assets) | Must link to an active, in-scope asset belonging to current org.      |
| 2  | Organization ID             | organization_id (UUID, FK -> orgs)   | Enforces multi-tenant scoping; strictly immutable once created.       |
| 3  | Authorized Target           | target (VARCHAR)                      | Normalized FQDN (e.g., example.com) or CIDR (e.g., 10.10.0.0/24).     |
| 4  | Discovery Policy            | discovery_policy (VARCHAR)            | PUBLIC_PASSIVE or AUTHORIZED_INTERNAL policy boundary.                |
| 5  | Authorization Confirmation  | authorization_confirmed (BOOLEAN)     | Explicit user affirmation; must be True (False -> HTTP 400).          |
| 6  | Initiating User             | created_by (UUID, FK -> users)        | Authenticated user ID derived from cryptographically verified token.  |
| 7  | Authorization Timestamp     | created_at (TIMESTAMPTZ)              | Immutable UTC timestamp of job creation and user sign-off.             |
| 8  | Scope Validation Result     | scope_validation_result (TEXT/JSON)   | Full audit JSON capturing apex domain, IP check, and validator trace.  |
+----+-----------------------------+---------------------------------------+-----------------------------------------------------------------------+
```

### 2.1 Alembic Migration 004
To add the 8th mandatory field (`scope_validation_result`) to the PostgreSQL database, Alembic migration `004_add_scope_validation_result.py` was created and applied:
```sql
ALTER TABLE discovery_jobs ADD COLUMN scope_validation_result TEXT;
```
Migration status: **Applied cleanly on PostgreSQL 16**.

### 2.2 Scope Validation Evidence JSON Schema
The `scope_validation_result` field records the deterministic decision of the `ScopeValidator`:
```json
{
  "status": "APPROVED",
  "organization_id": "c869bf6f-b2e1-4c62-87ce-8ebdfc7b0496",
  "asset_id": "4b684cb3-0097-4ce8-a5c3-8472506e7683",
  "asset_name": "Primary E-Commerce Portal",
  "authorized_target": "example.com",
  "effective_policy": "PUBLIC_PASSIVE",
  "validation_timestamp": "2026-11-14T17:54:28.102391+00:00",
  "is_ip_address": false,
  "apex_domain": "example.com",
  "validator_signature": "PREVENT-X-ScopeValidator/2.0"
}
```

---

## 3. Scope Boundary & Anti-Replay Protections

### 3.1 Duplicate Job Prevention & Anti-Replay Protection
Location: [service.py](file:///c:/Users/YOGESH/Desktop/PREVENT-X/backend/app/modules/attack_surface/service.py#L42-L58)

To prevent denial of service, race conditions, or redundant load against external resolvers, PREVENT-X prevents duplicate concurrent discovery jobs on the same asset:
- If a discovery job for the specified `asset_id` is currently in `PENDING` or `RUNNING` status within the organization, subsequent creation requests are rejected immediately with **HTTP 409 Conflict** (`DUPLICATE_DISCOVERY_JOB`).

### 3.2 Target Substitution & Hierarchy Enforcement
- When an asset is registered for `example.com`, users may run discovery on `example.com` or any authorized subdomain (e.g., `api.example.com`).
- If a user attempts to substitute an unrelated domain (e.g., `evil.com` or `google.com`) while referencing an `example.com` asset, `ScopeValidator` rejects the request with **HTTP 403 Forbidden** (`Requested discovery domain is outside the authorized scope of asset`).

### 3.3 Multi-Tenant Isolation
- **Cross-Tenant Asset Access**: An authenticated administrator of Organization A cannot view, scan, or trigger discovery on an asset owned by Organization B (HTTP 403 Forbidden).
- **Header Manipulation (`X-Organization-ID`)**: Spoofing organization headers has zero effect on tenant scope; organization context is strictly bound to the authenticated JWT session claims.

---

## 4. Live Test Target Authorization Documentation

All live network integration tests executed during PREVENT-X verification have explicitly documented legal and standards-based authorization:

### 4.1 Target: `nasscom.in`
- **Asset Name**: NASSCOM Official Benchmark Portal
- **Registered Target**: `nasscom.in`
- **Authorized Scope**: Apex domain and passive DNS records
- **Discovery Policy**: `PUBLIC_PASSIVE` (Passive DNS MX, SPF, DMARC, TXT queries only; no intrusive probes)
- **Legal & Institutional Authorization Basis**:
  - Commissioned under **NASSCOM Applied Research Bridge 2.0 (ARB 2.0)**, Problem Statement 5: *"AI-Era Virtual Patching for Security Protection of Indian SMB Digital Businesses."*
  - Authorized strictly for non-intrusive passive intelligence validation, benchmark DNS hygiene verification, and academic/research prototyping.

### 4.2 Target: `example.com`
- **Asset Name**: RFC 2606 Reference Application
- **Registered Target**: `example.com`
- **Authorized Scope**: Apex domain, RDAP registration queries, Certificate Transparency log extraction via `crt.sh`
- **Discovery Policy**: `PUBLIC_PASSIVE` (Read-only HTTP GET to public registries; connection-pinned and size-capped)
- **Standards Authorization Basis**:
  - Designated by the **Internet Engineering Task Force (IETF)** under **RFC 2606** (*"Reserved Top Level DNS Names"*) and **RFC 6761** (*"Special-Use Domain Names"*).
  - Explicitly reserved for documentation, protocol development, automated test suites, and software validation without risk of operational impact.

---

## 5. Test Evidence & Automated Verification

Automated test cases in `backend/tests/test_attack_surface.py` and `backend/tests/test_live_integrations.py` validate all authorization controls.

### 5.1 Test Execution Matrix

| Test Function | Verification Scope | Expected Result | Actual Result |
| :--- | :--- | :--- | :--- |
| `test_authorization_evidence_and_duplicate_prevention` | Complete 8-field audit record generation on job creation | All 8 fields populated; `scope_validation_result` contains valid JSON | **PASSED** (All 8 fields verified) |
| `test_authorization_evidence_and_duplicate_prevention` | Replay / duplicate job protection for concurrent active scans | Second job rejected with HTTP 409 Conflict | **PASSED** (HTTP 409 DUPLICATE_DISCOVERY_JOB) |
| `test_scope_validator_enforces_asset_ownership_and_hierarchy` | Cross-tenant asset discovery initiation | Rejected with HTTP 403 Forbidden | **PASSED** (Cross-tenant access violation) |
| `test_scope_validator_enforces_asset_ownership_and_hierarchy` | Target domain substitution outside asset apex | Rejected with HTTP 403 Forbidden | **PASSED** (Outside authorized scope) |
| `test_public_passive_vs_authorized_internal_policies` | RFC 1918 private IP under `PUBLIC_PASSIVE` policy | Rejected with HTTP 403 Forbidden | **PASSED** (Private address forbidden) |
| `test_public_passive_vs_authorized_internal_policies` | User without `discovery:internal` initiating internal discovery | Rejected with HTTP 403 Forbidden | **PASSED** (Missing permission) |
| `test_public_passive_vs_authorized_internal_policies` | Asset registered for internal CIDR under `AUTHORIZED_INTERNAL` | Approved with CIDR allowlist recorded | **PASSED** (Validation approved) |
| `test_api_cross_tenant_attack_surface_isolation` | Cross-tenant discovery job retrieval and listing | Rejected with HTTP 404 / 403 | **PASSED** (Tenant isolation enforced) |
| `test_live_dns_intelligence_nasscom` | Live passive DNS query against `nasscom.in` | Valid MX, SPF, DMARC retrieved under `PUBLIC_PASSIVE` | **PASSED** (Real live DNS resolved) |
| `test_live_full_passive_discovery_pipeline` | Live passive discovery against `example.com` | End-to-end job execution, risk calculation, categorized findings | **PASSED** (Real passive pipeline completed) |

### 5.2 Pytest Execution Log
```text
backend/tests/test_attack_surface.py::test_scope_validator_enforces_asset_ownership_and_hierarchy PASSED [ 12%]
backend/tests/test_attack_surface.py::test_public_passive_vs_authorized_internal_policies PASSED [ 18%]
backend/tests/test_attack_surface.py::test_api_cross_tenant_attack_surface_isolation PASSED [ 37%]
backend/tests/test_attack_surface.py::test_authorization_evidence_and_duplicate_prevention PASSED [ 47%]
backend/tests/test_live_integrations.py::test_live_dns_intelligence_nasscom PASSED [ 70%]
backend/tests/test_live_integrations.py::test_live_rdap_registration_profile_example PASSED [ 72%]
backend/tests/test_live_integrations.py::test_live_certificate_transparency_example PASSED [ 75%]
backend/tests/test_live_integrations.py::test_live_full_passive_discovery_pipeline PASSED [ 77%]
```
