# PREVENT-X — Attack Surface Authorization & Scope Validation Model

## 1. Multi-Tenant Authorization Enforcement

PREVENT-X strictly enforces tenant isolation and authorization boundaries across all attack surface operations:

1. **Authenticated Context**: Every request requires a valid user session or Bearer JWT token.
2. **Organization Scoping**: The request must supply a valid `X-Organization-Id` header matching an active organization membership.
3. **RBAC Permissions**:
   - `discovery:read`: Required to list discovery jobs, view discovered domains, inspect DNS/certificate evidence, and review exposure findings.
   - `discovery:create`: Required to initiate new passive discovery jobs.
   - `discovery:cancel`: Required to abort in-flight discovery runs.

---

## 2. Asset Scope Validation Boundary

The `ScopeValidator` enforces a multi-layered gate prior to creating or executing any discovery job:

```
[User Request]
      │
      ├─► 1. Check authorization_confirmed == True? ──(No)──► Reject HTTP 403
      │
      ├─► 2. Does asset belong to active organization? ─(No)─► Reject HTTP 403/404
      │
      ├─► 3. Is asset flagged in-scope (is_in_scope == True)? ─(No)─► Reject HTTP 403
      │
      ├─► 4. Does target pass SSRF and Forbidden Network checks? ─(No)─► Reject HTTP 403
      │
      ├─► 5. Does target match or fall under asset apex scope? ─(No)─► Reject HTTP 403
      │
      ▼ (All Passed)
[Approved for Discovery Execution]
```

### Target Domain Hierarchy Matching
- If asset target is registered as `portal.smbclient.in`, the user may discover:
  - `portal.smbclient.in` (exact match)
  - `*.portal.smbclient.in` (subdomain of asset target)
  - `smbclient.in` (if asset target covers the apex domain)
- If the user provides an arbitrary or competitor domain (e.g. `competitor.com`, `victimcorp.in`), the request is strictly blocked with `HTTP 403 Forbidden` (`Outside the authorized scope of asset`).

---

## 3. Server-Side Request Forgery (SSRF) & Internal IP Defenses

Adversaries might attempt to abuse the discovery engine to scan internal SMB subnets or cloud hypervisor metadata endpoints. `ScopeValidator` categorically rejects:

1. **RFC 1918 Private IPv4 Ranges**:
   - `10.0.0.0/8`
   - `172.16.0.0/12`
   - `192.168.0.0/16`
2. **Loopback & Local Addresses**:
   - `127.0.0.0/8`
   - `::1`
3. **Link-Local & Cloud Hypervisor Metadata**:
   - `169.254.0.0/16` (including `169.254.169.254` AWS/GCP/Azure instance metadata)
   - `fe80::/10`
4. **Multicast and Reserved Networks**:
   - `224.0.0.0/4`, `ff00::/8`
   - `0.0.0.0/8`, `240.0.0.0/4`
5. **Non-Routable & Internal TLDs**:
   - `.local`, `.internal`, `.localhost`, `.lan`, `.home`, `.corp`, `.test`, `.example`, `.invalid`

---

## 4. Audit Logging and Attribution

Every discovery job creation and cancellation generates an immutable `AuditEvent` record capturing:
- `organization_id`
- `user_id` (initiating user)
- `action`: `DISCOVERY_JOB_CREATED` or `DISCOVERY_JOB_CANCELLED`
- `resource_type`: `discovery_job`
- `resource_id`: Job UUID
- `details`: JSON payload containing target domain, asset ID, asset name, and timestamp.
