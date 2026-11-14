# PREVENT-X — Attack Surface Authorization & Scope Validation Model

## 1. Multi-Tenant Authorization & RBAC Enforcement

PREVENT-X strictly enforces tenant isolation and authorization boundaries across all attack surface operations:

1. **Authenticated Context**: Every request requires a valid user session or Bearer JWT token.
2. **Organization Scoping**: The request must supply a valid `X-Organization-Id` header matching an active organization membership.
3. **RBAC Permissions**:
   - `discovery:read`: List discovery jobs, view discovered domains, inspect DNS/certificate evidence, review exposure findings.
   - `discovery:create`: Initiate passive discovery jobs.
   - `discovery:cancel`: Abort in-flight discovery runs.
   - `discovery:internal`: Mandatory permission required to initiate discovery under the `AUTHORIZED_INTERNAL` policy.

---

## 2. Separate Discovery Policies: PUBLIC_PASSIVE vs. AUTHORIZED_INTERNAL

To accommodate Indian SMB deployment models without introducing SSRF vulnerabilities, PREVENT-X separates discovery into two distinct operational policies:

### Policy A: `PUBLIC_PASSIVE` (Default)
- **Scope**: Publicly accessible internet domain intelligence, Certificate Transparency logs, public DNS resolvers, and RDAP registration registries.
- **SSRF Restrictions**:
  - Strictly rejects all private RFC 1918 addresses (`10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`).
  - Rejects loopback addresses (`127.0.0.0/8`, `::1`).
  - Rejects cloud hypervisor metadata endpoints (`169.254.169.254`, `100.100.100.200`, `192.0.0.192`).
  - Rejects internal non-routable TLDs (`.local`, `.internal`, `.lan`, `.corp`, etc.).
  - Rejects all alternate IP encodings (decimal integers, octal, hex, IPv4-mapped IPv6).
- **Proactive Constraint**: Absolutely no active TCP/UDP connection is made to arbitrary discovered public or private IP addresses.

### Policy B: `AUTHORIZED_INTERNAL`
- **Scope**: Internal business domains and private IP ranges (`192.168.1.0/24`, `10.0.0.0/16`) for inventorying authorized on-premise or cloud VPC assets.
- **Strict Authorization Requirements**:
  1. The target asset must be explicitly registered under the organization with `asset_type` in `("INTERNAL_SERVER", "PRIVATE_NETWORK", "INTERNAL_NETWORK")` or with a private IP target.
  2. The initiating user must possess the explicit `discovery:internal` permission.
  3. The user must check the mandatory scope confirmation checkbox.
  4. The discovery target must fall strictly within the registered asset's CIDR allowlist (e.g. `10.50.0.0/16`). Targets outside the allowlist (e.g., `192.168.1.1`) are blocked with HTTP 403 Forbidden.
  5. Cloud hypervisor metadata (`169.254.169.254`) and loopback (`127.0.0.1`) remain **strictly prohibited** even under `AUTHORIZED_INTERNAL`.

---

## 3. Server-Side Request Forgery (SSRF) Defense Suite

The `SSRFDefense` module provides defense-in-depth against advanced SSRF and bypass techniques:

```
[Target String]
       │
       ▼
1. IP Syntax & Alternate Encoding Normalization
   ├─ Standard Dotted Decimal: 192.168.1.1
   ├─ Decimal Integer IP: 2130706433 -> 127.0.0.1 (Blocked)
   ├─ Dotted Octal Notation: 0177.0.0.1 -> 127.0.0.1 (Blocked)
   ├─ Dotted Hex Notation: 0x7f.0.0.1 -> 127.0.0.1 (Blocked)
   ├─ Hex Integer: 0x7f000001 -> 127.0.0.1 (Blocked)
   ├─ IPv4-Mapped IPv6: ::ffff:127.0.0.1 -> 127.0.0.1 (Blocked)
   ├─ IPv4-Compatible IPv6: ::127.0.0.1 -> 127.0.0.1 (Blocked)
   └─ 6to4 Address: 2002:7f00:0001:: -> 127.0.0.1 (Blocked)
       │
       ▼
2. Boundary Verification (SSRFDefense.is_ip_forbidden)
   ├─ Cloud Hypervisor Metadata: 169.254.169.254, 100.100.100.200, 192.0.0.192 (ALWAYS Blocked)
   ├─ Loopback: 127.0.0.0/8, ::1 (ALWAYS Blocked)
   ├─ Link-Local: 169.254.0.0/16, fe80::/10 (ALWAYS Blocked)
   ├─ Carrier-Grade NAT: 100.64.0.0/10 (Blocked)
   ├─ Multicast / Reserved: 224.0.0.0/4, 240.0.0.0/4 (Blocked)
   └─ RFC 1918 Private: 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16 (Blocked under PUBLIC_PASSIVE)
       │
       ▼
3. DNS Rebinding Defense (SSRFDefense.validate_dns_resolution)
   └─ Resolves hostname; if ANY resolved A or AAAA record resolves to a forbidden IP, request is rejected.
       │
       ▼
4. Safe HTTP Transport Gate (SSRFDefense.create_safe_client)
   ├─ Connect Timeout: 5.0 seconds
   ├─ Read Timeout: 10.0 seconds
   ├─ Response Payload Cap: 5 MB (prevents memory exhaustion bombs)
   ├─ Redirect Re-Validation: Every redirect hop inspects target host for SSRF violations.
   └─ Custom User-Agent: PREVENT-X-PassiveRecon/2.0
```

---

## 4. Audit Logging and Attribution

Every discovery job creation and cancellation generates an immutable `AuditEvent` record capturing:
- `organization_id`
- `user_id` (initiating user)
- `action`: `DISCOVERY_JOB_CREATED` or `DISCOVERY_JOB_CANCELLED`
- `resource_type`: `discovery_job`
- `resource_id`: Job UUID
- `details`: JSON payload containing target domain, discovery policy, asset ID, asset name, and timestamp.
