# PREVENT-X Security Design & Controls

## 1. Threat Model & Defense-in-Depth Architecture

PREVENT-X is engineered under a zero-implicit-trust model:
- **Perimeter Layer**: Reverse proxy (Nginx) strips malicious hop-by-hop headers, applies burst rate-limiting, and enforces TLS.
- **Transport & Browser Layer**: Strict OWASP security headers (CSP, HSTS, X-Frame-Options: DENY, X-Content-Type-Options: nosniff, Referrer-Policy).
- **Application Middleware Layer**:
  - Global IP sliding-window rate limiting.
  - Double-submit CSRF verification for state-changing browser cookie requests.
  - Sanitized, structured logging that scrubs credentials and sensitive headers.
- **Authentication Layer**: Modern Argon2id password hashing, single-use bootstrap tokens, and server-side session revocation.
- **Authorization & Multi-Tenancy Layer**: Granular RBAC, organization context resolution, and mandatory tenant-scoping on all data access queries.
- **Data Persistence Layer**: Parameterized ORM queries preventing SQL injection, UUID primary keys mitigating enumeration attacks, and explicit foreign key constraints.

---

## 2. OWASP Top 10 (2021) Alignment Matrix

| OWASP Threat Category | PREVENT-X Architectural Defense |
|:---|:---|
| **A01: Broken Access Control** | Enforced at repository and middleware levels. Every query to tenant-owned models includes `WHERE organization_id = :active_org_id`. Cross-tenant ID access returns 404 or 403. |
| **A02: Cryptographic Failures** | Passwords hashed with Argon2id ($argon2id$ with 64MB memory, 3 iterations, 4 parallelism). Secure random session tokens generated via `secrets.token_urlsafe(32)`. |
| **A03: Injection** | 100% parameterized queries via SQLAlchemy 2.0 ORM. Strict Pydantic v2 input schema validation. |
| **A04: Insecure Design** | Explicit asset authorization model: the system prohibits scanning or virtual patching of arbitrary IP/domain targets without verified asset ownership. |
| **A05: Security Misconfiguration** | Debug mode disabled in production Docker configurations. Nginx hides internal server version strings (`server_tokens off`). |
| **A06: Vulnerable & Outdated Components** | Pinned dependencies with automated vulnerability tracking; non-deprecated libraries. |
| **A07: Identification & Auth Failures** | Brute-force protection via sliding-window auth rate limiting (10 attempts/min). Session expiration (24h) and instant revocation. |
| **A08: Software & Data Integrity Failures** | Immutable audit logs tracking all administrative actions. Signed JWT tokens with HS256 validation. |
| **A09: Security Logging & Monitoring Failures** | Structured JSON logs with timestamp, user ID, tenant ID, action, and client IP. Database-backed audit trail. |
| **A10: Server-Side Request Forgery (SSRF)** | Asset onboarding requires explicit organization scoping and domain validation. |

