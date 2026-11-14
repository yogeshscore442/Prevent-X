# ADR-003: Hybrid Session Management and Double-Submit CSRF Protection

## Status
Accepted

## Context
A cybersecurity platform must defend browser sessions against Cross-Site Scripting (XSS) credential theft while protecting state-changing actions from Cross-Site Request Forgery (CSRF). Pure local storage JWTs are vulnerable to XSS exfiltration, while purely stateless cookies are vulnerable to CSRF.

## Decision
We implemented a **hybrid security model**:
1. Browser sessions receive an `HttpOnly`, `SameSite=Lax` session cookie (`preventx_session`), preventing JavaScript access to session tokens.
2. The server creates an active record in `user_sessions` in the database, allowing instant session revocation on logout or security incidents.
3. A client-accessible cookie (`preventx_csrf_token`) is paired with an `X-CSRF-Token` HTTP header on all mutating requests (`POST`, `PUT`, `PATCH`, `DELETE`). `CSRFMiddleware` enforces matching values via constant-time comparison.
4. API and automation clients can alternatively supply an explicit `Authorization: Bearer <token>` header, which is immune to browser CSRF.

## Consequences
- **Positive**:
  - Maximum resistance to both XSS token theft and ambient-credential CSRF attacks.
  - Native server-side session invalidation upon operator logout.
- **Negative**:
  - Single-page application frontend must inspect cookies and attach the `X-CSRF-Token` header for API calls. Handled seamlessly by Axios interceptors.

