# Authentication & Session Security Design

## 1. Password Security with Argon2id
PREVENT-X implements **Argon2id**, the winner of the Password Hashing Competition (PHC) and recommended standard by OWASP and NIST.

### Cryptographic Parameters
- **Type**: `Argon2id` (hybrid of Argon2d and Argon2i, resistant to side-channel and GPU cracking attacks).
- **Time Cost (Iterations)**: 3
- **Memory Cost**: 65,536 KiB (64 MiB)
- **Parallelism**: 4 lanes / threads
- **Hash Length**: 32 bytes

Plaintext passwords are never logged, never cached in memory, and never persisted.

---

## 2. Session Management Lifecycle

```mermaid
sequenceDiagram
    actor User as Browser / Operator
    participant API as FastAPI Backend
    participant Auth as AuthService
    participant DB as Database (user_sessions)
    participant Audit as Audit Logger

    User->>API: POST /api/v1/auth/login {email, password}
    API->>Auth: login(email, password)
    Auth->>DB: Query user & verify Argon2id hash
    Auth->>DB: Insert active session into user_sessions
    Auth->>Audit: Record AUTH_LOGIN_SUCCESS
    Auth-->>API: (session_token, jwt_token, user_me)
    API-->>User: Set-Cookie: preventx_session (HttpOnly)<br/>Set-Cookie: preventx_csrf_token<br/>Return JWT Access Token in JSON

    Note over User,API: Subsequent Mutating Request (e.g. POST /assets)
    User->>API: POST /api/v1/assets [Headers: X-CSRF-Token] [Cookie: preventx_session]
    API->>DB: Validate session_token exists, active=True, not revoked, expires_at > now
    API->>API: Validate X-CSRF-Token matches preventx_csrf_token cookie
    API-->>User: 201 Created

    Note over User,API: Logout
    User->>API: POST /api/v1/auth/logout
    API->>DB: Update user_sessions SET is_active=False, revoked_at=now()
    API->>Audit: Record AUTH_LOGOUT
    API-->>User: Clear Cookies (preventx_session, preventx_csrf_token)
```

---

## 3. Double-Submit CSRF Protection
To prevent Cross-Site Request Forgery while utilizing secure `HttpOnly` browser cookies:
1. Upon login, the backend issues an `HttpOnly` cookie (`preventx_session`) and a client-readable cookie (`preventx_csrf_token`).
2. The frontend reads `preventx_csrf_token` and includes it in the `X-CSRF-Token` HTTP header on all mutating requests (`POST`, `PUT`, `PATCH`, `DELETE`).
3. `CSRFMiddleware` verifies that the `X-CSRF-Token` header exactly matches the `preventx_csrf_token` cookie via constant-time string comparison (`hmac.compare_digest`).
4. Requests using explicit `Authorization: Bearer <token>` are exempt from CSRF checks because web browsers do not automatically attach custom Authorization headers cross-origin.
