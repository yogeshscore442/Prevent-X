# PREVENT-X Troubleshooting & Diagnostics Guide

## 1. Common Diagnostics & Solutions

### Issue: "email-validator is not installed"
- **Cause**: Pydantic's `EmailStr` requires the optional `email-validator` package.
- **Solution**: Run `pip install "email-validator>=2.1.0"` or ensure `pydantic[email]` is installed in your virtual environment.

### Issue: "can't compare offset-naive and offset-aware datetimes"
- **Cause**: SQLite persists datetimes as strings without timezones, while Python's `datetime.now(timezone.utc)` creates timezone-aware objects.
- **Solution**: PREVENT-X models normalize SQLite naive datetimes using `exp = exp.replace(tzinfo=timezone.utc)` prior to comparison.

### Issue: "CSRF token missing from request (HTTP 403)"
- **Cause**: A state-changing browser request (`POST`, `PUT`, `DELETE`) was made using cookie authentication without providing the matching `X-CSRF-Token` header.
- **Solution**: Ensure your client extracts the `preventx_csrf_token` cookie and sends it in the `X-CSRF-Token` HTTP header. Alternatively, pass an `Authorization: Bearer <token>` header, which automatically bypasses browser CSRF verification.

### Issue: "Redis client connection failed"
- **Cause**: Redis server is not running on localhost or inside container.
- **Solution**: PREVENT-X backend is resilient by design: if Redis is unavailable, the readiness check `/api/v1/ready` reports Redis as `DOWN`, but the core API and database remain fully operational without crashing. To start Redis locally, launch `docker compose up -d redis`.

### Issue: "TENANT_ACCESS_DENIED (HTTP 403)"
- **Cause**: The authenticated user attempted to specify an `X-Organization-Id` for an organization in which they do not hold an active membership.
- **Solution**: Verify the user's memberships via `GET /api/v1/auth/me`. Only platform superusers may switch between arbitrary tenant organizations.

