# PREVENT-X REST API Specification (v1)

All API endpoints are versioned under the `/api/v1` path prefix.
Interactive OpenAPI (Swagger) UI is accessible at `/api/v1/docs`.
ReDoc documentation is available at `/api/v1/redoc`.

---

## 1. System & Telemetry Endpoints

### `GET /api/v1/health`
- **Description**: Lightweight liveness probe for load balancers and orchestrators.
- **Authentication**: None.
- **Response `200 OK`**:
```json
{
  "status": "HEALTHY",
  "version": "1.0.0",
  "environment": "development",
  "timestamp": "2026-11-14T09:30:00Z"
}
```

### `GET /api/v1/ready`
- **Description**: Deep readiness probe verifying database query execution and Redis connectivity.
- **Authentication**: None.
- **Response `200 OK`**:
```json
{
  "ready": true,
  "database": {
    "status": "UP",
    "latency_ms": 1.25,
    "details": "Database connection verified"
  },
  "redis": {
    "status": "UP",
    "latency_ms": 0.85,
    "details": "Redis cluster/standalone operational"
  },
  "timestamp": "2026-11-14T09:30:00Z"
}
```

### `GET /api/v1/system/info`
- **Description**: Returns detailed platform runtime information, database backend dialect, and status of all 12 cybersecurity modules.
- **Authentication**: None.

---

## 2. Authentication & Session Endpoints

### `POST /api/v1/auth/bootstrap`
- **Description**: Secure first-run administrator provisioning. Requires pre-configured `BOOTSTRAP_TOKEN`.
- **Request Body**:
```json
{
  "bootstrap_token": "preventx-bootstrap-token-prod-2026",
  "email": "admin@preventx.internal",
  "password": "SuperSecurePassword123!",
  "full_name": "Lead Security Administrator",
  "initial_organization_name": "Default SMB Enterprise",
  "initial_organization_slug": "smb-default"
}
```
- **Response `201 Created`**:
```json
{
  "status": "SUCCESS",
  "message": "Administrator account and initial tenant organization bootstrapped successfully.",
  "user_id": "86cbc800-8515-4c85-9ed0-195267c2048d",
  "organization_id": "40cee75d-3e4b-4db3-8836-255991030622"
}
```

### `POST /api/v1/auth/login`
- **Description**: Authenticates user via Argon2id, creates server-side session, sets secure HttpOnly cookie and returns signed JWT access token.
- **Request Body**:
```json
{
  "email": "admin@preventx.internal",
  "password": "SuperSecurePassword123!",
  "organization_slug": "smb-default"
}
```
- **Response `200 OK`**: Returns user profile, access token payload, sets `preventx_session` (HttpOnly) and `preventx_csrf_token` cookies.

### `POST /api/v1/auth/logout`
- **Description**: Revokes the active session in database and clears authentication cookies.
- **Authentication**: Bearer token or HttpOnly session cookie + CSRF header.

### `GET /api/v1/auth/me`
- **Description**: Returns authenticated user profile, active tenant memberships, and assigned granular permissions.

---

## 3. Organization Management Endpoints

### `GET /api/v1/organizations`
- **Description**: Lists accessible tenant organizations for the current user. Superusers see all tenants; regular users see only their memberships.
- **Query Parameters**: `skip` (int, default 0), `limit` (int, default 50).

### `POST /api/v1/organizations`
- **Description**: Provisions a new SMB tenant organization.
- **Required Permission**: `is_superuser == True`.

### `GET /api/v1/organizations/{id}`
- **Description**: Retrieves organization profile by ID. Rejects cross-tenant access for non-superusers.

### `PATCH /api/v1/organizations/{id}`
- **Description**: Updates organization details.
- **Required Permission**: `org:write`.

---

## 4. User Management Endpoints

### `GET /api/v1/users`
- **Description**: Lists users belonging to the active tenant organization.
- **Required Permission**: `user:read`.

### `POST /api/v1/users`
- **Description**: Provisions or invites a user into the current tenant organization with assigned role.
- **Required Permission**: `user:write`.

---

## 5. Roles & Permissions Endpoints

### `GET /api/v1/roles`
- **Description**: Lists all system roles and their granted permissions.
- **Required Permission**: `role:read`.

### `GET /api/v1/roles/permissions`
- **Description**: Lists all granular security permissions grouped by module.
- **Required Permission**: `role:read`.

---

## 6. Managed Asset Endpoints

### `GET /api/v1/assets`
- **Description**: Lists authorized assets within current tenant protection scope.
- **Required Permission**: `asset:read`.

### `POST /api/v1/assets`
- **Description**: Registers a new authorized asset into tenant protection scope.
- **Required Permission**: `asset:write`.

### `GET /api/v1/assets/{id}`
- **Description**: Retrieves asset details. Strictly scoped to current organization.
- **Required Permission**: `asset:read`.

### `PATCH /api/v1/assets/{id}`
- **Description**: Updates asset properties.
- **Required Permission**: `asset:write`.

### `DELETE /api/v1/assets/{id}`
- **Description**: Removes asset from protection scope.
- **Required Permission**: `asset:delete`.

---

## 7. Audit Log Endpoints

### `GET /api/v1/audit-logs`
- **Description**: Queries immutable security audit events scoped to tenant.
- **Required Permission**: `audit:read`.

