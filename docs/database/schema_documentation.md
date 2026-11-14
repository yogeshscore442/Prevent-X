# PREVENT-X Database Schema Documentation

## 1. Architectural Strategy
PREVENT-X utilizes a **discriminator-column tenant isolation architecture** with strict repository-level query filtering. All primary keys use platform-independent 128-bit UUIDs (GUIDs), generated using `uuid.uuid4()`.

Foreign key referential integrity is enforced at both the database level and the ORM level. In SQLite, `PRAGMA foreign_keys=ON` is automatically executed on connection initialization.

---

## 2. Table Specifications

### `organizations`
Represents an Indian SMB tenant entity.
- `id` (UUID, Primary Key): Globally unique tenant identifier.
- `name` (VARCHAR(255), Not Null): Registered SMB business name.
- `slug` (VARCHAR(100), Unique, Indexed): URL-safe tenant identifier (e.g., `acme-retail`).
- `sector` (VARCHAR(100), Nullable): Industry category (e.g., `Fintech`, `Healthcare`, `Retail`).
- `contact_email` (VARCHAR(255), Not Null): Security escalation contact.
- `is_active` (BOOLEAN, Default True): Administrative active flag.
- `created_at`, `updated_at` (TIMESTAMPTZ): Audit timestamps.

### `users`
Authenticated human operators and system administrators.
- `id` (UUID, Primary Key): Unique user ID.
- `email` (VARCHAR(255), Unique, Indexed): Normalized email address.
- `hashed_password` (VARCHAR(255), Not Null): Modern **Argon2id** password hash. Plaintext passwords are never persisted.
- `full_name` (VARCHAR(255), Not Null): Display name.
- `is_active` (BOOLEAN, Default True): Account lock status.
- `is_superuser` (BOOLEAN, Default False): Global platform administrator flag.
- `last_login_at` (TIMESTAMPTZ, Nullable): Timestamp of most recent authentication.

### `roles` & `permissions` & `role_permissions`
Granular Role-Based Access Control schema.
- **Roles**: Pre-seeded with `SUPER_ADMIN`, `ORG_ADMIN`, `SECURITY_ANALYST`, `AUDITOR`, and `VIEWER`.
- **Permissions**: Atomic capability codes (`org:read`, `org:write`, `user:read`, `user:write`, `role:read`, `asset:read`, `asset:write`, `asset:delete`, `audit:read`, `system:read`, `system:write`).
- **RolePermissions**: Many-to-many junction table with cascade deletion.

### `organization_memberships`
Binds a user to an organization with a specific role.
- `id` (UUID, Primary Key).
- `user_id` (UUID, Foreign Key -> `users.id` on delete CASCADE).
- `organization_id` (UUID, Foreign Key -> `organizations.id` on delete CASCADE).
- `role_id` (UUID, Foreign Key -> `roles.id` on delete RESTRICT).
- `is_default` (BOOLEAN, Default False): Indicates default tenant context.
- **Constraint**: `UNIQUE(user_id, organization_id)`.

### `user_sessions`
Server-side authenticated session tracking and explicit revocation.
- `id` (UUID, Primary Key).
- `user_id` (UUID, Foreign Key -> `users.id` on delete CASCADE).
- `organization_id` (UUID, Foreign Key -> `organizations.id` on delete CASCADE, Nullable).
- `session_token` (VARCHAR(255), Unique, Indexed): Cryptographically secure random token (43 chars).
- `ip_address` (VARCHAR(45), Nullable): Origin client IP address.
- `user_agent` (VARCHAR(500), Nullable): Browser User-Agent telemetry.
- `expires_at` (TIMESTAMPTZ, Not Null): Expiration deadline (default 24 hours).
- `revoked_at` (TIMESTAMPTZ, Nullable): Explicit revocation timestamp (set upon logout).
- `is_active` (BOOLEAN, Default True).

### `managed_assets`
Authorized SMB attack surface elements.
- `id` (UUID, Primary Key).
- `organization_id` (UUID, Foreign Key -> `organizations.id` on delete CASCADE, Indexed).
- `name` (VARCHAR(255), Not Null): Descriptive asset label.
- `asset_type` (VARCHAR(50), Not Null): `WEB_APPLICATION`, `API_GATEWAY`, `PUBLIC_IP`, `INTERNAL_SERVER`, `DOMAIN`.
- `target` (VARCHAR(255), Not Null): FQDN, URL, or IP.
- `environment` (VARCHAR(50), Default `PRODUCTION`): `PRODUCTION`, `STAGING`, `DEVELOPMENT`.
- `criticality` (VARCHAR(50), Default `HIGH`): `CRITICAL`, `HIGH`, `MEDIUM`, `LOW`.
- `is_in_scope` (BOOLEAN, Default True): Explicit legal and operational authorization for inspection.
- `created_by_user_id` (UUID, Foreign Key -> `users.id` on delete SET NULL).

### `audit_events`
Tamper-resistant audit logs recording all security and tenant actions.
- `id` (UUID, Primary Key).
- `organization_id` (UUID, Foreign Key -> `organizations.id`, Nullable, Indexed).
- `user_id` (UUID, Foreign Key -> `users.id`, Nullable, Indexed).
- `action` (VARCHAR(100), Not Null, Indexed): `AUTH_LOGIN`, `AUTH_LOGOUT`, `AUTH_LOGIN_FAILED`, `ADMIN_BOOTSTRAP`, `USER_CREATE`, `ORG_CREATE`, `ASSET_CREATE`, `ASSET_DELETE`, `TENANT_ACCESS_DENIED`.
- `resource_type` (VARCHAR(50), Not Null).
- `resource_id` (VARCHAR(100), Nullable).
- `ip_address` (VARCHAR(45), Nullable).
- `user_agent` (VARCHAR(500), Nullable).
- `status` (VARCHAR(50), Not Null): `SUCCESS`, `FAILURE`, `DENIED`.
- `details` (TEXT, Nullable): JSON metadata or structured description.
- `created_at` (TIMESTAMPTZ, Default UTC Now, Indexed).
