# ADR-002: Multi-Tenant Data Isolation Strategy

## Status
Accepted

## Context
PREVENT-X must support multiple distinct SMB organizations with strict data segregation. Three patterns were evaluated:
1. Database-per-tenant
2. Schema-per-tenant
3. Discriminator-column with repository-level mandatory query scoping

## Decision
We chose the **discriminator-column with repository-level query scoping (`organization_id`)**.
All tenant-owned models inherit from `TenantScopedRepository`, which guarantees that every SQL query automatically includes `WHERE organization_id = :active_org_id`. In addition, the FastAPI dependency `get_current_organization` validates membership before any tenant context is activated.

## Consequences
- **Positive**:
  - High resource efficiency and low infrastructure cost, directly matching Indian SMB economics.
  - Straightforward cross-tenant reporting for managed security service providers (MSSPs) and platform superusers.
  - Single database connection pool and unified Alembic migration lifecycle.
- **Negative**:
  - Developers must conscientiously use `TenantScopedRepository` for any new tenant-owned tables to prevent accidental cross-tenant data leakage. Explicit security tests are enforced in CI.
