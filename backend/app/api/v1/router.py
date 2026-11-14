"""
PREVENT-X API v1 Router Assembly
"""

from fastapi import APIRouter
from backend.app.api.v1.endpoints import (
    assets,
    audit_logs,
    auth,
    organizations,
    roles,
    system,
    users,
)

api_router = APIRouter()

# System endpoints: /health, /ready, /system/info
api_router.include_router(system.router)

# Authentication & Session lifecycle
api_router.include_router(auth.router)

# Tenant Organization Management
api_router.include_router(organizations.router)

# User Provisioning and RBAC
api_router.include_router(users.router)
api_router.include_router(roles.router)

# Managed Asset Protection Scope
api_router.include_router(assets.router)

# Audit Log Ingestion and Compliance Trail
api_router.include_router(audit_logs.router)
