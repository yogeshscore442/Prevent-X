"""
PREVENT-X API v1 Router Assembly
"""

from fastapi import APIRouter
from backend.app.api.v1.endpoints import (
    assets,
    attack_surface,
    audit_logs,
    auth,
    organizations,
    roles,
    system,
    users,
    vulnerabilities,
    attack_paths,
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

# Attack Surface Intelligence Engine (MOD-01)
api_router.include_router(attack_surface.router)

# Advanced Vulnerability Mapping Engine (MOD-02)
api_router.include_router(vulnerabilities.router)

# Attack Path and Prevention Engine (MOD-03)
api_router.include_router(attack_paths.router)

# Audit Log Ingestion and Compliance Trail
api_router.include_router(audit_logs.router)

