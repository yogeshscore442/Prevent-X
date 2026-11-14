"""
PREVENT-X System Initialization Service
Seeds standard system permissions and roles if not already present.
"""

from sqlalchemy.orm import Session
from backend.app.core.logging import logger
from backend.app.models.permission import Permission
from backend.app.models.role import Role
from backend.app.security.permissions import (
    PermissionCode,
    ROLE_PERMISSIONS_MAP,
    SystemRole,
)

SYSTEM_PERMISSIONS = [
    (PermissionCode.ORG_READ, "View Organization", "Allows viewing organization profile and settings", "organizations"),
    (PermissionCode.ORG_WRITE, "Manage Organization", "Allows updating organization profile and settings", "organizations"),
    (PermissionCode.USER_READ, "View Users", "Allows viewing user accounts within organization", "users"),
    (PermissionCode.USER_WRITE, "Manage Users", "Allows creating and managing user accounts", "users"),
    (PermissionCode.ROLE_READ, "View Roles", "Allows viewing RBAC roles and permissions", "roles"),
    (PermissionCode.ASSET_READ, "View Assets", "Allows viewing protected SMB assets", "assets"),
    (PermissionCode.ASSET_WRITE, "Manage Assets", "Allows onboarding and modifying SMB assets", "assets"),
    (PermissionCode.ASSET_DELETE, "Delete Assets", "Allows removing assets from protection scope", "assets"),
    (PermissionCode.AUDIT_READ, "View Audit Logs", "Allows viewing immutable audit trail logs", "audit"),
    (PermissionCode.SYSTEM_READ, "View System Telemetry", "Allows viewing system health and performance", "system"),
    (PermissionCode.SYSTEM_WRITE, "Manage System Settings", "Allows updating platform-wide settings", "system"),
    (PermissionCode.DISCOVERY_READ, "View Attack Surface", "Allows viewing attack surface assets and discovery jobs", "attack_surface"),
    (PermissionCode.DISCOVERY_CREATE, "Initiate Discovery", "Allows initiating external passive discovery scans", "attack_surface"),
    (PermissionCode.DISCOVERY_CANCEL, "Cancel Discovery", "Allows cancelling running discovery operations", "attack_surface"),
    (PermissionCode.DISCOVERY_INTERNAL, "Authorized Internal Discovery", "Allows initiating internal scoped discovery on authorized internal assets", "attack_surface"),
    (PermissionCode.DISCOVERY_ACTIVE, "Initiate Active Discovery", "Allows initiating controlled active TCP port and service discovery scans", "attack_surface"),
    (PermissionCode.VULNERABILITY_READ, "View Vulnerabilities", "Allows viewing detected vulnerabilities and risk scores", "vulnerabilities"),
    (PermissionCode.VULNERABILITY_WRITE, "Manage Vulnerabilities", "Allows modifying vulnerability status and triage state", "vulnerabilities"),
    (PermissionCode.VULNERABILITY_SCAN, "Execute Vulnerability Scan", "Allows initiating vulnerability mapping scans against assets", "vulnerabilities"),
    (PermissionCode.VULNERABILITY_FEED_SYNC, "Sync Threat Feeds", "Allows updating CVE, CISA KEV, and EPSS threat intelligence feeds", "vulnerabilities"),
    (PermissionCode.ATTACK_PATH_READ, "View Attack Paths", "Allows viewing analyzed attack paths and MITRE ATT&CK mappings", "attack_paths"),
    (PermissionCode.ATTACK_PATH_ANALYZE, "Analyze Attack Paths", "Allows initiating graph-based attack path and prerequisite analysis", "attack_paths"),
    (PermissionCode.ATTACK_PATH_WRITE, "Manage Preventive Controls", "Allows updating preventive recommendation status and trust links", "attack_paths"),
    (PermissionCode.ZERO_TRUST_READ, "View Zero Trust Posture", "Allows viewing asset trust decisions and continuous evaluation metrics", "zero_trust"),
    (PermissionCode.ZERO_TRUST_EVALUATE, "Evaluate Asset Trust", "Allows triggering continuous trust posture assessments", "zero_trust"),
    (PermissionCode.ZERO_TRUST_WRITE, "Manage Zero Trust Policies", "Allows modifying trust thresholds and micro-segmentation policies", "zero_trust"),
    (PermissionCode.THREAT_INTEL_READ, "View Threat Intelligence", "Allows viewing threat indicators, IOCs, and asset correlations", "threat_intel"),
    (PermissionCode.THREAT_INTEL_SYNC, "Sync Threat Intelligence", "Allows ingesting external threat feeds and updating indicator database", "threat_intel"),
    (PermissionCode.RESPONSE_ACTION_READ, "View Response Actions", "Allows viewing automated response recommendations and execution status", "response_actions"),
    (PermissionCode.RESPONSE_ACTION_APPROVE, "Approve Response Actions", "Allows approving or rejecting disruptive containment and segmentation actions", "response_actions"),
    (PermissionCode.RESPONSE_ACTION_EXECUTE, "Execute Response Actions", "Allows triggering automated or approved containment actions", "response_actions"),
    (PermissionCode.VIRTUAL_PATCH_READ, "View Virtual Patches", "Allows viewing virtual patch rules, recommendations, and status", "virtual_patch"),
    (PermissionCode.VIRTUAL_PATCH_WRITE, "Manage Virtual Patches", "Allows creating and modifying virtual patch rules and drafts", "virtual_patch"),
    (PermissionCode.VIRTUAL_PATCH_APPROVE, "Approve Virtual Patches", "Allows approving virtual patch rules for production deployment", "virtual_patch"),
    (PermissionCode.VIRTUAL_PATCH_DEPLOY, "Deploy Virtual Patches", "Allows deploying virtual patches to staging and production reverse proxies", "virtual_patch"),
    (PermissionCode.WAF_LOGS_READ, "View WAF Enforcement Logs", "Allows inspecting real-time WAF request blocks, decisions, and evidence", "virtual_patch"),
]

SYSTEM_ROLES = [
    (SystemRole.SUPER_ADMIN, "Platform Super Administrator with unrestricted access across all tenants"),
    (SystemRole.ORG_ADMIN, "Tenant Organization Administrator with full management of organization assets and users"),
    (SystemRole.SECURITY_ANALYST, "Security Analyst with asset monitoring and virtual patch analysis capabilities"),
    (SystemRole.AUDITOR, "Compliance Auditor with read-only inspection and audit trail access"),
    (SystemRole.VIEWER, "Read-only viewer for executive reporting"),
]


def initialize_system_roles_and_permissions(db: Session) -> None:
    """Idempotently populates default roles, permissions, and their associations."""
    # 1. Seed permissions
    perm_lookup = {}
    for code, name, desc, module in SYSTEM_PERMISSIONS:
        perm = db.query(Permission).filter(Permission.code == code).first()
        if not perm:
            perm = Permission(code=code, name=name, description=desc, module=module)
            db.add(perm)
            db.flush()
        perm_lookup[code] = perm

    # 2. Seed roles and associate permissions
    for role_name, description in SYSTEM_ROLES:
        role = db.query(Role).filter(Role.name == role_name).first()
        if not role:
            role = Role(name=role_name, description=description, is_system_role=True)
            db.add(role)
            db.flush()

        # Update role permissions to match defined matrix
        target_codes = ROLE_PERMISSIONS_MAP.get(role_name, set())
        target_perms = [perm_lookup[c] for c in target_codes if c in perm_lookup]
        role.permissions = target_perms

    db.commit()
    logger.info("PREVENT-X system roles and permissions successfully synchronized.")

