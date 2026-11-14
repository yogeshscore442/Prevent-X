"""
PREVENT-X Database Models Registry
Exports all models to ensure complete metadata registration.
"""

from backend.app.database.base import Base, TimestampMixin
from backend.app.models.organization import Organization
from backend.app.models.permission import Permission
from backend.app.models.role import Role, role_permissions
from backend.app.models.user import User, OrganizationMembership
from backend.app.models.session import UserSession
from backend.app.models.asset import ManagedAsset
from backend.app.models.audit_log import AuditEvent
from backend.app.models.setting import SystemSetting
from backend.app.models.future_entities import (
    CveRecord,
    VulnerabilityRecord,
    ThreatIntelligenceFeed,
    AttackPathGraph,
    SecurityPolicy,
    VirtualPatchRule,
    ValidationResult,
    DeploymentRecord,
    SecurityEventRecord,
)

__all__ = [
    "Base",
    "TimestampMixin",
    "Organization",
    "Permission",
    "Role",
    "role_permissions",
    "User",
    "OrganizationMembership",
    "UserSession",
    "ManagedAsset",
    "AuditEvent",
    "SystemSetting",
    "CveRecord",
    "VulnerabilityRecord",
    "ThreatIntelligenceFeed",
    "AttackPathGraph",
    "SecurityPolicy",
    "VirtualPatchRule",
    "ValidationResult",
    "DeploymentRecord",
    "SecurityEventRecord",
]

