"""
PREVENT-X Intelligent Virtual Patching & Reverse Proxy WAF Models (MOD-06, MOD-08)
Relational models for deterministic WAF rules, versioning, deployment approvals,
reverse proxy configuration, and live enforcement audit logs.
"""

import enum
import uuid
from datetime import datetime
from typing import Any, Dict, List, Optional
from sqlalchemy import (
    Boolean,
    DateTime,
    Float,
    ForeignKey,
    Index,
    Integer,
    String,
    Text,
)
from sqlalchemy.orm import Mapped, mapped_column, relationship

from backend.app.database.base import Base, TimestampMixin, utc_now
from backend.app.database.guid import GUID


class AttackType(str, enum.Enum):
    SQLI = "SQLI"
    XSS = "XSS"
    PATH_TRAVERSAL = "PATH_TRAVERSAL"
    CMDI = "CMDI"
    METHOD_RESTRICTION = "METHOD_RESTRICTION"
    RATE_LIMIT = "RATE_LIMIT"
    PATTERN_BLOCK = "PATTERN_BLOCK"
    API_PROTECTION = "API_PROTECTION"


class PatchAction(str, enum.Enum):
    BLOCK = "BLOCK"
    ALLOW = "ALLOW"
    LOG_ONLY = "LOG_ONLY"


class PatchStatus(str, enum.Enum):
    DRAFT = "DRAFT"
    VALIDATING = "VALIDATING"
    STAGING = "STAGING"
    PENDING_APPROVAL = "PENDING_APPROVAL"
    APPROVED = "APPROVED"
    PRODUCTION = "PRODUCTION"
    DISABLED = "DISABLED"
    ROLLED_BACK = "ROLLED_BACK"


class DeploymentEnvironment(str, enum.Enum):
    STAGING = "STAGING"
    PRODUCTION = "PRODUCTION"


class DeploymentStatus(str, enum.Enum):
    PENDING_APPROVAL = "PENDING_APPROVAL"
    APPROVED = "APPROVED"
    DEPLOYED = "DEPLOYED"
    FAILED = "FAILED"
    ROLLED_BACK = "ROLLED_BACK"


class VirtualPatchRule(Base, TimestampMixin):
    """
    Intelligent Virtual Patch rule compensating for an unpatched vulnerability or attack path.
    """
    __tablename__ = "virtual_patch_rules"

    id: Mapped[uuid.UUID] = mapped_column(GUID(), primary_key=True, default=uuid.uuid4)
    organization_id: Mapped[uuid.UUID] = mapped_column(
        GUID(), ForeignKey("organizations.id", ondelete="CASCADE"), index=True, nullable=False
    )
    asset_id: Mapped[Optional[uuid.UUID]] = mapped_column(
        GUID(), ForeignKey("managed_assets.id", ondelete="SET NULL"), index=True, nullable=True
    )
    vulnerability_id: Mapped[Optional[uuid.UUID]] = mapped_column(
        GUID(), ForeignKey("vulnerability_records.id", ondelete="SET NULL"), index=True, nullable=True
    )
    cve_id: Mapped[Optional[str]] = mapped_column(String(50), nullable=True, index=True)
    cwe_id: Mapped[Optional[str]] = mapped_column(String(50), nullable=True, index=True)
    rule_name: Mapped[str] = mapped_column(String(255), nullable=False, index=True)
    attack_type: Mapped[str] = mapped_column(String(50), default=AttackType.SQLI.value, nullable=False, index=True)
    description: Mapped[str] = mapped_column(Text, nullable=False)
    severity: Mapped[str] = mapped_column(String(20), default="HIGH", nullable=False)
    priority: Mapped[int] = mapped_column(Integer, default=100, nullable=False, index=True)  # Lower executes first
    action: Mapped[str] = mapped_column(String(20), default=PatchAction.BLOCK.value, nullable=False)
    target_uri_pattern: Mapped[Optional[str]] = mapped_column(String(500), nullable=True)
    http_methods: Mapped[Optional[str]] = mapped_column(Text, nullable=True)  # JSON list
    match_conditions: Mapped[Optional[str]] = mapped_column(Text, nullable=True)  # JSON list
    status: Mapped[str] = mapped_column(String(30), default=PatchStatus.DRAFT.value, nullable=False, index=True)
    is_active: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False, index=True)
    is_system_rule: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    version: Mapped[int] = mapped_column(Integer, default=1, nullable=False)
    expires_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)
    false_positive_count: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    enforcement_count: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    config_snippet: Mapped[Optional[str]] = mapped_column(Text, nullable=True)

    # Relationships
    organization: Mapped["Organization"] = relationship("Organization")
    asset: Mapped[Optional["ManagedAsset"]] = relationship("ManagedAsset")
    vulnerability: Mapped[Optional["VulnerabilityRecord"]] = relationship("VulnerabilityRecord")
    versions: Mapped[List["VirtualPatchVersion"]] = relationship(
        "VirtualPatchVersion", back_populates="rule", cascade="all, delete-orphan", order_by="desc(VirtualPatchVersion.version_number)"
    )
    enforcement_logs: Mapped[List["WafEnforcementLog"]] = relationship(
        "WafEnforcementLog", back_populates="rule"
    )


class VirtualPatchVersion(Base):
    """
    Immutable version history for virtual patch rules, enabling auditing and instant rollback.
    """
    __tablename__ = "virtual_patch_versions"

    id: Mapped[uuid.UUID] = mapped_column(GUID(), primary_key=True, default=uuid.uuid4)
    rule_id: Mapped[uuid.UUID] = mapped_column(
        GUID(), ForeignKey("virtual_patch_rules.id", ondelete="CASCADE"), index=True, nullable=False
    )
    version_number: Mapped[int] = mapped_column(Integer, nullable=False, index=True)
    rule_name: Mapped[str] = mapped_column(String(255), nullable=False)
    action: Mapped[str] = mapped_column(String(20), nullable=False)
    target_uri_pattern: Mapped[Optional[str]] = mapped_column(String(500), nullable=True)
    match_conditions: Mapped[Optional[str]] = mapped_column(Text, nullable=True)  # JSON
    config_snippet: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    change_summary: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    created_by_user_id: Mapped[Optional[uuid.UUID]] = mapped_column(
        GUID(), ForeignKey("users.id", ondelete="SET NULL"), nullable=True
    )
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utc_now, nullable=False)

    # Relationships
    rule: Mapped["VirtualPatchRule"] = relationship("VirtualPatchRule", back_populates="versions")
    created_by_user: Mapped[Optional["User"]] = relationship("User")


class VirtualPatchDeployment(Base, TimestampMixin):
    """
    Deployment record tracking compilation and activation of virtual patch rule sets on Nginx.
    Strictly requires OrgAdmin approval for production enforcement.
    """
    __tablename__ = "virtual_patch_deployments"

    id: Mapped[uuid.UUID] = mapped_column(GUID(), primary_key=True, default=uuid.uuid4)
    organization_id: Mapped[uuid.UUID] = mapped_column(
        GUID(), ForeignKey("organizations.id", ondelete="CASCADE"), index=True, nullable=False
    )
    environment: Mapped[str] = mapped_column(
        String(30), default=DeploymentEnvironment.STAGING.value, nullable=False, index=True
    )
    status: Mapped[str] = mapped_column(
        String(30), default=DeploymentStatus.PENDING_APPROVAL.value, nullable=False, index=True
    )
    deployed_rules_count: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    config_hash: Mapped[str] = mapped_column(String(64), nullable=False)
    nginx_config_path: Mapped[Optional[str]] = mapped_column(String(500), nullable=True)
    listen_port: Mapped[int] = mapped_column(Integer, default=8085, nullable=False)
    upstream_url: Mapped[str] = mapped_column(String(255), default="http://127.0.0.1:8086", nullable=False)
    approved_by_user_id: Mapped[Optional[uuid.UUID]] = mapped_column(
        GUID(), ForeignKey("users.id", ondelete="SET NULL"), nullable=True
    )
    approved_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)
    deployed_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)
    rollback_target_deployment_id: Mapped[Optional[uuid.UUID]] = mapped_column(
        GUID(), ForeignKey("virtual_patch_deployments.id", ondelete="SET NULL"), nullable=True
    )
    deployment_log: Mapped[Optional[str]] = mapped_column(Text, nullable=True)

    # Relationships
    organization: Mapped["Organization"] = relationship("Organization")
    approved_by_user: Mapped[Optional["User"]] = relationship("User")


class WafEnforcementLog(Base):
    """
    Empirical log of requests evaluated by the Nginx reverse proxy WAF with evidence details.
    """
    __tablename__ = "waf_enforcement_logs"

    id: Mapped[uuid.UUID] = mapped_column(GUID(), primary_key=True, default=uuid.uuid4)
    organization_id: Mapped[uuid.UUID] = mapped_column(
        GUID(), ForeignKey("organizations.id", ondelete="CASCADE"), index=True, nullable=False
    )
    rule_id: Mapped[Optional[uuid.UUID]] = mapped_column(
        GUID(), ForeignKey("virtual_patch_rules.id", ondelete="SET NULL"), index=True, nullable=True
    )
    client_ip: Mapped[str] = mapped_column(String(45), nullable=False, index=True)
    http_method: Mapped[str] = mapped_column(String(10), nullable=False)
    uri: Mapped[str] = mapped_column(String(1000), nullable=False, index=True)
    query_string: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    headers_snippet: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    body_snippet: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    decision: Mapped[str] = mapped_column(String(20), default="BLOCKED", nullable=False, index=True)
    matched_pattern: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    block_reason: Mapped[str] = mapped_column(Text, nullable=False)
    response_status_code: Mapped[int] = mapped_column(Integer, default=403, nullable=False)
    is_false_positive_reported: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False, index=True)
    false_positive_notes: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utc_now, nullable=False, index=True)

    # Relationships
    organization: Mapped["Organization"] = relationship("Organization")
    rule: Mapped[Optional["VirtualPatchRule"]] = relationship("VirtualPatchRule", back_populates="enforcement_logs")


class VirtualPatchRecommendation(Base, TimestampMixin):
    """
    AI/Rule-synthesized virtual patch proposal derived from CVE, CWE, and attack path intelligence.
    Must be reviewed and accepted by a human security engineer before becoming a rule.
    """
    __tablename__ = "virtual_patch_recommendations"

    id: Mapped[uuid.UUID] = mapped_column(GUID(), primary_key=True, default=uuid.uuid4)
    organization_id: Mapped[uuid.UUID] = mapped_column(
        GUID(), ForeignKey("organizations.id", ondelete="CASCADE"), index=True, nullable=False
    )
    vulnerability_id: Mapped[uuid.UUID] = mapped_column(
        GUID(), ForeignKey("vulnerability_records.id", ondelete="CASCADE"), index=True, nullable=False
    )
    asset_id: Mapped[uuid.UUID] = mapped_column(
        GUID(), ForeignKey("managed_assets.id", ondelete="CASCADE"), index=True, nullable=False
    )
    cve_id: Mapped[Optional[str]] = mapped_column(String(50), nullable=True, index=True)
    cwe_id: Mapped[Optional[str]] = mapped_column(String(50), nullable=True, index=True)
    attack_type: Mapped[str] = mapped_column(String(50), nullable=False)
    suggested_rule_name: Mapped[str] = mapped_column(String(255), nullable=False)
    suggested_pattern: Mapped[str] = mapped_column(Text, nullable=False)
    target_uri_pattern: Mapped[Optional[str]] = mapped_column(String(500), nullable=True)
    rationale: Mapped[str] = mapped_column(Text, nullable=False)
    confidence: Mapped[int] = mapped_column(Integer, default=85, nullable=False)
    status: Mapped[str] = mapped_column(String(30), default="PROPOSED", nullable=False, index=True)
    generated_rule_id: Mapped[Optional[uuid.UUID]] = mapped_column(
        GUID(), ForeignKey("virtual_patch_rules.id", ondelete="SET NULL"), nullable=True
    )

    # Relationships
    organization: Mapped["Organization"] = relationship("Organization")
    vulnerability: Mapped["VulnerabilityRecord"] = relationship("VulnerabilityRecord")
    asset: Mapped["ManagedAsset"] = relationship("ManagedAsset")
    generated_rule: Mapped[Optional["VirtualPatchRule"]] = relationship("VirtualPatchRule")

