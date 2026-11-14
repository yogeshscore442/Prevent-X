"""
PREVENT-X Architectural Extension Models (Phases 2 - 9 Entity Definitions)
Declares relational schema definitions and foreign-key structures for future cybersecurity modules.
Note: These entities establish database integrity and extension points without activating unimplemented features in Phase 1.
"""

import uuid
from datetime import datetime
from typing import Optional
from sqlalchemy import String, Text, Boolean, Integer, Float, ForeignKey, DateTime
from sqlalchemy.orm import Mapped, mapped_column
from backend.app.database.base import Base, TimestampMixin, utc_now
from backend.app.database.guid import GUID


class CveRecord(Base, TimestampMixin):
    """CVE Database and National Vulnerability Database catalog representation."""
    __tablename__ = "cve_records"

    id: Mapped[uuid.UUID] = mapped_column(GUID(), primary_key=True, default=uuid.uuid4)
    cve_id: Mapped[str] = mapped_column(String(50), unique=True, index=True, nullable=False) # e.g. "CVE-2024-21413"
    description: Mapped[str] = mapped_column(Text, nullable=False)
    cvss_score: Mapped[Optional[float]] = mapped_column(Float, nullable=True)
    cvss_vector: Mapped[Optional[str]] = mapped_column(String(100), nullable=True)
    severity: Mapped[str] = mapped_column(String(20), default="UNKNOWN", nullable=False) # LOW, MEDIUM, HIGH, CRITICAL
    cwe_id: Mapped[Optional[str]] = mapped_column(String(50), nullable=True)
    published_date: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)


class VulnerabilityRecord(Base, TimestampMixin):
    """Discovered or ingested vulnerability mapped to a tenant asset."""
    __tablename__ = "vulnerability_records"

    id: Mapped[uuid.UUID] = mapped_column(GUID(), primary_key=True, default=uuid.uuid4)
    organization_id: Mapped[uuid.UUID] = mapped_column(GUID(), ForeignKey("organizations.id", ondelete="CASCADE"), index=True, nullable=False)
    asset_id: Mapped[uuid.UUID] = mapped_column(GUID(), ForeignKey("managed_assets.id", ondelete="CASCADE"), index=True, nullable=False)
    cve_id: Mapped[Optional[str]] = mapped_column(String(50), nullable=True, index=True)
    title: Mapped[str] = mapped_column(String(255), nullable=False)
    description: Mapped[Text] = mapped_column(Text, nullable=False)
    severity: Mapped[str] = mapped_column(String(20), default="MEDIUM", nullable=False)
    status: Mapped[str] = mapped_column(String(50), default="DETECTED", nullable=False) # DETECTED, MITIGATED, PATCHED, ACCEPTED


class ThreatIntelligenceFeed(Base, TimestampMixin):
    """External and internal threat signals and IoC indicators."""
    __tablename__ = "threat_intel_records"

    id: Mapped[uuid.UUID] = mapped_column(GUID(), primary_key=True, default=uuid.uuid4)
    indicator_type: Mapped[str] = mapped_column(String(50), nullable=False) # IP, DOMAIN, HASH, URL, PATTERN
    indicator_value: Mapped[str] = mapped_column(String(500), index=True, nullable=False)
    confidence: Mapped[int] = mapped_column(Integer, default=50, nullable=False) # 0 - 100
    source: Mapped[str] = mapped_column(String(100), nullable=False)
    threat_actor: Mapped[Optional[str]] = mapped_column(String(100), nullable=True)


class AttackPathGraph(Base, TimestampMixin):
    """Attack prerequisite tree and kill-chain exposure pathways."""
    __tablename__ = "attack_paths"

    id: Mapped[uuid.UUID] = mapped_column(GUID(), primary_key=True, default=uuid.uuid4)
    organization_id: Mapped[uuid.UUID] = mapped_column(GUID(), ForeignKey("organizations.id", ondelete="CASCADE"), index=True, nullable=False)
    name: Mapped[str] = mapped_column(String(255), nullable=False)
    entry_point_asset_id: Mapped[uuid.UUID] = mapped_column(GUID(), ForeignKey("managed_assets.id", ondelete="CASCADE"), nullable=False)
    target_asset_id: Mapped[uuid.UUID] = mapped_column(GUID(), ForeignKey("managed_assets.id", ondelete="CASCADE"), nullable=False)
    step_count: Mapped[int] = mapped_column(Integer, default=1, nullable=False)
    risk_score: Mapped[float] = mapped_column(Float, default=0.0, nullable=False)


class SecurityPolicy(Base, TimestampMixin):
    """Zero-Trust and perimeter inspection enforcement policies."""
    __tablename__ = "security_policies"

    id: Mapped[uuid.UUID] = mapped_column(GUID(), primary_key=True, default=uuid.uuid4)
    organization_id: Mapped[uuid.UUID] = mapped_column(GUID(), ForeignKey("organizations.id", ondelete="CASCADE"), index=True, nullable=False)
    name: Mapped[str] = mapped_column(String(255), nullable=False)
    policy_type: Mapped[str] = mapped_column(String(50), nullable=False) # WAF_RULE, RATE_LIMIT, ACCESS_CONTROL, IP_REPUTATION
    enforcement_mode: Mapped[str] = mapped_column(String(50), default="BLOCKING", nullable=False) # MONITORING, BLOCKING, DISABLED
    definition: Mapped[str] = mapped_column(Text, nullable=False) # JSON or ModSecurity rule syntax


class VirtualPatchRule(Base, TimestampMixin):
    """Synthesized compensating virtual patch specifications (ModSecurity, Envoy, Nginx, eBPF)."""
    __tablename__ = "virtual_patch_rules"

    id: Mapped[uuid.UUID] = mapped_column(GUID(), primary_key=True, default=uuid.uuid4)
    organization_id: Mapped[uuid.UUID] = mapped_column(GUID(), ForeignKey("organizations.id", ondelete="CASCADE"), index=True, nullable=False)
    asset_id: Mapped[uuid.UUID] = mapped_column(GUID(), ForeignKey("managed_assets.id", ondelete="CASCADE"), index=True, nullable=False)
    cve_id: Mapped[Optional[str]] = mapped_column(String(50), nullable=True)
    rule_name: Mapped[str] = mapped_column(String(255), nullable=False)
    target_engine: Mapped[str] = mapped_column(String(50), nullable=False) # MODSECURITY, ENVOY, NGINX, CLOUDFLARE
    rule_content: Mapped[str] = mapped_column(Text, nullable=False)
    version: Mapped[int] = mapped_column(Integer, default=1, nullable=False)
    state: Mapped[str] = mapped_column(String(50), default="DRAFT", nullable=False) # DRAFT, VALIDATED, ACTIVE, ROLLED_BACK


class ValidationResult(Base, TimestampMixin):
    """Pre-deployment verification, benign traffic replay, and false-positive assessments."""
    __tablename__ = "validation_results"

    id: Mapped[uuid.UUID] = mapped_column(GUID(), primary_key=True, default=uuid.uuid4)
    patch_rule_id: Mapped[uuid.UUID] = mapped_column(GUID(), ForeignKey("virtual_patch_rules.id", ondelete="CASCADE"), nullable=False)
    test_run_type: Mapped[str] = mapped_column(String(50), nullable=False) # SYNTHETIC_EXPLOIT, BENIGN_REPLAY, LOAD_TEST
    passed: Mapped[bool] = mapped_column(Boolean, nullable=False)
    false_positive_count: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    details: Mapped[Optional[str]] = mapped_column(Text, nullable=True)


class DeploymentRecord(Base, TimestampMixin):
    """Deployment history, enforcement state, and rollback audit logs."""
    __tablename__ = "deployment_records"

    id: Mapped[uuid.UUID] = mapped_column(GUID(), primary_key=True, default=uuid.uuid4)
    patch_rule_id: Mapped[uuid.UUID] = mapped_column(GUID(), ForeignKey("virtual_patch_rules.id", ondelete="CASCADE"), nullable=False)
    deployed_by_user_id: Mapped[uuid.UUID] = mapped_column(GUID(), ForeignKey("users.id", ondelete="RESTRICT"), nullable=False)
    target_node: Mapped[str] = mapped_column(String(255), nullable=False)
    status: Mapped[str] = mapped_column(String(50), default="DEPLOYED", nullable=False) # DEPLOYED, ROLLBACK_INITIATED, ROLLED_BACK
    rollback_token: Mapped[str] = mapped_column(String(100), nullable=False)


class SecurityEventRecord(Base):
    """High-throughput traffic and security inspection telemetry."""
    __tablename__ = "security_event_records"

    id: Mapped[uuid.UUID] = mapped_column(GUID(), primary_key=True, default=uuid.uuid4)
    organization_id: Mapped[uuid.UUID] = mapped_column(GUID(), ForeignKey("organizations.id", ondelete="CASCADE"), index=True, nullable=False)
    asset_id: Mapped[uuid.UUID] = mapped_column(GUID(), ForeignKey("managed_assets.id", ondelete="CASCADE"), index=True, nullable=False)
    source_ip: Mapped[str] = mapped_column(String(45), index=True, nullable=False)
    attack_category: Mapped[str] = mapped_column(String(100), nullable=False) # SQLI, XSS, RCE, PATH_TRAVERSAL, ZERO_DAY_ANOMALY
    mitigation_action: Mapped[str] = mapped_column(String(50), nullable=False) # BLOCKED, LOGGED, CHALLENGED
    payload_sample: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    timestamp: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utc_now, index=True, nullable=False)

