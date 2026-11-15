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


# Re-export Phase 3 & 4 & 5 & 6 operational models
from backend.app.models.vulnerability import CveRecord, VulnerabilityRecord
from backend.app.models.attack_path import AttackPath, AttackPathGraph
from backend.app.models.zero_trust import (
    AssetTrustAssessment,
    ThreatIntelRecord,
    ThreatIntelligenceFeed,
    ThreatAssetCorrelation,
    BehavioralAnomaly,
    ResponseAction,
    TrustDecision,
    IndicatorType,
    AnomalyType,
    AnomalySeverity,
    AnomalyConfidence,
    AnomalyStatus,
    ResponseActionType,
    ResponseActionStatus,
)
from backend.app.models.virtual_patch import (
    VirtualPatchRule,
    VirtualPatchVersion,
    VirtualPatchDeployment,
    WafEnforcementLog,
    VirtualPatchRecommendation,
    AttackType,
    PatchAction,
    PatchStatus,
    DeploymentEnvironment,
    DeploymentStatus,
)
from backend.app.models.security_validation import (
    ValidationJob,
    ValidationTestResult,
    RollbackRecord,
    CanaryPolicy,
    ValidationJobStatus,
    ValidationTriggerType,
    ValidationTestCategory,
    TestResultStatus,
    RollbackStatus,
    RollbackTriggerSource,
)




class SecurityPolicy(Base, TimestampMixin):
    """Zero-Trust and perimeter inspection enforcement policies."""
    __tablename__ = "security_policies"

    id: Mapped[uuid.UUID] = mapped_column(GUID(), primary_key=True, default=uuid.uuid4)
    organization_id: Mapped[uuid.UUID] = mapped_column(GUID(), ForeignKey("organizations.id", ondelete="CASCADE"), index=True, nullable=False)
    name: Mapped[str] = mapped_column(String(255), nullable=False)
    policy_type: Mapped[str] = mapped_column(String(50), nullable=False) # WAF_RULE, RATE_LIMIT, ACCESS_CONTROL, IP_REPUTATION
    enforcement_mode: Mapped[str] = mapped_column(String(50), default="BLOCKING", nullable=False) # MONITORING, BLOCKING, DISABLED
    definition: Mapped[str] = mapped_column(Text, nullable=False) # JSON or ModSecurity rule syntax


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

