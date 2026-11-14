"""
PREVENT-X Zero Trust & Threat Intelligence Models (MOD-04, MOD-05)
Relational models for continuous trust evaluation, threat intelligence indicators,
threat-to-asset correlation, behavioral anomaly alerts, and automated response actions.
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


class TrustDecision(str, enum.Enum):
    TRUSTED = "TRUSTED"
    RESTRICTED = "RESTRICTED"
    UNTRUSTED = "UNTRUSTED"
    INSUFFICIENT_EVIDENCE = "INSUFFICIENT_EVIDENCE"


class IndicatorType(str, enum.Enum):
    IP = "IP"
    DOMAIN = "DOMAIN"
    HASH = "HASH"
    URL = "URL"
    PATTERN = "PATTERN"


class AnomalyType(str, enum.Enum):
    UNUSUAL_CONNECTION_RATE = "UNUSUAL_CONNECTION_RATE"
    UNEXPECTED_SERVICE_PORT = "UNEXPECTED_SERVICE_PORT"
    UNEXPECTED_COMMUNICATION_LINK = "UNEXPECTED_COMMUNICATION_LINK"
    AUTHENTICATION_BURST = "AUTHENTICATION_BURST"
    UNKNOWN_PROTOCOL_PAYLOAD = "UNKNOWN_PROTOCOL_PAYLOAD"
    UNUSUAL_ACCESS_FREQUENCY = "UNUSUAL_ACCESS_FREQUENCY"
    BEHAVIORAL_BASELINE_DRIFT = "BEHAVIORAL_BASELINE_DRIFT"


class AnomalySeverity(str, enum.Enum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"


class AnomalyConfidence(str, enum.Enum):
    CONFIRMED = "CONFIRMED"
    LIKELY = "LIKELY"
    POTENTIAL = "POTENTIAL"


class AnomalyStatus(str, enum.Enum):
    OPEN = "OPEN"
    INVESTIGATING = "INVESTIGATING"
    RESOLVED = "RESOLVED"
    FALSE_POSITIVE = "FALSE_POSITIVE"


class ResponseActionType(str, enum.Enum):
    RESTRICT_SERVICE_ACCESS = "RESTRICT_SERVICE_ACCESS"
    NETWORK_ISOLATION = "NETWORK_ISOLATION"
    RATE_LIMIT_IP = "RATE_LIMIT_IP"
    SESSION_REVOCATION = "SESSION_REVOCATION"
    INCREASE_TELEMETRY_LOGGING = "INCREASE_TELEMETRY_LOGGING"
    VIRTUAL_PATCH_ENFORCEMENT = "VIRTUAL_PATCH_ENFORCEMENT"


class ResponseActionStatus(str, enum.Enum):
    PENDING_APPROVAL = "PENDING_APPROVAL"
    APPROVED = "APPROVED"
    EXECUTED = "EXECUTED"
    REJECTED = "REJECTED"
    ROLLED_BACK = "ROLLED_BACK"


class AssetTrustAssessment(Base, TimestampMixin):
    """
    Continuous Zero-Trust posture evaluation for a managed SMB asset.
    Never marks an asset TRUSTED merely because it is registered.
    """
    __tablename__ = "asset_trust_assessments"

    id: Mapped[uuid.UUID] = mapped_column(GUID(), primary_key=True, default=uuid.uuid4)
    organization_id: Mapped[uuid.UUID] = mapped_column(
        GUID(), ForeignKey("organizations.id", ondelete="CASCADE"), index=True, nullable=False
    )
    asset_id: Mapped[uuid.UUID] = mapped_column(
        GUID(), ForeignKey("managed_assets.id", ondelete="CASCADE"), index=True, unique=True, nullable=False
    )
    trust_decision: Mapped[str] = mapped_column(
        String(30), default=TrustDecision.INSUFFICIENT_EVIDENCE.value, nullable=False, index=True
    )
    trust_score: Mapped[float] = mapped_column(Float, default=0.0, nullable=False, index=True)  # 0.0 to 100.0
    positive_factors: Mapped[Optional[str]] = mapped_column(Text, nullable=True)  # JSON list
    risk_factors: Mapped[Optional[str]] = mapped_column(Text, nullable=True)  # JSON list
    least_privilege_recommendations: Mapped[Optional[str]] = mapped_column(Text, nullable=True)  # JSON list
    decision_reason: Mapped[str] = mapped_column(Text, nullable=False)
    last_evaluated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utc_now, nullable=False, index=True
    )
    is_stale: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)

    # Relationships
    asset: Mapped["ManagedAsset"] = relationship("ManagedAsset")
    organization: Mapped["Organization"] = relationship("Organization")


class ThreatIntelRecord(Base, TimestampMixin):
    """
    Verified indicators of compromise (IOCs) with attribution, freshness, and expiration.
    """
    __tablename__ = "threat_intel_records"

    id: Mapped[uuid.UUID] = mapped_column(GUID(), primary_key=True, default=uuid.uuid4)
    organization_id: Mapped[Optional[uuid.UUID]] = mapped_column(
        GUID(), ForeignKey("organizations.id", ondelete="CASCADE"), index=True, nullable=True
    )
    indicator_type: Mapped[str] = mapped_column(String(50), nullable=False, index=True)
    indicator_value: Mapped[str] = mapped_column(String(500), index=True, nullable=False)
    confidence: Mapped[int] = mapped_column(Integer, default=50, nullable=False)  # 0 - 100
    source: Mapped[str] = mapped_column(String(100), nullable=False)
    threat_actor: Mapped[Optional[str]] = mapped_column(String(100), nullable=True)
    description: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    severity: Mapped[str] = mapped_column(String(20), default="HIGH", nullable=False)
    tlp: Mapped[str] = mapped_column(String(20), default="WHITE", nullable=False)
    is_active: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False, index=True)
    expires_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True, index=True)
    last_seen_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)
    mitre_tactics: Mapped[Optional[str]] = mapped_column(Text, nullable=True)  # JSON list
    mitre_techniques: Mapped[Optional[str]] = mapped_column(Text, nullable=True)  # JSON list
    tags: Mapped[Optional[str]] = mapped_column(Text, nullable=True)  # JSON list

    # Relationships
    correlations: Mapped[List["ThreatAssetCorrelation"]] = relationship(
        "ThreatAssetCorrelation", back_populates="threat_intel", cascade="all, delete-orphan"
    )


# Alias for backward compatibility
ThreatIntelligenceFeed = ThreatIntelRecord


class ThreatAssetCorrelation(Base, TimestampMixin):
    """
    Evidence-backed correlation between a threat indicator and a local tenant asset.
    """
    __tablename__ = "threat_asset_correlations"

    id: Mapped[uuid.UUID] = mapped_column(GUID(), primary_key=True, default=uuid.uuid4)
    organization_id: Mapped[uuid.UUID] = mapped_column(
        GUID(), ForeignKey("organizations.id", ondelete="CASCADE"), index=True, nullable=False
    )
    threat_intel_id: Mapped[uuid.UUID] = mapped_column(
        GUID(), ForeignKey("threat_intel_records.id", ondelete="CASCADE"), index=True, nullable=False
    )
    asset_id: Mapped[uuid.UUID] = mapped_column(
        GUID(), ForeignKey("managed_assets.id", ondelete="CASCADE"), index=True, nullable=False
    )
    correlation_type: Mapped[str] = mapped_column(String(50), nullable=False)
    matched_value: Mapped[str] = mapped_column(String(255), nullable=False)
    severity: Mapped[str] = mapped_column(String(20), default="HIGH", nullable=False)
    confidence: Mapped[int] = mapped_column(Integer, default=80, nullable=False)
    details: Mapped[str] = mapped_column(Text, nullable=False)
    status: Mapped[str] = mapped_column(String(30), default="ACTIVE", nullable=False, index=True)

    # Relationships
    threat_intel: Mapped["ThreatIntelRecord"] = relationship("ThreatIntelRecord", back_populates="correlations")
    asset: Mapped["ManagedAsset"] = relationship("ManagedAsset")
    organization: Mapped["Organization"] = relationship("Organization")


class BehavioralAnomaly(Base, TimestampMixin):
    """
    Observed statistical or rule-based telemetry anomaly or zero-day behavior indicator.
    """
    __tablename__ = "behavioral_anomalies"

    id: Mapped[uuid.UUID] = mapped_column(GUID(), primary_key=True, default=uuid.uuid4)
    organization_id: Mapped[uuid.UUID] = mapped_column(
        GUID(), ForeignKey("organizations.id", ondelete="CASCADE"), index=True, nullable=False
    )
    asset_id: Mapped[uuid.UUID] = mapped_column(
        GUID(), ForeignKey("managed_assets.id", ondelete="CASCADE"), index=True, nullable=False
    )
    anomaly_type: Mapped[str] = mapped_column(String(50), nullable=False, index=True)
    severity: Mapped[str] = mapped_column(String(20), default="MEDIUM", nullable=False, index=True)
    confidence: Mapped[str] = mapped_column(String(30), default="POTENTIAL", nullable=False)
    anomaly_score: Mapped[float] = mapped_column(Float, default=50.0, nullable=False)  # 0.0 - 100.0
    description: Mapped[str] = mapped_column(Text, nullable=False)
    evidence_data: Mapped[Optional[str]] = mapped_column(Text, nullable=True)  # JSON details
    status: Mapped[str] = mapped_column(String(30), default="OPEN", nullable=False, index=True)
    is_zero_day_indicator: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False, index=True)

    # Relationships
    asset: Mapped["ManagedAsset"] = relationship("ManagedAsset")
    organization: Mapped["Organization"] = relationship("Organization")
    response_actions: Mapped[List["ResponseAction"]] = relationship(
        "ResponseAction", back_populates="anomaly", cascade="all, delete-orphan"
    )


class ResponseAction(Base, TimestampMixin):
    """
    Controlled response actions requiring human authorization before disruptive containment.
    """
    __tablename__ = "response_actions"

    id: Mapped[uuid.UUID] = mapped_column(GUID(), primary_key=True, default=uuid.uuid4)
    organization_id: Mapped[uuid.UUID] = mapped_column(
        GUID(), ForeignKey("organizations.id", ondelete="CASCADE"), index=True, nullable=False
    )
    asset_id: Mapped[Optional[uuid.UUID]] = mapped_column(
        GUID(), ForeignKey("managed_assets.id", ondelete="SET NULL"), index=True, nullable=True
    )
    anomaly_id: Mapped[Optional[uuid.UUID]] = mapped_column(
        GUID(), ForeignKey("behavioral_anomalies.id", ondelete="SET NULL"), index=True, nullable=True
    )
    action_type: Mapped[str] = mapped_column(String(50), nullable=False)
    title: Mapped[str] = mapped_column(String(255), nullable=False)
    description: Mapped[str] = mapped_column(Text, nullable=False)
    target_entity: Mapped[str] = mapped_column(String(255), nullable=False)
    execution_payload: Mapped[Optional[str]] = mapped_column(Text, nullable=True)  # JSON execution commands
    rollback_payload: Mapped[Optional[str]] = mapped_column(Text, nullable=True)  # JSON rollback instructions
    status: Mapped[str] = mapped_column(
        String(30), default=ResponseActionStatus.PENDING_APPROVAL.value, nullable=False, index=True
    )
    is_disruptive: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    approved_by_user_id: Mapped[Optional[uuid.UUID]] = mapped_column(
        GUID(), ForeignKey("users.id", ondelete="SET NULL"), nullable=True
    )
    approved_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)
    executed_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)
    execution_log: Mapped[Optional[str]] = mapped_column(Text, nullable=True)

    # Relationships
    asset: Mapped[Optional["ManagedAsset"]] = relationship("ManagedAsset")
    anomaly: Mapped[Optional["BehavioralAnomaly"]] = relationship("BehavioralAnomaly", back_populates="response_actions")
    approved_by_user: Mapped[Optional["User"]] = relationship("User")
    organization: Mapped["Organization"] = relationship("Organization")

