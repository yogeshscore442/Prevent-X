"""
PREVENT-X Real-Time Monitoring & Security Management Models (MOD-09, MOD-12)
Declares database entities for real-time security events, correlated incidents,
investigation timeline entries, in-app alerts, and retention policies.
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
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import Mapped, mapped_column, relationship
from sqlalchemy.types import JSON

from backend.app.database.base import Base, TimestampMixin, utc_now
from backend.app.database.guid import GUID


# =============================================================================
# ENUMS
# =============================================================================

class EventSource(str, enum.Enum):
    NGINX = "NGINX"
    WAF = "WAF"
    AUTH = "AUTH"
    DISCOVERY = "DISCOVERY"
    VULNERABILITY = "VULNERABILITY"
    THREAT_INTEL = "THREAT_INTEL"
    ZERO_TRUST = "ZERO_TRUST"
    VALIDATION = "VALIDATION"
    SYSTEM = "SYSTEM"


class EventCategory(str, enum.Enum):
    SECURITY = "SECURITY"
    AUDIT = "AUDIT"
    ANOMALY = "ANOMALY"
    SYSTEM = "SYSTEM"


class EventSeverity(str, enum.Enum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"


class IncidentStatus(str, enum.Enum):
    OPEN = "OPEN"
    ACKNOWLEDGED = "ACKNOWLEDGED"
    INVESTIGATING = "INVESTIGATING"
    CONTAINED = "CONTAINED"
    RESOLVED = "RESOLVED"
    CLOSED = "CLOSED"


class IncidentSeverity(str, enum.Enum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"


class AlertCategory(str, enum.Enum):
    CRITICAL_VULNERABILITY = "CRITICAL_VULNERABILITY"
    REPEATED_WAF_ATTACKS = "REPEATED_WAF_ATTACKS"
    THREAT_INTEL_MATCH = "THREAT_INTEL_MATCH"
    TRUST_DEGRADATION = "TRUST_DEGRADATION"
    CRITICAL_INCIDENT = "CRITICAL_INCIDENT"
    DEPLOYMENT_ROLLBACK_FAILURE = "DEPLOYMENT_ROLLBACK_FAILURE"
    MONITORING_FAILURE = "MONITORING_FAILURE"


# =============================================================================
# MODELS
# =============================================================================

class SecurityIncident(Base, TimestampMixin):
    """
    Correlated security incidents grouping related attack telemetry,
    vulnerability findings, and MITRE ATT&CK techniques with containment workflows.
    """
    __tablename__ = "security_incidents"

    id: Mapped[uuid.UUID] = mapped_column(GUID(), primary_key=True, default=uuid.uuid4)
    incident_number: Mapped[str] = mapped_column(String(32), nullable=False, index=True)
    organization_id: Mapped[uuid.UUID] = mapped_column(
        GUID(), ForeignKey("organizations.id", ondelete="CASCADE"), nullable=False, index=True
    )
    title: Mapped[str] = mapped_column(String(255), nullable=False)
    description: Mapped[str] = mapped_column(Text, nullable=False)
    severity: Mapped[str] = mapped_column(String(32), default=IncidentSeverity.MEDIUM.value, nullable=False, index=True)
    status: Mapped[str] = mapped_column(String(32), default=IncidentStatus.OPEN.value, nullable=False, index=True)
    source: Mapped[str] = mapped_column(String(64), default="CORRELATION_ENGINE", nullable=False)

    primary_asset_id: Mapped[Optional[uuid.UUID]] = mapped_column(
        GUID(), ForeignKey("managed_assets.id", ondelete="SET NULL"), nullable=True, index=True
    )

    mitre_attack_id: Mapped[Optional[str]] = mapped_column(String(32), nullable=True)
    mitre_technique: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)

    recommended_action: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    containment_action_taken: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    containment_requires_approval: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    containment_approved_by: Mapped[Optional[uuid.UUID]] = mapped_column(
        GUID(), ForeignKey("users.id", ondelete="SET NULL"), nullable=True
    )
    containment_executed_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)

    assigned_user_id: Mapped[Optional[uuid.UUID]] = mapped_column(
        GUID(), ForeignKey("users.id", ondelete="SET NULL"), nullable=True, index=True
    )

    # JSON structures for IOCs and linked event identifiers
    iocs: Mapped[Optional[Dict[str, Any]]] = mapped_column(JSON, default=dict, nullable=True)
    related_event_ids: Mapped[Optional[List[str]]] = mapped_column(JSON, default=list, nullable=True)

    first_seen_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utc_now, nullable=False)
    last_seen_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utc_now, nullable=False)
    resolved_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)
    closed_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)

    # Relationships
    organization: Mapped["Organization"] = relationship("Organization")
    primary_asset: Mapped[Optional["ManagedAsset"]] = relationship("ManagedAsset")
    assigned_user: Mapped[Optional["User"]] = relationship("User", foreign_keys=[assigned_user_id])
    timeline_entries: Mapped[List["IncidentTimelineEntry"]] = relationship(
        "IncidentTimelineEntry", back_populates="incident", cascade="all, delete-orphan", order_by="IncidentTimelineEntry.created_at.desc()"
    )
    events: Mapped[List["SecurityEvent"]] = relationship("SecurityEvent", back_populates="incident")

    __table_args__ = (
        Index("ix_sec_incidents_org_status", "organization_id", "status"),
        Index("ix_sec_incidents_org_severity", "organization_id", "severity"),
    )


class SecurityEvent(Base, TimestampMixin):
    """
    Ingested real-time security events (Nginx logs, WAF alerts, Auth audits, Discovery, etc.)
    with sanitization and deduplication fingerprints.
    """
    __tablename__ = "security_events"

    id: Mapped[uuid.UUID] = mapped_column(GUID(), primary_key=True, default=uuid.uuid4)
    organization_id: Mapped[uuid.UUID] = mapped_column(
        GUID(), ForeignKey("organizations.id", ondelete="CASCADE"), nullable=False, index=True
    )
    asset_id: Mapped[Optional[uuid.UUID]] = mapped_column(
        GUID(), ForeignKey("managed_assets.id", ondelete="SET NULL"), nullable=True, index=True
    )
    incident_id: Mapped[Optional[uuid.UUID]] = mapped_column(
        GUID(), ForeignKey("security_incidents.id", ondelete="SET NULL"), nullable=True, index=True
    )

    source: Mapped[str] = mapped_column(String(32), default=EventSource.SYSTEM.value, nullable=False, index=True)
    category: Mapped[str] = mapped_column(String(32), default=EventCategory.SECURITY.value, nullable=False, index=True)
    severity: Mapped[str] = mapped_column(String(32), default=EventSeverity.INFO.value, nullable=False, index=True)
    confidence: Mapped[float] = mapped_column(Float, default=1.0, nullable=False)

    title: Mapped[str] = mapped_column(String(255), nullable=False)
    description: Mapped[str] = mapped_column(Text, nullable=False)

    source_ip: Mapped[Optional[str]] = mapped_column(String(64), nullable=True, index=True)
    target_uri: Mapped[Optional[str]] = mapped_column(String(1024), nullable=True)
    http_method: Mapped[Optional[str]] = mapped_column(String(16), nullable=True)
    status_code: Mapped[Optional[int]] = mapped_column(Integer, nullable=True)

    fingerprint: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    raw_payload: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    event_metadata: Mapped[Optional[Dict[str, Any]]] = mapped_column(JSON, default=dict, nullable=True)

    is_correlated: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    timestamp: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utc_now, nullable=False, index=True)

    # Relationships
    organization: Mapped["Organization"] = relationship("Organization")
    asset: Mapped[Optional["ManagedAsset"]] = relationship("ManagedAsset")
    incident: Mapped[Optional["SecurityIncident"]] = relationship("SecurityIncident", back_populates="events")

    __table_args__ = (
        Index("ix_sec_events_org_time", "organization_id", "timestamp"),
        Index("ix_sec_events_org_fingerprint", "organization_id", "fingerprint"),
        Index("ix_sec_events_org_severity", "organization_id", "severity"),
    )


class IncidentTimelineEntry(Base, TimestampMixin):
    """
    Chronological investigation notes, status changes, and containment action logs.
    """
    __tablename__ = "incident_timeline_entries"

    id: Mapped[uuid.UUID] = mapped_column(GUID(), primary_key=True, default=uuid.uuid4)
    incident_id: Mapped[uuid.UUID] = mapped_column(
        GUID(), ForeignKey("security_incidents.id", ondelete="CASCADE"), nullable=False, index=True
    )
    organization_id: Mapped[uuid.UUID] = mapped_column(
        GUID(), ForeignKey("organizations.id", ondelete="CASCADE"), nullable=False, index=True
    )

    entry_type: Mapped[str] = mapped_column(String(64), nullable=False)  # STATUS_CHANGE, ANALYST_NOTE, CONTAINMENT_ACTION, etc.
    message: Mapped[str] = mapped_column(Text, nullable=False)
    evidence_data: Mapped[Optional[Dict[str, Any]]] = mapped_column(JSON, default=dict, nullable=True)
    actor_user_id: Mapped[Optional[uuid.UUID]] = mapped_column(
        GUID(), ForeignKey("users.id", ondelete="SET NULL"), nullable=True
    )

    # Relationships
    incident: Mapped["SecurityIncident"] = relationship("SecurityIncident", back_populates="timeline_entries")
    actor_user: Mapped[Optional["User"]] = relationship("User")


class SecurityAlert(Base, TimestampMixin):
    """
    In-app alerts notifying SMB administrators of critical vulnerabilities,
    repeated attacks, or deployment failures.
    """
    __tablename__ = "security_alerts"

    id: Mapped[uuid.UUID] = mapped_column(GUID(), primary_key=True, default=uuid.uuid4)
    organization_id: Mapped[uuid.UUID] = mapped_column(
        GUID(), ForeignKey("organizations.id", ondelete="CASCADE"), nullable=False, index=True
    )
    title: Mapped[str] = mapped_column(String(255), nullable=False)
    message: Mapped[str] = mapped_column(Text, nullable=False)
    category: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    severity: Mapped[str] = mapped_column(String(32), default=EventSeverity.MEDIUM.value, nullable=False, index=True)

    is_acknowledged: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False, index=True)
    acknowledged_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)
    acknowledged_by_user_id: Mapped[Optional[uuid.UUID]] = mapped_column(
        GUID(), ForeignKey("users.id", ondelete="SET NULL"), nullable=True
    )

    related_incident_id: Mapped[Optional[uuid.UUID]] = mapped_column(
        GUID(), ForeignKey("security_incidents.id", ondelete="SET NULL"), nullable=True
    )
    related_event_id: Mapped[Optional[uuid.UUID]] = mapped_column(
        GUID(), ForeignKey("security_events.id", ondelete="SET NULL"), nullable=True
    )

    # Relationships
    organization: Mapped["Organization"] = relationship("Organization")
    acknowledged_by_user: Mapped[Optional["User"]] = relationship("User")


class EventRetentionPolicy(Base, TimestampMixin):
    """
    Configurable retention policy per organization to prevent unbounded database growth.
    """
    __tablename__ = "event_retention_policies"

    id: Mapped[uuid.UUID] = mapped_column(GUID(), primary_key=True, default=uuid.uuid4)
    organization_id: Mapped[uuid.UUID] = mapped_column(
        GUID(), ForeignKey("organizations.id", ondelete="CASCADE"), unique=True, nullable=False, index=True
    )
    retention_days: Mapped[int] = mapped_column(Integer, default=30, nullable=False)
    max_stored_events: Mapped[int] = mapped_column(Integer, default=100000, nullable=False)
    auto_prune_enabled: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)
    last_pruned_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)

    # Relationships
    organization: Mapped["Organization"] = relationship("Organization")
