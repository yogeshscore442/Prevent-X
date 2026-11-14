"""
PREVENT-X Attack Path and Prevention Engine Models (MOD-03)
Relational models for attack graph paths, trust relationships, MITRE ATT&CK mapping,
and prioritized preventive control recommendations.
"""

import enum
import uuid
from datetime import datetime
from typing import List, Optional
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


class AttackPathSeverity(str, enum.Enum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"


class AttackPathConfidence(str, enum.Enum):
    CONFIRMED = "CONFIRMED"
    LIKELY = "LIKELY"
    POTENTIAL = "POTENTIAL"


class AttackPathStatus(str, enum.Enum):
    IDENTIFIED = "IDENTIFIED"
    UNDER_REVIEW = "UNDER_REVIEW"
    MITIGATED = "MITIGATED"
    ACCEPTED = "ACCEPTED"


class RecommendationCategory(str, enum.Enum):
    SERVICE_HARDENING = "SERVICE_HARDENING"
    NETWORK_SEGMENTATION = "NETWORK_SEGMENTATION"
    MFA_ACCESS_CONTROL = "MFA_ACCESS_CONTROL"
    VIRTUAL_PATCH = "VIRTUAL_PATCH"
    LEAST_PRIVILEGE = "LEAST_PRIVILEGE"
    LOGGING_MONITORING = "LOGGING_MONITORING"


class ComplexityLevel(str, enum.Enum):
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"


class ImpactLevel(str, enum.Enum):
    MINIMAL = "MINIMAL"
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"


class TrustRelationshipType(str, enum.Enum):
    DATABASE_LINK = "DATABASE_LINK"
    SSH_ADMIN_ACCESS = "SSH_ADMIN_ACCESS"
    ACTIVE_DIRECTORY_TRUST = "ACTIVE_DIRECTORY_TRUST"
    SAME_SUBNET = "SAME_SUBNET"
    API_DEPENDENCY = "API_DEPENDENCY"


class AttackPath(Base, TimestampMixin):
    """
    Evidence-backed attack path connecting exposed entry points through intermediate
    pivots to high-value target assets.
    """
    __tablename__ = "attack_paths"

    id: Mapped[uuid.UUID] = mapped_column(GUID(), primary_key=True, default=uuid.uuid4)
    organization_id: Mapped[uuid.UUID] = mapped_column(
        GUID(), ForeignKey("organizations.id", ondelete="CASCADE"), index=True, nullable=False
    )
    name: Mapped[str] = mapped_column(String(255), nullable=False)
    entry_point_asset_id: Mapped[uuid.UUID] = mapped_column(
        GUID(), ForeignKey("managed_assets.id", ondelete="CASCADE"), index=True, nullable=False
    )
    target_asset_id: Mapped[uuid.UUID] = mapped_column(
        GUID(), ForeignKey("managed_assets.id", ondelete="CASCADE"), index=True, nullable=False
    )
    step_count: Mapped[int] = mapped_column(Integer, default=1, nullable=False)
    risk_score: Mapped[float] = mapped_column(Float, default=0.0, nullable=False, index=True)

    # Phase 4 Extensions
    severity: Mapped[str] = mapped_column(
        String(20), default=AttackPathSeverity.MEDIUM.value, nullable=False, index=True
    )
    confidence: Mapped[str] = mapped_column(
        String(30), default=AttackPathConfidence.POTENTIAL.value, nullable=False, index=True
    )
    title: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)
    description: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    path_narrative: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    graph_data: Mapped[Optional[str]] = mapped_column(Text, nullable=True)  # JSON: {nodes: [], edges: []}
    mitre_tactics: Mapped[Optional[str]] = mapped_column(Text, nullable=True)  # JSON list
    mitre_techniques: Mapped[Optional[str]] = mapped_column(Text, nullable=True)  # JSON list of dicts
    prerequisites: Mapped[Optional[str]] = mapped_column(Text, nullable=True)  # JSON list
    evidence_references: Mapped[Optional[str]] = mapped_column(Text, nullable=True)  # JSON list
    status: Mapped[str] = mapped_column(
        String(30), default=AttackPathStatus.IDENTIFIED.value, nullable=False, index=True
    )

    # Relationships
    entry_point_asset: Mapped["ManagedAsset"] = relationship("ManagedAsset", foreign_keys=[entry_point_asset_id])
    target_asset: Mapped["ManagedAsset"] = relationship("ManagedAsset", foreign_keys=[target_asset_id])
    recommendations: Mapped[List["PreventionRecommendation"]] = relationship(
        "PreventionRecommendation", back_populates="attack_path", cascade="all, delete-orphan"
    )


# Alias for backward compatibility
AttackPathGraph = AttackPath


class AssetTrustRelationship(Base, TimestampMixin):
    """
    Evidence-backed trust or network connectivity relationship between two assets.
    """
    __tablename__ = "asset_trust_relationships"

    id: Mapped[uuid.UUID] = mapped_column(GUID(), primary_key=True, default=uuid.uuid4)
    organization_id: Mapped[uuid.UUID] = mapped_column(
        GUID(), ForeignKey("organizations.id", ondelete="CASCADE"), index=True, nullable=False
    )
    source_asset_id: Mapped[uuid.UUID] = mapped_column(
        GUID(), ForeignKey("managed_assets.id", ondelete="CASCADE"), index=True, nullable=False
    )
    target_asset_id: Mapped[uuid.UUID] = mapped_column(
        GUID(), ForeignKey("managed_assets.id", ondelete="CASCADE"), index=True, nullable=False
    )
    relationship_type: Mapped[str] = mapped_column(
        String(50), default=TrustRelationshipType.SAME_SUBNET.value, nullable=False
    )
    port: Mapped[Optional[int]] = mapped_column(Integer, nullable=True)
    evidence_source: Mapped[str] = mapped_column(String(100), default="DISCOVERED_SERVICE", nullable=False)
    is_verified: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)

    source_asset: Mapped["ManagedAsset"] = relationship("ManagedAsset", foreign_keys=[source_asset_id])
    target_asset: Mapped["ManagedAsset"] = relationship("ManagedAsset", foreign_keys=[target_asset_id])


class PreventionRecommendation(Base, TimestampMixin):
    """
    Prioritized compensating security control or mitigation recommended to break an attack path.
    """
    __tablename__ = "prevention_recommendations"

    id: Mapped[uuid.UUID] = mapped_column(GUID(), primary_key=True, default=uuid.uuid4)
    organization_id: Mapped[uuid.UUID] = mapped_column(
        GUID(), ForeignKey("organizations.id", ondelete="CASCADE"), index=True, nullable=False
    )
    attack_path_id: Mapped[Optional[uuid.UUID]] = mapped_column(
        GUID(), ForeignKey("attack_paths.id", ondelete="CASCADE"), index=True, nullable=True
    )
    target_asset_id: Mapped[Optional[uuid.UUID]] = mapped_column(
        GUID(), ForeignKey("managed_assets.id", ondelete="SET NULL"), index=True, nullable=True
    )
    title: Mapped[str] = mapped_column(String(255), nullable=False)
    category: Mapped[str] = mapped_column(String(50), nullable=False)  # SERVICE_HARDENING, NETWORK_SEGMENTATION...
    description: Mapped[str] = mapped_column(Text, nullable=False)
    risk_reduction: Mapped[str] = mapped_column(String(20), default="HIGH", nullable=False)
    implementation_complexity: Mapped[str] = mapped_column(String(20), default="LOW", nullable=False)
    smb_operational_impact: Mapped[str] = mapped_column(String(20), default="MINIMAL", nullable=False)
    priority_rank: Mapped[int] = mapped_column(Integer, default=1, nullable=False, index=True)
    mitre_technique_id: Mapped[Optional[str]] = mapped_column(String(50), nullable=True)
    status: Mapped[str] = mapped_column(String(30), default="PROPOSED", nullable=False, index=True)

    attack_path: Mapped[Optional["AttackPath"]] = relationship("AttackPath", back_populates="recommendations")
    target_asset: Mapped[Optional["ManagedAsset"]] = relationship("ManagedAsset")


class AttackPathAnalysisJob(Base, TimestampMixin):
    """
    Asynchronous job for analyzing attack paths and computing prevention recommendations.
    """
    __tablename__ = "attack_path_analysis_jobs"

    id: Mapped[uuid.UUID] = mapped_column(GUID(), primary_key=True, default=uuid.uuid4)
    organization_id: Mapped[uuid.UUID] = mapped_column(
        GUID(), ForeignKey("organizations.id", ondelete="CASCADE"), index=True, nullable=False
    )
    initiated_by_user_id: Mapped[Optional[uuid.UUID]] = mapped_column(
        GUID(), ForeignKey("users.id", ondelete="SET NULL"), nullable=True
    )
    status: Mapped[str] = mapped_column(String(30), default="PENDING", nullable=False, index=True)
    paths_discovered_count: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    recommendations_count: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    error_message: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    completed_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)
