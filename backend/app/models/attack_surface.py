"""
PREVENT-X Attack Surface Intelligence Models
Captures discovery jobs, external domain assets, DNS telemetry, certificate evidence, RDAP profiles, and exposure findings.
"""

import uuid
from datetime import datetime
from typing import Optional, List, TYPE_CHECKING
from sqlalchemy import String, Boolean, Integer, Float, Text, DateTime, ForeignKey, UniqueConstraint
from sqlalchemy.orm import Mapped, mapped_column, relationship
from backend.app.database.base import Base, TimestampMixin, utc_now
from backend.app.database.guid import GUID

if TYPE_CHECKING:
    from backend.app.models.organization import Organization
    from backend.app.models.asset import ManagedAsset
    from backend.app.models.user import User


class DiscoveryJobStatus:
    PENDING = "PENDING"
    QUEUED = "QUEUED"
    RUNNING = "RUNNING"
    COMPLETED = "COMPLETED"
    PARTIALLY_COMPLETED = "PARTIALLY_COMPLETED"
    FAILED = "FAILED"
    CANCELLED = "CANCELLED"


class FindingCategory:
    PUBLIC_DOMAIN = "PUBLIC_DOMAIN"
    DISCOVERED_SUBDOMAIN = "DISCOVERED_SUBDOMAIN"
    PUBLIC_IP = "PUBLIC_IP"
    DNS_CONFIGURATION = "DNS_CONFIGURATION"
    CERTIFICATE_EXPOSURE = "CERTIFICATE_EXPOSURE"
    UNKNOWN_ASSET_RELATIONSHIP = "UNKNOWN_ASSET_RELATIONSHIP"


class FindingSeverity:
    INFO = "INFO"
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


class FindingConfidence:
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"


class DiscoveryJob(Base, TimestampMixin):
    __tablename__ = "discovery_jobs"

    id: Mapped[uuid.UUID] = mapped_column(GUID(), primary_key=True, default=uuid.uuid4)
    organization_id: Mapped[uuid.UUID] = mapped_column(
        GUID(),
        ForeignKey("organizations.id", ondelete="CASCADE"),
        index=True,
        nullable=False,
    )
    asset_id: Mapped[uuid.UUID] = mapped_column(
        GUID(),
        ForeignKey("managed_assets.id", ondelete="CASCADE"),
        index=True,
        nullable=False,
    )
    target_domain: Mapped[str] = mapped_column(String(255), nullable=False, index=True)
    status: Mapped[str] = mapped_column(String(50), default=DiscoveryJobStatus.PENDING, nullable=False, index=True)
    progress_percent: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    current_stage: Mapped[str] = mapped_column(String(100), default="VALIDATION", nullable=False)
    authorized_scope: Mapped[str] = mapped_column(String(255), nullable=False)
    initiated_by_user_id: Mapped[Optional[uuid.UUID]] = mapped_column(
        GUID(),
        ForeignKey("users.id", ondelete="SET NULL"),
        nullable=True,
    )
    authorization_confirmed: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)
    authorized_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utc_now, nullable=False)
    started_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)
    completed_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)
    error_message: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    stage_errors: Mapped[Optional[str]] = mapped_column(Text, nullable=True)  # JSON-encoded dict
    domains_discovered_count: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    findings_count: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    initial_exposure_score: Mapped[Optional[float]] = mapped_column(Float, nullable=True)
    risk_score_details: Mapped[Optional[str]] = mapped_column(Text, nullable=True)  # JSON-encoded dict

    # Relationships
    discovered_domains: Mapped[List["DiscoveredDomain"]] = relationship("DiscoveredDomain", back_populates="job", cascade="all, delete-orphan")
    findings: Mapped[List["ExposureFinding"]] = relationship("ExposureFinding", back_populates="job", cascade="all, delete-orphan")


class DiscoveredDomain(Base, TimestampMixin):
    __tablename__ = "discovered_domains"
    __table_args__ = (
        UniqueConstraint("organization_id", "domain_name", name="uq_org_discovered_domain"),
    )

    id: Mapped[uuid.UUID] = mapped_column(GUID(), primary_key=True, default=uuid.uuid4)
    organization_id: Mapped[uuid.UUID] = mapped_column(
        GUID(),
        ForeignKey("organizations.id", ondelete="CASCADE"),
        index=True,
        nullable=False,
    )
    asset_id: Mapped[uuid.UUID] = mapped_column(
        GUID(),
        ForeignKey("managed_assets.id", ondelete="CASCADE"),
        index=True,
        nullable=False,
    )
    job_id: Mapped[uuid.UUID] = mapped_column(
        GUID(),
        ForeignKey("discovery_jobs.id", ondelete="CASCADE"),
        index=True,
        nullable=False,
    )
    domain_name: Mapped[str] = mapped_column(String(255), nullable=False, index=True)
    parent_domain: Mapped[Optional[str]] = mapped_column(String(255), nullable=True, index=True)
    is_subdomain: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    discovery_source: Mapped[str] = mapped_column(String(50), default="CERTIFICATE_TRANSPARENCY", nullable=False)
    confidence_score: Mapped[float] = mapped_column(Float, default=1.0, nullable=False)
    first_observed_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utc_now, nullable=False)
    last_observed_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utc_now, nullable=False)

    # Relationships
    job: Mapped["DiscoveryJob"] = relationship("DiscoveryJob", back_populates="discovered_domains")
    dns_records: Mapped[List["DNSRecord"]] = relationship("DNSRecord", back_populates="domain", cascade="all, delete-orphan")
    certificates: Mapped[List["CertificateEvidence"]] = relationship("CertificateEvidence", back_populates="domain", cascade="all, delete-orphan")
    rdap: Mapped[Optional["RDAPRecord"]] = relationship("RDAPRecord", back_populates="domain", uselist=False, cascade="all, delete-orphan")


class DNSRecord(Base):
    __tablename__ = "dns_records"

    id: Mapped[uuid.UUID] = mapped_column(GUID(), primary_key=True, default=uuid.uuid4)
    organization_id: Mapped[uuid.UUID] = mapped_column(
        GUID(),
        ForeignKey("organizations.id", ondelete="CASCADE"),
        index=True,
        nullable=False,
    )
    domain_id: Mapped[uuid.UUID] = mapped_column(
        GUID(),
        ForeignKey("discovered_domains.id", ondelete="CASCADE"),
        index=True,
        nullable=False,
    )
    domain_name: Mapped[str] = mapped_column(String(255), nullable=False, index=True)
    record_type: Mapped[str] = mapped_column(String(10), nullable=False, index=True)  # A, AAAA, CNAME, MX, NS, TXT
    record_value: Mapped[str] = mapped_column(Text, nullable=False)
    ttl: Mapped[Optional[int]] = mapped_column(Integer, nullable=True)
    source: Mapped[str] = mapped_column(String(50), default="DNS_RESOLVER", nullable=False)
    resolution_status: Mapped[str] = mapped_column(String(50), default="RESOLVED", nullable=False)
    collected_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utc_now, nullable=False)

    # Relationship
    domain: Mapped["DiscoveredDomain"] = relationship("DiscoveredDomain", back_populates="dns_records")


class CertificateEvidence(Base):
    __tablename__ = "certificate_evidence"

    id: Mapped[uuid.UUID] = mapped_column(GUID(), primary_key=True, default=uuid.uuid4)
    organization_id: Mapped[uuid.UUID] = mapped_column(
        GUID(),
        ForeignKey("organizations.id", ondelete="CASCADE"),
        index=True,
        nullable=False,
    )
    domain_id: Mapped[uuid.UUID] = mapped_column(
        GUID(),
        ForeignKey("discovered_domains.id", ondelete="CASCADE"),
        index=True,
        nullable=False,
    )
    issuer_name: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    common_name: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)
    subject_alt_names: Mapped[Optional[str]] = mapped_column(Text, nullable=True)  # JSON-encoded array
    not_before: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)
    not_after: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)
    is_expired: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    is_wildcard: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    serial_number: Mapped[Optional[str]] = mapped_column(String(128), nullable=True)
    logged_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)
    source: Mapped[str] = mapped_column(String(50), default="CRT_SH", nullable=False)
    raw_evidence: Mapped[Optional[str]] = mapped_column(Text, nullable=True)

    # Relationship
    domain: Mapped["DiscoveredDomain"] = relationship("DiscoveredDomain", back_populates="certificates")


class RDAPRecord(Base):
    __tablename__ = "rdap_records"

    id: Mapped[uuid.UUID] = mapped_column(GUID(), primary_key=True, default=uuid.uuid4)
    organization_id: Mapped[uuid.UUID] = mapped_column(
        GUID(),
        ForeignKey("organizations.id", ondelete="CASCADE"),
        index=True,
        nullable=False,
    )
    domain_id: Mapped[uuid.UUID] = mapped_column(
        GUID(),
        ForeignKey("discovered_domains.id", ondelete="CASCADE"),
        unique=True,
        index=True,
        nullable=False,
    )
    handle: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)
    registrar_name: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)
    whois_server: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)
    registration_date: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)
    expiration_date: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)
    last_updated_date: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)
    nameservers: Mapped[Optional[str]] = mapped_column(Text, nullable=True)  # JSON-encoded array
    status_codes: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    asn: Mapped[Optional[str]] = mapped_column(String(50), nullable=True)
    raw_data: Mapped[Optional[str]] = mapped_column(Text, nullable=True)

    # Relationship
    domain: Mapped["DiscoveredDomain"] = relationship("DiscoveredDomain", back_populates="rdap")


class ExposureFinding(Base, TimestampMixin):
    __tablename__ = "exposure_findings"

    id: Mapped[uuid.UUID] = mapped_column(GUID(), primary_key=True, default=uuid.uuid4)
    organization_id: Mapped[uuid.UUID] = mapped_column(
        GUID(),
        ForeignKey("organizations.id", ondelete="CASCADE"),
        index=True,
        nullable=False,
    )
    asset_id: Mapped[uuid.UUID] = mapped_column(
        GUID(),
        ForeignKey("managed_assets.id", ondelete="CASCADE"),
        index=True,
        nullable=False,
    )
    job_id: Mapped[uuid.UUID] = mapped_column(
        GUID(),
        ForeignKey("discovery_jobs.id", ondelete="CASCADE"),
        index=True,
        nullable=False,
    )
    target: Mapped[str] = mapped_column(String(255), nullable=False, index=True)
    finding_category: Mapped[str] = mapped_column(String(50), nullable=False, index=True)
    severity: Mapped[str] = mapped_column(String(20), default=FindingSeverity.LOW, nullable=False, index=True)
    confidence: Mapped[str] = mapped_column(String(20), default=FindingConfidence.HIGH, nullable=False)
    title: Mapped[str] = mapped_column(String(255), nullable=False)
    description: Mapped[str] = mapped_column(Text, nullable=False)
    evidence: Mapped[str] = mapped_column(Text, nullable=False)  # JSON-encoded payload
    discovery_source: Mapped[str] = mapped_column(String(50), default="PASSIVE_RECON", nullable=False)
    first_observed_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utc_now, nullable=False)
    last_observed_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utc_now, nullable=False)
    current_status: Mapped[str] = mapped_column(String(50), default="ACTIVE", nullable=False, index=True)

    # Relationship
    job: Mapped["DiscoveryJob"] = relationship("DiscoveryJob", back_populates="findings")
