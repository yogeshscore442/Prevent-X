"""
PREVENT-X Attack Surface Intelligence Schemas
Pydantic v2 data models for passive discovery, telemetry, risk metrics, and findings.
"""

from datetime import datetime
from typing import Optional, List, Dict, Any
from uuid import UUID
from pydantic import BaseModel, Field, ConfigDict


class DiscoveryJobCreate(BaseModel):
    """Schema for initiating an authorized passive discovery job."""
    asset_id: UUID = Field(..., description="Target managed asset ID owned by the active organization")
    target_domain: Optional[str] = Field(None, max_length=255, description="Domain or target to discover (must match asset scope)")
    authorization_confirmed: bool = Field(..., description="Mandatory confirmation that user possesses authorization to scan target")
    discovery_policy: str = Field("PUBLIC_PASSIVE", description="Discovery policy: PUBLIC_PASSIVE or AUTHORIZED_INTERNAL")


class DiscoveryJobCancel(BaseModel):
    """Schema for cancelling an in-flight discovery job."""
    reason: Optional[str] = Field(None, max_length=255, description="Optional cancellation justification")


class DiscoveryJobResponse(BaseModel):
    """Public representation of a discovery job."""
    model_config = ConfigDict(from_attributes=True)

    id: UUID
    organization_id: UUID
    asset_id: UUID
    target_domain: str
    discovery_policy: str = "PUBLIC_PASSIVE"
    status: str
    progress_percent: int
    current_stage: str
    authorized_scope: str
    initiated_by_user_id: Optional[UUID] = None
    authorization_confirmed: bool
    authorized_at: datetime
    started_at: Optional[datetime] = None
    completed_at: Optional[datetime] = None
    error_message: Optional[str] = None
    stage_errors: Optional[str] = None
    domains_discovered_count: int
    findings_count: int
    initial_exposure_score: Optional[float] = None
    risk_score_details: Optional[str] = None
    created_at: datetime
    updated_at: datetime


class DNSRecordResponse(BaseModel):
    """Public representation of an enumerated DNS record."""
    model_config = ConfigDict(from_attributes=True)

    id: UUID
    domain_id: UUID
    domain_name: str
    record_type: str
    record_value: str
    ttl: Optional[int] = None
    source: str
    resolution_status: str
    collected_at: datetime


class CertificateEvidenceResponse(BaseModel):
    """Public representation of certificate transparency evidence."""
    model_config = ConfigDict(from_attributes=True)

    id: UUID
    domain_id: UUID
    issuer_name: Optional[str] = None
    common_name: Optional[str] = None
    subject_alt_names: Optional[str] = None
    not_before: Optional[datetime] = None
    not_after: Optional[datetime] = None
    is_expired: bool
    is_wildcard: bool
    serial_number: Optional[str] = None
    source: str
    logged_at: Optional[datetime] = None


class RDAPRecordResponse(BaseModel):
    """Public representation of privacy-safe RDAP domain registration metadata."""
    model_config = ConfigDict(from_attributes=True)

    id: UUID
    domain_id: UUID
    handle: Optional[str] = None
    registrar_name: Optional[str] = None
    whois_server: Optional[str] = None
    registration_date: Optional[datetime] = None
    expiration_date: Optional[datetime] = None
    last_updated_date: Optional[datetime] = None
    nameservers: Optional[str] = None
    status_codes: Optional[str] = None
    asn: Optional[str] = None


class DiscoveredDomainResponse(BaseModel):
    """Summary representation of a discovered external domain/subdomain."""
    model_config = ConfigDict(from_attributes=True)

    id: UUID
    organization_id: UUID
    asset_id: UUID
    job_id: UUID
    domain_name: str
    parent_domain: Optional[str] = None
    is_subdomain: bool
    discovery_source: str
    confidence_score: float
    first_observed_at: datetime
    last_observed_at: datetime


class DiscoveredDomainDetailResponse(DiscoveredDomainResponse):
    """Detailed domain representation including associated DNS, certs, and RDAP."""
    dns_records: List[DNSRecordResponse] = []
    certificates: List[CertificateEvidenceResponse] = []
    rdap: Optional[RDAPRecordResponse] = None


class ExposureFindingResponse(BaseModel):
    """Public representation of an evidence-backed exposure finding."""
    model_config = ConfigDict(from_attributes=True)

    id: UUID
    organization_id: UUID
    asset_id: UUID
    job_id: UUID
    target: str
    finding_category: str
    verification_status: str = "UNVERIFIED_RESOURCE"
    evidence_nature: str = "POTENTIAL_WEAKNESS"
    severity: str
    confidence: str
    title: str
    description: str
    evidence: str
    discovery_source: str
    first_observed_at: datetime
    last_observed_at: datetime
    current_status: str


class RiskFactorDetail(BaseModel):
    """Breakdown component of the deterministic exposure risk score."""
    name: str
    factor_key: str
    category: str = "ATTACK_SURFACE_EXPOSURE"
    score: float
    max_weight: float
    impact: str
    confidence: float = 0.95
    evidence_quality: str = "HIGH"
    is_vulnerability: bool = False
    description: str


class RiskScoreBreakdown(BaseModel):
    """Complete explainable risk breakdown calculation."""
    total_score: float = Field(..., ge=0.0, le=100.0)
    max_possible_score: float = 100.0
    risk_level: str  # LOW, MEDIUM, HIGH, CRITICAL
    factors: List[RiskFactorDetail]
    interpretation: str


class AttackSurfaceOverviewResponse(BaseModel):
    """High-level metrics for tenant dashboard."""
    total_discovered_domains: int
    total_public_ips: int
    average_exposure_score: float
    active_findings_count: int
    findings_by_severity: Dict[str, int]
    findings_by_category: Dict[str, int]
    recent_jobs: List[DiscoveryJobResponse]

