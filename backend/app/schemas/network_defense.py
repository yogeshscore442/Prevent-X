"""
PREVENT-X Advanced Network Defense & Detection Layer Pydantic Schemas
Defines request and response validation contracts for all network defense capabilities:
- OS Firewall Integration
- Dynamic IP Blocking
- Advanced Rate Limiting
- Payload Normalization
- Advanced Attack Detection
- Traffic Replay & Differential Validation
- Honeypot Probing & Reconnaissance Detection
- GeoIP Policy Enforcement
- ML Traffic Classification (Advisory)
"""

import uuid
from datetime import datetime
from typing import Any, Dict, List, Optional
from pydantic import BaseModel, ConfigDict, Field

from backend.app.models.network_defense import (
    DynamicIPBlockStatus,
    FirewallEnforcementStatus,
    FirewallRuleAction,
    FirewallRuleDirection,
    FirewallRuleProtocol,
    GeoIPPolicyAction,
    RateLimitScope,
    RateLimitingAlgorithm,
)


# ==========================================
# 1. OS Firewall Schemas
# ==========================================

class FirewallRuleCreate(BaseModel):
    remote_ip_or_cidr: str = Field(..., description="Target IPv4 or IPv6 or CIDR (e.g. 192.168.1.100 or 10.0.0.0/24)")
    display_name: str = Field(..., max_length=128, description="Human-readable rule name")
    direction: FirewallRuleDirection = Field(FirewallRuleDirection.INBOUND)
    action: FirewallRuleAction = Field(FirewallRuleAction.BLOCK)
    protocol: FirewallRuleProtocol = Field(FirewallRuleProtocol.ANY)
    local_ports: Optional[str] = Field(None, description="Comma-separated ports or range e.g. '80,443' or '8000-8080'")
    remote_ports: Optional[str] = Field(None)
    description: Optional[str] = Field(None, max_length=255)
    expires_in_minutes: Optional[int] = Field(None, ge=1, le=525600, description="Auto-expiry in minutes")


class FirewallRuleResponse(BaseModel):
    id: str
    organization_id: uuid.UUID
    name: str
    display_name: str
    remote_ip_or_cidr: str
    direction: FirewallRuleDirection
    action: FirewallRuleAction
    protocol: FirewallRuleProtocol
    local_ports: Optional[str] = None
    remote_ports: Optional[str] = None
    rule_name: Optional[str] = None
    is_active: bool
    verified_active: bool
    enforcement_status: FirewallEnforcementStatus
    error_message: Optional[str] = None
    expires_at: Optional[datetime] = None
    last_verified_at: Optional[datetime] = None
    created_at: datetime
    updated_at: datetime

    model_config = ConfigDict(from_attributes=True)


class FirewallStatusResponse(BaseModel):
    os_type: str
    is_elevated: bool
    is_operational: bool = True
    active_rules_count: int = 0
    verified_rules_count: int = 0
    failed_rules_count: int = 0
    pending_rules_count: int = 0
    execution_mode: str = "RESTRICTED"
    managed_os_rules: List[str] = []
    notice: Optional[str] = None


# ==========================================
# 2. Dynamic IP Blocking Schemas
# ==========================================

class DynamicIPBlockCreate(BaseModel):
    ip_or_cidr: str = Field(..., description="IPv4 or IPv6 address or CIDR range")
    reason: str = Field(..., max_length=255, description="Incident or threat intelligence justification")
    duration_minutes: int = Field(60, ge=1, le=525600, description="Ban duration in minutes (default 60)")
    require_approval: bool = Field(False, description="Require manual admin approval before firewall sync")
    incident_id: Optional[uuid.UUID] = Field(None, description="Correlated SecurityIncident ID")
    threat_intel_record_id: Optional[uuid.UUID] = Field(None, description="Correlated ThreatIntelRecord ID")
    threat_intel_score: Optional[int] = Field(None, ge=0, le=100)


class DynamicIPBlockResponse(BaseModel):
    id: str
    organization_id: uuid.UUID
    ip_or_cidr: str
    reason: str
    duration_minutes: Optional[int] = None
    status: DynamicIPBlockStatus
    firewall_rule_id: Optional[str] = None
    incident_id: Optional[str] = None
    threat_intel_score: Optional[float] = None
    threat_intel_record_id: Optional[uuid.UUID] = None
    created_by_id: Optional[uuid.UUID] = None
    approved_by_id: Optional[uuid.UUID] = None
    approval_requested_by: Optional[uuid.UUID] = None
    approved_by: Optional[uuid.UUID] = None
    approved_at: Optional[datetime] = None
    expires_at: datetime
    unblocked_at: Optional[datetime] = None
    unblocked_by: Optional[uuid.UUID] = None
    created_at: datetime
    updated_at: datetime

    model_config = ConfigDict(from_attributes=True)


class DynamicIPBlockApprove(BaseModel):
    notes: Optional[str] = Field(None, max_length=255)


class DynamicIPUnblockRequest(BaseModel):
    reason: Optional[str] = Field(None, max_length=255)


# ==========================================
# 3. Advanced Rate Limiting Schemas
# ==========================================

class RateLimitPolicyCreate(BaseModel):
    name: str = Field(..., max_length=128)
    endpoint_pattern: str = Field(..., max_length=255, description="URL pattern e.g. /api/v1/auth/.* or exact path")
    scope: RateLimitScope = Field(RateLimitScope.IP)
    algorithm: RateLimitingAlgorithm = Field(RateLimitingAlgorithm.SLIDING_WINDOW)
    max_requests: int = Field(60, ge=1, le=1000000)
    window_seconds: int = Field(60, ge=1, le=86400)
    burst_capacity: int = Field(10, ge=1, le=100000)
    refill_rate_per_sec: float = Field(1.0, ge=0.01, le=10000.0)


class RateLimitPolicyResponse(BaseModel):
    id: str
    organization_id: uuid.UUID
    name: str
    endpoint_pattern: str
    scope: RateLimitScope
    algorithm: RateLimitingAlgorithm
    max_requests: int
    window_seconds: int
    burst_capacity: int
    refill_rate_per_sec: float
    is_active: bool
    created_at: datetime
    updated_at: datetime

    model_config = ConfigDict(from_attributes=True)


class RateLimitEvaluationResult(BaseModel):
    allowed: bool
    policy_name: Optional[str] = None
    remaining: int = 0
    limit: int = 0
    scope: Any = "ip"
    algorithm: Optional[Any] = None
    retry_after: int = 0
    reset_after_seconds: Optional[int] = None
    client_key: Optional[str] = None


# ==========================================
# 4. Payload Normalization Schemas
# ==========================================

class PayloadNormalizationRequest(BaseModel):
    payload: str = Field(..., max_length=65536, description="Raw input string to normalize")
    context: Optional[str] = Field("general", description="URI, JSON, Header, or General context")


class PayloadNormalizationResponse(BaseModel):
    raw_text: str
    normalized_text: str
    obfuscation_detected: bool
    detected_techniques: List[str]
    extracted_base64_fragments: List[str] = []


# Aliases
NormalizationRequest = PayloadNormalizationRequest
NormalizationResponse = PayloadNormalizationResponse


# ==========================================
# 5. Advanced Attack Detection Schemas
# ==========================================

class AttackDetectionRequest(BaseModel):
    method: str = Field("POST", max_length=10)
    path: str = Field(..., max_length=1024)
    query_string: Optional[str] = Field(None, max_length=8192)
    body: Optional[str] = Field(None, max_length=65536)
    headers: Optional[Dict[str, str]] = None


class AttackDetectionResponse(BaseModel):
    detected: bool
    category: Optional[str] = None
    confidence: float = 0.0
    severity: str = "LOW"
    cwe_id: Optional[str] = None
    mitre_attack_id: Optional[str] = None
    explanation: str = "Clean request."
    matched_pattern: Optional[str] = None
    obfuscation_detected: bool = False
    detected_techniques: List[str] = []


# ==========================================
# 6. Traffic Replay Schemas
# ==========================================

class TrafficReplayExecuteRequest(BaseModel):
    virtual_patch_id: Optional[uuid.UUID] = None
    custom_fixtures: Optional[List[Dict[str, Any]]] = None
    max_fixtures: Optional[int] = Field(50, ge=1, le=500)


class TrafficReplayReportResponse(BaseModel):
    id: str
    organization_id: uuid.UUID
    virtual_patch_id: Optional[uuid.UUID] = None
    total_replayed: int
    passed_benign: int
    false_positives: int
    missed_threats: int
    fp_rate: float
    is_regression_free: bool
    report_details: Optional[str] = None
    created_at: datetime

    model_config = ConfigDict(from_attributes=True)


# ==========================================
# 7. Honeypot Schemas
# ==========================================

class HoneypotProbeRequest(BaseModel):
    path: str = Field(..., max_length=1024, description="Target requested URL path")
    source_ip: str = Field(..., max_length=64, description="Source IP address of request")
    method: str = Field("GET", max_length=16)
    query_string: Optional[str] = Field(None, max_length=4096)
    user_agent: Optional[str] = Field(None, max_length=1024)
    payload_preview: Optional[str] = Field(None, max_length=2048)
    auto_recommend_block: bool = Field(True, description="Whether to create a dynamic blocking recommendation")


class HoneypotProbeResponse(BaseModel):
    is_honeypot: bool
    trap_path: Optional[str] = None
    source_ip: Optional[str] = None
    probe_id: Optional[str] = None
    incident_id: Optional[str] = None
    recommended_block_id: Optional[str] = None
    message: str = "Request evaluated against honeypot decoys."


class HoneypotProbeRecordResponse(BaseModel):
    id: str
    organization_id: uuid.UUID
    trap_path: str
    source_ip: str
    http_method: str
    user_agent: Optional[str] = None
    query_string: Optional[str] = None
    payload_preview: Optional[str] = None
    correlated_incident_id: Optional[str] = None
    recommended_block_id: Optional[str] = None
    created_at: datetime

    model_config = ConfigDict(from_attributes=True)


class HoneypotTrapCreate(BaseModel):
    path: str = Field(..., min_length=2, max_length=255, description="Decoy URI path to monitor (e.g. /admin/backup.sql)")


class HoneypotStatsResponse(BaseModel):
    total_probes: int
    unique_attacker_ips: int
    top_traps: List[Dict[str, Any]]
    active_decoy_count: int


# ==========================================
# 8. GeoIP Policy Schemas
# ==========================================

class GeoIPPolicyCreate(BaseModel):
    country_code: str = Field(..., min_length=2, max_length=2, description="ISO-3166-1 alpha-2 code e.g. 'RU', 'KP'")
    country_name: str = Field(..., max_length=64)
    action: GeoIPPolicyAction = Field(GeoIPPolicyAction.DENY)
    exception_cidrs: Optional[str] = Field(None, description="Comma-separated IP CIDRs allowed to bypass policy")
    risk_score_modifier: float = Field(30.0, ge=0.0, le=100.0)


class GeoIPPolicyResponse(BaseModel):
    id: str
    organization_id: uuid.UUID
    country_code: str
    country_name: str
    action: GeoIPPolicyAction
    exception_cidrs: Optional[str] = None
    risk_score_modifier: float
    is_active: bool
    created_at: datetime
    updated_at: datetime

    model_config = ConfigDict(from_attributes=True)


class GeoIPLookupRequest(BaseModel):
    ip_address: str = Field(..., max_length=64)


class GeoIPLookupResponse(BaseModel):
    ip_address: str
    country_code: str
    country_name: str
    is_denied: bool
    policy_action: Optional[str] = None
    risk_score_modifier: float
    is_exception_cidr: bool
    database_version: str
    is_advisory_only: bool = True


# ==========================================
# 9. ML Traffic Classification Schemas
# ==========================================

class MLClassificationRequest(BaseModel):
    method: str = Field("POST", max_length=10)
    path: str = Field(..., max_length=1024)
    query_string: Optional[str] = Field(None, max_length=8192)
    body: Optional[str] = Field(None, max_length=65536)
    headers: Optional[Dict[str, str]] = None


class MLClassificationResponse(BaseModel):
    is_anomalous: bool
    anomaly_score: float = Field(..., ge=0.0, le=1.0)
    predicted_class: str
    model_version: str
    is_advisory_only: bool = True
    top_feature_importances: Dict[str, float] = {}
    recommendation: str


class MLModelStatusResponse(BaseModel):
    model_version: str
    algorithm: str
    training_sample_count: int
    features_count: int
    is_ready: bool
    precision: float
    recall: float
    f1_score: float
    advisory_mode: bool = True
