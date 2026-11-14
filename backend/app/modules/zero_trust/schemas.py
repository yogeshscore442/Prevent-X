"""
Pydantic Schemas for Zero Trust & Threat Intelligence (MOD-04, MOD-05)
"""

import uuid
from datetime import datetime
from typing import Any, Dict, List, Optional
from pydantic import BaseModel, ConfigDict, Field


class TrustFactor(BaseModel):
    category: str
    factor: str
    impact: str  # POSITIVE, NEGATIVE
    score_delta: float
    description: str


class AssetTrustAssessmentRead(BaseModel):
    id: uuid.UUID
    organization_id: uuid.UUID
    asset_id: uuid.UUID
    asset_name: Optional[str] = None
    asset_target: Optional[str] = None
    asset_type: Optional[str] = None
    asset_criticality: Optional[str] = None
    trust_decision: str
    trust_score: float
    positive_factors: List[Dict[str, Any]] = Field(default_factory=list)
    risk_factors: List[Dict[str, Any]] = Field(default_factory=list)
    least_privilege_recommendations: List[str] = Field(default_factory=list)
    decision_reason: str
    last_evaluated_at: datetime
    is_stale: bool
    created_at: datetime
    updated_at: datetime

    model_config = ConfigDict(from_attributes=True)


class TrustEvaluationRequest(BaseModel):
    asset_id: Optional[uuid.UUID] = None
    force_refresh: bool = False


class ThreatIntelCreate(BaseModel):
    indicator_type: str  # IP, DOMAIN, HASH, URL, PATTERN
    indicator_value: str
    confidence: int = Field(default=80, ge=0, le=100)
    source: str
    threat_actor: Optional[str] = None
    description: Optional[str] = None
    severity: str = "HIGH"
    tlp: str = "WHITE"  # WHITE, GREEN, AMBER, RED
    expires_at: Optional[datetime] = None
    mitre_tactics: List[str] = Field(default_factory=list)
    mitre_techniques: List[str] = Field(default_factory=list)
    tags: List[str] = Field(default_factory=list)


class ThreatIntelRead(BaseModel):
    id: uuid.UUID
    organization_id: Optional[uuid.UUID] = None
    indicator_type: str
    indicator_value: str
    confidence: int
    source: str
    threat_actor: Optional[str] = None
    description: Optional[str] = None
    severity: str
    tlp: str
    is_active: bool
    expires_at: Optional[datetime] = None
    last_seen_at: Optional[datetime] = None
    mitre_tactics: List[str] = Field(default_factory=list)
    mitre_techniques: List[str] = Field(default_factory=list)
    tags: List[str] = Field(default_factory=list)
    is_expired: bool = False
    created_at: datetime
    updated_at: datetime

    model_config = ConfigDict(from_attributes=True)


class ThreatAssetCorrelationRead(BaseModel):
    id: uuid.UUID
    organization_id: uuid.UUID
    threat_intel_id: uuid.UUID
    asset_id: uuid.UUID
    asset_name: Optional[str] = None
    asset_target: Optional[str] = None
    threat_indicator: Optional[str] = None
    threat_type: Optional[str] = None
    correlation_type: str
    matched_value: str
    severity: str
    confidence: int
    details: str
    status: str
    created_at: datetime
    updated_at: datetime

    model_config = ConfigDict(from_attributes=True)


class BehavioralAnomalyRead(BaseModel):
    id: uuid.UUID
    organization_id: uuid.UUID
    asset_id: uuid.UUID
    asset_name: Optional[str] = None
    asset_target: Optional[str] = None
    anomaly_type: str
    severity: str
    confidence: str
    anomaly_score: float
    description: str
    evidence_data: Optional[Dict[str, Any]] = None
    status: str
    is_zero_day_indicator: bool
    created_at: datetime
    updated_at: datetime

    model_config = ConfigDict(from_attributes=True)


class BehavioralAnomalyStatusUpdate(BaseModel):
    status: str  # OPEN, INVESTIGATING, RESOLVED, FALSE_POSITIVE


class ResponseActionCreate(BaseModel):
    asset_id: Optional[uuid.UUID] = None
    anomaly_id: Optional[uuid.UUID] = None
    action_type: str
    title: str
    description: str
    target_entity: str
    execution_payload: Optional[Dict[str, Any]] = None
    rollback_payload: Optional[Dict[str, Any]] = None
    is_disruptive: bool = False


class ResponseActionRead(BaseModel):
    id: uuid.UUID
    organization_id: uuid.UUID
    asset_id: Optional[uuid.UUID] = None
    asset_name: Optional[str] = None
    anomaly_id: Optional[uuid.UUID] = None
    anomaly_type: Optional[str] = None
    action_type: str
    title: str
    description: str
    target_entity: str
    execution_payload: Optional[Dict[str, Any]] = None
    rollback_payload: Optional[Dict[str, Any]] = None
    status: str
    is_disruptive: bool
    approved_by_user_id: Optional[uuid.UUID] = None
    approved_by_user_name: Optional[str] = None
    approved_at: Optional[datetime] = None
    executed_at: Optional[datetime] = None
    execution_log: Optional[str] = None
    created_at: datetime
    updated_at: datetime

    model_config = ConfigDict(from_attributes=True)


class ZeroTrustOverviewStats(BaseModel):
    total_assets: int
    trusted_count: int
    restricted_count: int
    untrusted_count: int
    insufficient_evidence_count: int
    average_trust_score: float
    active_threat_indicators: int
    correlated_threats_count: int
    active_anomalies_count: int
    zero_day_indicators_count: int
    pending_approval_actions: int
    executed_actions: int

