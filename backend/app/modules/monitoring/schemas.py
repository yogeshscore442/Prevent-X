"""
PREVENT-X Monitoring & Centralized Security Management Schemas (MOD-09, MOD-12)
Declares Pydantic request and response schemas for real-time security events,
correlated incidents, SSE streams, alerts, and retention policies.
"""

import uuid
from datetime import datetime
from typing import Any, Dict, List, Optional

from pydantic import BaseModel, ConfigDict, Field

from backend.app.models.monitoring import (
    AlertCategory,
    EventCategory,
    EventSeverity,
    EventSource,
    IncidentSeverity,
    IncidentStatus,
)


# =============================================================================
# EVENT SCHEMAS
# =============================================================================

class SecurityEventCreate(BaseModel):
    source: EventSource = EventSource.SYSTEM
    category: EventCategory = EventCategory.SECURITY
    severity: EventSeverity = EventSeverity.INFO
    confidence: float = Field(default=1.0, ge=0.0, le=1.0)
    title: str = Field(..., max_length=255)
    description: str
    source_ip: Optional[str] = Field(default=None, max_length=64)
    target_uri: Optional[str] = Field(default=None, max_length=1024)
    http_method: Optional[str] = Field(default=None, max_length=16)
    status_code: Optional[int] = None
    asset_id: Optional[uuid.UUID] = None
    raw_payload: Optional[str] = None
    event_metadata: Optional[Dict[str, Any]] = Field(default_factory=dict)
    timestamp: Optional[datetime] = None


class BatchSecurityEventIngestRequest(BaseModel):
    events: List[SecurityEventCreate] = Field(default_factory=list, max_length=500)
    raw_nginx_logs: Optional[str] = Field(default=None, max_length=1048576)  # Up to 1MB log text
    asset_id: Optional[uuid.UUID] = None


class BatchSecurityEventIngestResponse(BaseModel):
    ingested_count: int
    deduplicated_count: int
    correlated_incidents_count: int
    event_ids: List[uuid.UUID]


class SecurityEventRead(BaseModel):
    id: uuid.UUID
    organization_id: uuid.UUID
    asset_id: Optional[uuid.UUID] = None
    incident_id: Optional[uuid.UUID] = None
    source: str
    category: str
    severity: str
    confidence: float
    title: str
    description: str
    source_ip: Optional[str] = None
    target_uri: Optional[str] = None
    http_method: Optional[str] = None
    status_code: Optional[int] = None
    fingerprint: str
    raw_payload: Optional[str] = None
    event_metadata: Optional[Dict[str, Any]] = None
    is_correlated: bool
    timestamp: datetime
    created_at: datetime

    model_config = ConfigDict(from_attributes=True)


class SecurityEventListResponse(BaseModel):
    items: List[SecurityEventRead]
    total: int
    page: int
    size: int


# =============================================================================
# TIMELINE ENTRY SCHEMAS
# =============================================================================

class IncidentTimelineEntryCreate(BaseModel):
    message: str
    entry_type: str = "ANALYST_NOTE"
    evidence_data: Optional[Dict[str, Any]] = Field(default_factory=dict)


class IncidentTimelineEntryRead(BaseModel):
    id: uuid.UUID
    incident_id: uuid.UUID
    organization_id: uuid.UUID
    entry_type: str
    message: str
    evidence_data: Optional[Dict[str, Any]] = None
    actor_user_id: Optional[uuid.UUID] = None
    created_at: datetime

    model_config = ConfigDict(from_attributes=True)


# =============================================================================
# INCIDENT SCHEMAS
# =============================================================================

class SecurityIncidentCreate(BaseModel):
    title: str = Field(..., max_length=255)
    description: str
    severity: IncidentSeverity = IncidentSeverity.MEDIUM
    primary_asset_id: Optional[uuid.UUID] = None
    mitre_attack_id: Optional[str] = Field(default=None, max_length=32)
    mitre_technique: Optional[str] = Field(default=None, max_length=255)
    recommended_action: Optional[str] = None
    iocs: Optional[Dict[str, Any]] = Field(default_factory=dict)


class SecurityIncidentUpdate(BaseModel):
    status: Optional[IncidentStatus] = None
    severity: Optional[IncidentSeverity] = None
    assigned_user_id: Optional[uuid.UUID] = None
    notes: Optional[str] = None


class IncidentContainmentRequest(BaseModel):
    containment_action: str = Field(..., max_length=128)
    notes: Optional[str] = None
    is_approved: bool = False


class SecurityIncidentRead(BaseModel):
    id: uuid.UUID
    incident_number: str
    organization_id: uuid.UUID
    title: str
    description: str
    severity: str
    status: str
    source: str
    primary_asset_id: Optional[uuid.UUID] = None
    mitre_attack_id: Optional[str] = None
    mitre_technique: Optional[str] = None
    recommended_action: Optional[str] = None
    containment_action_taken: Optional[str] = None
    containment_requires_approval: bool
    containment_approved_by: Optional[uuid.UUID] = None
    containment_executed_at: Optional[datetime] = None
    assigned_user_id: Optional[uuid.UUID] = None
    iocs: Optional[Dict[str, Any]] = None
    related_event_ids: Optional[List[str]] = None
    first_seen_at: datetime
    last_seen_at: datetime
    resolved_at: Optional[datetime] = None
    closed_at: Optional[datetime] = None
    created_at: datetime
    updated_at: datetime

    model_config = ConfigDict(from_attributes=True)


class SecurityIncidentDetail(SecurityIncidentRead):
    timeline_entries: List[IncidentTimelineEntryRead] = Field(default_factory=list)
    events: List[SecurityEventRead] = Field(default_factory=list)


class SecurityIncidentListResponse(BaseModel):
    items: List[SecurityIncidentRead]
    total: int
    page: int
    size: int


# =============================================================================
# ALERT SCHEMAS
# =============================================================================

class SecurityAlertRead(BaseModel):
    id: uuid.UUID
    organization_id: uuid.UUID
    title: str
    message: str
    category: str
    severity: str
    is_acknowledged: bool
    acknowledged_at: Optional[datetime] = None
    acknowledged_by_user_id: Optional[uuid.UUID] = None
    related_incident_id: Optional[uuid.UUID] = None
    related_event_id: Optional[uuid.UUID] = None
    created_at: datetime

    model_config = ConfigDict(from_attributes=True)


# =============================================================================
# RETENTION POLICY SCHEMAS
# =============================================================================

class EventRetentionPolicyUpdate(BaseModel):
    retention_days: Optional[int] = Field(default=None, ge=1, le=365)
    max_stored_events: Optional[int] = Field(default=None, ge=1000, le=1000000)
    auto_prune_enabled: Optional[bool] = None


class EventRetentionPolicyRead(BaseModel):
    id: uuid.UUID
    organization_id: uuid.UUID
    retention_days: int
    max_stored_events: int
    auto_prune_enabled: bool
    last_pruned_at: Optional[datetime] = None
    created_at: datetime
    updated_at: datetime

    model_config = ConfigDict(from_attributes=True)


# =============================================================================
# OVERVIEW & POSTURE SCHEMAS
# =============================================================================

class SecurityCenterOverviewStats(BaseModel):
    security_score: int
    security_grade: str
    open_incidents_total: int
    critical_incidents_count: int
    high_incidents_count: int
    medium_incidents_count: int
    events_24h_count: int
    waf_blocked_24h: int
    waf_allowed_24h: int
    exposed_assets_count: int
    active_virtual_patches_count: int
    trust_distribution: Dict[str, int]
    recent_rollbacks_count: int
    validation_failures_24h: int
    unacknowledged_alerts_count: int
