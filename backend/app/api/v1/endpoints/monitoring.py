"""
PREVENT-X Centralized Monitoring & Real-Time Security Operations REST API (MOD-09, MOD-12)
Endpoints for real-time security event ingestion, SSE streaming, automated correlation,
incident lifecycle and containment, executive SMB posture metrics, alerts, and data retention.
"""

import logging
import uuid
from typing import Any, Dict, List, Optional
from datetime import datetime

from fastapi import APIRouter, Depends, Header, HTTPException, Query, Request, status
from fastapi.responses import StreamingResponse
from sqlalchemy.orm import Session

from backend.app.database.session import get_db
from backend.app.models.organization import Organization
from backend.app.models.user import User
from backend.app.models.monitoring import (
    EventCategory,
    EventSeverity,
    EventSource,
    IncidentSeverity,
    IncidentStatus,
)
from backend.app.modules.monitoring.schemas import (
    BatchSecurityEventIngestRequest,
    BatchSecurityEventIngestResponse,
    EventRetentionPolicyRead,
    EventRetentionPolicyUpdate,
    IncidentContainmentRequest,
    IncidentTimelineEntryCreate,
    IncidentTimelineEntryRead,
    SecurityCenterOverviewStats,
    SecurityAlertRead,
    SecurityEventCreate,
    SecurityEventListResponse,
    SecurityEventRead,
    SecurityIncidentCreate,
    SecurityIncidentDetail,
    SecurityIncidentListResponse,
    SecurityIncidentRead,
    SecurityIncidentUpdate,
)
from backend.app.modules.monitoring.service import MonitoringService
from backend.app.modules.monitoring.sse_manager import SSEManager
from backend.app.security.permissions import (
    PermissionCode,
    get_current_organization,
    get_current_user,
    require_permission,
)

logger = logging.getLogger("preventx.api.monitoring")

router = APIRouter(prefix="/monitoring", tags=["Real-Time Monitoring & Security Center"])


# =============================================================================
# EXECUTIVE POSTURE & OVERVIEW
# =============================================================================

@router.get(
    "/overview",
    response_model=SecurityCenterOverviewStats,
    dependencies=[Depends(require_permission(PermissionCode.MONITORING_READ))],
    summary="Get Centralized Security Center Overview",
)
def get_security_center_overview(
    org: Organization = Depends(get_current_organization),
    db: Session = Depends(get_db),
) -> SecurityCenterOverviewStats:
    """
    Returns aggregated executive security health score (0-100), letter grade,
    open incident counts by severity, WAF telemetry, active patches, trust posture distribution,
    and recent rollbacks for the authenticated tenant.
    """
    return MonitoringService.get_security_center_overview(db, org.id)


# =============================================================================
# EVENT INGESTION & QUERYING
# =============================================================================

@router.post(
    "/events/ingest",
    response_model=BatchSecurityEventIngestResponse,
    dependencies=[Depends(require_permission(PermissionCode.MONITORING_INGEST))],
    summary="Ingest Real-Time Security Events or Raw Nginx Logs",
)
def ingest_events(
    request: BatchSecurityEventIngestRequest,
    org: Organization = Depends(get_current_organization),
    user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
) -> BatchSecurityEventIngestResponse:
    """
    Ingests structured security events or raw Nginx access/error logs.
    Performs credential sanitization, CRLF log-injection defense, deduplication fingerprinting,
    and triggers automated incident correlation and SSE dispatch.
    """
    return MonitoringService.ingest_batch(db, org.id, request)


@router.get(
    "/events",
    response_model=SecurityEventListResponse,
    dependencies=[Depends(require_permission(PermissionCode.MONITORING_READ))],
    summary="Query Security Events with Pagination and Filters",
)
def list_events(
    source: Optional[EventSource] = Query(None, description="Filter by event source"),
    category: Optional[EventCategory] = Query(None, description="Filter by event category"),
    severity: Optional[EventSeverity] = Query(None, description="Filter by event severity"),
    search: Optional[str] = Query(None, description="Keyword search in title, description, or IP"),
    start_time: Optional[datetime] = Query(None, description="Filter events after timestamp"),
    end_time: Optional[datetime] = Query(None, description="Filter events before timestamp"),
    page: int = Query(1, ge=1, description="Page number"),
    size: int = Query(50, ge=1, le=200, description="Page size"),
    org: Organization = Depends(get_current_organization),
    db: Session = Depends(get_db),
) -> SecurityEventListResponse:
    """
    Returns paginated security events for the tenant organization.
    """
    items, total = MonitoringService.get_events(
        db=db,
        organization_id=org.id,
        source=source.value if source else None,
        category=category.value if category else None,
        severity=severity.value if severity else None,
        search=search,
        start_time=start_time,
        end_time=end_time,
        page=page,
        size=size,
    )
    return SecurityEventListResponse(
        items=[SecurityEventRead.model_validate(item) for item in items],
        total=total,
        page=page,
        size=size,
    )


@router.get(
    "/events/stream",
    dependencies=[Depends(require_permission(PermissionCode.MONITORING_READ))],
    summary="Real-Time Server-Sent Events (SSE) Stream",
)
async def stream_events(
    request: Request,
    last_event_id_header: Optional[str] = Header(None, alias="Last-Event-ID"),
    last_event_id_query: Optional[str] = Query(None, alias="last_event_id"),
    org: Organization = Depends(get_current_organization),
    db: Session = Depends(get_db),
):
    """
    Real-Time SSE endpoint delivering live security events and incidents.
    Supports reconnection replay via `Last-Event-ID` header or query parameter.
    Sends periodic keepalive heartbeats every 15 seconds.
    """
    last_id = last_event_id_header or last_event_id_query
    generator = SSEManager.event_generator(
        db=db,
        organization_id=org.id,
        last_event_id=last_id,
        heartbeat_interval=15,
    )

    return StreamingResponse(
        generator,
        media_type="text/event-stream",
        headers={
            "Cache-Control": "no-cache",
            "Connection": "keep-alive",
            "X-Accel-Buffering": "no",
        },
    )


# =============================================================================
# INCIDENT LIFECYCLE MANAGEMENT
# =============================================================================

@router.get(
    "/incidents",
    response_model=SecurityIncidentListResponse,
    dependencies=[Depends(require_permission(PermissionCode.INCIDENT_READ))],
    summary="List Correlated Security Incidents",
)
def list_incidents(
    status_filter: Optional[IncidentStatus] = Query(None, alias="status", description="Filter by status"),
    severity_filter: Optional[IncidentSeverity] = Query(None, alias="severity", description="Filter by severity"),
    page: int = Query(1, ge=1),
    size: int = Query(20, ge=1, le=100),
    org: Organization = Depends(get_current_organization),
    db: Session = Depends(get_db),
) -> SecurityIncidentListResponse:
    """
    Lists correlated and manually created security incidents for the tenant.
    """
    items, total = MonitoringService.get_incidents(
        db=db,
        organization_id=org.id,
        status=status_filter.value if status_filter else None,
        severity=severity_filter.value if severity_filter else None,
        page=page,
        size=size,
    )
    return SecurityIncidentListResponse(
        items=[SecurityIncidentRead.model_validate(item) for item in items],
        total=total,
        page=page,
        size=size,
    )


@router.post(
    "/incidents",
    response_model=SecurityIncidentRead,
    dependencies=[Depends(require_permission(PermissionCode.INCIDENT_MANAGE))],
    status_code=status.HTTP_201_CREATED,
    summary="Create Manual Security Incident",
)
def create_incident(
    payload: SecurityIncidentCreate,
    org: Organization = Depends(get_current_organization),
    user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
) -> SecurityIncidentRead:
    """
    Creates an incident manually and records initial timeline entry.
    """
    incident = MonitoringService.create_incident(db, org.id, payload, actor_user_id=user.id)
    return SecurityIncidentRead.model_validate(incident)


@router.get(
    "/incidents/{incident_id}",
    response_model=SecurityIncidentDetail,
    dependencies=[Depends(require_permission(PermissionCode.INCIDENT_READ))],
    summary="Get Incident Detail with Timeline and Linked Events",
)
def get_incident_detail(
    incident_id: uuid.UUID,
    org: Organization = Depends(get_current_organization),
    db: Session = Depends(get_db),
) -> SecurityIncidentDetail:
    """
    Retrieves full incident details, audit timeline history, and correlated evidence events.
    """
    incident = MonitoringService.get_incident_detail(db, org.id, incident_id)
    if not incident:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Security incident '{incident_id}' not found.",
        )

    return SecurityIncidentDetail.model_validate(incident)


@router.patch(
    "/incidents/{incident_id}",
    response_model=SecurityIncidentRead,
    dependencies=[Depends(require_permission(PermissionCode.INCIDENT_MANAGE))],
    summary="Update Incident Status, Severity, or Assignee",
)
def update_incident(
    incident_id: uuid.UUID,
    payload: SecurityIncidentUpdate,
    org: Organization = Depends(get_current_organization),
    user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
) -> SecurityIncidentRead:
    """
    Transitions incident status (OPEN -> ACKNOWLEDGED -> INVESTIGATING -> RESOLVED -> CLOSED),
    updates severity, or reassigns investigator.
    """
    updated = MonitoringService.update_incident(db, org.id, incident_id, payload, actor_user_id=user.id)
    if not updated:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Security incident '{incident_id}' not found.",
        )
    return SecurityIncidentRead.model_validate(updated)


@router.post(
    "/incidents/{incident_id}/notes",
    response_model=IncidentTimelineEntryRead,
    dependencies=[Depends(require_permission(PermissionCode.INCIDENT_MANAGE))],
    status_code=status.HTTP_201_CREATED,
    summary="Add Analyst Note to Incident Timeline",
)
def add_incident_note(
    incident_id: uuid.UUID,
    payload: IncidentTimelineEntryCreate,
    org: Organization = Depends(get_current_organization),
    user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
) -> IncidentTimelineEntryRead:
    """
    Adds an analyst note or investigation evidence entry to the incident timeline.
    """
    entry = MonitoringService.add_incident_note(
        db=db,
        organization_id=org.id,
        incident_id=incident_id,
        payload=payload,
        actor_user_id=user.id,
    )
    if not entry:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Security incident '{incident_id}' not found.",
        )
    return IncidentTimelineEntryRead.model_validate(entry)


@router.post(
    "/incidents/{incident_id}/contain",
    response_model=SecurityIncidentRead,
    dependencies=[Depends(require_permission(PermissionCode.INCIDENT_MANAGE))],
    summary="Execute or Request Disruptive Incident Containment",
)
def execute_containment(
    incident_id: uuid.UUID,
    payload: IncidentContainmentRequest,
    org: Organization = Depends(get_current_organization),
    user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
) -> SecurityIncidentRead:
    """
    Executes or proposes containment action (e.g. IP block, virtual patch generation).
    Enforces human authorization approval gate if disruptive.
    """
    is_admin = user.is_superuser or any(
        m.role and m.role.name in ["SUPER_ADMIN", "ORG_ADMIN"]
        for m in user.memberships
        if m.organization_id == org.id
    )
    incident = MonitoringService.execute_containment(
        db=db,
        organization_id=org.id,
        incident_id=incident_id,
        payload=payload,
        actor_user_id=user.id,
        is_admin=is_admin,
    )
    if not incident:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Security incident '{incident_id}' not found.",
        )
    return SecurityIncidentRead.model_validate(incident)


# =============================================================================
# IN-APP ALERTS
# =============================================================================

@router.get(
    "/alerts",
    response_model=List[SecurityAlertRead],
    dependencies=[Depends(require_permission(PermissionCode.MONITORING_READ))],
    summary="List In-App Security Alerts",
)
def list_alerts(
    is_acknowledged: Optional[bool] = Query(None, description="Filter by acknowledged status"),
    limit: int = Query(50, ge=1, le=200),
    org: Organization = Depends(get_current_organization),
    db: Session = Depends(get_db),
) -> List[SecurityAlertRead]:
    """
    Lists in-app operational security alerts.
    """
    alerts = MonitoringService.get_alerts(
        db=db,
        organization_id=org.id,
        is_acknowledged=is_acknowledged,
        limit=limit,
    )
    return [SecurityAlertRead.model_validate(a) for a in alerts]


@router.post(
    "/alerts/{alert_id}/acknowledge",
    response_model=SecurityAlertRead,
    dependencies=[Depends(require_permission(PermissionCode.ALERT_MANAGE))],
    summary="Acknowledge In-App Alert",
)
def acknowledge_alert(
    alert_id: uuid.UUID,
    org: Organization = Depends(get_current_organization),
    user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
) -> SecurityAlertRead:
    """
    Marks an alert as acknowledged by the current authenticated user.
    """
    alert = MonitoringService.acknowledge_alert(
        db=db,
        organization_id=org.id,
        alert_id=alert_id,
        user_id=user.id,
    )
    if not alert:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Security alert '{alert_id}' not found.",
        )
    return SecurityAlertRead.model_validate(alert)


# =============================================================================
# DATA RETENTION POLICIES
# =============================================================================

@router.get(
    "/retention",
    response_model=EventRetentionPolicyRead,
    dependencies=[Depends(require_permission(PermissionCode.RETENTION_MANAGE))],
    summary="Get Event Retention Policy",
)
def get_retention_policy(
    org: Organization = Depends(get_current_organization),
    db: Session = Depends(get_db),
) -> EventRetentionPolicyRead:
    """
    Retrieves or initializes the event retention policy for the tenant.
    """
    policy = MonitoringService.get_or_create_retention_policy(db, org.id)
    return EventRetentionPolicyRead.model_validate(policy)


@router.put(
    "/retention",
    response_model=EventRetentionPolicyRead,
    dependencies=[Depends(require_permission(PermissionCode.RETENTION_MANAGE))],
    summary="Update Event Retention Policy",
)
def update_retention_policy(
    payload: EventRetentionPolicyUpdate,
    org: Organization = Depends(get_current_organization),
    db: Session = Depends(get_db),
) -> EventRetentionPolicyRead:
    """
    Updates event retention days, maximum stored events limit, and auto-prune flag.
    """
    policy = MonitoringService.update_retention_policy(db, org.id, payload)
    return EventRetentionPolicyRead.model_validate(policy)


@router.post(
    "/retention/prune",
    dependencies=[Depends(require_permission(PermissionCode.RETENTION_MANAGE))],
    summary="Execute Immediate Event Retention Pruning",
)
def prune_events_now(
    org: Organization = Depends(get_current_organization),
    db: Session = Depends(get_db),
) -> Dict[str, Any]:
    """
    Manually triggers immediate pruning of expired events according to tenant policy.
    """
    deleted_count = MonitoringService.prune_expired_events(db, org.id)
    return {
        "status": "success",
        "organization_id": str(org.id),
        "deleted_events_count": deleted_count,
    }
