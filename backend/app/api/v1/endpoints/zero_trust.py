"""
PREVENT-X Zero Trust & Threat Intelligence REST API (MOD-04, MOD-05)
Exposes endpoints for continuous trust assessment, threat indicators, threat correlations,
behavioral anomaly triage, and automated response actions with approval workflow.
"""

import logging
import uuid
from typing import Any, Dict, List, Optional
from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy.orm import Session

from backend.app.database.session import get_db
from backend.app.models.organization import Organization
from backend.app.models.user import User
from backend.app.modules.zero_trust.schemas import (
    AssetTrustAssessmentRead,
    BehavioralAnomalyRead,
    BehavioralAnomalyStatusUpdate,
    ResponseActionCreate,
    ResponseActionRead,
    ThreatAssetCorrelationRead,
    ThreatIntelCreate,
    ThreatIntelRead,
    TrustEvaluationRequest,
    ZeroTrustOverviewStats,
)
from backend.app.modules.zero_trust.service import ZeroTrustService
from backend.app.security.permissions import (
    PermissionCode,
    get_current_organization,
    get_current_user,
    require_permission,
)

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/zero-trust", tags=["Zero Trust & Threat Intelligence"])


@router.get(
    "/overview",
    response_model=ZeroTrustOverviewStats,
    dependencies=[Depends(require_permission(PermissionCode.ZERO_TRUST_READ))],
)
def get_zero_trust_overview(
    db: Session = Depends(get_db),
    org: Organization = Depends(get_current_organization),
):
    """Returns high-level posture KPIs across trust decisions, threats, anomalies, and actions."""
    return ZeroTrustService.get_overview_stats(db, org.id)


@router.get(
    "/assessments",
    response_model=List[AssetTrustAssessmentRead],
    dependencies=[Depends(require_permission(PermissionCode.ZERO_TRUST_READ))],
)
def get_asset_assessments(
    decision: Optional[str] = Query(None, description="Filter by decision: TRUSTED, RESTRICTED, UNTRUSTED, INSUFFICIENT_EVIDENCE"),
    skip: int = Query(0, ge=0),
    limit: int = Query(100, ge=1, le=500),
    db: Session = Depends(get_db),
    org: Organization = Depends(get_current_organization),
):
    """Retrieves all asset trust evaluations for the organization."""
    return ZeroTrustService.get_assessments(db, org.id, decision=decision, skip=skip, limit=limit)


@router.post(
    "/evaluate",
    dependencies=[Depends(require_permission(PermissionCode.ZERO_TRUST_EVALUATE))],
)
def trigger_trust_evaluation(
    request: TrustEvaluationRequest,
    db: Session = Depends(get_db),
    org: Organization = Depends(get_current_organization),
    user: User = Depends(get_current_user),
):
    """
    Triggers continuous Zero-Trust evaluation for a specific asset or all tenant assets.
    Dispatches to Celery worker or executes synchronously.
    """
    try:
        from backend.app.tasks.zero_trust_tasks import evaluate_zero_trust_job

        task = evaluate_zero_trust_job.delay(
            str(org.id),
            str(request.asset_id) if request.asset_id else None,
        )
        return {
            "status": "QUEUED",
            "task_id": task.id,
            "message": "Zero Trust evaluation task queued successfully.",
        }
    except Exception as exc:
        logger.warning("Celery dispatch unavailable, falling back to sync execution: %s", exc)
        if request.asset_id:
            assessment = ZeroTrustService.evaluate_asset(db, request.asset_id, org.id)
            return {
                "status": "COMPLETED",
                "asset_id": str(assessment.asset_id),
                "trust_decision": assessment.trust_decision,
                "trust_score": assessment.trust_score,
            }
        else:
            assessments = ZeroTrustService.evaluate_all_assets(db, org.id)
            ZeroTrustService.run_threat_correlation(db, org.id)
            ZeroTrustService.run_behavioral_evaluation(db, org.id)
            return {
                "status": "COMPLETED",
                "evaluated_assets": len(assessments),
            }


@router.get(
    "/threat-intel",
    response_model=List[ThreatIntelRead],
    dependencies=[Depends(require_permission(PermissionCode.THREAT_INTEL_READ))],
)
def get_threat_intel_records(
    indicator_type: Optional[str] = Query(None, description="IP, DOMAIN, HASH, URL, PATTERN"),
    is_active: Optional[bool] = Query(None),
    skip: int = Query(0, ge=0),
    limit: int = Query(100, ge=1, le=500),
    db: Session = Depends(get_db),
    org: Organization = Depends(get_current_organization),
):
    """Lists threat intelligence indicators visible to the organization."""
    return ZeroTrustService.get_threat_indicators(
        db, org.id, indicator_type=indicator_type, is_active=is_active, skip=skip, limit=limit
    )


@router.post(
    "/threat-intel",
    response_model=ThreatIntelRead,
    dependencies=[Depends(require_permission(PermissionCode.THREAT_INTEL_SYNC))],
)
def create_threat_intel_indicator(
    data: ThreatIntelCreate,
    db: Session = Depends(get_db),
    org: Organization = Depends(get_current_organization),
    user: User = Depends(get_current_user),
):
    """Ingests or updates a verified threat indicator."""
    record = ZeroTrustService.create_threat_indicator(db, org.id, data)
    return ThreatIntelRead.model_validate(record)


@router.post(
    "/threat-intel/sync",
    dependencies=[Depends(require_permission(PermissionCode.THREAT_INTEL_SYNC))],
)
def sync_threat_intel_feed(
    db: Session = Depends(get_db),
    org: Organization = Depends(get_current_organization),
):
    """Seeds verified threat intelligence feeds and updates existing indicators."""
    count = ZeroTrustService.sync_threat_intel(db, org.id)
    return {
        "status": "COMPLETED",
        "synced_indicators": count,
        "message": f"Successfully synchronized {count} threat intelligence indicators.",
    }


@router.post(
    "/threat-intel/correlate",
    dependencies=[Depends(require_permission(PermissionCode.THREAT_INTEL_SYNC))],
)
def trigger_threat_correlation(
    db: Session = Depends(get_db),
    org: Organization = Depends(get_current_organization),
):
    """Executes real-time correlation between threat indicators and tenant infrastructure."""
    summary = ZeroTrustService.run_threat_correlation(db, org.id)
    return {
        "status": "COMPLETED",
        "summary": summary,
    }


@router.get(
    "/threat-correlations",
    response_model=List[ThreatAssetCorrelationRead],
    dependencies=[Depends(require_permission(PermissionCode.THREAT_INTEL_READ))],
)
def get_threat_correlations(
    status: Optional[str] = Query(None, description="ACTIVE, RESOLVED, FALSE_POSITIVE"),
    skip: int = Query(0, ge=0),
    limit: int = Query(100, ge=1, le=500),
    db: Session = Depends(get_db),
    org: Organization = Depends(get_current_organization),
):
    """Retrieves threat-to-asset correlations for the organization."""
    return ZeroTrustService.get_correlations(db, org.id, status=status, skip=skip, limit=limit)


@router.get(
    "/anomalies",
    response_model=List[BehavioralAnomalyRead],
    dependencies=[Depends(require_permission(PermissionCode.ZERO_TRUST_READ))],
)
def get_behavioral_anomalies(
    status: Optional[str] = Query(None, description="OPEN, INVESTIGATING, RESOLVED, FALSE_POSITIVE"),
    is_zero_day: Optional[bool] = Query(None),
    skip: int = Query(0, ge=0),
    limit: int = Query(100, ge=1, le=500),
    db: Session = Depends(get_db),
    org: Organization = Depends(get_current_organization),
):
    """Lists behavioral baseline anomalies and zero-day resilience indicators."""
    return ZeroTrustService.get_anomalies(
        db, org.id, status=status, is_zero_day=is_zero_day, skip=skip, limit=limit
    )


@router.post(
    "/anomalies/detect",
    dependencies=[Depends(require_permission(PermissionCode.ZERO_TRUST_WRITE))],
)
def run_behavioral_anomaly_detection(
    db: Session = Depends(get_db),
    org: Organization = Depends(get_current_organization),
):
    """Executes anomaly detection suite across all tenant assets."""
    anomalies = ZeroTrustService.run_behavioral_evaluation(db, org.id)
    return {
        "status": "COMPLETED",
        "anomalies_detected": len(anomalies),
    }


@router.patch(
    "/anomalies/{anomaly_id}/status",
    dependencies=[Depends(require_permission(PermissionCode.ZERO_TRUST_WRITE))],
)
def update_anomaly_status(
    anomaly_id: uuid.UUID,
    data: BehavioralAnomalyStatusUpdate,
    db: Session = Depends(get_db),
    org: Organization = Depends(get_current_organization),
    user: User = Depends(get_current_user),
):
    """Updates status for a behavioral anomaly (OPEN, INVESTIGATING, RESOLVED, FALSE_POSITIVE)."""
    try:
        updated = ZeroTrustService.update_anomaly_status(db, anomaly_id, org.id, data.status, user)
        return {"status": "SUCCESS", "anomaly_id": str(updated.id), "new_status": updated.status}
    except ValueError as e:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(e))


@router.get(
    "/response-actions",
    response_model=List[ResponseActionRead],
    dependencies=[Depends(require_permission(PermissionCode.RESPONSE_ACTION_READ))],
)
def get_response_actions(
    status: Optional[str] = Query(None, description="PENDING_APPROVAL, APPROVED, EXECUTED, REJECTED, ROLLED_BACK"),
    skip: int = Query(0, ge=0),
    limit: int = Query(100, ge=1, le=500),
    db: Session = Depends(get_db),
    org: Organization = Depends(get_current_organization),
):
    """Lists mitigation response actions and approval states."""
    return ZeroTrustService.get_response_actions(db, org.id, status=status, skip=skip, limit=limit)


@router.post(
    "/response-actions",
    response_model=ResponseActionRead,
    dependencies=[Depends(require_permission(PermissionCode.RESPONSE_ACTION_APPROVE))],
)
def propose_response_action(
    data: ResponseActionCreate,
    db: Session = Depends(get_db),
    org: Organization = Depends(get_current_organization),
):
    """Proposes a new response action. Disruptive actions require PENDING_APPROVAL."""
    action = ZeroTrustService.propose_response_action(db, org.id, data)
    return ResponseActionRead.model_validate(action)


@router.post(
    "/response-actions/{action_id}/approve",
    dependencies=[Depends(require_permission(PermissionCode.RESPONSE_ACTION_APPROVE))],
)
def approve_response_action(
    action_id: uuid.UUID,
    db: Session = Depends(get_db),
    org: Organization = Depends(get_current_organization),
    user: User = Depends(get_current_user),
):
    """Explicit human approval gate by authenticated OrgAdmin/SuperAdmin."""
    try:
        action = ZeroTrustService.approve_response_action(db, action_id, org.id, user)
        return {
            "status": "APPROVED",
            "action_id": str(action.id),
            "approved_by": user.email,
            "message": "Action approved successfully. Ready for execution.",
        }
    except ValueError as e:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(e))


@router.post(
    "/response-actions/{action_id}/reject",
    dependencies=[Depends(require_permission(PermissionCode.RESPONSE_ACTION_APPROVE))],
)
def reject_response_action(
    action_id: uuid.UUID,
    reason: Optional[str] = Query(None),
    db: Session = Depends(get_db),
    org: Organization = Depends(get_current_organization),
    user: User = Depends(get_current_user),
):
    """Rejects a proposed response action."""
    try:
        action = ZeroTrustService.reject_response_action(db, action_id, org.id, user, reason)
        return {
            "status": "REJECTED",
            "action_id": str(action.id),
            "message": "Action rejected.",
        }
    except ValueError as e:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(e))


@router.post(
    "/response-actions/{action_id}/execute",
    dependencies=[Depends(require_permission(PermissionCode.RESPONSE_ACTION_EXECUTE))],
)
def execute_response_action(
    action_id: uuid.UUID,
    db: Session = Depends(get_db),
    org: Organization = Depends(get_current_organization),
    user: User = Depends(get_current_user),
):
    """
    Executes an approved response action.
    Strictly prevents execution of disruptive actions without prior approval.
    """
    try:
        action = ZeroTrustService.execute_response_action(db, action_id, org.id, user)
        return {
            "status": "EXECUTED",
            "action_id": str(action.id),
            "executed_at": action.executed_at.isoformat() if action.executed_at else None,
            "log": action.execution_log,
        }
    except ValueError as e:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(e))


@router.post(
    "/response-actions/{action_id}/rollback",
    dependencies=[Depends(require_permission(PermissionCode.RESPONSE_ACTION_EXECUTE))],
)
def rollback_response_action(
    action_id: uuid.UUID,
    db: Session = Depends(get_db),
    org: Organization = Depends(get_current_organization),
    user: User = Depends(get_current_user),
):
    """Reverts an executed action back to baseline state using its rollback payload."""
    try:
        action = ZeroTrustService.rollback_response_action(db, action_id, org.id, user)
        return {
            "status": "ROLLED_BACK",
            "action_id": str(action.id),
            "log": action.execution_log,
        }
    except ValueError as e:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(e))
