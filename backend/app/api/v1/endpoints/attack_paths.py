"""
PREVENT-X Attack Path and Prevention Engine REST API (MOD-03)
Exposes endpoints for attack graph paths, MITRE ATT&CK mapping, prioritized compensating
controls, and asset trust relationships.
"""

import json
import logging
import uuid
from typing import Any, Dict, List, Optional
from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy import select
from sqlalchemy.orm import Session

from backend.app.database.session import get_db
from backend.app.models.attack_path import (
    AssetTrustRelationship,
    AttackPath,
    AttackPathAnalysisJob,
    PreventionRecommendation,
)
from backend.app.models.organization import Organization
from backend.app.models.user import User
from backend.app.modules.attack_path.schemas import (
    AssetTrustRelationshipCreate,
    AssetTrustRelationshipRead,
    AttackPathAnalysisJobRead,
    AttackPathAnalyzeRequest,
    AttackPathOverviewStats,
    AttackPathRead,
    AttackPathStatusUpdate,
    PreventionRecommendationRead,
    PreventionRecommendationStatusUpdate,
)
from backend.app.modules.attack_path.service import AttackPathService
from backend.app.modules.attack_path.tasks.attack_path_tasks import execute_attack_path_analysis_job
from backend.app.security.permissions import (
    PermissionCode,
    get_current_organization,
    get_current_user,
    require_permission,
)

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/attack-paths", tags=["Attack Path and Prevention Engine"])


def _format_path(path: AttackPath) -> Dict[str, Any]:
    entry_name = path.entry_point_asset.name if path.entry_point_asset else "Unknown Entry"
    target_name = path.target_asset.name if path.target_asset else "Unknown Target"
    target_crit = path.target_asset.criticality if path.target_asset else "MEDIUM"

    graph_obj = None
    if path.graph_data:
        try:
            graph_obj = json.loads(path.graph_data)
        except Exception:
            graph_obj = None

    tactics = []
    if path.mitre_tactics:
        try:
            tactics = json.loads(path.mitre_tactics)
        except Exception:
            tactics = []

    techniques = []
    if path.mitre_techniques:
        try:
            techniques = json.loads(path.mitre_techniques)
        except Exception:
            techniques = []

    prereqs = []
    if path.prerequisites:
        try:
            prereqs = json.loads(path.prerequisites)
        except Exception:
            prereqs = []

    ev_refs = []
    if path.evidence_references:
        try:
            ev_refs = json.loads(path.evidence_references)
        except Exception:
            ev_refs = []

    return {
        "id": path.id,
        "organization_id": path.organization_id,
        "name": path.name,
        "title": path.title,
        "description": path.description,
        "severity": path.severity,
        "confidence": path.confidence,
        "step_count": path.step_count,
        "risk_score": path.risk_score,
        "status": path.status,
        "entry_point_asset_id": path.entry_point_asset_id,
        "target_asset_id": path.target_asset_id,
        "entry_point_asset_name": entry_name,
        "target_asset_name": target_name,
        "target_asset_criticality": target_crit,
        "path_narrative": path.path_narrative,
        "graph_data": graph_obj,
        "mitre_tactics": tactics,
        "mitre_techniques": techniques,
        "prerequisites": prereqs,
        "evidence_references": ev_refs,
        "recommendations_count": len(path.recommendations) if path.recommendations else 0,
        "created_at": path.created_at,
        "updated_at": path.updated_at,
    }


def _format_rec(rec: PreventionRecommendation) -> Dict[str, Any]:
    return {
        "id": rec.id,
        "organization_id": rec.organization_id,
        "attack_path_id": rec.attack_path_id,
        "attack_path_title": rec.attack_path.title if rec.attack_path else None,
        "target_asset_id": rec.target_asset_id,
        "target_asset_name": rec.target_asset.name if rec.target_asset else None,
        "title": rec.title,
        "category": rec.category,
        "description": rec.description,
        "risk_reduction": rec.risk_reduction,
        "implementation_complexity": rec.implementation_complexity,
        "smb_operational_impact": rec.smb_operational_impact,
        "priority_rank": rec.priority_rank,
        "mitre_technique_id": rec.mitre_technique_id,
        "status": rec.status,
        "created_at": rec.created_at,
        "updated_at": rec.updated_at,
    }


def _format_rel(rel: AssetTrustRelationship) -> Dict[str, Any]:
    return {
        "id": rel.id,
        "organization_id": rel.organization_id,
        "source_asset_id": rel.source_asset_id,
        "target_asset_id": rel.target_asset_id,
        "source_asset_name": rel.source_asset.name if rel.source_asset else None,
        "target_asset_name": rel.target_asset.name if rel.target_asset else None,
        "relationship_type": rel.relationship_type,
        "port": rel.port,
        "evidence_source": rel.evidence_source,
        "is_verified": rel.is_verified,
        "created_at": rel.created_at,
        "updated_at": rel.updated_at,
    }


@router.get(
    "/overview",
    response_model=AttackPathOverviewStats,
    summary="Get tenant attack path and prevention metrics",
)
def get_attack_path_overview(
    org: Organization = Depends(get_current_organization),
    _perm: bool = Depends(require_permission(PermissionCode.ATTACK_PATH_READ)),
    db: Session = Depends(get_db),
):
    """
    Returns summary metrics including paths by severity, crown jewels exposed,
    average risk score, and top MITRE tactics.
    """
    return AttackPathService.get_overview(db, org.id)


@router.get(
    "/paths",
    summary="List tenant attack paths",
)
def list_attack_paths(
    severity: Optional[str] = Query(None, description="Filter by severity: CRITICAL, HIGH, MEDIUM, LOW"),
    confidence: Optional[str] = Query(None, description="Filter by confidence: CONFIRMED, LIKELY, POTENTIAL"),
    status: Optional[str] = Query(None, description="Filter by status: IDENTIFIED, UNDER_REVIEW, MITIGATED, ACCEPTED"),
    entry_point_id: Optional[uuid.UUID] = Query(None, description="Filter by entry point asset ID"),
    target_id: Optional[uuid.UUID] = Query(None, description="Filter by target crown jewel asset ID"),
    limit: int = Query(50, ge=1, le=100),
    offset: int = Query(0, ge=0),
    org: Organization = Depends(get_current_organization),
    _perm: bool = Depends(require_permission(PermissionCode.ATTACK_PATH_READ)),
    db: Session = Depends(get_db),
):
    """
    Lists discovered evidence-backed attack paths with pagination and filters.
    """
    paths, total = AttackPathService.list_paths(
        db=db,
        org_id=org.id,
        severity=severity,
        confidence=confidence,
        status=status,
        entry_point_id=entry_point_id,
        target_id=target_id,
        limit=limit,
        offset=offset,
    )
    return {
        "total": total,
        "items": [_format_path(p) for p in paths],
        "limit": limit,
        "offset": offset,
    }


@router.get(
    "/paths/{path_id}",
    summary="Get detailed attack path by ID",
)
def get_attack_path(
    path_id: uuid.UUID,
    org: Organization = Depends(get_current_organization),
    _perm: bool = Depends(require_permission(PermissionCode.ATTACK_PATH_READ)),
    db: Session = Depends(get_db),
):
    """
    Returns a single attack path with full graph nodes, edges, narrative, and MITRE mapping.
    """
    path = AttackPathService.get_path(db, org.id, path_id)
    if not path:
        raise HTTPException(status_code=404, detail="Attack path not found")
    return _format_path(path)


@router.patch(
    "/paths/{path_id}/status",
    summary="Update attack path status",
)
def update_attack_path_status(
    path_id: uuid.UUID,
    payload: AttackPathStatusUpdate,
    org: Organization = Depends(get_current_organization),
    user: User = Depends(get_current_user),
    _perm: bool = Depends(require_permission(PermissionCode.ATTACK_PATH_WRITE)),
    db: Session = Depends(get_db),
):
    """
    Transitions attack path status (IDENTIFIED -> UNDER_REVIEW -> MITIGATED -> ACCEPTED).
    """
    valid_statuses = ["IDENTIFIED", "UNDER_REVIEW", "MITIGATED", "ACCEPTED"]
    if payload.status.upper() not in valid_statuses:
        raise HTTPException(
            status_code=400,
            detail=f"Invalid status '{payload.status}'. Must be one of {valid_statuses}.",
        )
    path = AttackPathService.update_path_status(db, org.id, path_id, payload.status, user.id)
    if not path:
        raise HTTPException(status_code=404, detail="Attack path not found")
    return _format_path(path)


@router.post(
    "/analyze",
    summary="Trigger attack path analysis",
)
def trigger_attack_path_analysis(
    payload: AttackPathAnalyzeRequest,
    org: Organization = Depends(get_current_organization),
    user: User = Depends(get_current_user),
    _perm: bool = Depends(require_permission(PermissionCode.ATTACK_PATH_ANALYZE)),
    db: Session = Depends(get_db),
):
    """
    Initiates attack path analysis across all organization assets.
    Supports asynchronous execution via Celery or synchronous fallback.
    """
    job = AttackPathService.create_analysis_job(db, org.id, user.id)

    if payload.sync:
        # Run synchronously
        completed_job = AttackPathService.execute_job(db, job.id)
        return {
            "job_id": completed_job.id,
            "status": completed_job.status,
            "paths_discovered": completed_job.paths_discovered_count,
            "recommendations_count": completed_job.recommendations_count,
            "message": "Attack path analysis completed synchronously.",
        }

    try:
        execute_attack_path_analysis_job.delay(str(job.id))
        return {
            "job_id": job.id,
            "status": "QUEUED",
            "message": "Attack path analysis job enqueued successfully.",
        }
    except Exception as exc:
        logger.warning(f"Celery enqueue failed ({exc}), falling back to synchronous execution.")
        completed_job = AttackPathService.execute_job(db, job.id)
        return {
            "job_id": completed_job.id,
            "status": completed_job.status,
            "paths_discovered": completed_job.paths_discovered_count,
            "recommendations_count": completed_job.recommendations_count,
            "message": "Analysis completed via synchronous fallback.",
        }


@router.get(
    "/jobs",
    summary="List attack path analysis jobs",
)
def list_analysis_jobs(
    limit: int = Query(20, ge=1, le=100),
    offset: int = Query(0, ge=0),
    org: Organization = Depends(get_current_organization),
    _perm: bool = Depends(require_permission(PermissionCode.ATTACK_PATH_READ)),
    db: Session = Depends(get_db),
):
    """
    Lists recent attack path analysis jobs.
    """
    jobs = (
        db.execute(
            select(AttackPathAnalysisJob)
            .where(AttackPathAnalysisJob.organization_id == org.id)
            .order_by(AttackPathAnalysisJob.created_at.desc())
            .limit(limit)
            .offset(offset)
        )
        .scalars()
        .all()
    )
    return jobs


@router.get(
    "/jobs/{job_id}",
    response_model=AttackPathAnalysisJobRead,
    summary="Get analysis job status by ID",
)
def get_analysis_job(
    job_id: uuid.UUID,
    org: Organization = Depends(get_current_organization),
    _perm: bool = Depends(require_permission(PermissionCode.ATTACK_PATH_READ)),
    db: Session = Depends(get_db),
):
    """
    Returns the execution status and findings count for a specific analysis job.
    """
    job = db.execute(
        select(AttackPathAnalysisJob).where(
            AttackPathAnalysisJob.id == job_id,
            AttackPathAnalysisJob.organization_id == org.id,
        )
    ).scalar_one_or_none()

    if not job:
        raise HTTPException(status_code=404, detail="Analysis job not found")
    return job


@router.get(
    "/recommendations",
    summary="List ranked prevention recommendations",
)
def list_prevention_recommendations(
    category: Optional[str] = Query(None, description="Filter by category"),
    status: Optional[str] = Query(None, description="Filter by status: PROPOSED, ACCEPTED, IMPLEMENTED, DISMISSED"),
    attack_path_id: Optional[uuid.UUID] = Query(None, description="Filter by attack path ID"),
    limit: int = Query(50, ge=1, le=100),
    offset: int = Query(0, ge=0),
    org: Organization = Depends(get_current_organization),
    _perm: bool = Depends(require_permission(PermissionCode.ATTACK_PATH_READ)),
    db: Session = Depends(get_db),
):
    """
    Returns prioritized compensating controls and mitigations ranked by risk reduction,
    implementation complexity, and SMB operational impact.
    """
    recs, total = AttackPathService.list_recommendations(
        db=db,
        org_id=org.id,
        category=category,
        status=status,
        attack_path_id=attack_path_id,
        limit=limit,
        offset=offset,
    )
    return {
        "total": total,
        "items": [_format_rec(r) for r in recs],
        "limit": limit,
        "offset": offset,
    }


@router.patch(
    "/recommendations/{recommendation_id}/status",
    summary="Update recommendation status",
)
def update_recommendation_status(
    recommendation_id: uuid.UUID,
    payload: PreventionRecommendationStatusUpdate,
    org: Organization = Depends(get_current_organization),
    user: User = Depends(get_current_user),
    _perm: bool = Depends(require_permission(PermissionCode.ATTACK_PATH_WRITE)),
    db: Session = Depends(get_db),
):
    """
    Updates prevention recommendation status (PROPOSED -> ACCEPTED -> IMPLEMENTED -> DISMISSED).
    """
    valid_statuses = ["PROPOSED", "ACCEPTED", "IMPLEMENTED", "DISMISSED"]
    if payload.status.upper() not in valid_statuses:
        raise HTTPException(
            status_code=400,
            detail=f"Invalid status '{payload.status}'. Must be one of {valid_statuses}.",
        )
    rec = AttackPathService.update_recommendation_status(
        db, org.id, recommendation_id, payload.status, user.id
    )
    if not rec:
        raise HTTPException(status_code=404, detail="Prevention recommendation not found")
    return _format_rec(rec)


@router.get(
    "/trust-relationships",
    summary="List asset trust relationships",
)
def list_trust_relationships(
    org: Organization = Depends(get_current_organization),
    _perm: bool = Depends(require_permission(PermissionCode.ATTACK_PATH_READ)),
    db: Session = Depends(get_db),
):
    """
    Lists verified trust relationships between assets in the organization.
    """
    rels = AttackPathService.list_trust_relationships(db, org.id)
    return [_format_rel(r) for r in rels]


@router.post(
    "/trust-relationships",
    status_code=status.HTTP_201_CREATED,
    summary="Create verified asset trust relationship",
)
def create_trust_relationship(
    payload: AssetTrustRelationshipCreate,
    org: Organization = Depends(get_current_organization),
    user: User = Depends(get_current_user),
    _perm: bool = Depends(require_permission(PermissionCode.ATTACK_PATH_WRITE)),
    db: Session = Depends(get_db),
):
    """
    Registers an explicit, evidence-backed trust link or network connection between two assets.
    """
    rel = AttackPathService.create_trust_relationship(db, org.id, payload, user.id)
    return _format_rel(rel)


@router.delete(
    "/trust-relationships/{rel_id}",
    status_code=status.HTTP_204_NO_CONTENT,
    summary="Delete asset trust relationship",
)
def delete_trust_relationship(
    rel_id: uuid.UUID,
    org: Organization = Depends(get_current_organization),
    user: User = Depends(get_current_user),
    _perm: bool = Depends(require_permission(PermissionCode.ATTACK_PATH_WRITE)),
    db: Session = Depends(get_db),
):
    """
    Deletes an asset trust relationship link.
    """
    deleted = AttackPathService.delete_trust_relationship(db, org.id, rel_id, user.id)
    if not deleted:
        raise HTTPException(status_code=404, detail="Trust relationship not found")
    return None

