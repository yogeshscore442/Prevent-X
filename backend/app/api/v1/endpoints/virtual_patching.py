"""
PREVENT-X Intelligent Virtual Patching & Reverse Proxy REST API (MOD-06, MOD-08)
Endpoints for rule authoring, versioning, AI recommendations, staging/production deployments,
human-in-the-loop approvals, and reverse proxy audit telemetry.
"""

import logging
import uuid
from typing import Any, Dict, List, Optional
from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy.orm import Session

from backend.app.database.session import get_db
from backend.app.models.organization import Organization
from backend.app.models.user import User
from backend.app.modules.virtual_patch.schemas import (
    FalsePositiveReportRequest,
    VirtualPatchDeploymentCreate,
    VirtualPatchDeploymentRead,
    VirtualPatchOverviewStats,
    VirtualPatchRecommendationRead,
    VirtualPatchRuleCreate,
    VirtualPatchRuleRead,
    VirtualPatchRuleUpdate,
    VirtualPatchVersionRead,
    WafEnforcementLogRead,
)
from backend.app.modules.virtual_patch.service import VirtualPatchService
from backend.app.security.permissions import (
    PermissionCode,
    get_current_organization,
    get_current_user,
    require_permission,
)

logger = logging.getLogger("preventx.api.virtual_patch")

router = APIRouter(prefix="/virtual-patching", tags=["Intelligent Virtual Patching"])


@router.get(
    "/overview",
    response_model=VirtualPatchOverviewStats,
    dependencies=[Depends(require_permission(PermissionCode.VIRTUAL_PATCH_READ))],
)
def get_virtual_patch_overview(
    db: Session = Depends(get_db),
    org: Organization = Depends(get_current_organization),
):
    """
    Returns aggregate metrics across virtual patch rules, staging/production deployments,
    reverse proxy health, and enforcement event counts.
    """
    return VirtualPatchService.get_overview_stats(db, org.id)


# =============================================================================
# RECOMMENDATIONS (AI / DETERMINISTIC SYNTHESIS)
# =============================================================================

@router.get(
    "/recommendations",
    response_model=List[VirtualPatchRecommendationRead],
    dependencies=[Depends(require_permission(PermissionCode.VIRTUAL_PATCH_READ))],
)
def list_recommendations(
    status_filter: Optional[str] = Query(None, alias="status", description="Filter by status: PROPOSED, ACCEPTED, REJECTED"),
    db: Session = Depends(get_db),
    org: Organization = Depends(get_current_organization),
):
    """
    Lists virtual patch proposals synthesized from detected vulnerabilities and attack paths.
    """
    recs = VirtualPatchService.get_recommendations(db, org.id, status=status_filter)
    # Populate asset_name for display
    result = []
    for r in recs:
        read_obj = VirtualPatchRecommendationRead.model_validate(r)
        if r.asset:
            read_obj.asset_name = r.asset.name
        result.append(read_obj)
    return result


@router.post(
    "/recommendations/generate",
    response_model=List[VirtualPatchRecommendationRead],
    dependencies=[Depends(require_permission(PermissionCode.VIRTUAL_PATCH_WRITE))],
)
def generate_recommendations(
    db: Session = Depends(get_db),
    org: Organization = Depends(get_current_organization),
):
    """
    Triggers analysis of tenant vulnerabilities and synthesizes explainable virtual patch proposals.
    """
    recs = VirtualPatchService.generate_recommendations_for_organization(db, org.id)
    result = []
    for r in recs:
        read_obj = VirtualPatchRecommendationRead.model_validate(r)
        if r.asset:
            read_obj.asset_name = r.asset.name
        result.append(read_obj)
    return result


@router.post(
    "/recommendations/{recommendation_id}/accept",
    response_model=VirtualPatchRuleRead,
    dependencies=[Depends(require_permission(PermissionCode.VIRTUAL_PATCH_WRITE))],
)
def accept_recommendation(
    recommendation_id: uuid.UUID,
    db: Session = Depends(get_db),
    org: Organization = Depends(get_current_organization),
    current_user: User = Depends(get_current_user),
):
    """
    Accepts a proposed virtual patch and instantiates an active draft rule with version 1.
    """
    try:
        rule = VirtualPatchService.accept_recommendation(
            db=db,
            recommendation_id=recommendation_id,
            organization_id=org.id,
            user_id=current_user.id,
        )
        read_obj = VirtualPatchRuleRead.model_validate(rule)
        if rule.asset:
            read_obj.asset_name = rule.asset.name
        return read_obj
    except ValueError as e:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(e))


@router.post(
    "/recommendations/{recommendation_id}/reject",
    response_model=VirtualPatchRecommendationRead,
    dependencies=[Depends(require_permission(PermissionCode.VIRTUAL_PATCH_WRITE))],
)
def reject_recommendation(
    recommendation_id: uuid.UUID,
    db: Session = Depends(get_db),
    org: Organization = Depends(get_current_organization),
):
    """
    Rejects a virtual patch proposal.
    """
    try:
        rec = VirtualPatchService.reject_recommendation(db, recommendation_id, org.id)
        return VirtualPatchRecommendationRead.model_validate(rec)
    except ValueError as e:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(e))


# =============================================================================
# VIRTUAL PATCH RULES
# =============================================================================

@router.get(
    "/rules",
    response_model=List[VirtualPatchRuleRead],
    dependencies=[Depends(require_permission(PermissionCode.VIRTUAL_PATCH_READ))],
)
def list_rules(
    is_active: Optional[bool] = Query(None),
    attack_type: Optional[str] = Query(None),
    db: Session = Depends(get_db),
    org: Organization = Depends(get_current_organization),
):
    """
    Lists tenant virtual patch rules.
    """
    rules = VirtualPatchService.get_rules(db, org.id, is_active=is_active, attack_type=attack_type)
    result = []
    for r in rules:
        read_obj = VirtualPatchRuleRead.model_validate(r)
        if r.asset:
            read_obj.asset_name = r.asset.name
        result.append(read_obj)
    return result


@router.post(
    "/rules",
    response_model=VirtualPatchRuleRead,
    status_code=status.HTTP_201_CREATED,
    dependencies=[Depends(require_permission(PermissionCode.VIRTUAL_PATCH_WRITE))],
)
def create_rule(
    payload: VirtualPatchRuleCreate,
    db: Session = Depends(get_db),
    org: Organization = Depends(get_current_organization),
    current_user: User = Depends(get_current_user),
):
    """
    Creates a new custom virtual patch rule and records version 1.
    """
    try:
        rule = VirtualPatchService.create_rule(db, org.id, payload, user_id=current_user.id)
        read_obj = VirtualPatchRuleRead.model_validate(rule)
        if rule.asset:
            read_obj.asset_name = rule.asset.name
        return read_obj
    except ValueError as e:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(e))


@router.post(
    "/rules/seed-baseline",
    response_model=List[VirtualPatchRuleRead],
    dependencies=[Depends(require_permission(PermissionCode.VIRTUAL_PATCH_WRITE))],
)
def seed_baseline_rules(
    db: Session = Depends(get_db),
    org: Organization = Depends(get_current_organization),
):
    """
    Installs SMB baseline virtual patch rules (SQLi, XSS, Path Traversal, Scanners) for the tenant.
    """
    rules = VirtualPatchService.seed_baseline_rules(db, org.id)
    return [VirtualPatchRuleRead.model_validate(r) for r in rules]


@router.get(
    "/rules/{rule_id}",
    response_model=VirtualPatchRuleRead,
    dependencies=[Depends(require_permission(PermissionCode.VIRTUAL_PATCH_READ))],
)
def get_rule(
    rule_id: uuid.UUID,
    db: Session = Depends(get_db),
    org: Organization = Depends(get_current_organization),
):
    """
    Retrieves details for a single virtual patch rule.
    """
    rule = VirtualPatchService.get_rule(db, rule_id, org.id)
    if not rule:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Rule not found.")
    read_obj = VirtualPatchRuleRead.model_validate(rule)
    if rule.asset:
        read_obj.asset_name = rule.asset.name
    return read_obj


@router.put(
    "/rules/{rule_id}",
    response_model=VirtualPatchRuleRead,
    dependencies=[Depends(require_permission(PermissionCode.VIRTUAL_PATCH_WRITE))],
)
def update_rule(
    rule_id: uuid.UUID,
    payload: VirtualPatchRuleUpdate,
    db: Session = Depends(get_db),
    org: Organization = Depends(get_current_organization),
    current_user: User = Depends(get_current_user),
):
    """
    Updates rule match criteria or action, incrementing version number and logging changes.
    """
    try:
        rule = VirtualPatchService.update_rule(db, rule_id, org.id, payload, user_id=current_user.id)
        read_obj = VirtualPatchRuleRead.model_validate(rule)
        if rule.asset:
            read_obj.asset_name = rule.asset.name
        return read_obj
    except ValueError as e:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(e))


@router.delete(
    "/rules/{rule_id}",
    dependencies=[Depends(require_permission(PermissionCode.VIRTUAL_PATCH_WRITE))],
)
def delete_rule(
    rule_id: uuid.UUID,
    db: Session = Depends(get_db),
    org: Organization = Depends(get_current_organization),
):
    """
    Deletes a virtual patch rule and its version history.
    """
    success = VirtualPatchService.delete_rule(db, rule_id, org.id)
    if not success:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Rule not found.")
    return {"status": "DELETED", "rule_id": str(rule_id)}


@router.get(
    "/rules/{rule_id}/versions",
    response_model=List[VirtualPatchVersionRead],
    dependencies=[Depends(require_permission(PermissionCode.VIRTUAL_PATCH_READ))],
)
def get_rule_versions(
    rule_id: uuid.UUID,
    db: Session = Depends(get_db),
    org: Organization = Depends(get_current_organization),
):
    """
    Retrieves the immutable audit trail of versions for a specific virtual patch rule.
    """
    try:
        versions = VirtualPatchService.get_rule_versions(db, rule_id, org.id)
        return [VirtualPatchVersionRead.model_validate(v) for v in versions]
    except ValueError as e:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(e))


# =============================================================================
# DEPLOYMENTS & HUMAN-IN-THE-LOOP APPROVAL WORKFLOW
# =============================================================================

@router.get(
    "/deployments",
    response_model=List[VirtualPatchDeploymentRead],
    dependencies=[Depends(require_permission(PermissionCode.VIRTUAL_PATCH_READ))],
)
def list_deployments(
    db: Session = Depends(get_db),
    org: Organization = Depends(get_current_organization),
):
    """
    Lists staging and production reverse proxy deployments.
    """
    deps = VirtualPatchService.get_deployments(db, org.id)
    result = []
    for d in deps:
        read_obj = VirtualPatchDeploymentRead.model_validate(d)
        if d.approved_by_user:
            read_obj.approved_by_user_email = d.approved_by_user.email
        result.append(read_obj)
    return result


@router.post(
    "/deployments/stage",
    response_model=VirtualPatchDeploymentRead,
    status_code=status.HTTP_201_CREATED,
    dependencies=[Depends(require_permission(PermissionCode.VIRTUAL_PATCH_WRITE))],
)
def stage_deployment(
    payload: VirtualPatchDeploymentCreate,
    db: Session = Depends(get_db),
    org: Organization = Depends(get_current_organization),
    current_user: User = Depends(get_current_user),
):
    """
    Compiles active rules into an Nginx reverse proxy configuration,
    executes 'nginx -t' syntax validation, and records a STAGING deployment.
    """
    deployment = VirtualPatchService.stage_deployment(
        db=db,
        organization_id=org.id,
        listen_port=payload.listen_port,
        upstream_url=payload.upstream_url,
        user_id=current_user.id,
    )
    return VirtualPatchDeploymentRead.model_validate(deployment)


@router.post(
    "/deployments/{deployment_id}/approve",
    response_model=VirtualPatchDeploymentRead,
    dependencies=[Depends(require_permission(PermissionCode.VIRTUAL_PATCH_APPROVE))],
)
def approve_deployment(
    deployment_id: uuid.UUID,
    db: Session = Depends(get_db),
    org: Organization = Depends(get_current_organization),
    current_user: User = Depends(get_current_user),
):
    """
    Strict human authorization gate: OrgAdmin explicitly signs off on a staged deployment.
    """
    try:
        dep = VirtualPatchService.approve_deployment(
            db=db,
            deployment_id=deployment_id,
            organization_id=org.id,
            user_id=current_user.id,
        )
        read_obj = VirtualPatchDeploymentRead.model_validate(dep)
        read_obj.approved_by_user_email = current_user.email
        return read_obj
    except ValueError as e:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(e))


@router.post(
    "/deployments/{deployment_id}/deploy",
    response_model=VirtualPatchDeploymentRead,
    dependencies=[Depends(require_permission(PermissionCode.VIRTUAL_PATCH_DEPLOY))],
)
def deploy_to_production(
    deployment_id: uuid.UUID,
    db: Session = Depends(get_db),
    org: Organization = Depends(get_current_organization),
    current_user: User = Depends(get_current_user),
):
    """
    Enforces approved virtual patches onto the live Nginx reverse proxy.
    Strictly blocked if the deployment was not previously approved by a human administrator.
    """
    try:
        dep = VirtualPatchService.deploy_to_production(
            db=db,
            deployment_id=deployment_id,
            organization_id=org.id,
            user_id=current_user.id,
        )
        return VirtualPatchDeploymentRead.model_validate(dep)
    except ValueError as e:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail=str(e))


@router.post(
    "/deployments/{deployment_id}/rollback",
    response_model=VirtualPatchDeploymentRead,
    dependencies=[Depends(require_permission(PermissionCode.VIRTUAL_PATCH_DEPLOY))],
)
def rollback_deployment(
    deployment_id: uuid.UUID,
    db: Session = Depends(get_db),
    org: Organization = Depends(get_current_organization),
    current_user: User = Depends(get_current_user),
):
    """
    Immediately rolls back live Nginx reverse proxy to the preceding stable deployment.
    """
    try:
        dep = VirtualPatchService.rollback_deployment(
            db=db,
            deployment_id=deployment_id,
            organization_id=org.id,
            user_id=current_user.id,
        )
        return VirtualPatchDeploymentRead.model_validate(dep)
    except ValueError as e:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(e))


# =============================================================================
# REVERSE PROXY WAF LOGS & FALSE POSITIVE REPORTING
# =============================================================================

@router.get(
    "/logs",
    response_model=List[WafEnforcementLogRead],
    dependencies=[Depends(require_permission(PermissionCode.WAF_LOGS_READ))],
)
def list_enforcement_logs(
    limit: int = Query(100, ge=1, le=500),
    decision: Optional[str] = Query(None),
    db: Session = Depends(get_db),
    org: Organization = Depends(get_current_organization),
):
    """
    Lists real-time reverse proxy request decisions with forensic metadata.
    """
    logs = VirtualPatchService.get_enforcement_logs(db, org.id, limit=limit, decision=decision)
    result = []
    for l in logs:
        read_obj = WafEnforcementLogRead.model_validate(l)
        if l.rule:
            read_obj.rule_name = l.rule.rule_name
        result.append(read_obj)
    return result


@router.post(
    "/logs/{log_id}/false-positive",
    response_model=WafEnforcementLogRead,
    dependencies=[Depends(require_permission(PermissionCode.WAF_LOGS_READ))],
)
def report_false_positive(
    log_id: uuid.UUID,
    payload: FalsePositiveReportRequest,
    db: Session = Depends(get_db),
    org: Organization = Depends(get_current_organization),
):
    """
    Flags a WAF enforcement event as a false positive with analyst commentary for rule tuning.
    """
    try:
        log_entry = VirtualPatchService.report_false_positive(
            db=db,
            log_id=log_id,
            organization_id=org.id,
            notes=payload.notes,
        )
        return WafEnforcementLogRead.model_validate(log_entry)
    except ValueError as e:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(e))

