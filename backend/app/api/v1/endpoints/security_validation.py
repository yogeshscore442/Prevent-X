"""
PREVENT-X Automated Security Validation & Reliable Rollback REST API (MOD-10, MOD-08)
Endpoints for non-destructive test execution, WAF regression matrices, live proxy health,
canary routing thresholds, and atomic configuration rollback.
"""

import logging
import uuid
from typing import Any, Dict, List, Optional

from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy.orm import Session

from backend.app.database.session import get_db
from backend.app.models.organization import Organization
from backend.app.models.security_validation import RollbackTriggerSource
from backend.app.models.user import User
from backend.app.modules.security_validation.schemas import (
    CanaryPolicyCreate,
    CanaryPolicyRead,
    CanaryPolicyUpdate,
    RollbackRecordRead,
    RollbackRequest,
    SecurityValidationOverviewStats,
    ValidationJobCreate,
    ValidationJobRead,
    ValidationTestResultRead,
)
from backend.app.modules.security_validation.service import SecurityValidationService
from backend.app.modules.security_validation.tasks import (
    execute_automated_rollback_job,
    run_security_validation_job,
)
from backend.app.security.permissions import (
    PermissionCode,
    get_current_organization,
    get_current_user,
    require_permission,
)

logger = logging.getLogger("preventx.api.security_validation")

router = APIRouter(prefix="/security-validation", tags=["Automated Security Validation & Rollback"])


@router.get(
    "/overview",
    response_model=SecurityValidationOverviewStats,
    dependencies=[Depends(require_permission(PermissionCode.VALIDATION_READ))],
)
def get_validation_overview(
    db: Session = Depends(get_db),
    org: Organization = Depends(get_current_organization),
):
    """
    Returns aggregate validation pass rate, attack block percentage,
    legitimate traffic pass-through, proxy health, and canary status.
    """
    return SecurityValidationService.get_overview_stats(db, org.id)


# =============================================================================
# VALIDATION RUNS & TEST PROBES
# =============================================================================

@router.get(
    "/jobs",
    response_model=List[ValidationJobRead],
    dependencies=[Depends(require_permission(PermissionCode.VALIDATION_READ))],
)
def list_validation_jobs(
    limit: int = Query(50, ge=1, le=200),
    environment: Optional[str] = Query(None, description="Filter by environment (e.g. STAGING, PRODUCTION)"),
    job_status: Optional[str] = Query(None, alias="status", description="Filter by status (e.g. PASSED, FAILED, RUNNING)"),
    db: Session = Depends(get_db),
    org: Organization = Depends(get_current_organization),
):
    """
    Lists execution history of security validation runs for the organization.
    """
    jobs = SecurityValidationService.get_jobs(
        db=db,
        organization_id=org.id,
        limit=limit,
        environment=environment,
        status=job_status,
    )
    return [ValidationJobRead.model_validate(j) for j in jobs]


@router.post(
    "/jobs/run",
    response_model=ValidationJobRead,
    dependencies=[Depends(require_permission(PermissionCode.VALIDATION_RUN))],
)
def trigger_validation_run(
    payload: ValidationJobCreate,
    async_mode: bool = Query(False, description="Whether to enqueue validation in Celery background worker"),
    db: Session = Depends(get_db),
    org: Organization = Depends(get_current_organization),
    user: User = Depends(get_current_user),
):
    """
    Triggers an automated non-destructive security validation test run against the Nginx proxy.
    Tests SQLi, XSS, Path Traversal, CMDI, regression encodings, and legitimate traffic.
    """
    if async_mode:
        # Enqueue via Celery worker
        task = run_security_validation_job.delay(
            organization_id=str(org.id),
            deployment_id=str(payload.deployment_id) if payload.deployment_id else None,
            environment=payload.environment,
            trigger_type=payload.trigger_type,
            canary_percentage=payload.canary_percentage,
            user_id=str(user.id),
            target_url=payload.target_url,
        )
        logger.info("Enqueued validation task %s for org %s", task.id, org.id)
        # Return initial created or recent job placeholder
        jobs = SecurityValidationService.get_jobs(db, org.id, limit=1)
        if jobs:
            return ValidationJobRead.model_validate(jobs[0])
        # Or create synchronous
    job = SecurityValidationService.create_and_run_validation_job(
        db=db,
        organization_id=org.id,
        data=payload,
        user_id=user.id,
    )
    return ValidationJobRead.model_validate(job)


@router.get(
    "/jobs/{job_id}",
    response_model=ValidationJobRead,
    dependencies=[Depends(require_permission(PermissionCode.VALIDATION_READ))],
)
def get_validation_job(
    job_id: uuid.UUID,
    db: Session = Depends(get_db),
    org: Organization = Depends(get_current_organization),
):
    """
    Retrieves execution summary and metrics for a specific validation run.
    """
    job = SecurityValidationService.get_job(db, job_id, org.id)
    if not job:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Validation job not found or does not belong to this organization",
        )
    return ValidationJobRead.model_validate(job)


@router.get(
    "/jobs/{job_id}/results",
    response_model=List[ValidationTestResultRead],
    dependencies=[Depends(require_permission(PermissionCode.VALIDATION_READ))],
)
def get_validation_job_results(
    job_id: uuid.UUID,
    category: Optional[str] = Query(None, description="Filter by test category (SQLI, XSS, etc.)"),
    test_result: Optional[str] = Query(None, alias="result", description="Filter by result (PASSED, FAILED)"),
    db: Session = Depends(get_db),
    org: Organization = Depends(get_current_organization),
):
    """
    Retrieves granular probe results and evidence for a specific validation run.
    """
    # Verify job belongs to tenant first
    job = SecurityValidationService.get_job(db, job_id, org.id)
    if not job:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Validation job not found or does not belong to this organization",
        )

    results = SecurityValidationService.get_job_results(
        db=db,
        job_id=job_id,
        organization_id=org.id,
        category=category,
        result=test_result,
    )
    return [ValidationTestResultRead.model_validate(r) for r in results]


# =============================================================================
# ROLLBACK ORCHESTRATION
# =============================================================================

@router.post(
    "/rollback",
    response_model=RollbackRecordRead,
    dependencies=[Depends(require_permission(PermissionCode.ROLLBACK_EXECUTE))],
)
def execute_configuration_rollback(
    payload: RollbackRequest,
    async_mode: bool = Query(False, description="Whether to enqueue rollback in background worker"),
    db: Session = Depends(get_db),
    org: Organization = Depends(get_current_organization),
    user: User = Depends(get_current_user),
):
    """
    Performs atomic configuration restoration to the previous validated state.
    Pre-validates syntax with `nginx -t`, restores snapshot atomically, and runs live HTTP verification.
    """
    if async_mode:
        task = execute_automated_rollback_job.delay(
            organization_id=str(org.id),
            deployment_id=str(payload.deployment_id),
            rollback_reason=payload.rollback_reason,
            operator_user_id=str(user.id),
        )
        logger.info("Enqueued rollback task %s for deployment %s", task.id, payload.deployment_id)
        records = SecurityValidationService.get_rollback_history(db, org.id, limit=1)
        if records:
            return RollbackRecordRead.model_validate(records[0])

    record = SecurityValidationService.execute_rollback(
        db=db,
        organization_id=org.id,
        deployment_id=payload.deployment_id,
        rollback_reason=payload.rollback_reason,
        target_deployment_id=payload.target_deployment_id,
        operator_user_id=user.id,
        trigger_source=RollbackTriggerSource.MANUAL.value,
    )
    return RollbackRecordRead.model_validate(record)


@router.get(
    "/rollback/history",
    response_model=List[RollbackRecordRead],
    dependencies=[Depends(require_permission(PermissionCode.VALIDATION_READ))],
)
def get_rollback_history(
    limit: int = Query(50, ge=1, le=200),
    db: Session = Depends(get_db),
    org: Organization = Depends(get_current_organization),
):
    """
    Retrieves full audit trail of configuration rollbacks and live verification outcomes.
    """
    records = SecurityValidationService.get_rollback_history(db, org.id, limit=limit)
    return [RollbackRecordRead.model_validate(r) for r in records]


# =============================================================================
# CANARY POLICIES & THRESHOLDS
# =============================================================================

@router.get(
    "/canary-policies",
    response_model=CanaryPolicyRead,
    dependencies=[Depends(require_permission(PermissionCode.VALIDATION_READ))],
)
def get_canary_policy(
    db: Session = Depends(get_db),
    org: Organization = Depends(get_current_organization),
):
    """
    Retrieves the active canary routing policy and safety thresholds for the organization.
    """
    return CanaryPolicyRead.model_validate(SecurityValidationService.get_or_create_canary_policy(db, org.id))


@router.put(
    "/canary-policies",
    response_model=CanaryPolicyRead,
    dependencies=[Depends(require_permission(PermissionCode.VALIDATION_RUN))],
)
def update_canary_policy(
    payload: CanaryPolicyUpdate,
    db: Session = Depends(get_db),
    org: Organization = Depends(get_current_organization),
):
    """
    Updates canary traffic allocation, latency limits, failure rate thresholds,
    and automated rollback toggles.
    """
    policy = SecurityValidationService.update_canary_policy(db, org.id, payload)
    return CanaryPolicyRead.model_validate(policy)

