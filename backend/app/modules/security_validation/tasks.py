"""
PREVENT-X Celery Background Tasks for Automated Security Validation & Reliable Rollback (MOD-10, MOD-08)
"""

import logging
import uuid
from typing import Any, Dict, Optional

from backend.app.database.session import SessionLocal
from backend.app.models.security_validation import RollbackTriggerSource, ValidationJobStatus
from backend.app.modules.security_validation.schemas import ValidationJobCreate
from backend.app.modules.security_validation.service import SecurityValidationService
from backend.app.workers.celery_app import celery_app

logger = logging.getLogger("preventx.tasks.security_validation")


@celery_app.task(name="preventx.tasks.run_security_validation_job", bind=True)
def run_security_validation_job(
    self,
    organization_id: str,
    deployment_id: Optional[str] = None,
    environment: str = "STAGING",
    trigger_type: str = "MANUAL",
    canary_percentage: int = 10,
    user_id: Optional[str] = None,
    target_url: str = "http://127.0.0.1:8085",
) -> Dict[str, Any]:
    """
    Background worker task to execute automated security validation test suites
    against active Nginx proxy deployments.
    """
    org_uuid = uuid.UUID(organization_id)
    dep_uuid = uuid.UUID(deployment_id) if deployment_id else None
    user_uuid = uuid.UUID(user_id) if user_id else None

    logger.info(
        "Starting automated security validation job for organization %s, deployment %s, env %s",
        org_uuid,
        dep_uuid,
        environment,
    )

    db = SessionLocal()
    try:
        job_data = ValidationJobCreate(
            deployment_id=dep_uuid,
            environment=environment,
            target_url=target_url,
            trigger_type=trigger_type,
            canary_percentage=canary_percentage,
        )

        completed_job = SecurityValidationService.create_and_run_validation_job(
            db=db,
            organization_id=org_uuid,
            data=job_data,
            user_id=user_uuid,
        )

        return {
            "job_id": str(completed_job.id),
            "status": completed_job.status,
            "organization_id": str(org_uuid),
            "total_tests": completed_job.total_tests,
            "passed_tests": completed_job.passed_tests,
            "failed_tests": completed_job.failed_tests,
            "pass_rate_percentage": completed_job.pass_rate_percentage,
            "blocked_attacks": completed_job.blocked_attacks,
            "false_positives_detected": completed_job.false_positives_detected,
        }
    except Exception as exc:
        logger.exception("Failed security validation background job: %s", exc)
        raise
    finally:
        db.close()


@celery_app.task(name="preventx.tasks.execute_automated_rollback_job", bind=True)
def execute_automated_rollback_job(
    self,
    organization_id: str,
    deployment_id: str,
    rollback_reason: str,
    operator_user_id: Optional[str] = None,
) -> Dict[str, Any]:
    """
    Background worker task to execute atomic rollback for a deployment.
    """
    org_uuid = uuid.UUID(organization_id)
    dep_uuid = uuid.UUID(deployment_id)
    user_uuid = uuid.UUID(operator_user_id) if operator_user_id else None

    logger.info(
        "Executing background rollback job for organization %s, deployment %s. Reason: %s",
        org_uuid,
        dep_uuid,
        rollback_reason,
    )

    db = SessionLocal()
    try:
        record = SecurityValidationService.execute_rollback(
            db=db,
            organization_id=org_uuid,
            deployment_id=dep_uuid,
            rollback_reason=rollback_reason,
            operator_user_id=user_uuid,
            trigger_source=RollbackTriggerSource.MANUAL.value,
        )

        return {
            "rollback_id": str(record.id),
            "deployment_id": str(record.deployment_id),
            "organization_id": str(org_uuid),
            "trigger_source": record.trigger_source,
            "status": record.status,
            "previous_config_hash": record.previous_config_hash,
            "restored_config_hash": record.restored_config_hash,
            "is_restoration_verified": record.is_restoration_verified,
        }
    except Exception as exc:
        logger.exception("Failed background rollback execution: %s", exc)
        raise
    finally:
        db.close()
