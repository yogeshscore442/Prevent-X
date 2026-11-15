"""
PREVENT-X Security Validation & Rollback Service (MOD-10, MOD-08)
Orchestrates automated security validation suites, WAF regression matrices,
deployment health verification, canary safety policies, and atomic rollbacks.
"""

import json
import logging
import uuid
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from backend.app.database.base import utc_now
from backend.app.models.organization import Organization
from backend.app.models.security_validation import (
    CanaryPolicy,
    RollbackRecord,
    RollbackStatus,
    RollbackTriggerSource,
    ValidationJob,
    ValidationJobStatus,
    ValidationTestCategory,
    ValidationTestResult,
)
from backend.app.models.virtual_patch import (
    DeploymentStatus,
    VirtualPatchDeployment,
)
from backend.app.modules.security_validation.engine import SecurityValidationEngine
from backend.app.modules.security_validation.rollback_orchestrator import RollbackOrchestrator
from backend.app.modules.security_validation.schemas import (
    CanaryPolicyCreate,
    CanaryPolicyUpdate,
    CategoryCoverageStats,
    SecurityValidationOverviewStats,
    ValidationJobCreate,
)
from backend.app.modules.virtual_patch.proxy_manager import NginxProxyManager

logger = logging.getLogger("preventx.security_validation.service")


class SecurityValidationService:
    """
    Central service orchestrating security validation jobs, regression checks, and rollback workflows.
    """

    @classmethod
    def get_overview_stats(cls, db: Session, organization_id: uuid.UUID) -> Dict[str, Any]:
        """
        Aggregates security validation, bypass protection, regression coverage, and rollback KPIs.
        """
        total_jobs = db.scalar(
            select(func.count(ValidationJob.id)).where(ValidationJob.organization_id == organization_id)
        ) or 0

        passed_jobs = db.scalar(
            select(func.count(ValidationJob.id)).where(
                ValidationJob.organization_id == organization_id,
                ValidationJob.status == ValidationJobStatus.PASSED.value,
            )
        ) or 0

        failed_jobs = db.scalar(
            select(func.count(ValidationJob.id)).where(
                ValidationJob.organization_id == organization_id,
                ValidationJob.status == ValidationJobStatus.FAILED.value,
            )
        ) or 0

        overall_pass_rate = round((passed_jobs / total_jobs * 100.0) if total_jobs > 0 else 100.0, 1)

        # Attacks vs Legitimate traffic metrics
        total_attacks = db.scalar(
            select(func.count(ValidationTestResult.id)).where(
                ValidationTestResult.organization_id == organization_id,
                ValidationTestResult.expected_decision == "BLOCKED",
            )
        ) or 0

        blocked_attacks = db.scalar(
            select(func.count(ValidationTestResult.id)).where(
                ValidationTestResult.organization_id == organization_id,
                ValidationTestResult.expected_decision == "BLOCKED",
                ValidationTestResult.actual_decision == "BLOCKED",
            )
        ) or 0

        attacks_blocked_percent = round((blocked_attacks / total_attacks * 100.0) if total_attacks > 0 else 100.0, 1)

        total_legit = db.scalar(
            select(func.count(ValidationTestResult.id)).where(
                ValidationTestResult.organization_id == organization_id,
                ValidationTestResult.expected_decision == "ALLOWED",
            )
        ) or 0

        allowed_legit = db.scalar(
            select(func.count(ValidationTestResult.id)).where(
                ValidationTestResult.organization_id == organization_id,
                ValidationTestResult.expected_decision == "ALLOWED",
                ValidationTestResult.actual_decision == "ALLOWED",
            )
        ) or 0

        legit_allowed_percent = round((allowed_legit / total_legit * 100.0) if total_legit > 0 else 100.0, 1)

        # Last rollback record
        last_rollback = db.scalar(
            select(RollbackRecord)
            .where(RollbackRecord.organization_id == organization_id)
            .order_by(RollbackRecord.created_at.desc())
            .limit(1)
        )

        # Proxy health
        listen_port = 8085
        latest_dep = db.scalar(
            select(VirtualPatchDeployment)
            .where(
                VirtualPatchDeployment.organization_id == organization_id,
                VirtualPatchDeployment.status == DeploymentStatus.DEPLOYED.value,
            )
            .order_by(VirtualPatchDeployment.deployed_at.desc().nullslast())
            .limit(1)
        )
        if latest_dep:
            listen_port = latest_dep.listen_port

        proxy_health = NginxProxyManager.check_proxy_health(listen_port)
        proxy_running = proxy_health.get("is_running", False)

        # Canary policy weight
        canary_policy = cls.get_canary_policy(db, organization_id)
        active_canary_weight = canary_policy.canary_traffic_weight if canary_policy else 10

        # Category coverage breakdown
        categories = [c.value for c in ValidationTestCategory]
        category_stats = []
        for cat in categories:
            cat_total = db.scalar(
                select(func.count(ValidationTestResult.id)).where(
                    ValidationTestResult.organization_id == organization_id,
                    ValidationTestResult.test_category == cat,
                )
            ) or 0

            cat_passed = db.scalar(
                select(func.count(ValidationTestResult.id)).where(
                    ValidationTestResult.organization_id == organization_id,
                    ValidationTestResult.test_category == cat,
                    ValidationTestResult.result == "PASSED",
                )
            ) or 0

            cat_failed = cat_total - cat_passed
            cat_rate = round((cat_passed / cat_total * 100.0) if cat_total > 0 else 100.0, 1)

            category_stats.append({
                "category": cat,
                "total_tests": cat_total,
                "passed_tests": cat_passed,
                "failed_tests": cat_failed,
                "pass_rate_percentage": cat_rate,
            })

        return {
            "total_validation_jobs": total_jobs,
            "passed_validation_jobs": passed_jobs,
            "failed_validation_jobs": failed_jobs,
            "overall_pass_rate_percent": overall_pass_rate,
            "total_attacks_tested": total_attacks,
            "attacks_blocked_percent": attacks_blocked_percent,
            "legitimate_traffic_allowed_percent": legit_allowed_percent,
            "active_canary_weight": active_canary_weight,
            "last_rollback_status": last_rollback.status if last_rollback else None,
            "last_rollback_time": last_rollback.created_at if last_rollback else None,
            "active_proxy_port": listen_port,
            "active_proxy_healthy": proxy_running,
            "coverage_by_category": category_stats,
        }

    @classmethod
    def get_jobs(
        cls,
        db: Session,
        organization_id: uuid.UUID,
        limit: int = 50,
        environment: Optional[str] = None,
        status: Optional[str] = None,
    ) -> List[ValidationJob]:
        """
        Lists validation jobs scoped by tenant.
        """
        query = select(ValidationJob).where(ValidationJob.organization_id == organization_id)
        if environment:
            query = query.where(ValidationJob.environment == environment)
        if status:
            query = query.where(ValidationJob.status == status)

        query = query.order_by(ValidationJob.created_at.desc()).limit(limit)
        return list(db.scalars(query).all())

    @classmethod
    def get_job(
        cls,
        db: Session,
        job_id: uuid.UUID,
        organization_id: uuid.UUID,
    ) -> Optional[ValidationJob]:
        """
        Retrieves a single validation job record.
        """
        return db.scalar(
            select(ValidationJob).where(
                ValidationJob.id == job_id,
                ValidationJob.organization_id == organization_id,
            )
        )

    @classmethod
    def get_job_results(
        cls,
        db: Session,
        job_id: uuid.UUID,
        organization_id: uuid.UUID,
        category: Optional[str] = None,
        result: Optional[str] = None,
    ) -> List[ValidationTestResult]:
        """
        Lists granular test probe execution results for a job.
        """
        query = select(ValidationTestResult).where(
            ValidationTestResult.job_id == job_id,
            ValidationTestResult.organization_id == organization_id,
        )
        if category:
            query = query.where(ValidationTestResult.test_category == category)
        if result:
            query = query.where(ValidationTestResult.result == result)

        query = query.order_by(ValidationTestResult.created_at.asc())
        return list(db.scalars(query).all())

    @classmethod
    def create_and_run_validation_job(
        cls,
        db: Session,
        organization_id: uuid.UUID,
        data: ValidationJobCreate,
        user_id: Optional[uuid.UUID] = None,
    ) -> ValidationJob:
        """
        Creates a new validation run, executes test probes, logs evidence,
        and triggers automated rollback if failure thresholds are breached.
        """
        # Resolve target deployment
        dep_id = data.deployment_id
        config_hash = None
        target_url = data.target_url

        if dep_id:
            dep = db.scalar(
                select(VirtualPatchDeployment).where(
                    VirtualPatchDeployment.id == dep_id,
                    VirtualPatchDeployment.organization_id == organization_id,
                )
            )
            if dep:
                config_hash = dep.config_hash
                target_url = f"http://127.0.0.1:{dep.listen_port}"
        else:
            # Pick latest active deployment
            latest_dep = db.scalar(
                select(VirtualPatchDeployment)
                .where(
                    VirtualPatchDeployment.organization_id == organization_id,
                    VirtualPatchDeployment.status.in_([DeploymentStatus.DEPLOYED.value, DeploymentStatus.APPROVED.value]),
                )
                .order_by(VirtualPatchDeployment.created_at.desc())
                .limit(1)
            )
            if latest_dep:
                dep_id = latest_dep.id
                config_hash = latest_dep.config_hash
                target_url = f"http://127.0.0.1:{latest_dep.listen_port}"

        job = ValidationJob(
            id=uuid.uuid4(),
            organization_id=organization_id,
            deployment_id=dep_id,
            environment=data.environment,
            target_url=target_url,
            status=ValidationJobStatus.PENDING.value,
            trigger_type=data.trigger_type,
            canary_percentage=data.canary_percentage,
            active_config_hash=config_hash,
            initiated_by_user_id=user_id,
        )
        db.add(job)
        db.commit()
        db.refresh(job)

        # Execute test suite
        completed_job = SecurityValidationEngine.run_validation_job(db=db, job=job)

        # Safety Check: If validation failed on production or staging with canary policy, check auto-rollback
        if completed_job.status == ValidationJobStatus.FAILED.value and dep_id:
            policy = cls.get_canary_policy(db, organization_id)
            if policy and policy.auto_rollback_enabled:
                failure_rate = 100.0 - completed_job.pass_rate_percentage
                if failure_rate > policy.max_failure_rate_percent or completed_job.false_positives_detected > policy.max_false_positive_count:
                    logger.warning(
                        "Validation job %s failed threshold (Failure rate: %s%%, FPs: %s). Triggering auto-rollback for deployment %s",
                        completed_job.id,
                        failure_rate,
                        completed_job.false_positives_detected,
                        dep_id,
                    )
                    try:
                        RollbackOrchestrator.execute_atomic_rollback(
                            db=db,
                            organization_id=organization_id,
                            deployment_id=dep_id,
                            rollback_reason=(
                                f"Automatic rollback triggered by failed validation job {completed_job.id}. "
                                f"Failure rate: {failure_rate}%, FPs: {completed_job.false_positives_detected}."
                            ),
                            operator_user_id=user_id,
                            trigger_source=RollbackTriggerSource.AUTOMATIC_VALIDATION_FAILURE.value,
                        )
                    except Exception as rb_exc:
                        logger.critical("Automated rollback failed: %s", rb_exc)

        return completed_job

    # =========================================================================
    # ROLLBACK ORCHESTRATION
    # =========================================================================

    @classmethod
    def execute_rollback(
        cls,
        db: Session,
        organization_id: uuid.UUID,
        deployment_id: uuid.UUID,
        rollback_reason: str,
        target_deployment_id: Optional[uuid.UUID] = None,
        operator_user_id: Optional[uuid.UUID] = None,
        trigger_source: str = RollbackTriggerSource.MANUAL.value,
    ) -> RollbackRecord:
        """
        Triggers an audited atomic configuration rollback.
        """
        return RollbackOrchestrator.execute_atomic_rollback(
            db=db,
            organization_id=organization_id,
            deployment_id=deployment_id,
            rollback_reason=rollback_reason,
            target_deployment_id=target_deployment_id,
            operator_user_id=operator_user_id,
            trigger_source=trigger_source,
        )

    @classmethod
    def get_rollback_history(
        cls,
        db: Session,
        organization_id: uuid.UUID,
        limit: int = 50,
    ) -> List[RollbackRecord]:
        """
        Lists rollback audit history.
        """
        return list(
            db.scalars(
                select(RollbackRecord)
                .where(RollbackRecord.organization_id == organization_id)
                .order_by(RollbackRecord.created_at.desc())
                .limit(limit)
            ).all()
        )

    # =========================================================================
    # CANARY POLICIES
    # =========================================================================

    @classmethod
    def get_canary_policy(cls, db: Session, organization_id: uuid.UUID) -> CanaryPolicy:
        """
        Retrieves or initializes the tenant's canary and safety threshold policy.
        """
        policy = db.scalar(
            select(CanaryPolicy).where(CanaryPolicy.organization_id == organization_id)
        )
        if not policy:
            policy = CanaryPolicy(
                id=uuid.uuid4(),
                organization_id=organization_id,
                name="Default SMB Canary Safety Policy",
                canary_traffic_weight=10,
                max_failure_rate_percent=5.0,
                max_latency_ms=1000.0,
                max_false_positive_count=1,
                auto_rollback_enabled=True,
                auto_promotion_enabled=False,
                is_active=True,
            )
            db.add(policy)
            db.commit()
            db.refresh(policy)
        return policy

    get_or_create_canary_policy = get_canary_policy

    @classmethod
    def update_canary_policy(
        cls,
        db: Session,
        organization_id: uuid.UUID,
        data: CanaryPolicyUpdate,
    ) -> CanaryPolicy:
        """
        Updates tenant canary rollout safety thresholds.
        """
        policy = cls.get_canary_policy(db, organization_id)

        if data.name is not None:
            policy.name = data.name
        if data.canary_traffic_weight is not None:
            policy.canary_traffic_weight = data.canary_traffic_weight
        if data.max_failure_rate_percent is not None:
            policy.max_failure_rate_percent = data.max_failure_rate_percent
        if data.max_latency_ms is not None:
            policy.max_latency_ms = data.max_latency_ms
        if data.max_false_positive_count is not None:
            policy.max_false_positive_count = data.max_false_positive_count
        if data.auto_rollback_enabled is not None:
            policy.auto_rollback_enabled = data.auto_rollback_enabled
        if data.auto_promotion_enabled is not None:
            policy.auto_promotion_enabled = data.auto_promotion_enabled
        if data.is_active is not None:
            policy.is_active = data.is_active

        db.commit()
        db.refresh(policy)
        return policy

