"""
PREVENT-X Attack Surface Service
Coordinates domain validation, job queuing, Celery task dispatch, queries, and audit logging.
"""

from datetime import datetime, timezone
import json
import logging
from typing import Optional, List, Dict, Any, Tuple
from uuid import UUID
from sqlalchemy.orm import Session
from sqlalchemy import func, desc
from fastapi import HTTPException, status

from backend.app.models.attack_surface import (
    DiscoveryJob,
    DiscoveryJobStatus,
    DiscoveredDomain,
    DNSRecord,
    ExposureFinding,
    FindingSeverity,
)
from backend.app.models.audit_log import AuditEvent
from backend.app.modules.attack_surface.scope_validator import ScopeValidator, ScopeValidationError
from backend.app.modules.attack_surface.schemas import (
    AttackSurfaceOverviewResponse,
    DiscoveryJobResponse,
)

logger = logging.getLogger("preventx.attack_surface.service")


class AttackSurfaceService:
    """Core domain logic service for attack surface intelligence."""

    @classmethod
    def create_discovery_job(
        cls,
        db: Session,
        organization_id: UUID,
        user_id: Optional[UUID],
        asset_id: UUID,
        target_domain: Optional[str],
        authorization_confirmed: bool,
    ) -> DiscoveryJob:
        """
        Validates scope boundary, stores job, and enqueues Celery background task.
        """
        # 1. Enforce scope & authorization boundary
        asset, validated_domain = ScopeValidator.validate_and_authorize_job(
            db=db,
            organization_id=organization_id,
            asset_id=asset_id,
            target_domain=target_domain,
            authorization_confirmed=authorization_confirmed,
        )

        # 2. Check for active duplicate job
        active_job = db.query(DiscoveryJob).filter(
            DiscoveryJob.organization_id == organization_id,
            DiscoveryJob.asset_id == asset_id,
            DiscoveryJob.target_domain == validated_domain,
            DiscoveryJob.status.in_([DiscoveryJobStatus.PENDING, DiscoveryJobStatus.QUEUED, DiscoveryJobStatus.RUNNING]),
        ).first()

        if active_job:
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail=f"An active discovery job ({active_job.id}) is already in progress for target '{validated_domain}'.",
            )

        now = datetime.now(timezone.utc)
        job = DiscoveryJob(
            organization_id=organization_id,
            asset_id=asset.id,
            target_domain=validated_domain,
            status=DiscoveryJobStatus.QUEUED,
            progress_percent=0,
            current_stage="QUEUED",
            authorized_scope=asset.target,
            initiated_by_user_id=user_id,
            authorization_confirmed=True,
            authorized_at=now,
        )
        db.add(job)
        db.flush()

        # Log audit event
        audit = AuditEvent(
            organization_id=organization_id,
            user_id=user_id,
            action="DISCOVERY_JOB_CREATED",
            resource_type="discovery_job",
            resource_id=str(job.id),
            details=json.dumps({
                "target_domain": validated_domain,
                "asset_id": str(asset.id),
                "asset_name": asset.name,
            }),
            status="SUCCESS",
        )
        db.add(audit)
        db.commit()
        db.refresh(job)

        # 3. Dispatch to Celery worker via Redis
        try:
            from backend.app.modules.attack_surface.tasks.discovery_tasks import execute_discovery_job
            execute_discovery_job.delay(str(job.id))
            logger.info(f"Dispatched discovery job {job.id} to Celery queue.")
        except Exception as e:
            logger.warning(f"Could not dispatch discovery job {job.id} to Celery: {e}. Executing inline or pending worker pickup.")

        return job

    @classmethod
    def cancel_discovery_job(
        cls,
        db: Session,
        organization_id: UUID,
        user_id: Optional[UUID],
        job_id: UUID,
        reason: Optional[str] = None,
    ) -> DiscoveryJob:
        """
        Flags an in-flight job as cancelled.
        """
        job = db.query(DiscoveryJob).filter(
            DiscoveryJob.id == job_id,
            DiscoveryJob.organization_id == organization_id,
        ).first()

        if not job:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Discovery job not found in active organization.",
            )

        if job.status in (DiscoveryJobStatus.COMPLETED, DiscoveryJobStatus.FAILED, DiscoveryJobStatus.CANCELLED):
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"Cannot cancel job in terminal state '{job.status}'.",
            )

        job.status = DiscoveryJobStatus.CANCELLED
        job.current_stage = "CANCELLED"
        job.error_message = reason or "Cancelled by user request."
        job.completed_at = datetime.now(timezone.utc)

        audit = AuditEvent(
            organization_id=organization_id,
            user_id=user_id,
            action="DISCOVERY_JOB_CANCELLED",
            resource_type="discovery_job",
            resource_id=str(job.id),
            details=json.dumps({"reason": reason}),
            status="SUCCESS",
        )
        db.add(audit)
        db.commit()
        db.refresh(job)
        return job

    @classmethod
    def get_job(cls, db: Session, organization_id: UUID, job_id: UUID) -> DiscoveryJob:
        job = db.query(DiscoveryJob).filter(
            DiscoveryJob.id == job_id,
            DiscoveryJob.organization_id == organization_id,
        ).first()
        if not job:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Discovery job not found.",
            )
        return job

    @classmethod
    def list_jobs(
        cls,
        db: Session,
        organization_id: UUID,
        asset_id: Optional[UUID] = None,
        limit: int = 50,
        offset: int = 0,
    ) -> List[DiscoveryJob]:
        q = db.query(DiscoveryJob).filter(DiscoveryJob.organization_id == organization_id)
        if asset_id:
            q = q.filter(DiscoveryJob.asset_id == asset_id)
        return q.order_by(desc(DiscoveryJob.created_at)).offset(offset).limit(limit).all()

    @classmethod
    def list_domains(
        cls,
        db: Session,
        organization_id: UUID,
        asset_id: Optional[UUID] = None,
        job_id: Optional[UUID] = None,
        search: Optional[str] = None,
        limit: int = 50,
        offset: int = 0,
    ) -> List[DiscoveredDomain]:
        q = db.query(DiscoveredDomain).filter(DiscoveredDomain.organization_id == organization_id)
        if asset_id:
            q = q.filter(DiscoveredDomain.asset_id == asset_id)
        if job_id:
            q = q.filter(DiscoveredDomain.job_id == job_id)
        if search:
            q = q.filter(DiscoveredDomain.domain_name.ilike(f"%{search}%"))
        return q.order_by(desc(DiscoveredDomain.created_at)).offset(offset).limit(limit).all()

    @classmethod
    def get_domain_detail(cls, db: Session, organization_id: UUID, domain_id: UUID) -> DiscoveredDomain:
        dom = db.query(DiscoveredDomain).filter(
            DiscoveredDomain.id == domain_id,
            DiscoveredDomain.organization_id == organization_id,
        ).first()
        if not dom:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Domain not found.")
        return dom

    @classmethod
    def list_findings(
        cls,
        db: Session,
        organization_id: UUID,
        asset_id: Optional[UUID] = None,
        job_id: Optional[UUID] = None,
        severity: Optional[str] = None,
        category: Optional[str] = None,
        limit: int = 50,
        offset: int = 0,
    ) -> List[ExposureFinding]:
        q = db.query(ExposureFinding).filter(ExposureFinding.organization_id == organization_id)
        if asset_id:
            q = q.filter(ExposureFinding.asset_id == asset_id)
        if job_id:
            q = q.filter(ExposureFinding.job_id == job_id)
        if severity:
            q = q.filter(ExposureFinding.severity == severity.upper())
        if category:
            q = q.filter(ExposureFinding.finding_category == category.upper())
        return q.order_by(desc(ExposureFinding.created_at)).offset(offset).limit(limit).all()

    @classmethod
    def get_overview(cls, db: Session, organization_id: UUID) -> AttackSurfaceOverviewResponse:
        """Calculates tenant-wide attack surface metrics."""
        # 1. Total unique discovered domains
        total_domains = db.query(func.count(DiscoveredDomain.id)).filter(
            DiscoveredDomain.organization_id == organization_id
        ).scalar() or 0

        # 2. Total unique public IPs recorded in DNS
        total_public_ips = db.query(func.count(func.distinct(DNSRecord.record_value))).filter(
            DNSRecord.organization_id == organization_id,
            DNSRecord.record_type.in_(["A", "AAAA"]),
        ).scalar() or 0

        # 3. Average exposure score
        avg_score = db.query(func.avg(DiscoveryJob.initial_exposure_score)).filter(
            DiscoveryJob.organization_id == organization_id,
            DiscoveryJob.status.in_([DiscoveryJobStatus.COMPLETED, DiscoveryJobStatus.PARTIALLY_COMPLETED]),
        ).scalar()
        average_exposure_score = round(float(avg_score), 1) if avg_score is not None else 0.0

        # 4. Findings count & breakdown by severity
        findings = db.query(ExposureFinding.severity, func.count(ExposureFinding.id)).filter(
            ExposureFinding.organization_id == organization_id,
            ExposureFinding.current_status == "ACTIVE",
        ).group_by(ExposureFinding.severity).all()

        findings_by_severity = {
            "CRITICAL": 0,
            "HIGH": 0,
            "MEDIUM": 0,
            "LOW": 0,
            "INFO": 0,
        }
        active_findings_count = 0
        for sev, count in findings:
            findings_by_severity[sev] = count
            active_findings_count += count

        # 5. Findings breakdown by category
        cat_findings = db.query(ExposureFinding.finding_category, func.count(ExposureFinding.id)).filter(
            ExposureFinding.organization_id == organization_id,
            ExposureFinding.current_status == "ACTIVE",
        ).group_by(ExposureFinding.finding_category).all()

        findings_by_category = {cat: count for cat, count in cat_findings}

        # 6. Recent jobs
        recent_jobs_db = db.query(DiscoveryJob).filter(
            DiscoveryJob.organization_id == organization_id
        ).order_by(desc(DiscoveryJob.created_at)).limit(5).all()

        recent_jobs = [DiscoveryJobResponse.model_validate(j) for j in recent_jobs_db]

        return AttackSurfaceOverviewResponse(
            total_discovered_domains=total_domains,
            total_public_ips=total_public_ips,
            average_exposure_score=average_exposure_score,
            active_findings_count=active_findings_count,
            findings_by_severity=findings_by_severity,
            findings_by_category=findings_by_category,
            recent_jobs=recent_jobs,
        )
