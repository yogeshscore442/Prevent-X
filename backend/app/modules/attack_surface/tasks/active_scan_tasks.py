"""
PREVENT-X Active Scan Celery Tasks
Executes controlled active service discovery jobs in the background worker pool.
Enforces worker-side authorization revalidation, cancellation support, and evidence persistence.
"""

from datetime import datetime, timezone
import json
import logging
from uuid import UUID
from typing import Dict, Any

from backend.app.database.session import SessionLocal
from backend.app.database.base import utc_now
from backend.app.models.attack_surface import (
    ActiveScanJob,
    ActiveScanJobStatus,
    DiscoveredService,
    ServiceState,
)
from backend.app.models.audit_log import AuditEvent
from backend.app.modules.attack_surface.active_scanner import ActiveScanner, PortScanResult
from backend.app.modules.attack_surface.scope_validator import ScopeValidator, WorkerAuthorizationError
from backend.app.workers.celery_app import celery_app

logger = logging.getLogger("preventx.tasks.active_scan")


@celery_app.task(name="preventx.tasks.execute_active_scan_job", bind=True, max_retries=0)
def execute_active_scan_job(self, job_id_str: str) -> Dict[str, Any]:
    """
    Celery task that executes a controlled active service discovery job.
    Revalidates authorization boundaries immediately prior to scanning.
    """
    logger.info(f"Starting Celery background execution for active scan job {job_id_str}")
    db = SessionLocal()
    try:
        job_uuid = UUID(job_id_str)
        job = db.query(ActiveScanJob).filter(ActiveScanJob.id == job_uuid).first()
        if not job:
            logger.error(f"Active scan job {job_id_str} not found in database.")
            return {"job_id": job_id_str, "status": "FAILED", "error": "Job not found"}

        # 1. Worker Authorization Revalidation
        try:
            ScopeValidator.validate_worker_execution_authorization(db, job)
        except WorkerAuthorizationError as auth_err:
            logger.error(f"Celery worker authorization rejected for active scan job {job_id_str}: {auth_err.detail}")
            job.status = ActiveScanJobStatus.FAILED
            job.error_message = f"Worker authorization rejected: {auth_err.detail}"
            job.completed_at = utc_now()
            
            # Record security rejection in audit trail
            audit_ev = AuditEvent(
                organization_id=job.organization_id,
                user_id=job.initiated_by_user_id,
                action="ACTIVE_DISCOVERY_WORKER_AUTH_REJECTED",
                resource_type="ACTIVE_SCAN_JOB",
                resource_id=str(job.id),
                status="DENIED",
                details=json.dumps({"reason": auth_err.detail, "job_id": str(job.id)}),
            )
            db.add(audit_ev)
            db.commit()
            return {
                "job_id": job_id_str,
                "status": "FAILED",
                "error": f"Worker authorization rejected: {auth_err.detail}",
            }

        # 2. Check if already cancelled
        if job.status == ActiveScanJobStatus.CANCELLED:
            logger.info(f"Active scan job {job_id_str} was already cancelled before execution.")
            return {"job_id": job_id_str, "status": "CANCELLED"}

        # 3. Transition to RUNNING
        job.status = ActiveScanJobStatus.RUNNING
        job.started_at = utc_now()
        job.current_stage = "PORT_SCANNING"
        job.progress_percent = 5
        db.commit()

        # Parse ports
        try:
            ports = json.loads(job.selected_ports)
        except Exception as e:
            logger.error(f"Failed to parse selected_ports for job {job_id_str}: {e}")
            job.status = ActiveScanJobStatus.FAILED
            job.error_message = f"Invalid selected_ports JSON: {e}"
            job.completed_at = utc_now()
            db.commit()
            return {"job_id": job_id_str, "status": "FAILED", "error": str(e)}

        target_ip = job.target_ip or job.target
        target_host = job.target

        # Helper to check cancellation
        def is_cancelled() -> bool:
            check_db = SessionLocal()
            try:
                curr = check_db.query(ActiveScanJob).filter(ActiveScanJob.id == job_uuid).first()
                return curr.status == ActiveScanJobStatus.CANCELLED if curr else True
            finally:
                check_db.close()

        # Helper to report progress
        def on_progress(scanned: int, total: int, current_results: list) -> None:
            prog_db = SessionLocal()
            try:
                curr = prog_db.query(ActiveScanJob).filter(ActiveScanJob.id == job_uuid).first()
                if curr and curr.status == ActiveScanJobStatus.RUNNING:
                    curr.ports_scanned_count = scanned
                    curr.progress_percent = min(95, int((scanned / max(total, 1)) * 90) + 5)
                    prog_db.commit()
            finally:
                prog_db.close()

        # 4. Execute Scanner
        scanner = ActiveScanner(
            max_concurrency=job.max_concurrency,
            connect_timeout=job.timeout_seconds,
        )
        scan_results = scanner.scan_ports(
            target_ip=target_ip,
            target_host=target_host,
            ports=ports,
            cancellation_check=is_cancelled,
            progress_callback=on_progress,
        )

        # Refresh job state
        db.refresh(job)
        if job.status == ActiveScanJobStatus.CANCELLED or is_cancelled():
            logger.info(f"Active scan job {job_id_str} was cancelled during execution.")
            job.status = ActiveScanJobStatus.CANCELLED
            job.completed_at = utc_now()
            db.commit()
            return {"job_id": job_id_str, "status": "CANCELLED"}

        # 5. Persist Discovered Services
        open_count = 0
        for res in scan_results:
            if res.state == ServiceState.OPEN:
                open_count += 1
                svc = DiscoveredService(
                    organization_id=job.organization_id,
                    asset_id=job.asset_id,
                    job_id=job.id,
                    target=job.target,
                    target_ip=target_ip,
                    port=res.port,
                    protocol=res.protocol,
                    service_name=res.service_name,
                    state=res.state,
                    confidence=res.confidence,
                    banner=res.banner,
                    tls_metadata=json.dumps(res.tls_metadata) if res.tls_metadata else None,
                    http_metadata=json.dumps(res.http_metadata) if res.http_metadata else None,
                    raw_evidence=json.dumps(res.raw_evidence) if res.raw_evidence else None,
                    discovered_at=utc_now(),
                )
                db.add(svc)

        # 6. Complete Job
        job.status = ActiveScanJobStatus.COMPLETED
        job.progress_percent = 100
        job.current_stage = "COMPLETED"
        job.ports_scanned_count = len(scan_results)
        job.services_discovered_count = open_count
        job.completed_at = utc_now()

        # Audit event
        audit_ev = AuditEvent(
            organization_id=job.organization_id,
            user_id=job.initiated_by_user_id,
            action="ACTIVE_DISCOVERY_COMPLETED",
            resource_type="ACTIVE_SCAN_JOB",
            resource_id=str(job.id),
            status="SUCCESS",
            details=json.dumps({
                "job_id": str(job.id),
                "target": job.target,
                "ports_scanned": len(scan_results),
                "open_services": open_count,
            }),
        )
        db.add(audit_ev)
        db.commit()

        logger.info(
            f"Completed active scan job {job_id_str}: scanned {len(scan_results)} ports, "
            f"discovered {open_count} open services."
        )

        return {
            "job_id": job_id_str,
            "status": "COMPLETED",
            "ports_scanned": len(scan_results),
            "services_discovered": open_count,
        }

    except Exception as exc:
        logger.error(f"Active scan Celery task failed for job {job_id_str}: {exc}", exc_info=True)
        try:
            job = db.query(ActiveScanJob).filter(ActiveScanJob.id == UUID(job_id_str)).first()
            if job:
                job.status = ActiveScanJobStatus.FAILED
                job.error_message = str(exc)
                job.completed_at = utc_now()
                db.commit()
        except Exception:
            pass
        raise exc
    finally:
        db.close()

