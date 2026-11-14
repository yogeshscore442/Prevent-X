"""
PREVENT-X Attack Surface Celery Tasks
Executes asynchronous passive intelligence gathering through the worker pool.
"""

import logging
from uuid import UUID
from backend.app.workers.celery_app import celery_app
from backend.app.database.session import SessionLocal
from backend.app.modules.attack_surface.discovery_manager import DiscoveryManager

logger = logging.getLogger("preventx.tasks.discovery")


@celery_app.task(name="preventx.tasks.execute_discovery_job", bind=True, max_retries=1)
def execute_discovery_job(self, job_id_str: str) -> dict:
    """
    Celery task that executes an authorized passive discovery job.
    """
    logger.info(f"Starting Celery background execution for discovery job {job_id_str}")
    db = SessionLocal()
    try:
        job_uuid = UUID(job_id_str)
        manager = DiscoveryManager()
        job = manager.run_discovery(db, job_uuid)
        logger.info(
            f"Completed Celery discovery job {job_id_str} with status={job.status}, "
            f"domains={job.domains_discovered_count}, findings={job.findings_count}"
        )
        return {
            "job_id": job_id_str,
            "status": job.status,
            "domains_discovered": job.domains_discovered_count,
            "findings_count": job.findings_count,
            "exposure_score": job.initial_exposure_score,
        }
    except Exception as exc:
        logger.error(f"Celery task failed for discovery job {job_id_str}: {exc}", exc_info=True)
        raise exc
    finally:
        db.close()

