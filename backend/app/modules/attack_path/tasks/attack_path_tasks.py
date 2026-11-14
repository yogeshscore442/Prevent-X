"""
PREVENT-X Attack Path Analysis Celery Tasks (MOD-03)
Executes asynchronous graph analysis, multi-hop pathfinding, and prevention synthesis.
"""

import logging
from typing import Any, Dict
from uuid import UUID
from backend.app.database.session import SessionLocal
from backend.app.models.attack_path import AttackPathAnalysisJob
from backend.app.modules.attack_path.service import AttackPathService
from backend.app.workers.celery_app import celery_app

logger = logging.getLogger("preventx.tasks.attack_path")


@celery_app.task(name="preventx.tasks.execute_attack_path_analysis_job", bind=True, max_retries=0)
def execute_attack_path_analysis_job(self, job_id_str: str) -> Dict[str, Any]:
    """
    Celery task that computes evidence-backed attack paths and ranked compensating controls.
    """
    logger.info(f"Starting Celery background attack path analysis for job {job_id_str}")
    db = SessionLocal()
    try:
        job_uuid = UUID(job_id_str)
        job = db.query(AttackPathAnalysisJob).filter(AttackPathAnalysisJob.id == job_uuid).first()
        if not job:
            logger.error(f"Attack path analysis job {job_id_str} not found.")
            return {"job_id": job_id_str, "status": "FAILED", "error": "Job not found"}

        # Execute graph analysis and recommendation engine
        completed_job = AttackPathService.execute_job(db, job_uuid)
        logger.info(
            f"Attack path analysis job {job_id_str} completed with status {completed_job.status}: "
            f"paths={completed_job.paths_discovered_count}, recommendations={completed_job.recommendations_count}"
        )
        return {
            "job_id": job_id_str,
            "status": completed_job.status,
            "paths_discovered": completed_job.paths_discovered_count,
            "recommendations_created": completed_job.recommendations_count,
        }
    except Exception as exc:
        logger.exception(f"Unexpected error in execute_attack_path_analysis_job {job_id_str}: {exc}")
        if "job" in locals() and job:
            job.status = "FAILED"
            job.error_message = str(exc)
            db.commit()
        return {"job_id": job_id_str, "status": "FAILED", "error": str(exc)}
    finally:
        db.close()

