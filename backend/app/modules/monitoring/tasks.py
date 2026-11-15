"""
Celery Background Tasks for Monitoring & Security Center.
"""

from typing import Dict, Any
from celery.utils.log import get_task_logger
from sqlalchemy.orm import Session

from backend.app.workers.celery_app import celery_app
from backend.app.database.session import SessionLocal
from backend.app.models.monitoring import SecurityEvent, EventRetentionPolicy
from backend.app.modules.monitoring.service import MonitoringService
from backend.app.modules.monitoring.correlation_engine import SecurityCorrelationEngine

logger = get_task_logger(__name__)


@celery_app.task(name="backend.app.modules.monitoring.tasks.process_security_event_job", bind=True, max_retries=3)
def process_security_event_job(self, event_id: str) -> Dict[str, Any]:
    """
    Asynchronously process an ingested security event for correlation and alerting.
    """
    logger.info("Processing security event job: %s", event_id)
    db: Session = SessionLocal()
    try:
        import uuid as _uuid
        evt_uuid = _uuid.UUID(event_id) if isinstance(event_id, str) else event_id
        event = db.query(SecurityEvent).filter(SecurityEvent.id == evt_uuid).first()
        if not event:
            logger.warning("Security event not found: %s", event_id)
            return {"status": "not_found", "event_id": event_id}

        # Run correlation engine
        incident = SecurityCorrelationEngine.evaluate_event(db, event)
        incident_id = str(incident.id) if incident else None

        db.commit()
        return {
            "status": "processed",
            "event_id": event_id,
            "incident_id": incident_id,
        }
    except Exception as exc:
        db.rollback()
        logger.error("Error processing security event %s: %s", event_id, exc)
        raise self.retry(exc=exc, countdown=5)
    finally:
        db.close()


@celery_app.task(name="backend.app.modules.monitoring.tasks.prune_retained_events_job", bind=True)
def prune_retained_events_job(self) -> Dict[str, Any]:
    """
    Scheduled job to prune expired security events according to tenant retention policies.
    """
    logger.info("Starting automated event retention pruning job")
    db: Session = SessionLocal()
    pruned_summary = {}
    try:
        policies = db.query(EventRetentionPolicy).filter(EventRetentionPolicy.auto_prune_enabled == True).all()  # noqa: E712
        for policy in policies:
            deleted_count = MonitoringService.prune_expired_events(db, policy.organization_id)
            pruned_summary[str(policy.organization_id)] = deleted_count
            logger.info("Pruned %d events for organization %s", deleted_count, policy.organization_id)

        db.commit()
        return {
            "status": "completed",
            "organizations_pruned": len(policies),
            "summary": pruned_summary,
        }
    except Exception as exc:
        db.rollback()
        logger.error("Error during event retention pruning: %s", exc)
        raise exc
    finally:
        db.close()
