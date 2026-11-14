"""
PREVENT-X Background Celery Tasks
Executes asynchronous maintenance, session purges, and background jobs.
"""

from datetime import datetime, timezone
from backend.app.database.session import SessionLocal
from backend.app.models.session import UserSession
from backend.app.workers.celery_app import celery_app
from backend.app.core.logging import logger


@celery_app.task(name="preventx.tasks.purge_expired_sessions")
def purge_expired_sessions() -> int:
    """Purges expired user sessions from database."""
    db = SessionLocal()
    try:
        now = datetime.now(timezone.utc)
        expired = db.query(UserSession).filter(UserSession.expires_at < now, UserSession.is_active == True).all()
        count = len(expired)
        for s in expired:
            s.is_active = False
        db.commit()
        logger.info(f"Purged {count} expired user sessions.")
        return count
    except Exception as e:
        db.rollback()
        logger.error(f"Error purging expired sessions: {str(e)}")
        raise
    finally:
        db.close()


@celery_app.task(name="preventx.tasks.worker_health_ping")
def worker_health_ping() -> str:
    """Healthcheck ping task for Celery worker."""
    return "pong"
