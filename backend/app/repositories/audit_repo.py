"""
PREVENT-X Audit Log Repository
"""

import uuid
from typing import List, Optional
from sqlalchemy.orm import Session
from backend.app.models.audit_log import AuditEvent
from backend.app.repositories.base import BaseRepository


class AuditRepository(BaseRepository[AuditEvent]):
    def __init__(self):
        super().__init__(AuditEvent)

    def log_event(
        self,
        db: Session,
        action: str,
        resource_type: str,
        status: str,
        organization_id: Optional[uuid.UUID] = None,
        user_id: Optional[uuid.UUID] = None,
        resource_id: Optional[str] = None,
        ip_address: Optional[str] = None,
        user_agent: Optional[str] = None,
        details: Optional[str] = None,
    ) -> AuditEvent:
        event = AuditEvent(
            organization_id=organization_id,
            user_id=user_id,
            action=action,
            resource_type=resource_type,
            resource_id=resource_id,
            ip_address=ip_address,
            user_agent=user_agent,
            status=status,
            details=details,
        )
        db.add(event)
        db.commit()
        db.refresh(event)
        return event

    def get_logs_for_organization(
        self,
        db: Session,
        organization_id: Optional[uuid.UUID],
        skip: int = 0,
        limit: int = 100,
    ) -> List[AuditEvent]:
        query = db.query(AuditEvent)
        if organization_id:
            query = query.filter(AuditEvent.organization_id == organization_id)
        return query.order_by(AuditEvent.created_at.desc()).offset(skip).limit(limit).all()

    def count_logs_for_organization(
        self,
        db: Session,
        organization_id: Optional[uuid.UUID],
    ) -> int:
        query = db.query(AuditEvent)
        if organization_id:
            query = query.filter(AuditEvent.organization_id == organization_id)
        return query.count()


audit_repo = AuditRepository()
