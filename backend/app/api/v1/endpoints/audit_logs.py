"""
PREVENT-X Audit Log Query Endpoints
"""

from fastapi import APIRouter, Depends, Query
from sqlalchemy.orm import Session
from backend.app.database.session import get_db
from backend.app.models.organization import Organization
from backend.app.models.user import User
from backend.app.repositories.audit_repo import audit_repo
from backend.app.schemas.audit_log import AuditLogListResponse
from backend.app.security.permissions import (
    PermissionCode,
    get_current_organization,
    get_current_user,
    require_permission,
)

router = APIRouter(prefix="/audit-logs", tags=["Audit Trail"])


@router.get(
    "",
    response_model=AuditLogListResponse,
    summary="Retrieve immutable audit log events scoped to tenant",
)
def get_audit_logs(
    skip: int = Query(0, ge=0),
    limit: int = Query(50, ge=1, le=100),
    org: Organization = Depends(get_current_organization),
    user: User = Depends(get_current_user),
    _perm: bool = Depends(require_permission(PermissionCode.AUDIT_READ)),
    db: Session = Depends(get_db),
):
    target_org_id = None if user.is_superuser else org.id
    items = audit_repo.get_logs_for_organization(db=db, organization_id=target_org_id, skip=skip, limit=limit)
    total = audit_repo.count_logs_for_organization(db=db, organization_id=target_org_id)
    return AuditLogListResponse(items=items, total=total)

