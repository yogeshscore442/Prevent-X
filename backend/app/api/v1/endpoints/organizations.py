"""
PREVENT-X Organization Management Endpoints
"""

import uuid
from fastapi import APIRouter, Depends, Query, status
from sqlalchemy.orm import Session
from backend.app.database.session import get_db
from backend.app.models.organization import Organization
from backend.app.models.user import User
from backend.app.schemas.organization import (
    OrganizationCreate,
    OrganizationListResponse,
    OrganizationResponse,
    OrganizationUpdate,
)
from backend.app.security.permissions import (
    PermissionCode,
    get_current_user,
    require_permission,
    require_superuser,
)
from backend.app.services.organization_service import organization_service

router = APIRouter(prefix="/organizations", tags=["Organizations"])


@router.get(
    "",
    response_model=OrganizationListResponse,
    summary="List tenant organizations accessible to the current user",
)
def list_organizations(
    skip: int = Query(0, ge=0),
    limit: int = Query(50, ge=1, le=100),
    user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    items, total = organization_service.list_organizations(db=db, current_user=user, skip=skip, limit=limit)
    return OrganizationListResponse(items=items, total=total)


@router.post(
    "",
    response_model=OrganizationResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Create a new tenant organization (SMB)",
)
def create_organization(
    req: OrganizationCreate,
    user: User = Depends(require_superuser),
    db: Session = Depends(get_db),
):
    return organization_service.create_organization(db=db, req=req, current_user=user)


@router.get(
    "/{org_id}",
    response_model=OrganizationResponse,
    summary="Retrieve tenant organization by identifier",
)
def get_organization(
    org_id: uuid.UUID,
    user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    # If not superuser, verify membership
    if not user.is_superuser:
        if not any(m.organization_id == org_id for m in user.memberships):
            from backend.app.core.exceptions import TenantAccessDeniedException
            raise TenantAccessDeniedException("Access denied to organization")

    return organization_service.get_organization(db=db, org_id=org_id)


@router.patch(
    "/{org_id}",
    response_model=OrganizationResponse,
    summary="Update organization profile",
)
def update_organization(
    org_id: uuid.UUID,
    req: OrganizationUpdate,
    user: User = Depends(get_current_user),
    _perm: bool = Depends(require_permission(PermissionCode.ORG_WRITE)),
    db: Session = Depends(get_db),
):
    return organization_service.update_organization(db=db, org_id=org_id, req=req, current_user=user)
