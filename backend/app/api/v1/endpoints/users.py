"""
PREVENT-X User Management Endpoints
"""

from fastapi import APIRouter, Depends, Query, status
from sqlalchemy.orm import Session
from backend.app.database.session import get_db
from backend.app.models.organization import Organization
from backend.app.models.user import User
from backend.app.schemas.user import UserCreate, UserListResponse, UserResponse
from backend.app.security.permissions import (
    PermissionCode,
    get_current_organization,
    get_current_user,
    require_permission,
)
from backend.app.services.user_service import user_service

router = APIRouter(prefix="/users", tags=["Users"])


@router.get(
    "",
    response_model=UserListResponse,
    summary="List users within the current active tenant organization",
)
def list_users(
    skip: int = Query(0, ge=0),
    limit: int = Query(50, ge=1, le=100),
    org: Organization = Depends(get_current_organization),
    _perm: bool = Depends(require_permission(PermissionCode.USER_READ)),
    db: Session = Depends(get_db),
):
    items, total = user_service.list_users_in_org(db=db, org=org, skip=skip, limit=limit)
    return UserListResponse(items=items, total=total)


@router.post(
    "",
    response_model=UserResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Create or invite a user into the current tenant organization",
)
def create_user(
    req: UserCreate,
    org: Organization = Depends(get_current_organization),
    current_user: User = Depends(get_current_user),
    _perm: bool = Depends(require_permission(PermissionCode.USER_WRITE)),
    db: Session = Depends(get_db),
):
    user = user_service.create_user_in_org(db=db, org=org, req=req, current_user=current_user)
    return UserResponse(
        id=user.id,
        email=user.email,
        full_name=user.full_name,
        is_active=user.is_active,
        is_superuser=user.is_superuser,
        created_at=user.created_at,
        last_login_at=user.last_login_at,
        role_name=req.role_name,
    )

