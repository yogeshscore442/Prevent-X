"""
PREVENT-X Role and Permission Inspection Endpoints
"""

from typing import List
from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session
from backend.app.database.session import get_db
from backend.app.models.permission import Permission
from backend.app.models.role import Role
from backend.app.schemas.role import PermissionResponse, RoleResponse
from backend.app.security.permissions import (
    PermissionCode,
    get_current_user,
    require_permission,
)

router = APIRouter(prefix="/roles", tags=["Roles & Permissions"])


@router.get(
    "",
    response_model=List[RoleResponse],
    summary="List all RBAC roles and assigned permissions",
)
def list_roles(
    _user=Depends(get_current_user),
    _perm: bool = Depends(require_permission(PermissionCode.ROLE_READ)),
    db: Session = Depends(get_db),
):
    roles = db.query(Role).all()
    return roles


@router.get(
    "/permissions",
    response_model=List[PermissionResponse],
    summary="List all granular security permissions",
)
def list_permissions(
    _user=Depends(get_current_user),
    _perm: bool = Depends(require_permission(PermissionCode.ROLE_READ)),
    db: Session = Depends(get_db),
):
    perms = db.query(Permission).order_by(Permission.module.asc(), Permission.code.asc()).all()
    return perms

