"""
PREVENT-X Managed Asset Endpoints
Enforces strict tenant isolation for SMB digital assets.
"""

import uuid
from fastapi import APIRouter, Depends, Query, status
from sqlalchemy.orm import Session
from backend.app.database.session import get_db
from backend.app.models.organization import Organization
from backend.app.models.user import User
from backend.app.schemas.asset import (
    AssetCreate,
    AssetListResponse,
    AssetResponse,
    AssetUpdate,
)
from backend.app.security.permissions import (
    PermissionCode,
    get_current_organization,
    get_current_user,
    require_permission,
)
from backend.app.services.asset_service import asset_service

router = APIRouter(prefix="/assets", tags=["Managed Assets"])


@router.get(
    "",
    response_model=AssetListResponse,
    summary="List authorized attack surface assets for the current organization",
)
def list_assets(
    skip: int = Query(0, ge=0),
    limit: int = Query(50, ge=1, le=100),
    org: Organization = Depends(get_current_organization),
    _perm: bool = Depends(require_permission(PermissionCode.ASSET_READ)),
    db: Session = Depends(get_db),
):
    items, total = asset_service.list_assets(db=db, org=org, skip=skip, limit=limit)
    return AssetListResponse(items=items, total=total)


@router.post(
    "",
    response_model=AssetResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Register a new authorized digital asset into protection scope",
)
def create_asset(
    req: AssetCreate,
    org: Organization = Depends(get_current_organization),
    current_user: User = Depends(get_current_user),
    _perm: bool = Depends(require_permission(PermissionCode.ASSET_WRITE)),
    db: Session = Depends(get_db),
):
    return asset_service.create_asset(db=db, org=org, req=req, current_user=current_user)


@router.get(
    "/{asset_id}",
    response_model=AssetResponse,
    summary="Retrieve managed asset details by ID",
)
def get_asset(
    asset_id: uuid.UUID,
    org: Organization = Depends(get_current_organization),
    _perm: bool = Depends(require_permission(PermissionCode.ASSET_READ)),
    db: Session = Depends(get_db),
):
    return asset_service.get_asset(db=db, org=org, asset_id=asset_id)


@router.patch(
    "/{asset_id}",
    response_model=AssetResponse,
    summary="Update managed asset attributes",
)
def update_asset(
    asset_id: uuid.UUID,
    req: AssetUpdate,
    org: Organization = Depends(get_current_organization),
    current_user: User = Depends(get_current_user),
    _perm: bool = Depends(require_permission(PermissionCode.ASSET_WRITE)),
    db: Session = Depends(get_db),
):
    return asset_service.update_asset(db=db, org=org, asset_id=asset_id, req=req, current_user=current_user)


@router.delete(
    "/{asset_id}",
    status_code=status.HTTP_204_NO_CONTENT,
    summary="Remove asset from protection inventory",
)
def delete_asset(
    asset_id: uuid.UUID,
    org: Organization = Depends(get_current_organization),
    current_user: User = Depends(get_current_user),
    _perm: bool = Depends(require_permission(PermissionCode.ASSET_DELETE)),
    db: Session = Depends(get_db),
):
    asset_service.delete_asset(db=db, org=org, asset_id=asset_id, current_user=current_user)
    return None

