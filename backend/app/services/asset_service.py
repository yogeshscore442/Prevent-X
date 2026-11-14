"""
PREVENT-X Managed Asset Service
Enforces tenant isolation for all asset lifecycle events.
"""

import uuid
from typing import List, Optional
from sqlalchemy.orm import Session
from backend.app.core.exceptions import ResourceNotFoundException
from backend.app.models.asset import ManagedAsset
from backend.app.models.organization import Organization
from backend.app.models.user import User
from backend.app.repositories.asset_repo import asset_repo
from backend.app.repositories.audit_repo import audit_repo
from backend.app.schemas.asset import AssetCreate, AssetUpdate


class AssetService:
    def create_asset(
        self,
        db: Session,
        org: Organization,
        req: AssetCreate,
        current_user: User,
    ) -> ManagedAsset:
        asset = ManagedAsset(
            organization_id=org.id,
            name=req.name,
            asset_type=req.asset_type,
            target=req.target,
            environment=req.environment,
            criticality=req.criticality,
            is_in_scope=req.is_in_scope,
            created_by_user_id=current_user.id,
        )
        created = asset_repo.create(db, asset)
        db.commit()
        db.refresh(created)

        audit_repo.log_event(
            db=db,
            action="ASSET_CREATE",
            resource_type="ASSET",
            resource_id=str(created.id),
            organization_id=org.id,
            user_id=current_user.id,
            status="SUCCESS",
            details=f"Asset '{created.name}' ({created.target}) created for {org.name}",
        )
        return created

    def get_asset(
        self,
        db: Session,
        org: Organization,
        asset_id: uuid.UUID,
    ) -> ManagedAsset:
        asset = asset_repo.get_by_id_scoped(db, asset_id, organization_id=org.id)
        if not asset:
            raise ResourceNotFoundException("Asset", asset_id)
        return asset

    def list_assets(
        self,
        db: Session,
        org: Organization,
        skip: int = 0,
        limit: int = 100,
    ) -> tuple[List[ManagedAsset], int]:
        items = asset_repo.get_all_scoped(db, organization_id=org.id, skip=skip, limit=limit)
        total = asset_repo.count_scoped(db, organization_id=org.id)
        return items, total

    def update_asset(
        self,
        db: Session,
        org: Organization,
        asset_id: uuid.UUID,
        req: AssetUpdate,
        current_user: User,
    ) -> ManagedAsset:
        asset = self.get_asset(db, org, asset_id)
        if req.name is not None:
            asset.name = req.name
        if req.criticality is not None:
            asset.criticality = req.criticality
        if req.environment is not None:
            asset.environment = req.environment
        if req.is_in_scope is not None:
            asset.is_in_scope = req.is_in_scope

        db.commit()
        db.refresh(asset)

        audit_repo.log_event(
            db=db,
            action="ASSET_UPDATE",
            resource_type="ASSET",
            resource_id=str(asset.id),
            organization_id=org.id,
            user_id=current_user.id,
            status="SUCCESS",
            details=f"Asset '{asset.name}' updated by {current_user.email}",
        )
        return asset

    def delete_asset(
        self,
        db: Session,
        org: Organization,
        asset_id: uuid.UUID,
        current_user: User,
    ) -> None:
        asset = self.get_asset(db, org, asset_id)
        asset_repo.delete(db, asset)
        db.commit()

        audit_repo.log_event(
            db=db,
            action="ASSET_DELETE",
            resource_type="ASSET",
            resource_id=str(asset_id),
            organization_id=org.id,
            user_id=current_user.id,
            status="SUCCESS",
            details=f"Asset '{asset.name}' removed from protection scope by {current_user.email}",
        )


asset_service = AssetService()
