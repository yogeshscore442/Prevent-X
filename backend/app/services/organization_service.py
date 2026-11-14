"""
PREVENT-X Organization Service
Manages tenant onboarding, profile updates, and audit verification.
"""

import uuid
from typing import List, Optional
from sqlalchemy.orm import Session
from backend.app.core.exceptions import ResourceNotFoundException, ValidationException
from backend.app.models.organization import Organization
from backend.app.models.user import User
from backend.app.repositories.audit_repo import audit_repo
from backend.app.repositories.organization_repo import organization_repo
from backend.app.schemas.organization import OrganizationCreate, OrganizationUpdate


class OrganizationService:
    def create_organization(
        self,
        db: Session,
        req: OrganizationCreate,
        current_user: User,
    ) -> Organization:
        existing = organization_repo.get_by_slug(db, req.slug.lower())
        if existing:
            raise ValidationException(f"Organization slug '{req.slug}' is already taken.")

        org = Organization(
            name=req.name,
            slug=req.slug.lower(),
            sector=req.sector,
            contact_email=req.contact_email.lower(),
            is_active=True,
        )
        created_org = organization_repo.create(db, org)
        db.commit()
        db.refresh(created_org)

        audit_repo.log_event(
            db=db,
            action="ORG_CREATE",
            resource_type="ORGANIZATION",
            resource_id=str(created_org.id),
            organization_id=created_org.id,
            user_id=current_user.id,
            status="SUCCESS",
            details=f"Tenant '{created_org.name}' ({created_org.slug}) created by {current_user.email}",
        )
        return created_org

    def get_organization(self, db: Session, org_id: uuid.UUID) -> Organization:
        org = organization_repo.get_by_id(db, org_id)
        if not org:
            raise ResourceNotFoundException("Organization", org_id)
        return org

    def list_organizations(
        self,
        db: Session,
        current_user: User,
        skip: int = 0,
        limit: int = 100,
    ) -> tuple[List[Organization], int]:
        """
        Lists organizations. If superuser, lists all.
        If normal user, lists only organizations where user has membership.
        """
        if current_user.is_superuser:
            items = organization_repo.get_all(db, skip=skip, limit=limit)
            total = organization_repo.count(db)
            return items, total

        org_ids = [m.organization_id for m in current_user.memberships]
        items = (
            db.query(Organization)
            .filter(Organization.id.in_(org_ids))
            .offset(skip)
            .limit(limit)
            .all()
        )
        total = len(org_ids)
        return items, total

    def update_organization(
        self,
        db: Session,
        org_id: uuid.UUID,
        req: OrganizationUpdate,
        current_user: User,
    ) -> Organization:
        org = self.get_organization(db, org_id)
        if req.name is not None:
            org.name = req.name
        if req.sector is not None:
            org.sector = req.sector
        if req.contact_email is not None:
            org.contact_email = req.contact_email.lower()
        if req.is_active is not None:
            org.is_active = req.is_active

        db.commit()
        db.refresh(org)

        audit_repo.log_event(
            db=db,
            action="ORG_UPDATE",
            resource_type="ORGANIZATION",
            resource_id=str(org.id),
            organization_id=org.id,
            user_id=current_user.id,
            status="SUCCESS",
            details=f"Organization {org.slug} updated by {current_user.email}",
        )
        return org


organization_service = OrganizationService()
