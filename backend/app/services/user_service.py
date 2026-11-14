"""
PREVENT-X User Management Service
Enforces organization boundaries for user provisioning and role assignment.
"""

import uuid
from typing import List, Optional
from sqlalchemy.orm import Session
from backend.app.core.exceptions import ResourceNotFoundException, ValidationException
from backend.app.models.organization import Organization
from backend.app.models.role import Role
from backend.app.models.user import OrganizationMembership, User
from backend.app.repositories.audit_repo import audit_repo
from backend.app.repositories.user_repo import user_repo
from backend.app.schemas.user import UserCreate, UserResponse, UserUpdate
from backend.app.security.passwords import hash_password


class UserService:
    def create_user_in_org(
        self,
        db: Session,
        org: Organization,
        req: UserCreate,
        current_user: User,
    ) -> User:
        # Check if user already exists
        existing_user = user_repo.get_by_email(db, req.email.lower())
        target_role = db.query(Role).filter(Role.name == req.role_name).first()
        if not target_role:
            raise ValidationException(f"Role '{req.role_name}' does not exist.")

        if existing_user:
            # Check if user is already a member of this organization
            existing_mem = (
                db.query(OrganizationMembership)
                .filter(
                    OrganizationMembership.user_id == existing_user.id,
                    OrganizationMembership.organization_id == org.id,
                )
                .first()
            )
            if existing_mem:
                raise ValidationException(f"User '{req.email}' is already a member of {org.name}.")

            # Add membership to this organization
            membership = OrganizationMembership(
                user_id=existing_user.id,
                organization_id=org.id,
                role_id=target_role.id,
                is_default=False,
            )
            db.add(membership)
            db.commit()
            db.refresh(existing_user)
            target_user = existing_user
        else:
            # Create new user
            hashed_pwd = hash_password(req.password)
            new_user = User(
                email=req.email.lower(),
                hashed_password=hashed_pwd,
                full_name=req.full_name,
                is_active=True,
                is_superuser=req.is_superuser if current_user.is_superuser else False,
            )
            db.add(new_user)
            db.flush()

            membership = OrganizationMembership(
                user_id=new_user.id,
                organization_id=org.id,
                role_id=target_role.id,
                is_default=True,
            )
            db.add(membership)
            db.commit()
            db.refresh(new_user)
            target_user = new_user

        audit_repo.log_event(
            db=db,
            action="USER_CREATE",
            resource_type="USER",
            resource_id=str(target_user.id),
            organization_id=org.id,
            user_id=current_user.id,
            status="SUCCESS",
            details=f"User {target_user.email} provisioned in {org.name} with role {target_role.name}",
        )
        return target_user

    def list_users_in_org(
        self,
        db: Session,
        org: Organization,
        skip: int = 0,
        limit: int = 100,
    ) -> tuple[List[UserResponse], int]:
        users = user_repo.get_users_in_organization(db, org.id, skip=skip, limit=limit)
        total = user_repo.count_users_in_organization(db, org.id)

        responses = []
        for u in users:
            mem = next((m for m in u.memberships if m.organization_id == org.id), None)
            role_name = mem.role.name if mem and mem.role else "UNKNOWN"
            responses.append(
                UserResponse(
                    id=u.id,
                    email=u.email,
                    full_name=u.full_name,
                    is_active=u.is_active,
                    is_superuser=u.is_superuser,
                    created_at=u.created_at,
                    last_login_at=u.last_login_at,
                    role_name=role_name,
                )
            )
        return responses, total


user_service = UserService()

