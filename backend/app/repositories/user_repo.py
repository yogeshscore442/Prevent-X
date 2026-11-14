"""
PREVENT-X User Repository
"""

import uuid
from typing import Optional, List
from sqlalchemy.orm import Session
from backend.app.models.user import User, OrganizationMembership
from backend.app.repositories.base import BaseRepository


class UserRepository(BaseRepository[User]):
    def __init__(self):
        super().__init__(User)

    def get_by_email(self, db: Session, email: str) -> Optional[User]:
        return db.query(User).filter(User.email == email.lower()).first()

    def get_users_in_organization(
        self,
        db: Session,
        organization_id: uuid.UUID,
        skip: int = 0,
        limit: int = 100,
    ) -> List[User]:
        return (
            db.query(User)
            .join(OrganizationMembership, OrganizationMembership.user_id == User.id)
            .filter(OrganizationMembership.organization_id == organization_id)
            .offset(skip)
            .limit(limit)
            .all()
        )

    def count_users_in_organization(
        self,
        db: Session,
        organization_id: uuid.UUID,
    ) -> int:
        return (
            db.query(User)
            .join(OrganizationMembership, OrganizationMembership.user_id == User.id)
            .filter(OrganizationMembership.organization_id == organization_id)
            .count()
        )


user_repo = UserRepository()
