"""
PREVENT-X Organization Repository
"""

from typing import Optional
from sqlalchemy.orm import Session
from backend.app.models.organization import Organization
from backend.app.repositories.base import BaseRepository


class OrganizationRepository(BaseRepository[Organization]):
    def __init__(self):
        super().__init__(Organization)

    def get_by_slug(self, db: Session, slug: str) -> Optional[Organization]:
        return db.query(Organization).filter(Organization.slug == slug).first()

    def get_by_contact_email(self, db: Session, email: str) -> Optional[Organization]:
        return db.query(Organization).filter(Organization.contact_email == email).first()


organization_repo = OrganizationRepository()
