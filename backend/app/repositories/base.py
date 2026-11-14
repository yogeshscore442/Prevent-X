"""
PREVENT-X Base Repository Pattern
Provides standardized CRUD operations and tenant query scoping.
"""

import uuid
from typing import Generic, TypeVar, Type, Optional, List
from sqlalchemy.orm import Session
from backend.app.database.base import Base

ModelType = TypeVar("ModelType", bound=Base)


class BaseRepository(Generic[ModelType]):
    def __init__(self, model: Type[ModelType]):
        self.model = model

    def get_by_id(self, db: Session, id: uuid.UUID) -> Optional[ModelType]:
        return db.query(self.model).filter(self.model.id == id).first()

    def get_all(self, db: Session, skip: int = 0, limit: int = 100) -> List[ModelType]:
        return db.query(self.model).offset(skip).limit(limit).all()

    def count(self, db: Session) -> int:
        return db.query(self.model).count()

    def create(self, db: Session, obj: ModelType) -> ModelType:
        db.add(obj)
        db.flush()
        return obj

    def delete(self, db: Session, obj: ModelType) -> None:
        db.delete(obj)
        db.flush()


class TenantScopedRepository(BaseRepository[ModelType]):
    """
    Guarantees strict tenant isolation by scoping every query to organization_id.
    """
    def get_by_id_scoped(
        self,
        db: Session,
        id: uuid.UUID,
        organization_id: uuid.UUID,
    ) -> Optional[ModelType]:
        return (
            db.query(self.model)
            .filter(
                self.model.id == id,
                self.model.organization_id == organization_id,
            )
            .first()
        )

    def get_all_scoped(
        self,
        db: Session,
        organization_id: uuid.UUID,
        skip: int = 0,
        limit: int = 100,
    ) -> List[ModelType]:
        return (
            db.query(self.model)
            .filter(self.model.organization_id == organization_id)
            .offset(skip)
            .limit(limit)
            .all()
        )

    def count_scoped(self, db: Session, organization_id: uuid.UUID) -> int:
        return (
            db.query(self.model)
            .filter(self.model.organization_id == organization_id)
            .count()
        )
