"""
PREVENT-X Role and Role-Permission Association Models
"""

import uuid
from typing import List, TYPE_CHECKING
from sqlalchemy import String, Boolean, Table, Column, ForeignKey
from sqlalchemy.orm import Mapped, mapped_column, relationship
from backend.app.database.base import Base, utc_now
from backend.app.database.guid import GUID

if TYPE_CHECKING:
    from backend.app.models.permission import Permission
    from backend.app.models.user import OrganizationMembership


role_permissions = Table(
    "role_permissions",
    Base.metadata,
    Column(
        "role_id",
        GUID(),
        ForeignKey("roles.id", ondelete="CASCADE"),
        primary_key=True,
    ),
    Column(
        "permission_id",
        GUID(),
        ForeignKey("permissions.id", ondelete="CASCADE"),
        primary_key=True,
    ),
)


class Role(Base):
    __tablename__ = "roles"

    id: Mapped[uuid.UUID] = mapped_column(
        GUID(),
        primary_key=True,
        default=uuid.uuid4,
    )
    name: Mapped[str] = mapped_column(
        String(100),
        unique=True,
        index=True,
        nullable=False,
    )
    description: Mapped[str] = mapped_column(String(255), nullable=False)
    is_system_role: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)

    permissions: Mapped[List["Permission"]] = relationship(
        "Permission",
        secondary=role_permissions,
        back_populates="roles",
        lazy="selectin",
    )
    memberships: Mapped[List["OrganizationMembership"]] = relationship(
        "OrganizationMembership",
        back_populates="role",
    )

    def __repr__(self) -> str:
        return f"<Role {self.name}>"
