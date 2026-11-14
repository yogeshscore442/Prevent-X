"""
PREVENT-X Managed Asset Model
Represents authorized SMB attack surface elements scoped strictly to tenant organizations.
"""

import uuid
from typing import Optional, TYPE_CHECKING
from sqlalchemy import String, Boolean, ForeignKey
from sqlalchemy.orm import Mapped, mapped_column, relationship
from backend.app.database.base import Base, TimestampMixin
from backend.app.database.guid import GUID

if TYPE_CHECKING:
    from backend.app.models.organization import Organization
    from backend.app.models.user import User


class ManagedAsset(Base, TimestampMixin):
    __tablename__ = "managed_assets"

    id: Mapped[uuid.UUID] = mapped_column(
        GUID(),
        primary_key=True,
        default=uuid.uuid4,
    )
    organization_id: Mapped[uuid.UUID] = mapped_column(
        GUID(),
        ForeignKey("organizations.id", ondelete="CASCADE"),
        index=True,
        nullable=False,
    )
    name: Mapped[str] = mapped_column(String(255), nullable=False)
    # Asset types: WEB_APPLICATION, API_GATEWAY, PUBLIC_IP, INTERNAL_SERVER, DOMAIN
    asset_type: Mapped[str] = mapped_column(String(50), nullable=False)
    # Target value: e.g. "https://portal.smbclient.in", "api.smbclient.in", "203.0.113.15"
    target: Mapped[str] = mapped_column(String(255), nullable=False)
    # Environments: PRODUCTION, STAGING, DEVELOPMENT
    environment: Mapped[str] = mapped_column(String(50), default="PRODUCTION", nullable=False)
    # Criticalities: CRITICAL, HIGH, MEDIUM, LOW
    criticality: Mapped[str] = mapped_column(String(50), default="HIGH", nullable=False)
    # Explicit SMB authorization scope check
    is_in_scope: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)

    created_by_user_id: Mapped[Optional[uuid.UUID]] = mapped_column(
        GUID(),
        ForeignKey("users.id", ondelete="SET NULL"),
        nullable=True,
    )

    organization: Mapped["Organization"] = relationship("Organization", back_populates="assets")
    created_by: Mapped[Optional["User"]] = relationship("User", back_populates="created_assets")

    def __repr__(self) -> str:
        return f"<ManagedAsset {self.name} ({self.target}) org={self.organization_id}>"

