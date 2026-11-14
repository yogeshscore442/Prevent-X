"""
PREVENT-X Audit Event Model
Provides tamper-resistant, structured logging of security and tenant actions.
"""

import uuid
from datetime import datetime
from typing import Optional
from sqlalchemy import String, Text, DateTime, ForeignKey
from sqlalchemy.orm import Mapped, mapped_column
from backend.app.database.base import Base, utc_now
from backend.app.database.guid import GUID


class AuditEvent(Base):
    __tablename__ = "audit_events"

    id: Mapped[uuid.UUID] = mapped_column(
        GUID(),
        primary_key=True,
        default=uuid.uuid4,
    )
    organization_id: Mapped[Optional[uuid.UUID]] = mapped_column(
        GUID(),
        ForeignKey("organizations.id", ondelete="SET NULL"),
        index=True,
        nullable=True,
    )
    user_id: Mapped[Optional[uuid.UUID]] = mapped_column(
        GUID(),
        ForeignKey("users.id", ondelete="SET NULL"),
        index=True,
        nullable=True,
    )
    # Action type: AUTH_LOGIN, AUTH_LOGOUT, AUTH_LOGIN_FAILED, ADMIN_BOOTSTRAP,
    # ORG_CREATE, USER_CREATE, ASSET_CREATE, ASSET_DELETE, TENANT_ACCESS_DENIED, etc.
    action: Mapped[str] = mapped_column(String(100), index=True, nullable=False)
    # Resource type: USER, ORGANIZATION, ASSET, SESSION, SYSTEM, SECURITY_CONTROL
    resource_type: Mapped[str] = mapped_column(String(50), nullable=False)
    resource_id: Mapped[Optional[str]] = mapped_column(String(100), nullable=True)
    ip_address: Mapped[Optional[str]] = mapped_column(String(45), nullable=True)
    user_agent: Mapped[Optional[str]] = mapped_column(String(500), nullable=True)
    # Status: SUCCESS, FAILURE, DENIED
    status: Mapped[str] = mapped_column(String(50), nullable=False)
    # JSON payload details
    details: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=utc_now,
        index=True,
        nullable=False,
    )

    def __repr__(self) -> str:
        return f"<AuditEvent action={self.action} status={self.status} org={self.organization_id} time={self.created_at}>"
