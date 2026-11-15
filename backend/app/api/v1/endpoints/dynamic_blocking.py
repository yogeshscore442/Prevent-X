"""
PREVENT-X Dynamic IP Blocking REST API
Provides endpoints for creating temporary IP bans, handling analyst approvals,
manual unblocking, expiration sweep, and threat-intel recommendations.
"""

import logging
import uuid
from typing import Any, Dict, List, Optional

from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy import and_, select
from sqlalchemy.orm import Session

from backend.app.database.session import get_db
from backend.app.models.network_defense import (
    DynamicIPBlock,
    DynamicIPBlockStatus,
)
from backend.app.models.organization import Organization
from backend.app.models.user import User
from backend.app.modules.network_defense.blocking.service import (
    dynamic_blocking_service,
)
from backend.app.modules.network_defense.firewall.service import (
    FirewallSafetyException,
)
from backend.app.schemas.network_defense import (
    DynamicIPBlockCreate,
    DynamicIPBlockResponse,
    DynamicIPUnblockRequest,
)
from backend.app.security.permissions import (
    PermissionCode,
    get_current_organization,
    get_current_user,
    require_permission,
)

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/network-defense/blocking", tags=["Advanced Network Defense - Dynamic Blocking"])


@router.get(
    "/blocks",
    response_model=List[DynamicIPBlockResponse],
    dependencies=[Depends(require_permission(PermissionCode.ZERO_TRUST_READ))],
)
def list_dynamic_blocks(
    status_filter: Optional[DynamicIPBlockStatus] = Query(None, alias="status"),
    db: Session = Depends(get_db),
    org: Organization = Depends(get_current_organization),
):
    """Lists all dynamic IP bans for the authenticated tenant."""
    stmt = select(DynamicIPBlock).where(DynamicIPBlock.organization_id == org.id)
    if status_filter:
        stmt = stmt.where(DynamicIPBlock.status == status_filter)
    stmt = stmt.order_by(DynamicIPBlock.created_at.desc())
    return db.execute(stmt).scalars().all()


@router.post(
    "/blocks",
    response_model=DynamicIPBlockResponse,
    status_code=status.HTTP_201_CREATED,
    dependencies=[Depends(require_permission(PermissionCode.RESPONSE_ACTION_EXECUTE))],
)
def create_dynamic_block(
    payload: DynamicIPBlockCreate,
    db: Session = Depends(get_db),
    org: Organization = Depends(get_current_organization),
    user: User = Depends(get_current_user),
):
    """Creates a temporary IP ban with auto-expiration and optional approval requirement."""
    try:
        return dynamic_blocking_service.create_block(
            db=db,
            organization_id=org.id,
            ip_or_cidr=payload.ip_or_cidr,
            reason=payload.reason,
            duration_minutes=payload.duration_minutes,
            incident_id=payload.incident_id,
            threat_intel_score=payload.threat_intel_score,
            require_approval=payload.require_approval,
            user_id=user.id,
        )
    except FirewallSafetyException as ex:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(ex))
    except ValueError as ex:
        raise HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, detail=str(ex))


@router.get(
    "/blocks/{block_id}",
    response_model=DynamicIPBlockResponse,
    dependencies=[Depends(require_permission(PermissionCode.ZERO_TRUST_READ))],
)
def get_dynamic_block(
    block_id: str,
    db: Session = Depends(get_db),
    org: Organization = Depends(get_current_organization),
):
    """Retrieves details of a specific dynamic block."""
    block = db.execute(
        select(DynamicIPBlock).where(
            and_(DynamicIPBlock.id == block_id, DynamicIPBlock.organization_id == org.id)
        )
    ).scalar_one_or_none()
    if not block:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Dynamic block not found.")
    return block


@router.post(
    "/blocks/{block_id}/approve",
    response_model=DynamicIPBlockResponse,
    dependencies=[Depends(require_permission(PermissionCode.RESPONSE_ACTION_APPROVE))],
)
def approve_dynamic_block(
    block_id: str,
    db: Session = Depends(get_db),
    org: Organization = Depends(get_current_organization),
    user: User = Depends(get_current_user),
):
    """Approves a pending block and enforces it in the OS Firewall."""
    try:
        return dynamic_blocking_service.approve_block(
            db=db,
            block_id=block_id,
            organization_id=org.id,
            approver_id=user.id,
        )
    except ValueError as ex:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(ex))


@router.post(
    "/blocks/{block_id}/unblock",
    response_model=DynamicIPBlockResponse,
    dependencies=[Depends(require_permission(PermissionCode.RESPONSE_ACTION_EXECUTE))],
)
def unblock_dynamic_ip(
    block_id: str,
    payload: DynamicIPUnblockRequest,
    db: Session = Depends(get_db),
    org: Organization = Depends(get_current_organization),
    user: User = Depends(get_current_user),
):
    """Manually lifts a dynamic ban and removes the OS firewall rule."""
    try:
        return dynamic_blocking_service.unblock_ip(
            db=db,
            block_id=block_id,
            organization_id=org.id,
            unblock_reason=payload.reason,
            user_id=user.id,
        )
    except ValueError as ex:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(ex))


@router.post(
    "/process-expirations",
    dependencies=[Depends(require_permission(PermissionCode.SYSTEM_WRITE))],
)
def process_block_expirations(db: Session = Depends(get_db)):
    """Sweeps and removes expired dynamic IP bans from OS firewall."""
    count = dynamic_blocking_service.process_expired_blocks(db)
    return {"status": "SUCCESS", "expired_blocks_processed": count}


@router.get(
    "/recommendations",
    dependencies=[Depends(require_permission(PermissionCode.ZERO_TRUST_READ))],
)
def get_blocking_recommendations(
    db: Session = Depends(get_db),
    org: Organization = Depends(get_current_organization),
):
    """Provides threat-intel backed recommendations for temporary IP bans."""
    return dynamic_blocking_service.get_recommendations(db, org.id)
