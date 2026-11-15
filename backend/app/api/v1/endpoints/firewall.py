"""
PREVENT-X Windows Defender Firewall REST API
Provides endpoints for creating, verifying, rolling back, and auditing OS firewall rules.
Strictly enforces tenant isolation and RBAC permissions.
"""

import logging
import uuid
from datetime import datetime, timedelta, timezone
from typing import List, Optional

from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy import and_, select
from sqlalchemy.orm import Session

from backend.app.database.session import get_db
from backend.app.models.network_defense import (
    FirewallEnforcementStatus,
    FirewallRule,
)
from backend.app.models.organization import Organization
from backend.app.models.user import User
from backend.app.modules.network_defense.firewall.service import (
    FirewallSafetyException,
    windows_firewall_service,
)
from backend.app.schemas.network_defense import (
    FirewallRuleCreate,
    FirewallRuleResponse,
    FirewallStatusResponse,
)
from backend.app.security.permissions import (
    PermissionCode,
    get_current_organization,
    get_current_user,
    require_permission,
)

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/network-defense/firewall", tags=["Advanced Network Defense - Firewall"])


@router.get(
    "/status",
    response_model=FirewallStatusResponse,
    dependencies=[Depends(require_permission(PermissionCode.ZERO_TRUST_READ))],
)
def get_firewall_status(
    db: Session = Depends(get_db),
    org: Organization = Depends(get_current_organization),
):
    """
    Returns the real-time operational status of the OS Firewall subsystem and active rule counts.
    """
    rules = db.execute(
        select(FirewallRule).where(
            and_(
                FirewallRule.organization_id == org.id,
                FirewallRule.is_active == True,
            )
        )
    ).scalars().all()

    verified_count = sum(1 for r in rules if r.verified_active)
    failed_count = sum(1 for r in rules if r.enforcement_status == FirewallEnforcementStatus.FAILED)
    managed_os = windows_firewall_service.executor.list_preventx_rules()

    return FirewallStatusResponse(
        os_type=windows_firewall_service.executor.os_type,
        is_elevated=windows_firewall_service.executor.is_elevated_admin(),
        active_rules_count=len(rules),
        verified_rules_count=verified_count,
        failed_rules_count=failed_count,
        managed_os_rules=managed_os,
    )


@router.get(
    "/rules",
    response_model=List[FirewallRuleResponse],
    dependencies=[Depends(require_permission(PermissionCode.ZERO_TRUST_READ))],
)
def list_firewall_rules(
    status_filter: Optional[FirewallEnforcementStatus] = Query(None, alias="status"),
    db: Session = Depends(get_db),
    org: Organization = Depends(get_current_organization),
):
    """
    Lists all firewall rules configured for the authenticated organization.
    """
    stmt = select(FirewallRule).where(FirewallRule.organization_id == org.id)
    if status_filter:
        stmt = stmt.where(FirewallRule.enforcement_status == status_filter)
    stmt = stmt.order_by(FirewallRule.created_at.desc())
    rules = db.execute(stmt).scalars().all()
    return rules


@router.post(
    "/rules",
    response_model=FirewallRuleResponse,
    status_code=status.HTTP_201_CREATED,
    dependencies=[Depends(require_permission(PermissionCode.RESPONSE_ACTION_EXECUTE))],
)
def create_firewall_rule(
    payload: FirewallRuleCreate,
    db: Session = Depends(get_db),
    org: Organization = Depends(get_current_organization),
    user: User = Depends(get_current_user),
):
    """
    Creates and enforces an OS Firewall rule.
    Returns the rule with verified_active indicating authentic OS confirmation.
    """
    expires_at = None
    if payload.expires_in_minutes:
        expires_at = datetime.now(timezone.utc) + timedelta(minutes=payload.expires_in_minutes)

    try:
        rule = windows_firewall_service.create_firewall_rule(
            db=db,
            organization_id=org.id,
            remote_ip_or_cidr=payload.remote_ip_or_cidr,
            display_name=payload.display_name,
            direction=payload.direction,
            action=payload.action,
            protocol=payload.protocol,
            local_ports=payload.local_ports,
            description=payload.description,
            expires_at=expires_at,
            user_id=user.id,
        )
        return rule
    except FirewallSafetyException as ex:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(ex),
        )
    except ValueError as ex:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail=str(ex),
        )


@router.get(
    "/rules/{rule_id}",
    response_model=FirewallRuleResponse,
    dependencies=[Depends(require_permission(PermissionCode.ZERO_TRUST_READ))],
)
def get_firewall_rule(
    rule_id: str,
    db: Session = Depends(get_db),
    org: Organization = Depends(get_current_organization),
):
    """
    Retrieves details for a single firewall rule.
    """
    rule = db.execute(
        select(FirewallRule).where(
            and_(FirewallRule.id == rule_id, FirewallRule.organization_id == org.id)
        )
    ).scalar_one_or_none()
    if not rule:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Firewall rule not found.")
    return rule


@router.post(
    "/rules/{rule_id}/verify",
    response_model=FirewallRuleResponse,
    dependencies=[Depends(require_permission(PermissionCode.ZERO_TRUST_READ))],
)
def verify_firewall_rule(
    rule_id: str,
    db: Session = Depends(get_db),
    org: Organization = Depends(get_current_organization),
):
    """
    Performs live verification of the rule against the Windows Filtering Platform table.
    """
    try:
        return windows_firewall_service.verify_rule(db, rule_id, org.id)
    except ValueError as ex:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(ex))


@router.post(
    "/rules/{rule_id}/rollback",
    response_model=FirewallRuleResponse,
    dependencies=[Depends(require_permission(PermissionCode.ROLLBACK_EXECUTE))],
)
def rollback_firewall_rule(
    rule_id: str,
    db: Session = Depends(get_db),
    org: Organization = Depends(get_current_organization),
    user: User = Depends(get_current_user),
):
    """
    Rolls back / deletes the firewall rule from Windows Defender Firewall.
    """
    try:
        return windows_firewall_service.rollback_rule(db, rule_id, org.id, user.id)
    except ValueError as ex:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(ex))


@router.delete(
    "/rules/{rule_id}",
    response_model=FirewallRuleResponse,
    dependencies=[Depends(require_permission(PermissionCode.RESPONSE_ACTION_EXECUTE))],
)
def delete_firewall_rule(
    rule_id: str,
    db: Session = Depends(get_db),
    org: Organization = Depends(get_current_organization),
    user: User = Depends(get_current_user),
):
    """
    Deactivates and removes a firewall rule.
    """
    try:
        return windows_firewall_service.remove_rule(db, rule_id, org.id, user.id)
    except ValueError as ex:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(ex))
