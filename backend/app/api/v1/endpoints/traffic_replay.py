"""
PREVENT-X Traffic Replay REST API
Provides endpoints for executing differential traffic replay validation,
detecting false positive regressions, and inspecting sanitization & replay fixtures.
"""

import json
import logging
import uuid
from typing import Any, Dict, List, Optional

from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy import select
from sqlalchemy.orm import Session

from backend.app.database.session import get_db
from backend.app.models.network_defense import TrafficReplayReport
from backend.app.models.organization import Organization
from backend.app.models.user import User
from backend.app.models.virtual_patch import VirtualPatchRule
from backend.app.modules.network_defense.replay.engine import (
    STANDARD_BENIGN_FIXTURES,
    STANDARD_EXPLOIT_FIXTURES,
    traffic_replay_engine,
)
from backend.app.schemas.network_defense import (
    TrafficReplayExecuteRequest,
    TrafficReplayReportResponse,
)
from backend.app.security.permissions import (
    PermissionCode,
    get_current_organization,
    get_current_user,
    require_permission,
)

logger = logging.getLogger(__name__)

router = APIRouter(
    prefix="/network-defense/replay",
    tags=["Advanced Network Defense - Traffic Replay"],
)


@router.get(
    "/fixtures",
    dependencies=[Depends(require_permission(PermissionCode.VALIDATION_READ))],
)
def get_sample_fixtures() -> Dict[str, Any]:
    """
    Returns standard benchmark fixtures (benign SMB requests and exploit payloads)
    used for automated differential regression testing.
    """
    return {
        "standard_benign_count": len(STANDARD_BENIGN_FIXTURES),
        "standard_exploit_count": len(STANDARD_EXPLOIT_FIXTURES),
        "benign_samples": STANDARD_BENIGN_FIXTURES[:5],
        "exploit_samples": STANDARD_EXPLOIT_FIXTURES[:3],
    }


@router.post(
    "/run",
    response_model=TrafficReplayReportResponse,
    dependencies=[Depends(require_permission(PermissionCode.VALIDATION_RUN))],
)
def run_traffic_replay(
    payload: TrafficReplayExecuteRequest,
    db: Session = Depends(get_db),
    org: Organization = Depends(get_current_organization),
    user: User = Depends(get_current_user),
):
    """
    Executes differential replay testing for a virtual patch rule against sanitized fixtures.
    Computes false-positive rate and missed-exploit metrics.
    """
    rule = None
    if payload.virtual_patch_id:
        rule = db.execute(
            select(VirtualPatchRule).where(
                VirtualPatchRule.id == payload.virtual_patch_id,
                VirtualPatchRule.organization_id == org.id,
            )
        ).scalar_one_or_none()
        if not rule:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=f"Virtual patch rule '{payload.virtual_patch_id}' not found for organization.",
            )
    else:
        # Find latest available patch rule for tenant
        rule = db.execute(
            select(VirtualPatchRule)
            .where(VirtualPatchRule.organization_id == org.id)
            .order_by(VirtualPatchRule.created_at.desc())
        ).scalars().first()

        if not rule:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="No virtual patch rules exist for this tenant. Create a virtual patch rule first.",
            )

    report = traffic_replay_engine.run_replay_validation(
        db=db,
        organization_id=org.id,
        rule=rule,
        custom_fixtures=payload.custom_fixtures,
        max_fixtures=payload.max_fixtures or 50,
    )

    return report


@router.get(
    "/reports",
    response_model=List[TrafficReplayReportResponse],
    dependencies=[Depends(require_permission(PermissionCode.VALIDATION_READ))],
)
def list_replay_reports(
    virtual_patch_id: Optional[uuid.UUID] = Query(None),
    limit: int = Query(50, ge=1, le=200),
    db: Session = Depends(get_db),
    org: Organization = Depends(get_current_organization),
):
    """Lists traffic replay validation reports for the current organization."""
    query = select(TrafficReplayReport).where(
        TrafficReplayReport.organization_id == org.id
    )
    if virtual_patch_id:
        query = query.where(TrafficReplayReport.virtual_patch_id == virtual_patch_id)

    query = query.order_by(TrafficReplayReport.created_at.desc()).limit(limit)
    return db.execute(query).scalars().all()


@router.get(
    "/reports/{report_id}",
    response_model=TrafficReplayReportResponse,
    dependencies=[Depends(require_permission(PermissionCode.VALIDATION_READ))],
)
def get_replay_report(
    report_id: str,
    db: Session = Depends(get_db),
    org: Organization = Depends(get_current_organization),
):
    """Retrieves a specific traffic replay report."""
    report = db.execute(
        select(TrafficReplayReport).where(
            TrafficReplayReport.id == report_id,
            TrafficReplayReport.organization_id == org.id,
        )
    ).scalar_one_or_none()

    if not report:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Replay report '{report_id}' not found.",
        )
    return report
