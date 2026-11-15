"""
PREVENT-X Honeypot Detection REST API
Provides endpoints for monitoring decoy traps, simulating probes,
inspecting attacker telemetry, and configuring decoy tripwires.
"""

import logging
import uuid
from typing import Any, Dict, List, Optional

from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy.orm import Session

from backend.app.database.session import get_db
from backend.app.models.organization import Organization
from backend.app.models.user import User
from backend.app.modules.network_defense.honeypot.service import honeypot_service
from backend.app.schemas.network_defense import (
    HoneypotProbeRecordResponse,
    HoneypotProbeRequest,
    HoneypotProbeResponse,
    HoneypotStatsResponse,
    HoneypotTrapCreate,
)
from backend.app.security.permissions import (
    PermissionCode,
    get_current_organization,
    get_current_user,
    require_permission,
)

logger = logging.getLogger(__name__)

router = APIRouter(
    prefix="/network-defense/honeypot",
    tags=["Advanced Network Defense - Honeypot Detection"],
)


@router.post(
    "/simulate",
    response_model=HoneypotProbeResponse,
    dependencies=[Depends(require_permission(PermissionCode.ZERO_TRUST_WRITE))],
)
def simulate_probe(
    req: HoneypotProbeRequest,
    db: Session = Depends(get_db),
    org: Organization = Depends(get_current_organization),
):
    """
    Evaluates a simulated or live HTTP probe against honeypot decoy paths.
    If a trap is tripped, logs the probe, creates an incident, and recommends a dynamic IP block.
    """
    is_hit, probe = honeypot_service.inspect_and_record_probe(
        db=db,
        organization_id=org.id,
        path=req.path,
        source_ip=req.source_ip,
        method=req.method,
        query_string=req.query_string,
        user_agent=req.user_agent,
        payload_preview=req.payload_preview,
        auto_recommend_block=req.auto_recommend_block,
    )

    if is_hit and probe:
        return HoneypotProbeResponse(
            is_honeypot=True,
            trap_path=probe.trap_path,
            source_ip=probe.source_ip,
            probe_id=probe.id,
            incident_id=probe.correlated_incident_id,
            recommended_block_id=probe.recommended_block_id,
            message=f"Honeypot trap '{probe.trap_path}' triggered! Incident generated.",
        )
    else:
        return HoneypotProbeResponse(
            is_honeypot=False,
            source_ip=req.source_ip,
            message="Clean path. No honeypot decoy was triggered.",
        )


@router.get(
    "/probes",
    response_model=List[HoneypotProbeRecordResponse],
    dependencies=[Depends(require_permission(PermissionCode.ZERO_TRUST_READ))],
)
def list_probes(
    source_ip: Optional[str] = Query(None),
    limit: int = Query(50, ge=1, le=200),
    db: Session = Depends(get_db),
    org: Organization = Depends(get_current_organization),
):
    """Lists captured reconnaissance probes for the organization."""
    return honeypot_service.list_probes(
        db=db,
        organization_id=org.id,
        source_ip=source_ip,
        limit=limit,
    )


@router.get(
    "/probes/{probe_id}",
    response_model=HoneypotProbeRecordResponse,
    dependencies=[Depends(require_permission(PermissionCode.ZERO_TRUST_READ))],
)
def get_probe_details(
    probe_id: str,
    db: Session = Depends(get_db),
    org: Organization = Depends(get_current_organization),
):
    """Retrieves full telemetry for a single honeypot probe."""
    probe = honeypot_service.get_probe(db, probe_id, org.id)
    if not probe:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Honeypot probe '{probe_id}' not found.",
        )
    return probe


@router.get(
    "/traps",
    response_model=List[str],
    dependencies=[Depends(require_permission(PermissionCode.ZERO_TRUST_READ))],
)
def list_traps(
    org: Organization = Depends(get_current_organization),
):
    """Lists all active decoy trap paths monitored for this tenant."""
    return honeypot_service.get_all_traps(org.id)


@router.post(
    "/traps",
    dependencies=[Depends(require_permission(PermissionCode.ZERO_TRUST_WRITE))],
)
def add_custom_trap(
    req: HoneypotTrapCreate,
    org: Organization = Depends(get_current_organization),
):
    """Adds a custom decoy trap path to monitor for reconnaissance probes."""
    honeypot_service.add_custom_trap(org.id, req.path)
    return {"message": f"Decoy trap '{req.path}' registered successfully."}


@router.get(
    "/stats",
    response_model=HoneypotStatsResponse,
    dependencies=[Depends(require_permission(PermissionCode.ZERO_TRUST_READ))],
)
def get_honeypot_statistics(
    db: Session = Depends(get_db),
    org: Organization = Depends(get_current_organization),
):
    """Returns aggregated honeypot statistics including total probes and top attacked traps."""
    return honeypot_service.get_statistics(db, org.id)
