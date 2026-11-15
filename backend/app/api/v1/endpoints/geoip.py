"""
PREVENT-X GeoIP Policies REST API
Provides endpoints for managing geographic access policies,
CIDR exception overrides, and evaluating IP location risk signals.
"""

import logging
import uuid
from typing import List

from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy.orm import Session

from backend.app.database.session import get_db
from backend.app.models.organization import Organization
from backend.app.models.user import User
from backend.app.modules.network_defense.geoip.service import (
    GEOIP_DB_VERSION,
    geoip_service,
)
from backend.app.schemas.network_defense import (
    GeoIPLookupRequest,
    GeoIPLookupResponse,
    GeoIPPolicyCreate,
    GeoIPPolicyResponse,
)
from backend.app.security.permissions import (
    PermissionCode,
    get_current_organization,
    get_current_user,
    require_permission,
)

logger = logging.getLogger(__name__)

router = APIRouter(
    prefix="/network-defense/geoip",
    tags=["Advanced Network Defense - GeoIP Policies"],
)


@router.get(
    "/policies",
    response_model=List[GeoIPPolicyResponse],
    dependencies=[Depends(require_permission(PermissionCode.ZERO_TRUST_READ))],
)
def list_geoip_policies(
    db: Session = Depends(get_db),
    org: Organization = Depends(get_current_organization),
):
    """Lists all GeoIP country policies for the authenticated organization."""
    return geoip_service.list_policies(db, org.id)


@router.post(
    "/policies",
    response_model=GeoIPPolicyResponse,
    dependencies=[Depends(require_permission(PermissionCode.ZERO_TRUST_WRITE))],
)
def create_geoip_policy(
    payload: GeoIPPolicyCreate,
    db: Session = Depends(get_db),
    org: Organization = Depends(get_current_organization),
):
    """Creates or updates a country-level access policy."""
    return geoip_service.create_policy(db, org.id, payload)


@router.get(
    "/policies/{policy_id}",
    response_model=GeoIPPolicyResponse,
    dependencies=[Depends(require_permission(PermissionCode.ZERO_TRUST_READ))],
)
def get_geoip_policy(
    policy_id: str,
    db: Session = Depends(get_db),
    org: Organization = Depends(get_current_organization),
):
    """Retrieves a specific GeoIP policy by ID."""
    policy = geoip_service.get_policy(db, policy_id, org.id)
    if not policy:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"GeoIP policy '{policy_id}' not found.",
        )
    return policy


@router.delete(
    "/policies/{policy_id}",
    dependencies=[Depends(require_permission(PermissionCode.ZERO_TRUST_WRITE))],
)
def delete_geoip_policy(
    policy_id: str,
    db: Session = Depends(get_db),
    org: Organization = Depends(get_current_organization),
):
    """Deletes a GeoIP policy."""
    success = geoip_service.delete_policy(db, policy_id, org.id)
    if not success:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"GeoIP policy '{policy_id}' not found.",
        )
    return {"message": f"GeoIP policy '{policy_id}' deleted successfully."}


@router.post(
    "/evaluate",
    response_model=GeoIPLookupResponse,
    dependencies=[Depends(require_permission(PermissionCode.ZERO_TRUST_READ))],
)
def evaluate_ip_address(
    req: GeoIPLookupRequest,
    db: Session = Depends(get_db),
    org: Organization = Depends(get_current_organization),
):
    """
    Evaluates an IP address against active tenant GeoIP policies,
    accounting for CIDR exceptions and returning an advisory risk modifier.
    """
    return geoip_service.evaluate_ip(db, org.id, req.ip_address)


@router.get(
    "/lookup/{ip_address}",
    response_model=GeoIPLookupResponse,
    dependencies=[Depends(require_permission(PermissionCode.ZERO_TRUST_READ))],
)
def lookup_ip_address(
    ip_address: str,
    db: Session = Depends(get_db),
    org: Organization = Depends(get_current_organization),
):
    """Resolves IP address location and evaluates tenant policy."""
    return geoip_service.evaluate_ip(db, org.id, ip_address)
