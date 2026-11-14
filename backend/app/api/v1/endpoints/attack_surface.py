"""
PREVENT-X Attack Surface Intelligence Endpoints
Exposes passive discovery execution, domain inventory, DNS telemetry, and exposure findings.
"""

from typing import List, Optional
from uuid import UUID
from fastapi import APIRouter, Depends, Query, status
from sqlalchemy.orm import Session

from backend.app.database.session import get_db
from backend.app.models.organization import Organization
from backend.app.models.user import User
from backend.app.security.permissions import (
    PermissionCode,
    get_current_organization,
    get_current_user,
    require_permission,
)
from backend.app.modules.attack_surface.service import AttackSurfaceService
from backend.app.modules.attack_surface.schemas import (
    DiscoveryJobCreate,
    DiscoveryJobCancel,
    DiscoveryJobResponse,
    DiscoveredDomainResponse,
    DiscoveredDomainDetailResponse,
    ExposureFindingResponse,
    AttackSurfaceOverviewResponse,
    ActiveScanCreateRequest,
    ActiveScanCancelRequest,
    ActiveScanJobResponse,
    DiscoveredServiceResponse,
)

router = APIRouter(prefix="/attack-surface", tags=["Attack Surface Intelligence"])


@router.post(
    "/discovery",
    response_model=DiscoveryJobResponse,
    status_code=status.HTTP_202_ACCEPTED,
    summary="Initiate authorized passive attack surface discovery",
)
def initiate_discovery(
    req: DiscoveryJobCreate,
    org: Organization = Depends(get_current_organization),
    current_user: User = Depends(get_current_user),
    _perm: bool = Depends(require_permission(PermissionCode.DISCOVERY_CREATE)),
    db: Session = Depends(get_db),
):
    """
    Initiates an asynchronous passive discovery job against an authorized managed asset.
    Mandatory scope validation and SSRF defenses are strictly enforced.
    """
    return AttackSurfaceService.create_discovery_job(
        db=db,
        organization_id=org.id,
        user_id=current_user.id,
        asset_id=req.asset_id,
        target_domain=req.target_domain,
        authorization_confirmed=req.authorization_confirmed,
        discovery_policy=req.discovery_policy,
    )


@router.get(
    "/jobs",
    response_model=List[DiscoveryJobResponse],
    summary="List discovery jobs for current organization",
)
def list_jobs(
    asset_id: Optional[UUID] = Query(None, description="Filter by asset ID"),
    limit: int = Query(50, ge=1, le=100),
    offset: int = Query(0, ge=0),
    org: Organization = Depends(get_current_organization),
    _perm: bool = Depends(require_permission(PermissionCode.DISCOVERY_READ)),
    db: Session = Depends(get_db),
):
    return AttackSurfaceService.list_jobs(
        db=db,
        organization_id=org.id,
        asset_id=asset_id,
        limit=limit,
        offset=offset,
    )


@router.get(
    "/jobs/{job_id}",
    response_model=DiscoveryJobResponse,
    summary="Get status and details of a specific discovery job",
)
def get_job_status(
    job_id: UUID,
    org: Organization = Depends(get_current_organization),
    _perm: bool = Depends(require_permission(PermissionCode.DISCOVERY_READ)),
    db: Session = Depends(get_db),
):
    return AttackSurfaceService.get_job(db=db, organization_id=org.id, job_id=job_id)


@router.post(
    "/jobs/{job_id}/cancel",
    response_model=DiscoveryJobResponse,
    summary="Cancel an active or queued discovery job",
)
def cancel_job(
    job_id: UUID,
    req: Optional[DiscoveryJobCancel] = None,
    org: Organization = Depends(get_current_organization),
    current_user: User = Depends(get_current_user),
    _perm: bool = Depends(require_permission(PermissionCode.DISCOVERY_CANCEL)),
    db: Session = Depends(get_db),
):
    reason = req.reason if req else None
    return AttackSurfaceService.cancel_discovery_job(
        db=db,
        organization_id=org.id,
        user_id=current_user.id,
        job_id=job_id,
        reason=reason,
    )


@router.get(
    "/domains",
    response_model=List[DiscoveredDomainResponse],
    summary="List discovered external domains and subdomains",
)
def list_domains(
    asset_id: Optional[UUID] = Query(None),
    job_id: Optional[UUID] = Query(None),
    search: Optional[str] = Query(None),
    limit: int = Query(50, ge=1, le=100),
    offset: int = Query(0, ge=0),
    org: Organization = Depends(get_current_organization),
    _perm: bool = Depends(require_permission(PermissionCode.DISCOVERY_READ)),
    db: Session = Depends(get_db),
):
    return AttackSurfaceService.list_domains(
        db=db,
        organization_id=org.id,
        asset_id=asset_id,
        job_id=job_id,
        search=search,
        limit=limit,
        offset=offset,
    )


@router.get(
    "/domains/{domain_id}",
    response_model=DiscoveredDomainDetailResponse,
    summary="Get detailed view of a domain including DNS, certificates, and RDAP",
)
def get_domain_detail(
    domain_id: UUID,
    org: Organization = Depends(get_current_organization),
    _perm: bool = Depends(require_permission(PermissionCode.DISCOVERY_READ)),
    db: Session = Depends(get_db),
):
    return AttackSurfaceService.get_domain_detail(
        db=db,
        organization_id=org.id,
        domain_id=domain_id,
    )


@router.get(
    "/findings",
    response_model=List[ExposureFindingResponse],
    summary="List exposure findings across attack surface",
)
def list_findings(
    asset_id: Optional[UUID] = Query(None),
    job_id: Optional[UUID] = Query(None),
    severity: Optional[str] = Query(None),
    category: Optional[str] = Query(None),
    limit: int = Query(50, ge=1, le=100),
    offset: int = Query(0, ge=0),
    org: Organization = Depends(get_current_organization),
    _perm: bool = Depends(require_permission(PermissionCode.DISCOVERY_READ)),
    db: Session = Depends(get_db),
):
    return AttackSurfaceService.list_findings(
        db=db,
        organization_id=org.id,
        asset_id=asset_id,
        job_id=job_id,
        severity=severity,
        category=category,
        limit=limit,
        offset=offset,
    )


@router.get(
    "/overview",
    response_model=AttackSurfaceOverviewResponse,
    summary="Get attack surface metrics and exposure risk summary",
)
def get_overview(
    org: Organization = Depends(get_current_organization),
    _perm: bool = Depends(require_permission(PermissionCode.DISCOVERY_READ)),
    db: Session = Depends(get_db),
):
    return AttackSurfaceService.get_overview(db=db, organization_id=org.id)


@router.get(
    "/assets/{asset_id}/history",
    response_model=List[DiscoveryJobResponse],
    summary="Get discovery run history for a managed asset",
)
def get_asset_history(
    asset_id: UUID,
    org: Organization = Depends(get_current_organization),
    _perm: bool = Depends(require_permission(PermissionCode.DISCOVERY_READ)),
    db: Session = Depends(get_db),
):
    return AttackSurfaceService.list_jobs(
        db=db,
        organization_id=org.id,
        asset_id=asset_id,
        limit=50,
        offset=0,
    )


# ==========================================
# Controlled Active Service Discovery Endpoints
# ==========================================

@router.post(
    "/active-scans",
    response_model=ActiveScanJobResponse,
    status_code=status.HTTP_202_ACCEPTED,
    summary="Initiate authorized active service discovery scan",
)
def initiate_active_scan(
    req: ActiveScanCreateRequest,
    org: Organization = Depends(get_current_organization),
    current_user: User = Depends(get_current_user),
    _perm: bool = Depends(require_permission(PermissionCode.DISCOVERY_ACTIVE)),
    db: Session = Depends(get_db),
):
    """
    Initiates a controlled active service discovery scan against an authorized managed asset.
    Strictly restricted port profiles, concurrency limits, connect timeouts, and non-destructive
    protocol handshakes are enforced. Requires explicit authorization confirmation and
    discovery:active permission.
    """
    return AttackSurfaceService.create_active_scan(
        db=db,
        organization_id=org.id,
        user_id=current_user.id,
        asset_id=req.asset_id,
        scan_profile=req.scan_profile,
        custom_ports=req.custom_ports,
        authorization_confirmed=req.authorization_confirmed,
    )


@router.get(
    "/active-scans",
    response_model=List[ActiveScanJobResponse],
    summary="List active scan jobs for current organization",
)
def list_active_scans(
    asset_id: Optional[UUID] = Query(None, description="Filter by asset ID"),
    skip: int = Query(0, ge=0),
    limit: int = Query(50, ge=1, le=100),
    org: Organization = Depends(get_current_organization),
    _perm: bool = Depends(require_permission(PermissionCode.DISCOVERY_READ)),
    db: Session = Depends(get_db),
):
    jobs, _ = AttackSurfaceService.list_active_scans(
        db=db,
        organization_id=org.id,
        asset_id=asset_id,
        skip=skip,
        limit=limit,
    )
    return jobs


@router.get(
    "/active-scans/{job_id}",
    response_model=ActiveScanJobResponse,
    summary="Get status and details of a specific active scan job",
)
def get_active_scan(
    job_id: UUID,
    org: Organization = Depends(get_current_organization),
    _perm: bool = Depends(require_permission(PermissionCode.DISCOVERY_READ)),
    db: Session = Depends(get_db),
):
    return AttackSurfaceService.get_active_scan(
        db=db,
        organization_id=org.id,
        job_id=job_id,
    )


@router.post(
    "/active-scans/{job_id}/cancel",
    response_model=ActiveScanJobResponse,
    summary="Cancel an active scan job in progress",
)
def cancel_active_scan(
    job_id: UUID,
    req: Optional[ActiveScanCancelRequest] = None,
    org: Organization = Depends(get_current_organization),
    current_user: User = Depends(get_current_user),
    _perm: bool = Depends(require_permission(PermissionCode.DISCOVERY_CANCEL)),
    db: Session = Depends(get_db),
):
    reason = req.reason if req else None
    return AttackSurfaceService.cancel_active_scan(
        db=db,
        organization_id=org.id,
        job_id=job_id,
        user_id=current_user.id,
        reason=reason,
    )


@router.get(
    "/active-scans/{job_id}/services",
    response_model=List[DiscoveredServiceResponse],
    summary="List discovered services for a specific active scan job",
)
def list_scan_services(
    job_id: UUID,
    skip: int = Query(0, ge=0),
    limit: int = Query(100, ge=1, le=200),
    org: Organization = Depends(get_current_organization),
    _perm: bool = Depends(require_permission(PermissionCode.DISCOVERY_READ)),
    db: Session = Depends(get_db),
):
    # Verify scan belongs to organization
    AttackSurfaceService.get_active_scan(db=db, organization_id=org.id, job_id=job_id)
    services, _ = AttackSurfaceService.list_discovered_services(
        db=db,
        organization_id=org.id,
        job_id=job_id,
        skip=skip,
        limit=limit,
    )
    return services


@router.get(
    "/services",
    response_model=List[DiscoveredServiceResponse],
    summary="List discovered network services across tenant assets",
)
def list_all_services(
    asset_id: Optional[UUID] = Query(None, description="Filter by asset ID"),
    port: Optional[int] = Query(None, ge=1, le=65535, description="Filter by port"),
    service_name: Optional[str] = Query(None, description="Filter by service name"),
    state: Optional[str] = Query(None, description="Filter by state (e.g. OPEN)"),
    skip: int = Query(0, ge=0),
    limit: int = Query(100, ge=1, le=200),
    org: Organization = Depends(get_current_organization),
    _perm: bool = Depends(require_permission(PermissionCode.DISCOVERY_READ)),
    db: Session = Depends(get_db),
):
    services, _ = AttackSurfaceService.list_discovered_services(
        db=db,
        organization_id=org.id,
        asset_id=asset_id,
        port=port,
        service_name=service_name,
        state=state,
        skip=skip,
        limit=limit,
    )
    return services


