"""
PREVENT-X Vulnerability Management REST API (MOD-02)
Exposes endpoints for threat feed synchronization, vulnerability mapping,
risk prioritization, and triage tracking.
"""

import uuid
from typing import Any, Dict, List, Optional
from fastapi import APIRouter, Depends, Query, status
from sqlalchemy.orm import Session
from backend.app.database.session import get_db
from backend.app.models.organization import Organization
from backend.app.models.user import User
from backend.app.modules.vulnerability.feed_ingestion import VulnerabilityFeedIngester
from backend.app.modules.vulnerability.schemas import (
    CveRecordResponse,
    FeedSyncRequest,
    FeedSyncResponse,
    VulnerabilityOverviewResponse,
    VulnerabilityRecordResponse,
    VulnerabilityScanCreateRequest,
    VulnerabilityScanJobResponse,
    VulnerabilityStatusUpdateRequest,
)
from backend.app.modules.vulnerability.service import VulnerabilityService
from backend.app.modules.vulnerability.tasks.vulnerability_tasks import execute_vulnerability_scan_job
from backend.app.security.permissions import (
    PermissionCode,
    get_current_organization,
    get_current_user,
    require_permission,
)

router = APIRouter(prefix="/vulnerabilities", tags=["Vulnerability Management"])


@router.get(
    "/overview",
    response_model=VulnerabilityOverviewResponse,
    summary="Get tenant vulnerability summary metrics",
)
def get_vulnerability_overview(
    org: Organization = Depends(get_current_organization),
    _perm: bool = Depends(require_permission(PermissionCode.VULNERABILITY_READ)),
    db: Session = Depends(get_db),
):
    """
    Returns high-level vulnerability metrics including counts by severity,
    CISA KEV active exploitation indicators, and average contextual risk score.
    """
    return VulnerabilityService.get_overview(db, org.id)


@router.get(
    "/records",
    summary="List tenant mapped vulnerabilities",
)
def list_vulnerability_records(
    asset_id: Optional[uuid.UUID] = Query(None, description="Filter by managed asset ID"),
    severity: Optional[str] = Query(None, description="Filter by severity: CRITICAL, HIGH, MEDIUM, LOW, INFO"),
    confidence: Optional[str] = Query(None, description="Filter by match confidence"),
    status_filter: Optional[str] = Query(None, alias="status", description="Filter by triage status"),
    is_kev: Optional[bool] = Query(None, description="Filter by CISA KEV exploitation status"),
    min_risk: Optional[float] = Query(None, description="Filter by minimum contextual risk score (0-100)"),
    search: Optional[str] = Query(None, description="Search query for CVE ID, title, or asset"),
    skip: int = Query(0, ge=0),
    limit: int = Query(50, ge=1, le=200),
    org: Organization = Depends(get_current_organization),
    _perm: bool = Depends(require_permission(PermissionCode.VULNERABILITY_READ)),
    db: Session = Depends(get_db),
):
    """
    Lists mapped vulnerabilities affecting tenant infrastructure with contextual risk scores.
    """
    items, total = VulnerabilityService.list_vulnerabilities(
        db=db,
        organization_id=org.id,
        asset_id=asset_id,
        severity=severity,
        confidence=confidence,
        status=status_filter,
        is_kev=is_kev,
        min_risk=min_risk,
        search=search,
        skip=skip,
        limit=limit,
    )
    return {"items": items, "total": total, "skip": skip, "limit": limit}


@router.get(
    "/records/{record_id}",
    response_model=VulnerabilityRecordResponse,
    summary="Get detailed vulnerability record",
)
def get_vulnerability_record(
    record_id: uuid.UUID,
    org: Organization = Depends(get_current_organization),
    _perm: bool = Depends(require_permission(PermissionCode.VULNERABILITY_READ)),
    db: Session = Depends(get_db),
):
    """
    Retrieves full details for a mapped vulnerability, including observed evidence,
    CPE match telemetry, and prioritization rationale.
    """
    return VulnerabilityService.get_vulnerability(db, org.id, record_id)


@router.patch(
    "/records/{record_id}/status",
    response_model=VulnerabilityRecordResponse,
    summary="Update vulnerability triage/remediation status",
)
def update_vulnerability_status(
    record_id: uuid.UUID,
    payload: VulnerabilityStatusUpdateRequest,
    user: User = Depends(get_current_user),
    org: Organization = Depends(get_current_organization),
    _perm: bool = Depends(require_permission(PermissionCode.VULNERABILITY_WRITE)),
    db: Session = Depends(get_db),
):
    """
    Updates triage lifecycle state (e.g. IN_TRIAGE, MITIGATED, FALSE_POSITIVE) with audit logging.
    """
    vuln = VulnerabilityService.update_status(
        db=db,
        organization_id=org.id,
        record_id=record_id,
        user_id=user.id,
        new_status=payload.status,
        notes=payload.notes,
    )
    return VulnerabilityService.get_vulnerability(db, org.id, vuln.id)


@router.post(
    "/scan",
    response_model=VulnerabilityScanJobResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Trigger asynchronous vulnerability mapping scan",
)
def trigger_vulnerability_scan(
    payload: VulnerabilityScanCreateRequest,
    user: User = Depends(get_current_user),
    org: Organization = Depends(get_current_organization),
    _perm: bool = Depends(require_permission(PermissionCode.VULNERABILITY_SCAN)),
    db: Session = Depends(get_db),
):
    """
    Initiates an asynchronous mapping scan against discovered services of target asset(s).
    """
    job = VulnerabilityService.create_scan_job(
        db=db,
        organization_id=org.id,
        user_id=user.id,
        asset_id=payload.asset_id,
    )
    # Dispatch to Celery background worker
    try:
        execute_vulnerability_scan_job.delay(str(job.id))
    except Exception:
        # Fallback to direct synchronous execution if broker unavailable
        VulnerabilityService.execute_scan_for_services(db, job.id)

    db.refresh(job)
    return job


@router.get(
    "/jobs",
    response_model=List[VulnerabilityScanJobResponse],
    summary="List vulnerability scan jobs",
)
def list_vulnerability_scan_jobs(
    limit: int = Query(20, ge=1, le=100),
    org: Organization = Depends(get_current_organization),
    _perm: bool = Depends(require_permission(PermissionCode.VULNERABILITY_READ)),
    db: Session = Depends(get_db),
):
    """
    Lists recent vulnerability scan job history for the organization.
    """
    return VulnerabilityService.list_scan_jobs(db, org.id, limit=limit)


@router.get(
    "/jobs/{job_id}",
    response_model=VulnerabilityScanJobResponse,
    summary="Get vulnerability scan job status",
)
def get_vulnerability_scan_job(
    job_id: uuid.UUID,
    org: Organization = Depends(get_current_organization),
    _perm: bool = Depends(require_permission(PermissionCode.VULNERABILITY_READ)),
    db: Session = Depends(get_db),
):
    return VulnerabilityService.get_scan_job(db, org.id, job_id)


@router.post(
    "/feed-sync",
    response_model=FeedSyncResponse,
    summary="Trigger threat intelligence feed synchronization",
)
def trigger_feed_sync(
    payload: FeedSyncRequest,
    user: User = Depends(get_current_user),
    _perm: bool = Depends(require_permission(PermissionCode.VULNERABILITY_FEED_SYNC)),
    db: Session = Depends(get_db),
):
    """
    Updates CISA KEV, FIRST EPSS, and CVE threat intelligence feeds.
    """
    res = VulnerabilityFeedIngester.sync_all_feeds(db, fetch_remote=payload.fetch_remote)
    return FeedSyncResponse(
        status=res["status"],
        cisa_kev_updated=res["cisa_kev_updated"],
        epss_updated=res["epss_updated"],
        cve_total=res["cve_total"],
        synced_at=res["synced_at"],
        details=f"Processed seed catalog ({res['seed_catalog_processed']} entries).",
    )


@router.get(
    "/cve-catalog",
    summary="Search global CVE threat catalog",
)
def search_cve_catalog(
    query: Optional[str] = Query(None, description="Search term for CVE ID or description"),
    severity: Optional[str] = Query(None, description="Filter by severity: CRITICAL, HIGH, MEDIUM, LOW"),
    is_kev: Optional[bool] = Query(None, description="Filter by CISA KEV exploitation"),
    skip: int = Query(0, ge=0),
    limit: int = Query(50, ge=1, le=100),
    _perm: bool = Depends(require_permission(PermissionCode.VULNERABILITY_READ)),
    db: Session = Depends(get_db),
):
    records, total = VulnerabilityService.list_cve_catalog(
        db=db, query=query, severity=severity, is_kev=is_kev, skip=skip, limit=limit
    )
    return {
        "items": [CveRecordResponse.model_validate(r) for r in records],
        "total": total,
        "skip": skip,
        "limit": limit,
    }


@router.get(
    "/cve-catalog/{cve_id}",
    response_model=CveRecordResponse,
    summary="Get single CVE details",
)
def get_cve_detail(
    cve_id: str,
    _perm: bool = Depends(require_permission(PermissionCode.VULNERABILITY_READ)),
    db: Session = Depends(get_db),
):
    record = VulnerabilityService.get_cve_detail(db, cve_id)
    return CveRecordResponse.model_validate(record)
