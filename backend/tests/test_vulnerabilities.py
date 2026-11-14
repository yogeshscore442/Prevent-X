"""
PREVENT-X Phase 3 Advanced Vulnerability Mapping Engine Tests
Verifies CVE ingestion, deduplication, CPE and version matching, ambiguous version handling,
risk calculation (0-100 scale), KEV/EPSS weighting, multi-tenant isolation, and RBAC controls.
"""

import json
import uuid
from datetime import datetime, timezone
import pytest
from fastapi.testclient import TestClient
from sqlalchemy.orm import Session

from backend.app.models.asset import ManagedAsset
from backend.app.models.attack_surface import (
    ActiveScanJob,
    ActiveScanJobStatus,
    DiscoveredService,
    ScanProfile,
    ServiceConfidence,
    ServiceState,
)
from backend.app.models.audit_log import AuditEvent
from backend.app.models.vulnerability import (
    CveRecord,
    VulnerabilityConfidence,
    VulnerabilityRecord,
    VulnerabilityScanJob,
    VulnerabilityScanStatus,
    VulnerabilitySeverity,
    VulnerabilityStatus,
)
from backend.app.modules.vulnerability.cpe_matcher import CpeMatcher, IdentifiedSoftware, parse_version_tuple
from backend.app.modules.vulnerability.feed_ingestion import VulnerabilityFeedIngester
from backend.app.modules.vulnerability.risk_engine import VulnerabilityRiskEngine
from backend.app.modules.vulnerability.service import VulnerabilityService


def _login_user(client: TestClient, email: str, password: str = "AlphaAdminPass123!") -> str:
    resp = client.post("/api/v1/auth/login", json={"email": email, "password": password})
    assert resp.status_code == 200
    return resp.json()["tokens"]["access_token"]


# ==============================================================================
# 1. CVE INGESTION & DEDUPLICATION TESTS
# ==============================================================================

def test_cve_seed_ingestion_and_deduplication(db_session: Session):
    """
    Verifies that the seed catalog populates authentic CVE records
    and subsequent sync operations strictly deduplicate without duplicating rows.
    """
    count_1 = VulnerabilityFeedIngester.seed_initial_catalog(db_session)
    assert count_1 > 0

    total_1 = db_session.query(CveRecord).count()
    assert total_1 >= count_1

    # Check key CVE presence
    log4j = db_session.query(CveRecord).filter(CveRecord.cve_id == "CVE-2021-44228").first()
    assert log4j is not None
    assert log4j.cvss_score == 10.0
    assert log4j.is_known_exploited is True
    assert log4j.epss_score is not None

    apache = db_session.query(CveRecord).filter(CveRecord.cve_id == "CVE-2021-41773").first()
    assert apache is not None
    assert apache.cvss_score == 7.5
    assert apache.is_known_exploited is True

    # Re-run seed: strict deduplication must keep row count identical
    count_2 = VulnerabilityFeedIngester.seed_initial_catalog(db_session)
    total_2 = db_session.query(CveRecord).count()
    assert total_2 == total_1


def test_parse_version_tuple_comparisons():
    """Verifies that version comparison handles semver, OpenSSH, and vendor formats."""
    assert parse_version_tuple("2.4.49") == (2, 4, 49, 0)
    assert parse_version_tuple("8.5p1") == (8, 5, 1, 0)
    assert parse_version_tuple("2.4.49") < parse_version_tuple("2.4.50")
    assert parse_version_tuple("8.5p1") < parse_version_tuple("9.7p1")
    assert parse_version_tuple("1.20.0") <= parse_version_tuple("1.20.0")
    assert parse_version_tuple("2.4.58") > parse_version_tuple("2.4.50")


# ==============================================================================
# 2. INTELLIGENT CPE & VERSION MATCHING TESTS
# ==============================================================================

def test_cpe_matcher_confirmed_match(db_session: Session, test_tenants):
    """
    When an identified banner contains product and exact version inside the vulnerable range,
    matching confidence must be CONFIRMED_MATCH.
    """
    VulnerabilityFeedIngester.seed_initial_catalog(db_session)
    cve = db_session.query(CveRecord).filter(CveRecord.cve_id == "CVE-2021-41773").first()

    dummy_job_id = uuid.uuid4()
    service = DiscoveredService(
        organization_id=test_tenants["org_a"].id,
        asset_id=test_tenants["org_a"].id,
        job_id=dummy_job_id,
        target="web.alphacorp.in",
        target_ip="203.0.113.10",
        port=80,
        protocol="tcp",
        service_name="http",
        state=ServiceState.OPEN,
        confidence=ServiceConfidence.CONFIRMED_OBSERVATION,
        http_metadata=json.dumps({"server": "Apache/2.4.49 (Unix)"}),
    )

    software = CpeMatcher.identify_service_software(service)
    assert software is not None
    assert software.vendor == "apache"
    assert software.product == "http_server"
    assert software.version == "2.4.49"
    assert software.is_version_ambiguous is False

    match = CpeMatcher.match_service_against_cve(software, cve, service)
    assert match.confidence == VulnerabilityConfidence.CONFIRMED_MATCH
    assert "2.4.49" in match.evidence_notes


def test_cpe_matcher_not_affected_version(db_session: Session, test_tenants):
    """
    When a patched or later version outside the vulnerable range is detected,
    confidence must be NOT_AFFECTED.
    """
    VulnerabilityFeedIngester.seed_initial_catalog(db_session)
    cve = db_session.query(CveRecord).filter(CveRecord.cve_id == "CVE-2021-41773").first()

    dummy_job_id = uuid.uuid4()
    service = DiscoveredService(
        organization_id=test_tenants["org_a"].id,
        asset_id=test_tenants["org_a"].id,
        job_id=dummy_job_id,
        target="web.alphacorp.in",
        target_ip="203.0.113.10",
        port=80,
        protocol="tcp",
        service_name="http",
        state=ServiceState.OPEN,
        confidence=ServiceConfidence.CONFIRMED_OBSERVATION,
        http_metadata=json.dumps({"server": "Apache/2.4.58 (Unix)"}),
    )

    software = CpeMatcher.identify_service_software(service)
    assert software.version == "2.4.58"

    match = CpeMatcher.match_service_against_cve(software, cve, service)
    assert match.confidence == VulnerabilityConfidence.NOT_AFFECTED
    assert "outside the vulnerable range" in match.evidence_notes


def test_cpe_matcher_ambiguous_version_reduces_confidence(db_session: Session, test_tenants):
    """
    CRITICAL: Missing or ambiguous version information MUST reduce confidence to POTENTIAL_MATCH.
    """
    VulnerabilityFeedIngester.seed_initial_catalog(db_session)
    cve = db_session.query(CveRecord).filter(CveRecord.cve_id == "CVE-2021-41773").first()

    dummy_job_id = uuid.uuid4()
    service = DiscoveredService(
        organization_id=test_tenants["org_a"].id,
        asset_id=test_tenants["org_a"].id,
        job_id=dummy_job_id,
        target="web.alphacorp.in",
        target_ip="203.0.113.10",
        port=80,
        protocol="tcp",
        service_name="http",
        state=ServiceState.OPEN,
        confidence=ServiceConfidence.CONFIRMED_OBSERVATION,
        http_metadata=json.dumps({"server": "Apache"}),  # Version obscured/missing
    )

    software = CpeMatcher.identify_service_software(service)
    assert software is not None
    assert software.is_version_ambiguous is True
    assert software.version is None

    match = CpeMatcher.match_service_against_cve(software, cve, service)
    assert match.confidence == VulnerabilityConfidence.POTENTIAL_MATCH
    assert "Reduced to POTENTIAL_MATCH" in match.evidence_notes


def test_generic_banner_port_alone_never_confirmed(db_session: Session, test_tenants):
    """
    CRITICAL: An open port or generic banner alone must NEVER produce a confirmed vulnerability.
    """
    VulnerabilityFeedIngester.seed_initial_catalog(db_session)
    cve = db_session.query(CveRecord).filter(CveRecord.cve_id == "CVE-2021-44228").first()

    dummy_job_id = uuid.uuid4()
    service = DiscoveredService(
        organization_id=test_tenants["org_a"].id,
        asset_id=test_tenants["org_a"].id,
        job_id=dummy_job_id,
        target="web.alphacorp.in",
        target_ip="203.0.113.10",
        port=443,
        protocol="tcp",
        service_name="https",
        state=ServiceState.OPEN,
        confidence=ServiceConfidence.INFERRED_SERVICE,
        banner="HTTP/1.1 200 OK\r\nContent-Type: text/html",
    )

    software = CpeMatcher.identify_service_software(service)
    match = CpeMatcher.match_service_against_cve(software, cve, service)

    assert match.confidence == VulnerabilityConfidence.INSUFFICIENT_EVIDENCE
    assert match.confidence != VulnerabilityConfidence.CONFIRMED_MATCH
    assert "alone does not establish" in match.evidence_notes


# ==============================================================================
# 3. CONTEXTUAL RISK PRIORITIZATION ENGINE TESTS
# ==============================================================================

def test_vulnerability_risk_engine_bounds_and_kev_boost(db_session: Session, test_tenants):
    """
    Verifies that the risk score strictly adheres to 0-100 bounds
    and CISA KEV exploitation adds significant prioritization weight.
    """
    VulnerabilityFeedIngester.seed_initial_catalog(db_session)
    cve_kev = db_session.query(CveRecord).filter(CveRecord.cve_id == "CVE-2021-44228").first()

    dummy_job_id = uuid.uuid4()
    service = DiscoveredService(
        organization_id=test_tenants["org_a"].id,
        asset_id=test_tenants["org_a"].id,
        job_id=dummy_job_id,
        target="web.alphacorp.in",
        target_ip="203.0.113.10",
        port=443,
        protocol="tcp",
        service_name="https",
        state=ServiceState.OPEN,
        confidence=ServiceConfidence.CONFIRMED_OBSERVATION,
    )

    score, severity, explanation, remediation = VulnerabilityRiskEngine.calculate_risk(
        cve=cve_kev,
        service=service,
        confidence=VulnerabilityConfidence.CONFIRMED_MATCH,
        is_internet_facing=True,
    )

    assert 0.0 <= score <= 100.0
    assert score >= 90.0
    assert severity == VulnerabilitySeverity.CRITICAL
    assert "CISA KEV" in explanation
    assert "Actively exploited" in explanation


def test_confidence_discount_on_risk_score(db_session: Session, test_tenants):
    """
    Ambiguous version (POTENTIAL_MATCH) must receive a ~50% confidence discount
    compared to a CONFIRMED_MATCH for the exact same vulnerability.
    """
    VulnerabilityFeedIngester.seed_initial_catalog(db_session)
    cve = db_session.query(CveRecord).filter(CveRecord.cve_id == "CVE-2021-41773").first()

    dummy_job_id = uuid.uuid4()
    service = DiscoveredService(
        organization_id=test_tenants["org_a"].id,
        asset_id=test_tenants["org_a"].id,
        job_id=dummy_job_id,
        target="web.alphacorp.in",
        target_ip="203.0.113.10",
        port=80,
        protocol="tcp",
        service_name="http",
        state=ServiceState.OPEN,
        confidence=ServiceConfidence.CONFIRMED_OBSERVATION,
    )

    score_confirmed, sev_confirmed, _, _ = VulnerabilityRiskEngine.calculate_risk(
        cve=cve,
        service=service,
        confidence=VulnerabilityConfidence.CONFIRMED_MATCH,
        is_internet_facing=True,
    )

    score_potential, sev_potential, _, _ = VulnerabilityRiskEngine.calculate_risk(
        cve=cve,
        service=service,
        confidence=VulnerabilityConfidence.POTENTIAL_MATCH,
        is_internet_facing=True,
    )

    assert score_confirmed > score_potential
    assert abs(score_potential - (score_confirmed * 0.5)) <= 1.0


# ==============================================================================
# 4. END-TO-END VULNERABILITY SCAN & LIFECYCLE TESTS
# ==============================================================================

def test_vulnerability_scan_job_lifecycle(client: TestClient, db_session: Session, test_tenants):
    """
    Executes a complete vulnerability mapping flow:
    1. Onboards asset and discovered service.
    2. Submits vulnerability scan.
    3. Verifies scan job completion and mapped findings.
    """
    org_a = test_tenants["org_a"]
    token = _login_user(client, "admin@alphacorp.in", "AlphaAdminPass123!")
    headers = {"Authorization": f"Bearer {token}"}

    # Onboard test asset
    asset = ManagedAsset(
        organization_id=org_a.id,
        name="Web Application Server",
        asset_type="WEB_APPLICATION",
        target="web.alphacorp.in",
        criticality="HIGH",
        environment="PRODUCTION",
        is_in_scope=True,
    )
    db_session.add(asset)
    db_session.flush()

    # Create dummy active scan job for foreign key
    active_job = ActiveScanJob(
        organization_id=org_a.id,
        asset_id=asset.id,
        target=asset.target,
        target_ip="203.0.113.10",
        scan_profile=ScanProfile.BASIC,
        selected_ports="[80, 443]",
        authorized_scope=asset.target,
        initiated_by_user_id=test_tenants["admin_a"].id,
        authorization_confirmed=True,
        authorized_at=datetime.now(timezone.utc),
        status=ActiveScanJobStatus.COMPLETED,
    )
    db_session.add(active_job)
    db_session.flush()

    # Add discovered service running vulnerable Apache 2.4.49
    service = DiscoveredService(
        organization_id=org_a.id,
        asset_id=asset.id,
        job_id=active_job.id,
        target=asset.target,
        target_ip="203.0.113.10",
        port=80,
        protocol="tcp",
        service_name="http",
        state=ServiceState.OPEN,
        confidence=ServiceConfidence.CONFIRMED_OBSERVATION,
        http_metadata=json.dumps({"server": "Apache/2.4.49 (Unix)"}),
    )
    db_session.add(service)
    db_session.commit()

    # Trigger scan via API
    resp = client.post(
        "/api/v1/vulnerabilities/scan",
        headers=headers,
        json={"asset_id": str(asset.id)},
    )
    assert resp.status_code == 201
    job_data = resp.json()
    assert job_data["status"] in ["PENDING", "COMPLETED"]

    # If pending, execute synchronously for test verification
    if job_data["status"] == "PENDING":
        VulnerabilityService.execute_scan_for_services(db_session, uuid.UUID(job_data["id"]))

    # Verify findings via API
    resp_vulns = client.get("/api/v1/vulnerabilities/records", headers=headers)
    assert resp_vulns.status_code == 200
    data = resp_vulns.json()
    assert data["total"] >= 1

    found_cves = [item["cve_id"] for item in data["items"]]
    assert "CVE-2021-41773" in found_cves

    record = next(item for item in data["items"] if item["cve_id"] == "CVE-2021-41773")
    assert record["confidence"] == "CONFIRMED_MATCH"
    assert record["risk_score"] >= 70.0
    assert record["status"] == "DETECTED"
    assert record["asset_name"] == "Web Application Server"


def test_tenant_isolation_vulnerability_records(client: TestClient, db_session: Session, test_tenants):
    """
    Multi-tenant isolation: Tenant B must NEVER see Tenant A's vulnerability records or overview.
    """
    org_a = test_tenants["org_a"]
    org_b = test_tenants["org_b"]

    token_b = _login_user(client, "admin@betaind.in", "BetaAdminPass123!")

    # Create asset and vulnerability for Tenant A
    asset_a = ManagedAsset(
        organization_id=org_a.id,
        name="Finance Portal",
        asset_type="WEB_APPLICATION",
        target="finance.alphacorp.in",
        criticality="CRITICAL",
        is_in_scope=True,
    )
    db_session.add(asset_a)
    db_session.flush()

    vuln_a = VulnerabilityRecord(
        organization_id=org_a.id,
        asset_id=asset_a.id,
        cve_id="CVE-2021-44228",
        title="CVE-2021-44228 in log4j",
        description="Log4Shell RCE",
        severity="CRITICAL",
        confidence="CONFIRMED_MATCH",
        risk_score=99.4,
        status="DETECTED",
    )
    db_session.add(vuln_a)
    db_session.commit()

    # Tenant B queries records
    resp_b = client.get(
        "/api/v1/vulnerabilities/records",
        headers={"Authorization": f"Bearer {token_b}"},
    )
    assert resp_b.status_code == 200
    assert resp_b.json()["total"] == 0

    # Tenant B attempts to fetch Tenant A's record directly
    resp_direct = client.get(
        f"/api/v1/vulnerabilities/records/{vuln_a.id}",
        headers={"Authorization": f"Bearer {token_b}"},
    )
    assert resp_direct.status_code == 404


def test_vulnerability_status_update_and_audit_log(client: TestClient, db_session: Session, test_tenants):
    """
    Updating vulnerability status updates the record and writes an immutable audit log.
    """
    org_a = test_tenants["org_a"]
    token = _login_user(client, "admin@alphacorp.in", "AlphaAdminPass123!")
    headers = {"Authorization": f"Bearer {token}"}

    asset = ManagedAsset(
        organization_id=org_a.id,
        name="Portal",
        asset_type="DOMAIN",
        target="portal.alphacorp.in",
        is_in_scope=True,
    )
    db_session.add(asset)
    db_session.flush()

    vuln = VulnerabilityRecord(
        organization_id=org_a.id,
        asset_id=asset.id,
        cve_id="CVE-2024-6387",
        title="regreSSHion in OpenSSH",
        description="Signal race condition RCE",
        severity="HIGH",
        confidence="CONFIRMED_MATCH",
        risk_score=81.0,
        status="DETECTED",
    )
    db_session.add(vuln)
    db_session.commit()

    # Update status to IN_TRIAGE
    patch_resp = client.patch(
        f"/api/v1/vulnerabilities/records/{vuln.id}/status",
        headers=headers,
        json={"status": "IN_TRIAGE", "notes": "Under analyst investigation"},
    )
    assert patch_resp.status_code == 200
    assert patch_resp.json()["status"] == "IN_TRIAGE"

    # Verify audit event recorded
    audit = db_session.query(AuditEvent).filter(
        AuditEvent.organization_id == org_a.id,
        AuditEvent.action == "VULNERABILITY_STATUS_UPDATED",
    ).first()
    assert audit is not None
    assert audit.status == "SUCCESS"
    assert "IN_TRIAGE" in audit.details


def test_cve_catalog_search(client: TestClient, db_session: Session, test_tenants):
    """Verifies global CVE catalog search by query and KEV status."""
    VulnerabilityFeedIngester.seed_initial_catalog(db_session)
    token = _login_user(client, "admin@alphacorp.in", "AlphaAdminPass123!")
    headers = {"Authorization": f"Bearer {token}"}

    resp = client.get("/api/v1/vulnerabilities/cve-catalog?query=log4j&is_kev=true", headers=headers)
    assert resp.status_code == 200
    data = resp.json()
    assert data["total"] >= 1
    assert any(c["cve_id"] == "CVE-2021-44228" for c in data["items"])


def test_feed_sync_api_and_graceful_offline_fallback(client: TestClient, db_session: Session, test_tenants):
    """
    Threat feed sync API runs safely and falls back cleanly without crashing.
    """
    token = _login_user(client, "admin@alphacorp.in", "AlphaAdminPass123!")
    headers = {"Authorization": f"Bearer {token}"}

    resp = client.post(
        "/api/v1/vulnerabilities/feed-sync",
        headers=headers,
        json={"fetch_remote": False},
    )
    assert resp.status_code == 200
    data = resp.json()
    assert data["status"] == "SUCCESS"
    assert data["cve_total"] >= 10


def test_rbac_viewer_denied_scan_and_feed_sync(client: TestClient, db_session: Session, test_tenants):
    """
    RBAC enforcement: VIEWER role cannot initiate scans or feed syncs, but can view overview.
    """
    token = _login_user(client, "viewer@betaind.in", "BetaViewerPass123!")
    headers = {"Authorization": f"Bearer {token}"}

    # Overview read is allowed
    resp_overview = client.get("/api/v1/vulnerabilities/overview", headers=headers)
    assert resp_overview.status_code == 200

    # Scan initiation must be rejected with 403 Forbidden
    resp_scan = client.post(
        "/api/v1/vulnerabilities/scan",
        headers=headers,
        json={},
    )
    assert resp_scan.status_code == 403

    # Feed sync must be rejected with 403 Forbidden
    resp_feed = client.post(
        "/api/v1/vulnerabilities/feed-sync",
        headers=headers,
        json={"fetch_remote": False},
    )
    assert resp_feed.status_code == 403


# ==============================================================================
# 5. CELERY WORKER TASK EXECUTION TESTS
# ==============================================================================

class _TestDBSessionWrapper:
    """Prevents Celery task finally: db.close() from closing test transaction session."""
    def __init__(self, session):
        self._session = session
    def __getattr__(self, name):
        if name == "close":
            return lambda: None
        return getattr(self._session, name)


def test_celery_vulnerability_tasks_execution(db_session: Session, test_tenants):
    """
    Verifies that execute_vulnerability_scan_job and sync_vulnerability_feeds
    execute properly in the Celery task runner.
    """
    from unittest.mock import patch
    from backend.app.modules.vulnerability.tasks.vulnerability_tasks import (
        execute_vulnerability_scan_job,
        sync_vulnerability_feeds,
    )

    org_a = test_tenants["org_a"]

    # 1. Create asset and service
    asset = ManagedAsset(
        organization_id=org_a.id,
        name="Celery Test Host",
        asset_type="WEB_APPLICATION",
        target="celery.alphacorp.in",
        is_in_scope=True,
    )
    db_session.add(asset)
    db_session.flush()

    active_job = ActiveScanJob(
        organization_id=org_a.id,
        asset_id=asset.id,
        target=asset.target,
        target_ip="203.0.113.11",
        scan_profile=ScanProfile.BASIC,
        selected_ports="[80, 443]",
        authorized_scope=asset.target,
        initiated_by_user_id=test_tenants["admin_a"].id,
        authorization_confirmed=True,
        authorized_at=datetime.now(timezone.utc),
        status=ActiveScanJobStatus.COMPLETED,
    )
    db_session.add(active_job)
    db_session.flush()

    service = DiscoveredService(
        organization_id=org_a.id,
        asset_id=asset.id,
        job_id=active_job.id,
        target=asset.target,
        target_ip="203.0.113.11",
        port=80,
        protocol="tcp",
        service_name="http",
        state=ServiceState.OPEN,
        confidence=ServiceConfidence.CONFIRMED_OBSERVATION,
        http_metadata=json.dumps({"server": "Apache/2.4.49 (Unix)"}),
    )
    db_session.add(service)

    # Create vulnerability scan job
    job = VulnerabilityScanJob(
        organization_id=org_a.id,
        asset_id=asset.id,
        initiated_by_user_id=test_tenants["admin_a"].id,
        status=VulnerabilityScanStatus.PENDING.value,
    )
    db_session.add(job)
    db_session.commit()

    wrapped_db = _TestDBSessionWrapper(db_session)
    with patch("backend.app.modules.vulnerability.tasks.vulnerability_tasks.SessionLocal", return_value=wrapped_db):
        res_scan = execute_vulnerability_scan_job.apply(args=[str(job.id)]).get()
        assert res_scan["status"] == "COMPLETED"
        assert res_scan["services_scanned"] >= 1
        assert res_scan["vulnerabilities_found"] >= 1

        res_sync = sync_vulnerability_feeds.apply(kwargs={"fetch_remote": False}).get()
        assert res_sync["status"] == "SUCCESS"
        assert res_sync["cve_total"] >= 10

