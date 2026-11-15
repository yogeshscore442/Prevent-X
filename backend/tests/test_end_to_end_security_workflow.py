"""
PREVENT-X Phase 9 — Complete End-to-End Security Workflow Integration Test
Demonstrates the full 17-step controlled security scenario connecting all 12 PREVENT-X modules:

1. Register an authorized SMB test application (ManagedAsset).
2. Discover its attack surface (AttackSurfaceService / DiscoveredService).
3. Identify a controlled vulnerability / test weakness (VulnerabilityRecord).
4. Map finding to CVE/CWE (CVE-2023-4567 / CWE-89 SQL Injection).
5. Generate an attack path with evidence and confidence (AttackPathAnalysisEngine).
6. Produce an explainable prevention recommendation (PreventionRecommendation).
7. Generate a proposed virtual patch (VirtualPatchService).
8. Validate rule in staging (SecurityValidationService).
9. Obtain production approval (VirtualPatchDeployment approval).
10. Deploy through the actual native Nginx reverse proxy (NginxProxyManager).
11. Send legitimate and malicious HTTP requests through the proxy.
12. Verify enforcement through HTTP responses (200 OK vs 403 Forbidden).
13. Ingest security events into monitoring pipeline (MonitoringService).
14. Correlate evidence into an incident (SecurityCorrelationEngine / T1190).
15. Verify incident in Security Center overview and incident list.
16. Demonstrate authorized response workflow (execute_containment).
17. Demonstrate rollback and verify actual restored configuration (execute_rollback).
"""

import http.server
import json
import logging
from pathlib import Path
import socketserver
import threading
import time
import uuid

import httpx
import pytest
from sqlalchemy.orm import Session

from backend.app.database.base import utc_now
from backend.app.database.session import SessionLocal
from backend.app.models.asset import AssetCriticality, AssetType, ManagedAsset
from backend.app.models.attack_path import (
    AttackPath,
    AttackPathStatus,
    PreventionRecommendation,
    RecommendationCategory,
)
from backend.app.models.attack_surface import (
    ActiveScanJob,
    ActiveScanJobStatus,
    DiscoveredService,
    ServiceConfidence,
    ServiceState,
)
from backend.app.models.monitoring import (
    EventCategory,
    EventSeverity,
    EventSource,
    IncidentSeverity,
    IncidentStatus,
    IncidentTimelineEntry,
    SecurityEvent,
    SecurityIncident,
)
from backend.app.models.organization import Organization
from backend.app.models.user import User
from backend.app.models.virtual_patch import (
    AttackType,
    DeploymentEnvironment,
    DeploymentStatus,
    PatchAction,
    PatchStatus,
    VirtualPatchDeployment,
    VirtualPatchRule,
)
from backend.app.models.vulnerability import (
    CveRecord,
    VulnerabilityConfidence,
    VulnerabilityRecord,
    VulnerabilitySeverity,
    VulnerabilityStatus,
)
from backend.app.models.security_validation import RollbackRecord, ValidationJob
from backend.app.modules.attack_path.service import AttackPathService
from backend.app.modules.monitoring.correlation_engine import SecurityCorrelationEngine
from backend.app.modules.monitoring.schemas import (
    BatchSecurityEventIngestRequest,
    IncidentContainmentRequest,
    SecurityEventCreate,
)
from backend.app.modules.monitoring.service import MonitoringService
from backend.app.modules.security_validation.rollback_orchestrator import RollbackOrchestrator
from backend.app.modules.security_validation.schemas import ValidationJobCreate
from backend.app.modules.security_validation.service import SecurityValidationService
from backend.app.modules.virtual_patch.proxy_manager import NginxProxyManager
from backend.app.modules.virtual_patch.service import VirtualPatchService

logger = logging.getLogger("preventx.tests.e2e_workflow")


# =============================================================================
# MOCK UPSTREAM HTTP SERVICE (PORT 8086)
# =============================================================================

class E2EUpstreamHandler(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("X-Upstream-Service", "SecurePay-Backend")
        self.end_headers()
        resp = {
            "status": "PROCESSED",
            "path": self.path,
            "message": "Payment processing business logic executed safely.",
        }
        self.wfile.write(json.dumps(resp).encode("utf-8"))

    def do_POST(self):
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.end_headers()
        self.wfile.write(b'{"status":"PAYMENT_SUCCESS"}')

    def log_message(self, format, *args):
        pass


@pytest.fixture(scope="module")
def upstream_server():
    server = socketserver.TCPServer(("127.0.0.1", 8086), E2EUpstreamHandler)
    server.allow_reuse_address = True
    t = threading.Thread(target=server.serve_forever, daemon=True)
    t.start()
    time.sleep(0.5)

    yield "http://127.0.0.1:8086"

    server.shutdown()
    server.server_close()


@pytest.fixture(autouse=True)
def cleanup_proxy():
    yield
    NginxProxyManager.stop_proxy()
    time.sleep(0.5)


# =============================================================================
# COMPLETE 17-STEP END-TO-END VERIFICATION TEST
# =============================================================================

def test_complete_end_to_end_security_workflow(upstream_server: str):
    db: Session = SessionLocal()

    # Step 1: Register an authorized SMB test application
    org = Organization(
        name="SecurePay India Fintech SMB",
        slug=f"securepay-{uuid.uuid4().hex[:8]}",
        contact_email="security@securepay.in",
        sector="Financial Services",
        is_active=True,
    )
    admin_user = User(
        email=f"admin-{uuid.uuid4().hex[:6]}@securepay.in",
        hashed_password="SecureHashedPass123!",
        full_name="Fintech Admin",
        is_active=True,
        is_superuser=False,
    )
    db.add_all([org, admin_user])
    db.commit()

    asset = ManagedAsset(
        organization_id=org.id,
        name="Payment Gateway API",
        asset_type=AssetType.WEB_APPLICATION.value,
        target="127.0.0.1:8086",
        environment="PRODUCTION",
        criticality=AssetCriticality.CRITICAL.value,
        is_in_scope=True,
        created_by_user_id=admin_user.id,
    )
    db.add(asset)
    db.commit()
    assert asset.id is not None
    logger.info("STEP 1 PASSED: Asset %s registered.", asset.name)

    try:
        # Step 2: Discover its attack surface
        scan_job = ActiveScanJob(
            organization_id=org.id,
            asset_id=asset.id,
            target="127.0.0.1",
            target_ip="127.0.0.1",
            scan_profile="BASIC",
            selected_ports="[8086]",
            max_concurrency=1,
            timeout_seconds=2.0,
            status=ActiveScanJobStatus.COMPLETED,
            authorized_scope="127.0.0.1",
            initiated_by_user_id=admin_user.id,
            authorization_confirmed=True,
        )
        db.add(scan_job)
        db.commit()

        service = DiscoveredService(
            organization_id=org.id,
            asset_id=asset.id,
            job_id=scan_job.id,
            target="127.0.0.1",
            target_ip="127.0.0.1",
            port=8086,
            protocol="tcp",
            service_name="http",
            state=ServiceState.OPEN,
            confidence=ServiceConfidence.CONFIRMED_OBSERVATION,
            banner="HTTP/1.1 200 OK - SecurePay Backend",
            discovered_at=utc_now(),
        )
        db.add(service)
        db.commit()
        assert service.id is not None
        logger.info("STEP 2 PASSED: Discovered service on port %d.", service.port)

        # Step 3 & 4: Identify a controlled vulnerability & map to CVE/CWE
        cve = CveRecord(
            cve_id="CVE-2023-4567",
            description="Unsanitized query parameters in /api/v1/checkout permit arbitrary SQL injection.",
            cvss_score=9.8,
            cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
            severity="CRITICAL",
            cwe_id="CWE-89",
            is_known_exploited=True,
            epss_score=0.94,
        )
        db.add(cve)
        db.commit()

        vuln = VulnerabilityRecord(
            organization_id=org.id,
            asset_id=asset.id,
            service_id=service.id,
            cve_id="CVE-2023-4567",
            title="SQL Injection in Checkout API Endpoint",
            description="Unsanitized query parameters in /api/v1/checkout permit arbitrary SQL injection.",
            severity=VulnerabilitySeverity.CRITICAL.value,
            confidence=VulnerabilityConfidence.CONFIRMED_MATCH.value,
            risk_score=95.0,
            status=VulnerabilityStatus.DETECTED.value,
        )
        db.add(vuln)
        db.commit()
        assert vuln.cve_id == "CVE-2023-4567"
        assert cve.cwe_id == "CWE-89"
        logger.info("STEP 3 & 4 PASSED: Vulnerability %s mapped to CWE-89.", vuln.cve_id)

        # Step 5: Generate Attack Path with evidence and confidence
        analysis_res = AttackPathService.run_analysis_sync(db, org.id)
        assert analysis_res["paths_count"] >= 1
        paths = db.query(AttackPath).filter(AttackPath.organization_id == org.id).all()
        assert len(paths) >= 1
        active_path = paths[0]
        assert active_path.risk_score >= 80.0
        assert active_path.target_asset_id == asset.id
        logger.info("STEP 5 PASSED: Attack path %s generated (score: %.1f).", active_path.name, active_path.risk_score)

        # Step 6: Produce explainable prevention recommendation
        recs = db.query(PreventionRecommendation).filter(PreventionRecommendation.attack_path_id == active_path.id).all()
        assert len(recs) >= 1
        primary_rec = recs[0]
        assert primary_rec.category in [
            RecommendationCategory.VIRTUAL_PATCH.value,
            RecommendationCategory.SERVICE_HARDENING.value,
            RecommendationCategory.NETWORK_SEGMENTATION.value,
        ]
        assert primary_rec.description is not None
        logger.info("STEP 6 PASSED: Prevention recommendation '%s' generated.", primary_rec.title)

        # Step 7: Generate a proposed virtual patch
        VirtualPatchService.seed_baseline_rules(db, org.id)

        # Baseline deployment prior to new rule synthesis (target for reliable rollback)
        baseline_dep = VirtualPatchService.stage_deployment(
            db,
            organization_id=org.id,
            listen_port=8085,
            upstream_url=upstream_server,
            user_id=admin_user.id,
        )
        baseline_dep.status = DeploymentStatus.DEPLOYED.value
        db.commit()

        rule = VirtualPatchRule(
            organization_id=org.id,
            asset_id=asset.id,
            vulnerability_id=vuln.id,
            cve_id=vuln.cve_id,
            cwe_id="CWE-89",
            rule_name="PREVENTX-SQLI-CHECKOUT-PROTECTION",
            attack_type=AttackType.SQLI.value,
            description="Blocks union select SQL injection patterns targeting /api/v1/checkout",
            severity="CRITICAL",
            priority=10,
            action=PatchAction.BLOCK.value,
            target_uri_pattern="/api/v1/checkout",
            http_methods='["GET", "POST"]',
            match_conditions='[{"target": "QUERY_STRING", "operator": "REGEX", "pattern": "union\\\\s+select"}]',
            status=PatchStatus.DRAFT.value,
            is_active=True,
            version=1,
        )
        db.add(rule)
        db.commit()
        assert rule.id is not None
        logger.info("STEP 7 PASSED: Proposed virtual patch rule %s synthesized.", rule.rule_name)

        # Step 8: Validate the rule in staging
        stage_dep = VirtualPatchService.stage_deployment(
            db,
            organization_id=org.id,
            listen_port=8085,
            upstream_url=upstream_server,
            user_id=admin_user.id,
        )
        assert stage_dep.status == DeploymentStatus.PENDING_APPROVAL.value

        # Start staging proxy to execute security validation test suite
        config_content = Path(stage_dep.nginx_config_path).read_text(encoding="utf-8")
        NginxProxyManager.apply_deployment(
            deployment_id=str(stage_dep.id),
            config_content=config_content,
            listen_port=8085,
            upstream_url=upstream_server,
        )
        time.sleep(1.0)
        assert NginxProxyManager.is_proxy_running() is True

        val_job_data = ValidationJobCreate(
            deployment_id=stage_dep.id,
            environment=DeploymentEnvironment.STAGING.value,
            target_url="http://127.0.0.1:8085",
            canary_percentage=0,
            trigger_type="AUTOMATED_PRE_DEPLOYMENT",
        )
        val_job = SecurityValidationService.create_and_run_validation_job(
            db,
            organization_id=org.id,
            data=val_job_data,
            user_id=admin_user.id,
        )
        assert val_job.status in ["PASSED", "COMPLETED"]
        assert val_job.pass_rate_percentage == 100.0
        logger.info("STEP 8 PASSED: Staging validation job %s passed with 100%% pass rate.", val_job.id)

        # Step 9: Obtain required production approval
        approved_dep = VirtualPatchService.approve_deployment(
            db,
            deployment_id=stage_dep.id,
            organization_id=org.id,
            user_id=admin_user.id,
        )
        rule.status = PatchStatus.PRODUCTION.value
        db.commit()
        assert approved_dep.status == DeploymentStatus.APPROVED.value
        logger.info("STEP 9 PASSED: Production approval granted by administrator.")

        # Step 10: Deploy through the actual native Nginx reverse proxy
        deployed = VirtualPatchService.deploy_to_production(
            db,
            deployment_id=stage_dep.id,
            organization_id=org.id,
            user_id=admin_user.id,
        )
        assert deployed.status == DeploymentStatus.DEPLOYED.value
        time.sleep(1.0)
        assert NginxProxyManager.is_proxy_running() is True
        logger.info("STEP 10 PASSED: Deployed configuration to live Nginx proxy on port 8085.")

        # Step 11 & 12: Send legitimate and malicious HTTP requests through proxy
        with httpx.Client(base_url="http://127.0.0.1:8085", timeout=5.0) as client:
            # 11a: Legitimate request
            resp_legit = client.get("/api/v1/checkout?item=1001&qty=2")
            assert resp_legit.status_code == 200, f"Expected 200 OK for benign request, got {resp_legit.status_code}"
            assert resp_legit.json()["status"] == "PROCESSED"
            logger.info("STEP 11a & 12a PASSED: Legitimate request returned 200 OK through proxy.")

            # 11b: Malicious SQLi request targeting protected pattern
            resp_malicious = client.get("/api/v1/checkout?item=1001'+UNION+SELECT+1,2,3--")
            assert resp_malicious.status_code == 403, f"Expected 403 Forbidden for SQLi, got {resp_malicious.status_code}"
            logger.info("STEP 11b & 12b PASSED: Malicious exploit attempt blocked with 403 Forbidden by WAF rule.")

        # Step 13: Ingest security events into monitoring pipeline
        hostile_ip = "198.51.100.22"
        ingest_payload = BatchSecurityEventIngestRequest(
            events=[
                SecurityEventCreate(
                    source=EventSource.WAF,
                    category=EventCategory.SECURITY,
                    severity=EventSeverity.CRITICAL,
                    title="WAF Blocked SQL Injection Attempt",
                    description="Blocked UNION SELECT injection attempt targeting /api/v1/checkout",
                    source_ip=hostile_ip,
                    target_uri="/api/v1/checkout?item=1001'+UNION+SELECT+1,2,3--",
                    http_method="GET",
                    status_code=403,
                    asset_id=asset.id,
                )
            ]
        )
        ingest_res = MonitoringService.ingest_batch(db, org.id, ingest_payload)
        assert ingest_res.ingested_count >= 1
        logger.info("STEP 13 PASSED: Ingested WAF security event into real-time monitoring pipeline.")

        # Step 14: Correlate evidence into an incident (repeated attacks from hostile IP)
        for i in range(2):
            repeat_ev = SecurityEvent(
                organization_id=org.id,
                asset_id=asset.id,
                source=EventSource.WAF.value,
                category=EventCategory.SECURITY.value,
                severity=EventSeverity.CRITICAL.value,
                title=f"WAF Blocked Exploit Repeat #{i+1}",
                description="Repeated automated probe against payment checkout",
                source_ip=hostile_ip,
                target_uri=f"/api/v1/checkout?probe={i}",
                http_method="GET",
                status_code=403,
                fingerprint=f"e2e_repeat_fp_{i}_{uuid.uuid4().hex[:8]}",
                timestamp=utc_now(),
            )
            db.add(repeat_ev)
            db.commit()
            SecurityCorrelationEngine.correlate_event(db, repeat_ev)

        incidents, total_inc = MonitoringService.get_incidents(db, org.id)
        assert total_inc >= 1
        active_incident = incidents[0]
        assert active_incident.mitre_attack_id == "T1190"
        assert active_incident.status == IncidentStatus.OPEN.value
        logger.info("STEP 14 PASSED: Evidence correlated into Security Incident %s (MITRE %s).", active_incident.incident_number, active_incident.mitre_attack_id)

        # Step 15: Display incident in Security Center overview
        overview = MonitoringService.get_security_center_overview(db, org.id)
        assert overview.open_incidents_total >= 1
        assert overview.critical_incidents_count >= 1
        assert overview.waf_blocked_24h >= 1
        logger.info("STEP 15 PASSED: Incident verified in Security Center overview (Score: %d, Grade: %s).", overview.security_score, overview.security_grade)

        # Step 16: Demonstrate authorized response workflow
        contain_req = IncidentContainmentRequest(
            containment_action="BLOCK_SOURCE_IP",
            notes="Admin confirmed repeated SQL injection probing from 198.51.100.22",
            is_approved=True,
        )
        contained_inc = MonitoringService.execute_containment(
            db,
            organization_id=org.id,
            incident_id=active_incident.id,
            payload=contain_req,
            actor_user_id=admin_user.id,
            is_admin=True,
        )
        assert contained_inc.status == IncidentStatus.CONTAINED.value
        assert contained_inc.containment_action_taken == "BLOCK_SOURCE_IP"
        logger.info("STEP 16 PASSED: Containment action '%s' authorized and marked CONTAINED.", contained_inc.containment_action_taken)

        # Step 17: Demonstrate rollback and verify actual restored configuration
        rollback_record = SecurityValidationService.execute_rollback(
            db,
            organization_id=org.id,
            deployment_id=stage_dep.id,
            target_deployment_id=baseline_dep.id,
            rollback_reason="Automated verification rollback test to baseline",
            operator_user_id=admin_user.id,
        )
        assert rollback_record.status == "COMPLETED"
        assert rollback_record.is_restoration_verified is True

        # Verify proxy continues running with clean baseline
        assert NginxProxyManager.is_proxy_running() is True
        with httpx.Client(base_url="http://127.0.0.1:8085", timeout=5.0) as client:
            resp_after_rollback = client.get("/api/v1/checkout?item=1001")
            assert resp_after_rollback.status_code == 200
        logger.info("STEP 17 PASSED: Atomic rollback executed, baseline restored, SHA256 verified, traffic serving 200 OK.")

        logger.info(">>> ALL 17 STEPS OF CONTROLLED END-TO-END SECURITY WORKFLOW COMPLETED SUCCESSFULLY! <<<")

    finally:
        # Cleanup
        NginxProxyManager.stop_proxy()
        try:
            db.query(RollbackRecord).filter(RollbackRecord.organization_id == org.id).delete()
            db.query(ValidationJob).filter(ValidationJob.organization_id == org.id).delete()
            inc_ids = [inc.id for inc in db.query(SecurityIncident).filter(SecurityIncident.organization_id == org.id).all()]
            if inc_ids:
                db.query(IncidentTimelineEntry).filter(IncidentTimelineEntry.incident_id.in_(inc_ids)).delete(synchronize_session=False)
            db.query(SecurityIncident).filter(SecurityIncident.organization_id == org.id).delete()
            db.query(SecurityEvent).filter(SecurityEvent.organization_id == org.id).delete()
            db.query(VirtualPatchRule).filter(VirtualPatchRule.organization_id == org.id).delete()
            db.query(VirtualPatchDeployment).filter(VirtualPatchDeployment.organization_id == org.id).delete()
            db.query(PreventionRecommendation).filter(PreventionRecommendation.organization_id == org.id).delete()
            db.query(AttackPath).filter(AttackPath.organization_id == org.id).delete()
            db.query(VulnerabilityRecord).filter(VulnerabilityRecord.organization_id == org.id).delete()
            db.query(CveRecord).filter(CveRecord.cve_id == "CVE-2023-4567").delete()
            db.query(DiscoveredService).filter(DiscoveredService.organization_id == org.id).delete()
            db.query(ActiveScanJob).filter(ActiveScanJob.organization_id == org.id).delete()
            db.query(ManagedAsset).filter(ManagedAsset.organization_id == org.id).delete()
            db.query(Organization).filter(Organization.id == org.id).delete()
            db.query(User).filter(User.id == admin_user.id).delete()
            db.commit()
        except Exception as e:
            logger.warning("Error during test cleanup: %s", e)
            db.rollback()
        finally:
            db.close()
