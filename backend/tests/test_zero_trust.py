"""
PREVENT-X Phase 5 Zero Trust & Zero-Day Resilience Engine Tests (MOD-04, MOD-05)
Verifies continuous trust evaluation, evidence requirements, threat IOC ingestion & correlation,
behavioral anomaly detection, human-in-the-loop authorization gates, rollback execution,
multi-tenant isolation, RBAC permissions, and Celery asynchronous tasks on PostgreSQL 16.
"""

import json
import uuid
from datetime import datetime, timedelta, timezone
import pytest
from fastapi.testclient import TestClient
from sqlalchemy.orm import Session

from backend.app.models.asset import AssetCriticality, AssetType, ManagedAsset
from backend.app.models.attack_surface import (
    ActiveScanJob,
    ActiveScanJobStatus,
    DiscoveredService,
    ServiceState,
)
from backend.app.models.vulnerability import VulnerabilityRecord, VulnerabilitySeverity
from backend.app.models.zero_trust import (
    AnomalyStatus,
    AnomalyType,
    AssetTrustAssessment,
    BehavioralAnomaly,
    IndicatorType,
    ResponseAction,
    ResponseActionStatus,
    ResponseActionType,
    ThreatAssetCorrelation,
    ThreatIntelRecord,
    TrustDecision,
)
from backend.app.modules.zero_trust.anomaly_engine import BehavioralAnomalyEngine
from backend.app.modules.zero_trust.response_engine import AutomatedResponseEngine
from backend.app.modules.zero_trust.service import ZeroTrustService
from backend.app.modules.zero_trust.threat_intel_engine import ThreatIntelligenceEngine
from backend.app.modules.zero_trust.trust_engine import ZeroTrustEvaluationEngine
from backend.app.tasks.zero_trust_tasks import evaluate_zero_trust_job, sync_threat_intel_job


def _login_user(client: TestClient, email: str, password: str = "AlphaAdminPass123!") -> str:
    resp = client.post("/api/v1/auth/login", json={"email": email, "password": password})
    assert resp.status_code == 200
    return resp.json()["tokens"]["access_token"]


def _create_scan_job(db: Session, org_id: uuid.UUID, asset_id: uuid.UUID, user_id: uuid.UUID) -> ActiveScanJob:
    job = ActiveScanJob(
        organization_id=org_id,
        asset_id=asset_id,
        target="127.0.0.1",
        scan_profile="BASIC",
        selected_ports="[80, 443]",
        authorized_scope="127.0.0.1",
        authorization_confirmed=True,
        status=ActiveScanJobStatus.COMPLETED,
        initiated_by_user_id=user_id,
    )
    db.add(job)
    db.flush()
    return job


class TestZeroTrustEngine:
    def test_insufficient_evidence_when_no_telemetry(self, db_session: Session, test_tenants):
        """
        CRITICAL ZERO-TRUST PRINCIPLE:
        Never mark an asset TRUSTED merely because it is registered.
        An asset with no discovery services, no scans, and no telemetry
        must receive INSUFFICIENT_EVIDENCE (Score: 20.0).
        """
        org_a = test_tenants["org_a"]
        asset = ManagedAsset(
            organization_id=org_a.id,
            name="Unscanned Internal Server",
            target="10.0.0.50",
            asset_type=AssetType.INTERNAL_SERVER,
            criticality=AssetCriticality.MEDIUM,
            is_in_scope=True,
        )
        db_session.add(asset)
        db_session.commit()

        assessment = ZeroTrustEvaluationEngine.evaluate_asset_trust(db_session, asset, org_a.id)

        assert assessment.trust_decision == TrustDecision.INSUFFICIENT_EVIDENCE.value
        assert assessment.trust_score == 20.0
        assert "insufficient telemetry" in assessment.decision_reason.lower()
        assert len(assessment.asset.name) > 0

    def test_untrusted_decision_when_high_risk_ports_and_vulns(self, db_session: Session, test_tenants):
        """
        Asset exposing management port (22/3389) with a critical CVE is classified UNTRUSTED.
        """
        org_a = test_tenants["org_a"]
        admin_a = test_tenants["admin_a"]

        asset = ManagedAsset(
            organization_id=org_a.id,
            name="Exposed Bastion Host",
            target="bastion.alphacorp.in",
            asset_type=AssetType.WEB_APPLICATION,
            criticality=AssetCriticality.CRITICAL,
            is_in_scope=True,
        )
        db_session.add(asset)
        db_session.flush()

        job = _create_scan_job(db_session, org_a.id, asset.id, admin_a.id)

        # Open SSH port 22
        svc_ssh = DiscoveredService(
            organization_id=org_a.id,
            asset_id=asset.id,
            job_id=job.id,
            target="bastion.alphacorp.in",
            target_ip="198.51.100.10",
            port=22,
            protocol="tcp",
            service_name="ssh",
            state=ServiceState.OPEN,
        )
        db_session.add(svc_ssh)

        # Critical CVE finding
        vuln_crit = VulnerabilityRecord(
            organization_id=org_a.id,
            asset_id=asset.id,
            service_id=svc_ssh.id,
            cve_id="CVE-2024-6387",
            title="OpenSSH regreSSHion Remote Code Execution",
            description="Signal handler race condition in OpenSSH server allowing root RCE.",
            severity=VulnerabilitySeverity.CRITICAL.value,
            risk_score=98.0,
            status="DETECTED",
        )
        db_session.add(vuln_crit)
        db_session.commit()

        assessment = ZeroTrustEvaluationEngine.evaluate_asset_trust(db_session, asset, org_a.id)

        assert assessment.trust_decision == TrustDecision.UNTRUSTED.value
        assert assessment.trust_score < 30.0
        assert "UNTRUSTED" in assessment.decision_reason
        risk_factors = json.loads(assessment.risk_factors or "[]")
        assert any("Critical severity" in f["factor"] for f in risk_factors)
        recs = json.loads(assessment.least_privilege_recommendations or "[]")
        assert any("port 22" in r.lower() for r in recs)

    def test_trusted_decision_when_verified_clean(self, db_session: Session, test_tenants):
        """
        Positively verified asset with only standard web port, valid TLS 1.3,
        zero high/critical vulnerabilities, and clean posture receives TRUSTED.
        """
        org_a = test_tenants["org_a"]
        admin_a = test_tenants["admin_a"]

        asset = ManagedAsset(
            organization_id=org_a.id,
            name="Hardened E-Commerce Portal",
            target="shop.alphacorp.in",
            asset_type=AssetType.WEB_APPLICATION,
            criticality=AssetCriticality.HIGH,
            is_in_scope=True,
        )
        db_session.add(asset)
        db_session.flush()

        job = _create_scan_job(db_session, org_a.id, asset.id, admin_a.id)

        # Discovered HTTPS port with verified TLS
        svc_https = DiscoveredService(
            organization_id=org_a.id,
            asset_id=asset.id,
            job_id=job.id,
            target="shop.alphacorp.in",
            target_ip="198.51.100.20",
            port=443,
            protocol="tcp",
            service_name="https",
            state=ServiceState.OPEN,
            tls_metadata=json.dumps({"valid": True, "version": "TLSv1.3", "issuer": "DigiCert"}),
        )
        db_session.add(svc_https)
        db_session.commit()

        assessment = ZeroTrustEvaluationEngine.evaluate_asset_trust(db_session, asset, org_a.id)

        assert assessment.trust_decision == TrustDecision.TRUSTED.value
        assert assessment.trust_score >= 70.0
        pos_factors = json.loads(assessment.positive_factors or "[]")
        assert any("TLS encryption verified" in f["factor"] for f in pos_factors)


class TestThreatIntelligenceEngine:
    def test_threat_intel_ingestion_normalization_and_deduplication(self, db_session: Session, test_tenants):
        """
        Tests indicator normalization, deduplication, and confidence updating.
        """
        org_a = test_tenants["org_a"]

        # Ingest raw domain with scheme and uppercase
        rec1 = ThreatIntelligenceEngine.ingest_indicator(
            db=db_session,
            indicator_type=IndicatorType.DOMAIN.value,
            indicator_value="  HTTPS://Phishing-Portal.BIZ/login/ ",
            confidence=80,
            source="CERT-In Advisory",
            organization_id=org_a.id,
        )
        assert rec1.indicator_value == "phishing-portal.biz"
        assert rec1.confidence == 80

        # Ingest duplicate indicator with higher confidence
        rec2 = ThreatIntelligenceEngine.ingest_indicator(
            db=db_session,
            indicator_type=IndicatorType.DOMAIN.value,
            indicator_value="phishing-portal.biz",
            confidence=95,
            source="Threat Intel Exchange",
            organization_id=org_a.id,
            threat_actor="Actor-X",
        )
        assert rec1.id == rec2.id
        assert rec2.confidence == 95
        assert rec2.threat_actor == "Actor-X"

    def test_threat_intel_expiration_handling(self, db_session: Session, test_tenants):
        """
        Expired indicators are excluded from active threat correlations.
        """
        org_a = test_tenants["org_a"]
        past_time = datetime.now(timezone.utc) - timedelta(days=2)

        expired_ioc = ThreatIntelligenceEngine.ingest_indicator(
            db=db_session,
            indicator_type=IndicatorType.IP.value,
            indicator_value="198.51.100.99",
            confidence=70,
            source="Legacy Threat Feed",
            organization_id=org_a.id,
            expires_at=past_time,
        )
        db_session.commit()

        # Asset matching the expired IP
        asset = ManagedAsset(
            organization_id=org_a.id,
            name="Target IP Asset",
            target="198.51.100.99",
            asset_type=AssetType.INTERNAL_SERVER,
            criticality=AssetCriticality.MEDIUM,
            is_in_scope=True,
        )
        db_session.add(asset)
        db_session.commit()

        summary = ThreatIntelligenceEngine.correlate_threats(db_session, org_a.id)
        # Should not correlate because indicator has expired
        assert summary["total_active_correlations"] == 0

    def test_threat_to_asset_correlation(self, db_session: Session, test_tenants):
        """
        Active indicator matching asset target creates ThreatAssetCorrelation.
        """
        org_a = test_tenants["org_a"]

        # Ingest active C2 IP indicator
        ioc = ThreatIntelligenceEngine.ingest_indicator(
            db=db_session,
            indicator_type=IndicatorType.IP.value,
            indicator_value="203.0.113.88",
            confidence=90,
            source="CISA KEV Feed",
            organization_id=org_a.id,
            severity="CRITICAL",
        )
        db_session.commit()

        # Create asset with matching target IP
        asset = ManagedAsset(
            organization_id=org_a.id,
            name="Suspicious Outbound Asset",
            target="203.0.113.88",
            asset_type=AssetType.INTERNAL_SERVER,
            criticality=AssetCriticality.HIGH,
            is_in_scope=True,
        )
        db_session.add(asset)
        db_session.commit()

        summary = ThreatIntelligenceEngine.correlate_threats(db_session, org_a.id)

        assert summary["new_correlations_created"] >= 1
        assert summary["total_active_correlations"] >= 1

        corr = db_session.query(ThreatAssetCorrelation).filter(
            ThreatAssetCorrelation.asset_id == asset.id,
            ThreatAssetCorrelation.threat_intel_id == ioc.id,
        ).first()
        assert corr is not None
        assert corr.correlation_type == "ASSET_IP_MATCH"
        assert corr.status == "ACTIVE"


class TestBehavioralAnomalyEngine:
    def test_behavioral_unexpected_port_anomaly(self, db_session: Session, test_tenants):
        """
        Detection of unexpected backdoor port (4444) triggers AnomalyType.UNEXPECTED_SERVICE_PORT.
        """
        org_a = test_tenants["org_a"]
        admin_a = test_tenants["admin_a"]

        asset = ManagedAsset(
            organization_id=org_a.id,
            name="Infected SMB Workstation",
            target="10.0.0.120",
            asset_type=AssetType.INTERNAL_SERVER,
            criticality=AssetCriticality.MEDIUM,
            is_in_scope=True,
        )
        db_session.add(asset)
        db_session.flush()

        job = _create_scan_job(db_session, org_a.id, asset.id, admin_a.id)

        # Backdoor Metasploit port 4444
        svc_backdoor = DiscoveredService(
            organization_id=org_a.id,
            asset_id=asset.id,
            job_id=job.id,
            target="10.0.0.120",
            target_ip="10.0.0.120",
            port=4444,
            protocol="tcp",
            service_name="unknown",
            state=ServiceState.OPEN,
        )
        db_session.add(svc_backdoor)
        db_session.commit()

        anomalies = BehavioralAnomalyEngine.detect_unexpected_ports(db_session, asset, org_a.id)

        assert len(anomalies) == 1
        assert anomalies[0].anomaly_type == AnomalyType.UNEXPECTED_SERVICE_PORT.value
        assert anomalies[0].anomaly_score == 95.0
        assert "Metasploit default listener port" in anomalies[0].description

    def test_behavioral_statistical_z_score_anomaly(self, db_session: Session, test_tenants):
        """
        Statistical connection rate deviation Z >= 2.5 triggers UNUSUAL_CONNECTION_RATE.
        """
        org_a = test_tenants["org_a"]
        asset = ManagedAsset(
            organization_id=org_a.id,
            name="Web Server",
            target="web.alphacorp.in",
            asset_type=AssetType.WEB_APPLICATION,
            criticality=AssetCriticality.HIGH,
            is_in_scope=True,
        )
        db_session.add(asset)
        db_session.commit()

        # Normal baseline: mean 50 req/s, std 10 req/s
        # Observed rate: 90 req/s -> Z = (90 - 50) / 10 = 4.0 >= 2.5
        anomaly = BehavioralAnomalyEngine.evaluate_connection_rate_anomaly(
            db=db_session,
            asset=asset,
            organization_id=org_a.id,
            observed_rate=90.0,
            baseline_mean=50.0,
            baseline_std=10.0,
        )

        assert anomaly is not None
        assert anomaly.anomaly_type == AnomalyType.UNUSUAL_CONNECTION_RATE.value
        assert anomaly.anomaly_score >= 80.0
        ev_data = json.loads(anomaly.evidence_data or "{}")
        assert ev_data["z_score"] == 4.0

    def test_zero_day_payload_indicator(self, db_session: Session, test_tenants):
        """
        Records zero-day behavioral payload anomaly with is_zero_day_indicator=True.
        """
        org_a = test_tenants["org_a"]
        asset = ManagedAsset(
            organization_id=org_a.id,
            name="API Endpoint",
            target="api.alphacorp.in",
            asset_type=AssetType.WEB_APPLICATION,
            criticality=AssetCriticality.HIGH,
            is_in_scope=True,
        )
        db_session.add(asset)
        db_session.commit()

        anomaly = BehavioralAnomalyEngine.record_zero_day_payload_indicator(
            db=db_session,
            asset=asset,
            organization_id=org_a.id,
            service_port=8443,
            payload_signature="\\x90\\x90\\x90\\x31\\xc0\\x50\\x68",
            heuristic_evidence="Non-RFC header length and polymorphic NOP sled sequence detected.",
        )

        assert anomaly.is_zero_day_indicator is True
        assert anomaly.anomaly_type == AnomalyType.UNKNOWN_PROTOCOL_PAYLOAD.value
        assert anomaly.anomaly_score == 92.0
        assert "Zero-Day Resilience Alert" in anomaly.description


class TestAutomatedResponseEngine:
    def test_response_action_human_approval_gate(self, db_session: Session, test_tenants):
        """
        Disruptive actions REQUIRE explicit OrgAdmin human approval before execution.
        """
        org_a = test_tenants["org_a"]
        admin_a = test_tenants["admin_a"]

        # Propose disruptive action (NETWORK_ISOLATION)
        action = AutomatedResponseEngine.propose_action(
            db=db_session,
            organization_id=org_a.id,
            action_type=ResponseActionType.NETWORK_ISOLATION.value,
            title="Quarantine Compromised Workstation",
            description="Isolate host from subnet.",
            target_entity="10.0.0.120",
            execution_payload={"rule": "iptables -I FORWARD -s 10.0.0.120 -j DROP"},
            rollback_payload={"rule": "iptables -D FORWARD -s 10.0.0.120 -j DROP"},
            is_disruptive=True,
        )
        db_session.commit()

        assert action.status == ResponseActionStatus.PENDING_APPROVAL.value
        assert action.is_disruptive is True

        # Attempting to execute unapproved disruptive action must raise ValueError
        with pytest.raises(ValueError) as excinfo:
            AutomatedResponseEngine.execute_action(db_session, action.id, org_a.id, admin_a)
        assert "cannot be executed without prior OrgAdmin approval" in str(excinfo.value)

        # Explicit Human Approval
        approved_action = AutomatedResponseEngine.approve_action(db_session, action.id, org_a.id, admin_a)
        db_session.commit()
        assert approved_action.status == ResponseActionStatus.APPROVED.value
        assert approved_action.approved_by_user_id == admin_a.id

        # Now execution succeeds
        executed_action = AutomatedResponseEngine.execute_action(db_session, action.id, org_a.id, admin_a)
        db_session.commit()
        assert executed_action.status == ResponseActionStatus.EXECUTED.value
        assert executed_action.executed_at is not None
        assert "Successfully executed" in executed_action.execution_log

    def test_response_action_rollback(self, db_session: Session, test_tenants):
        """
        Executed action can be cleanly rolled back to ROLLED_BACK state.
        """
        org_a = test_tenants["org_a"]
        admin_a = test_tenants["admin_a"]

        # Create already-approved non-disruptive action and execute it
        action = AutomatedResponseEngine.propose_action(
            db=db_session,
            organization_id=org_a.id,
            action_type=ResponseActionType.INCREASE_TELEMETRY_LOGGING.value,
            title="Elevate Logging to DEBUG",
            description="Elevate logging verbosity.",
            target_entity="TELEMETRY_GATEWAY",
            execution_payload={"log_level": "DEBUG"},
            rollback_payload={"log_level": "INFO"},
            is_disruptive=False,
        )
        db_session.commit()

        AutomatedResponseEngine.execute_action(db_session, action.id, org_a.id, admin_a)
        db_session.commit()
        assert action.status == ResponseActionStatus.EXECUTED.value

        # Rollback
        rolled_back = AutomatedResponseEngine.rollback_action(db_session, action.id, org_a.id, admin_a)
        db_session.commit()

        assert rolled_back.status == ResponseActionStatus.ROLLED_BACK.value
        assert "[ROLLBACK]" in rolled_back.execution_log


class TestZeroTrustApiAndTenantIsolation:
    def test_zero_trust_api_endpoints_and_tenant_isolation(self, client: TestClient, db_session: Session, test_tenants):
        """
        Verifies REST endpoints and strict multi-tenant isolation.
        Org B cannot view or manipulate Org A's Zero Trust telemetry or response actions.
        """
        org_a = test_tenants["org_a"]
        org_b = test_tenants["org_b"]
        admin_a = test_tenants["admin_a"]
        admin_b = test_tenants["admin_b"]

        token_a = _login_user(client, admin_a.email, "AlphaAdminPass123!")
        token_b = _login_user(client, admin_b.email, "BetaAdminPass123!")

        # Create asset in Org A and evaluate posture
        asset_a = ManagedAsset(
            organization_id=org_a.id,
            name="Org A Core Gateway",
            target="10.0.0.1",
            asset_type=AssetType.WEB_APPLICATION,
            criticality=AssetCriticality.HIGH,
            is_in_scope=True,
        )
        db_session.add(asset_a)
        db_session.commit()

        ZeroTrustService.evaluate_asset(db_session, asset_a.id, org_a.id)

        # 1. Org A overview returns stats
        resp_a = client.get("/api/v1/zero-trust/overview", headers={"Authorization": f"Bearer {token_a}"})
        assert resp_a.status_code == 200
        data_a = resp_a.json()
        assert data_a["total_assets"] >= 1

        # 2. Org B overview has 0 assets
        resp_b = client.get("/api/v1/zero-trust/overview", headers={"Authorization": f"Bearer {token_b}"})
        assert resp_b.status_code == 200
        data_b = resp_b.json()
        assert data_b["total_assets"] == 0

        # 3. Org A lists assessments
        resp_ass_a = client.get("/api/v1/zero-trust/assessments", headers={"Authorization": f"Bearer {token_a}"})
        assert resp_ass_a.status_code == 200
        assert len(resp_ass_a.json()) >= 1

        # 4. Org B assessments list is empty (Tenant Isolation)
        resp_ass_b = client.get("/api/v1/zero-trust/assessments", headers={"Authorization": f"Bearer {token_b}"})
        assert resp_ass_b.status_code == 200
        assert len(resp_ass_b.json()) == 0

        # 5. Propose response action in Org A
        action_a = AutomatedResponseEngine.propose_action(
            db=db_session,
            organization_id=org_a.id,
            action_type=ResponseActionType.RATE_LIMIT_IP.value,
            title="Rate Limit External Scanner",
            description="Apply rate limit.",
            target_entity="198.51.100.5",
            is_disruptive=True,
        )
        db_session.commit()

        # Org B cannot approve Org A's response action
        resp_b_approve = client.post(
            f"/api/v1/zero-trust/response-actions/{action_a.id}/approve",
            headers={"Authorization": f"Bearer {token_b}"},
        )
        assert resp_b_approve.status_code in [400, 404]

        # Org A can approve it
        resp_a_approve = client.post(
            f"/api/v1/zero-trust/response-actions/{action_a.id}/approve",
            headers={"Authorization": f"Bearer {token_a}"},
        )
        assert resp_a_approve.status_code == 200
        assert resp_a_approve.json()["status"] == "APPROVED"


class TestZeroTrustCeleryTasks:
    def test_zero_trust_celery_task_execution(self, db_session: Session):
        """
        Executes Celery background tasks evaluate_zero_trust_job and sync_threat_intel_job
        against real PostgreSQL 16 database session.
        """
        from backend.app.database.session import SessionLocal
        from backend.app.models.organization import Organization

        # 1. Sync Threat Intel Task (global indicators seed)
        task_sync = sync_threat_intel_job.apply(args=[None])
        assert task_sync.status == "SUCCESS"
        result_sync = task_sync.result
        assert result_sync["status"] == "COMPLETED"
        assert result_sync["indicators_synced"] >= 5

        # 2. Evaluate Zero Trust Task on committed test organization
        local_db = SessionLocal()
        test_org = Organization(
            name="Celery ZeroTrust Test Org",
            slug=f"celery-zt-{uuid.uuid4().hex[:8]}",
            contact_email="celery-zt@preventx.test",
            is_active=True,
        )
        local_db.add(test_org)
        local_db.commit()
        org_id_str = str(test_org.id)

        try:
            task_eval = evaluate_zero_trust_job.apply(args=[org_id_str])
            assert task_eval.status == "SUCCESS"
            result_eval = task_eval.result
            assert result_eval["status"] == "COMPLETED"
            assert "threat_correlations" in result_eval
        finally:
            local_db.query(AssetTrustAssessment).filter(AssetTrustAssessment.organization_id == test_org.id).delete()
            local_db.query(Organization).filter(Organization.id == test_org.id).delete()
            local_db.commit()
            local_db.close()
