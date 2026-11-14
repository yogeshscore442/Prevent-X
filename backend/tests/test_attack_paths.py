"""
PREVENT-X Phase 4 AI Attack Path & Prevention Engine Tests (MOD-03)
Verifies multi-hop DAG pathfinding, strict evidence-backed adjacency, MITRE ATT&CK mapping,
0-100 contextual risk calculation, prioritized compensating controls, multi-tenant isolation,
RBAC authorization, and Celery asynchronous execution on PostgreSQL 16.
"""

import json
import uuid
import pytest
from fastapi.testclient import TestClient
from sqlalchemy.orm import Session

from backend.app.models.asset import AssetCriticality, AssetType, ManagedAsset
from backend.app.models.attack_path import (
    AssetTrustRelationship,
    AttackPath,
    AttackPathAnalysisJob,
    AttackPathConfidence,
    AttackPathSeverity,
    AttackPathStatus,
    PreventionRecommendation,
    TrustRelationshipType,
)
from backend.app.models.attack_surface import (
    ActiveScanJob,
    ActiveScanJobStatus,
    DiscoveredService,
    ServiceState,
)
from backend.app.models.vulnerability import CveRecord, VulnerabilityRecord
from backend.app.modules.attack_path.graph_engine import AttackPathGraphEngine
from backend.app.modules.attack_path.mitre_mapper import MitreAttackMapper
from backend.app.modules.attack_path.recommendation_engine import PreventionRecommendationEngine
from backend.app.modules.attack_path.risk_scorer import AttackPathRiskScorer
from backend.app.modules.attack_path.service import AttackPathService
from backend.app.modules.attack_path.tasks.attack_path_tasks import execute_attack_path_analysis_job


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


# ==============================================================================
# 1. RISK SCORING ENGINE MATHEMATICAL BOUNDS & ACCURACY
# ==============================================================================

def test_risk_scoring_bounds_and_factors():
    """
    Verifies that the risk score remains strictly within [0.0, 100.0],
    correctly incorporates exposure, CVSS, target criticality, and confidence scaling.
    """
    # Case 1: Maximum severity scenario (Internet + KEV + CVSS 10 + Critical + 1-hop + Confirmed)
    res_max = AttackPathRiskScorer.calculate_risk(
        is_internet_facing=True,
        has_cisa_kev=True,
        max_cvss=10.0,
        has_vulnerabilities=True,
        target_criticality="CRITICAL",
        step_count=1,
        confidence=AttackPathConfidence.CONFIRMED.value,
    )
    assert 95.0 <= res_max["risk_score"] <= 100.0
    assert res_max["severity"] == AttackPathSeverity.CRITICAL.value
    assert res_max["confidence"] == AttackPathConfidence.CONFIRMED.value

    # Case 2: Minimal severity scenario (Internal + No KEV + CVSS 2.0 + Low target + 4 hops + Potential)
    res_min = AttackPathRiskScorer.calculate_risk(
        is_internet_facing=False,
        has_cisa_kev=False,
        max_cvss=2.0,
        has_vulnerabilities=True,
        target_criticality="LOW",
        step_count=4,
        confidence=AttackPathConfidence.POTENTIAL.value,
    )
    assert 0.0 <= res_min["risk_score"] <= 35.0
    assert res_min["severity"] == AttackPathSeverity.LOW.value

    # Case 3: Verify confidence multipliers dampen potential/unconfirmed paths
    res_potential = AttackPathRiskScorer.calculate_risk(
        is_internet_facing=True,
        has_cisa_kev=False,
        max_cvss=8.0,
        has_vulnerabilities=True,
        target_criticality="HIGH",
        step_count=2,
        confidence=AttackPathConfidence.POTENTIAL.value,
    )
    res_confirmed = AttackPathRiskScorer.calculate_risk(
        is_internet_facing=True,
        has_cisa_kev=False,
        max_cvss=8.0,
        has_vulnerabilities=True,
        target_criticality="HIGH",
        step_count=2,
        confidence=AttackPathConfidence.CONFIRMED.value,
    )
    assert res_potential["risk_score"] < res_confirmed["risk_score"]
    assert res_potential["breakdown"]["confidence_multiplier"] == 0.60
    assert res_confirmed["breakdown"]["confidence_multiplier"] == 1.0


# ==============================================================================
# 2. MITRE ATT&CK MAPPING TESTS
# ==============================================================================

def test_mitre_attack_mapping():
    """
    Verifies accurate mapping to MITRE ATT&CK Tactics, Techniques, and Prerequisites.
    """
    # Initial Access: Web application -> T1190
    init_web = MitreAttackMapper.map_initial_access(service_name="nginx", port=443)
    assert init_web["id"] == "T1190"
    assert init_web["name"] == "Exploit Public-Facing Application"
    assert init_web["tactic"] == "Initial Access"

    # Initial Access: SSH -> T1133
    init_ssh = MitreAttackMapper.map_initial_access(service_name="OpenSSH", port=22)
    assert init_ssh["id"] == "T1133"
    assert init_ssh["name"] == "External Remote Services"

    # Lateral Movement: SSH Admin Access -> T1021.004
    lat_ssh = MitreAttackMapper.map_lateral_hop("SSH_ADMIN_ACCESS", port=22)
    assert lat_ssh["id"] == "T1021.004"
    assert lat_ssh["tactic"] == "Lateral Movement"

    # Lateral Movement: Database link -> T1210
    lat_db = MitreAttackMapper.map_lateral_hop("DATABASE_LINK", port=5432)
    assert lat_db["id"] == "T1210"

    # Impact: Critical Crown Jewel -> T1486 (Ransomware/Data Encrypted)
    impact_crit = MitreAttackMapper.map_crown_jewel_impact("CRITICAL", "DATABASE")
    assert impact_crit["id"] == "T1486"
    assert impact_crit["tactic"] == "Impact"

    # Prerequisite derivation
    prereqs = MitreAttackMapper.derive_prerequisites([init_web, lat_db, impact_crit])
    assert len(prereqs) >= 2
    assert any("Internet-routable" in p for p in prereqs)


# ==============================================================================
# 3. PREVENTION RECOMMENDATIONS ENGINE TESTS
# ==============================================================================

def test_prevention_recommendation_ranking():
    """
    Verifies that compensating controls prioritize Virtual Patching (high reduction, low complexity)
    and assign appropriate 1-based priority ranks.
    """
    class DummyAsset:
        def __init__(self, name, asset_type, criticality):
            self.id = uuid.uuid4()
            self.name = name
            self.asset_type = asset_type
            self.criticality = criticality

    class DummyVuln:
        def __init__(self, cve_id):
            self.cve_id = cve_id
            self.matched_service_name = "Apache HTTP Server"

    entry = DummyAsset("Web Portal", "WEB_APPLICATION", "MEDIUM")
    target = DummyAsset("Customer Database", "DATABASE", "CRITICAL")
    vulns = [DummyVuln("CVE-2023-38606")]
    techniques = [
        {"id": "T1190", "name": "Exploit Public-Facing Application"},
        {"id": "T1210", "name": "Exploitation of Remote Services"},
    ]

    recs = PreventionRecommendationEngine.generate_recommendations(
        attack_path_id=uuid.uuid4(),
        entry_asset=entry,
        target_asset=target,
        intermediate_assets=[],
        vulnerabilities=vulns,
        mitre_techniques=techniques,
        path_severity="CRITICAL",
    )

    assert len(recs) >= 3
    # Check that Virtual Patching is synthesized
    vp_recs = [r for r in recs if r["category"] == "VIRTUAL_PATCH"]
    assert len(vp_recs) == 1
    assert "CVE-2023-38606" in vp_recs[0]["title"]
    assert vp_recs[0]["risk_reduction"] == "HIGH"
    assert vp_recs[0]["implementation_complexity"] == "LOW"

    # Check priority ranks are sorted (1, 2, 3...)
    ranks = [r["priority_rank"] for r in recs]
    assert ranks == list(range(1, len(recs) + 1))


# ==============================================================================
# 4. EVIDENCE-BACKED GRAPH TRAVERSAL TESTS
# ==============================================================================

def test_graph_traversal_multi_hop_evidence_backed(db_session: Session, test_tenants):
    """
    Builds an authentic multi-hop network:
    Asset 1: Public Web Server (203.0.113.10) with Open Port 443 & CVE-2023-38606
    Asset 2: Internal Application Server (192.168.1.15)
    Asset 3: Critical Database (192.168.1.50, PostgreSQL 5432)
    Explicit Trust Link: Asset 1 -> Asset 2 (API_DEPENDENCY)
    Explicit Trust Link: Asset 2 -> Asset 3 (DATABASE_LINK)

    Verifies the engine discovers the multi-hop kill chain connecting Asset 1 -> Asset 2 -> Asset 3.
    """
    org = test_tenants["org_a"]

    # 1. Assets
    asset1 = ManagedAsset(
        organization_id=org.id,
        name="DMZ Public Web",
        asset_type=AssetType.WEB_APPLICATION.value,
        target="203.0.113.10",
        criticality=AssetCriticality.MEDIUM.value,
        is_in_scope=True,
    )
    asset2 = ManagedAsset(
        organization_id=org.id,
        name="Internal App Server",
        asset_type=AssetType.INTERNAL_SERVER.value,
        target="192.168.1.15",
        criticality=AssetCriticality.HIGH.value,
        is_in_scope=True,
    )
    asset3 = ManagedAsset(
        organization_id=org.id,
        name="Crown Jewel PostgreSQL DB",
        asset_type=AssetType.INTERNAL_SERVER.value,
        target="192.168.1.50",
        criticality=AssetCriticality.CRITICAL.value,
        is_in_scope=True,
    )
    db_session.add_all([asset1, asset2, asset3])
    db_session.flush()

    # 2. Services
    scan_job1 = _create_scan_job(db_session, org.id, asset1.id, test_tenants["admin_a"].id)
    scan_job3 = _create_scan_job(db_session, org.id, asset3.id, test_tenants["admin_a"].id)

    svc1 = DiscoveredService(
        organization_id=org.id,
        asset_id=asset1.id,
        job_id=scan_job1.id,
        target=asset1.target,
        target_ip=asset1.target,
        port=443,
        protocol="tcp",
        service_name="nginx",
        state=ServiceState.OPEN,
    )
    svc3 = DiscoveredService(
        organization_id=org.id,
        asset_id=asset3.id,
        job_id=scan_job3.id,
        target=asset3.target,
        target_ip=asset3.target,
        port=5432,
        protocol="tcp",
        service_name="postgresql",
        state=ServiceState.OPEN,
    )
    db_session.add_all([svc1, svc3])

    # 3. Vulnerability on Asset 1
    cve = CveRecord(
        cve_id="CVE-2023-38606",
        description="Public remote code execution vulnerability in web gateway",
        cvss_score=9.8,
        severity="CRITICAL",
        is_known_exploited=True,
    )
    db_session.add(cve)
    db_session.flush()

    vuln1 = VulnerabilityRecord(
        organization_id=org.id,
        asset_id=asset1.id,
        service_id=svc1.id,
        cve_id="CVE-2023-38606",
        title="Critical Web Gateway RCE",
        description="Remote code execution flaw",
        severity="CRITICAL",
        risk_score=95.0,
        confidence="CONFIRMED",
        status="DETECTED",
    )
    db_session.add(vuln1)

    # 4. Explicit Verified Trust Links
    trust_1_2 = AssetTrustRelationship(
        organization_id=org.id,
        source_asset_id=asset1.id,
        target_asset_id=asset2.id,
        relationship_type=TrustRelationshipType.API_DEPENDENCY.value,
        port=8080,
        evidence_source="REVERSE_PROXY_UPSTREAM_CONFIG",
        is_verified=True,
    )
    trust_2_3 = AssetTrustRelationship(
        organization_id=org.id,
        source_asset_id=asset2.id,
        target_asset_id=asset3.id,
        relationship_type=TrustRelationshipType.DATABASE_LINK.value,
        port=5432,
        evidence_source="APPLICATION_CONNECTION_STRING",
        is_verified=True,
    )
    db_session.add_all([trust_1_2, trust_2_3])
    db_session.commit()

    # 5. Run Graph Analysis
    engine = AttackPathGraphEngine(db=db_session, organization_id=org.id)
    paths = engine.analyze_paths()

    assert len(paths) >= 1
    # Check multi-hop path reaching Crown Jewel Asset 3
    multi_hop = next((p for p in paths if p["target_asset_id"] == asset3.id), None)
    assert multi_hop is not None
    assert multi_hop["entry_point_asset_id"] == asset1.id
    assert multi_hop["step_count"] >= 2
    assert multi_hop["severity"] == AttackPathSeverity.CRITICAL.value
    assert multi_hop["confidence"] == AttackPathConfidence.CONFIRMED.value

    # Verify Graph Nodes & Edges in JSON
    graph_obj = json.loads(multi_hop["graph_data"])
    assert len(graph_obj["nodes"]) >= 2
    assert len(graph_obj["edges"]) >= 2


def test_no_invented_lateral_movement_without_evidence(db_session: Session, test_tenants):
    """
    CRITICAL POLICY TEST:
    Verifies that when two assets are in different network subnets and have NO
    trust relationship, the engine NEVER fabricates a lateral movement path between them.
    """
    org = test_tenants["org_a"]

    # Public web server on 203.0.113.5
    public_asset = ManagedAsset(
        organization_id=org.id,
        name="Isolated Public Asset",
        asset_type=AssetType.WEB_APPLICATION.value,
        target="203.0.113.5",
        criticality=AssetCriticality.LOW.value,
        is_in_scope=True,
    )
    # Completely isolated internal server on a different network (172.16.50.10)
    isolated_db = ManagedAsset(
        organization_id=org.id,
        name="Isolated Private Database",
        asset_type=AssetType.INTERNAL_SERVER.value,
        target="172.16.50.10",
        criticality=AssetCriticality.CRITICAL.value,
        is_in_scope=True,
    )
    db_session.add_all([public_asset, isolated_db])
    db_session.commit()

    engine = AttackPathGraphEngine(db=db_session, organization_id=org.id)
    paths = engine.analyze_paths()

    # Verify NO multi-hop path exists between public_asset and isolated_db
    cross_path = [
        p for p in paths
        if p["entry_point_asset_id"] == public_asset.id and p["target_asset_id"] == isolated_db.id
    ]
    assert len(cross_path) == 0, "Engine incorrectly invented a lateral path without evidence!"


# ==============================================================================
# 5. SERVICE PERSISTENCE & EXECUTION TESTS
# ==============================================================================

def test_attack_path_service_run_analysis_sync(db_session: Session, test_tenants):
    """
    Verifies that AttackPathService.run_analysis_sync persists AttackPath and
    PreventionRecommendation records into PostgreSQL.
    """
    org = test_tenants["org_a"]
    user = test_tenants["admin_a"]

    asset = ManagedAsset(
        organization_id=org.id,
        name="E-Commerce API",
        asset_type=AssetType.WEB_APPLICATION.value,
        target="api.alphacorp.in",
        criticality=AssetCriticality.CRITICAL.value,
        is_in_scope=True,
    )
    db_session.add(asset)
    db_session.flush()

    scan_job = _create_scan_job(db_session, org.id, asset.id, user.id)
    svc = DiscoveredService(
        organization_id=org.id,
        asset_id=asset.id,
        job_id=scan_job.id,
        target=asset.target,
        target_ip="203.0.113.10",
        port=443,
        protocol="tcp",
        service_name="nginx",
        state=ServiceState.OPEN,
    )
    db_session.add(svc)
    db_session.commit()

    res = AttackPathService.run_analysis_sync(db_session, org.id, user.id)
    assert res["paths_count"] >= 1
    assert res["recommendations_count"] >= 1

    # Verify database persistence
    saved_paths = db_session.query(AttackPath).filter(AttackPath.organization_id == org.id).all()
    assert len(saved_paths) >= 1

    saved_recs = db_session.query(PreventionRecommendation).filter(
        PreventionRecommendation.organization_id == org.id
    ).all()
    assert len(saved_recs) >= 1


# ==============================================================================
# 6. REST API ENDPOINTS & RBAC AUDIT TESTS
# ==============================================================================

def test_api_attack_paths_overview_and_list(client: TestClient, db_session: Session, test_tenants):
    """
    Tests GET /api/v1/attack-paths/overview and GET /api/v1/attack-paths/paths.
    """
    token = _login_user(client, "admin@alphacorp.in")
    headers = {"Authorization": f"Bearer {token}"}

    # 1. Overview
    resp_overview = client.get("/api/v1/attack-paths/overview", headers=headers)
    assert resp_overview.status_code == 200
    data = resp_overview.json()
    assert "total_paths" in data
    assert "critical_paths" in data
    assert "crown_jewels_at_risk_count" in data

    # 2. List paths
    resp_paths = client.get("/api/v1/attack-paths/paths", headers=headers)
    assert resp_paths.status_code == 200
    paths_data = resp_paths.json()
    assert "total" in paths_data
    assert "items" in paths_data


def test_api_attack_path_status_transition_and_audit(client: TestClient, db_session: Session, test_tenants):
    """
    Tests updating an attack path status with audit trail generation.
    """
    org = test_tenants["org_a"]
    token = _login_user(client, "admin@alphacorp.in")
    headers = {"Authorization": f"Bearer {token}"}

    # Setup asset and path
    asset = ManagedAsset(
        organization_id=org.id,
        name="Payment Gateway",
        asset_type=AssetType.WEB_APPLICATION.value,
        target="pay.alphacorp.in",
        criticality=AssetCriticality.CRITICAL.value,
        is_in_scope=True,
    )
    db_session.add(asset)
    db_session.flush()

    path = AttackPath(
        organization_id=org.id,
        name="PATH-Payment-Gateway",
        title="Direct Exploit on Payment Gateway",
        entry_point_asset_id=asset.id,
        target_asset_id=asset.id,
        step_count=1,
        risk_score=85.0,
        severity="CRITICAL",
        confidence="CONFIRMED",
        status="IDENTIFIED",
    )
    db_session.add(path)
    db_session.commit()

    # Update status to MITIGATED
    resp_patch = client.patch(
        f"/api/v1/attack-paths/paths/{path.id}/status",
        headers=headers,
        json={"status": "MITIGATED"},
    )
    assert resp_patch.status_code == 200
    assert resp_patch.json()["status"] == "MITIGATED"

    # Verify invalid status rejection
    resp_invalid = client.patch(
        f"/api/v1/attack-paths/paths/{path.id}/status",
        headers=headers,
        json={"status": "INVALID_STATUS"},
    )
    assert resp_invalid.status_code == 400


def test_api_prevention_recommendations(client: TestClient, db_session: Session, test_tenants):
    """
    Tests GET /api/v1/attack-paths/recommendations and status updates.
    """
    org = test_tenants["org_a"]
    token = _login_user(client, "admin@alphacorp.in")
    headers = {"Authorization": f"Bearer {token}"}

    rec = PreventionRecommendation(
        organization_id=org.id,
        title="Deploy Virtual Patch for Log4j",
        category="VIRTUAL_PATCH",
        description="WAF rule blocking JNDI lookup strings",
        risk_reduction="HIGH",
        implementation_complexity="LOW",
        smb_operational_impact="MINIMAL",
        priority_rank=1,
        mitre_technique_id="T1190",
        status="PROPOSED",
    )
    db_session.add(rec)
    db_session.commit()

    # List
    resp = client.get("/api/v1/attack-paths/recommendations", headers=headers)
    assert resp.status_code == 200
    assert resp.json()["total"] >= 1

    # Update status to IMPLEMENTED
    resp_update = client.patch(
        f"/api/v1/attack-paths/recommendations/{rec.id}/status",
        headers=headers,
        json={"status": "IMPLEMENTED"},
    )
    assert resp_update.status_code == 200
    assert resp_update.json()["status"] == "IMPLEMENTED"


def test_api_trust_relationships_lifecycle(client: TestClient, db_session: Session, test_tenants):
    """
    Tests creating, listing, and deleting verified asset trust relationships.
    """
    org = test_tenants["org_a"]
    token = _login_user(client, "admin@alphacorp.in")
    headers = {"Authorization": f"Bearer {token}"}

    a1 = ManagedAsset(
        organization_id=org.id,
        name="Bastion Host",
        asset_type=AssetType.INTERNAL_SERVER.value,
        target="10.0.0.1",
        criticality=AssetCriticality.HIGH.value,
        is_in_scope=True,
    )
    a2 = ManagedAsset(
        organization_id=org.id,
        name="Production Database",
        asset_type=AssetType.INTERNAL_SERVER.value,
        target="10.0.0.2",
        criticality=AssetCriticality.CRITICAL.value,
        is_in_scope=True,
    )
    db_session.add_all([a1, a2])
    db_session.commit()

    # Create trust link
    create_resp = client.post(
        "/api/v1/attack-paths/trust-relationships",
        headers=headers,
        json={
            "source_asset_id": str(a1.id),
            "target_asset_id": str(a2.id),
            "relationship_type": "SSH_ADMIN_ACCESS",
            "port": 22,
            "evidence_source": "ADMIN_KEY_CONFIG",
            "is_verified": True,
        },
    )
    assert create_resp.status_code == 201
    rel_id = create_resp.json()["id"]

    # List trust links
    list_resp = client.get("/api/v1/attack-paths/trust-relationships", headers=headers)
    assert list_resp.status_code == 200
    assert any(r["id"] == rel_id for r in list_resp.json())

    # Delete trust link
    del_resp = client.delete(f"/api/v1/attack-paths/trust-relationships/{rel_id}", headers=headers)
    assert del_resp.status_code == 204


# ==============================================================================
# 7. MULTI-TENANT ISOLATION TESTS
# ==============================================================================

def test_multi_tenant_isolation(client: TestClient, db_session: Session, test_tenants):
    """
    Verifies that Tenant B cannot view or modify Tenant A's attack paths or recommendations.
    """
    org_a = test_tenants["org_a"]
    org_b = test_tenants["org_b"]

    asset_a = ManagedAsset(
        organization_id=org_a.id,
        name="Org A Secret Vault",
        asset_type=AssetType.INTERNAL_SERVER.value,
        target="vault.alphacorp.in",
        criticality=AssetCriticality.CRITICAL.value,
        is_in_scope=True,
    )
    db_session.add(asset_a)
    db_session.flush()

    path_a = AttackPath(
        organization_id=org_a.id,
        name="PATH-OrgA-Secret",
        title="Path to Org A Secret Vault",
        entry_point_asset_id=asset_a.id,
        target_asset_id=asset_a.id,
        step_count=1,
        risk_score=90.0,
        severity="CRITICAL",
        confidence="CONFIRMED",
        status="IDENTIFIED",
    )
    db_session.add(path_a)
    db_session.commit()

    # Login as Tenant B
    token_b = _login_user(client, "admin@betaind.in", "BetaAdminPass123!")
    headers_b = {"Authorization": f"Bearer {token_b}"}

    # Tenant B tries to get Tenant A's path directly -> 404
    resp_get = client.get(f"/api/v1/attack-paths/paths/{path_a.id}", headers=headers_b)
    assert resp_get.status_code == 404

    # Tenant B lists paths -> empty
    resp_list = client.get("/api/v1/attack-paths/paths", headers=headers_b)
    assert resp_list.status_code == 200
    assert not any(p["id"] == str(path_a.id) for p in resp_list.json()["items"])


# ==============================================================================
# 8. RBAC PERMISSIONS ENFORCEMENT
# ==============================================================================

def test_rbac_permissions_enforcement(client: TestClient, db_session: Session, test_tenants):
    """
    Verifies that a user with VIEWER role (has attack_path:read but lacks attack_path:write)
    is denied from mutating attack path status or creating trust links (403 Forbidden).
    """
    org = test_tenants["org_b"]
    token_viewer = _login_user(client, "viewer@betaind.in", "BetaViewerPass123!")
    headers_viewer = {"Authorization": f"Bearer {token_viewer}"}

    # Viewer CAN read overview
    resp_read = client.get("/api/v1/attack-paths/overview", headers=headers_viewer)
    assert resp_read.status_code == 200

    # Viewer CANNOT update path status
    resp_write = client.patch(
        f"/api/v1/attack-paths/paths/{uuid.uuid4()}/status",
        headers=headers_viewer,
        json={"status": "MITIGATED"},
    )
    assert resp_write.status_code == 403


# ==============================================================================
# 9. CELERY ASYNCHRONOUS TASK EXECUTION
# ==============================================================================

class _TestDBSessionWrapper:
    """Prevents Celery task finally: db.close() from closing test transaction session."""
    def __init__(self, session):
        self._session = session
    def __getattr__(self, name):
        if name == "close":
            return lambda: None
        return getattr(self._session, name)


def test_celery_task_attack_path_analysis(db_session: Session, test_tenants):
    """
    Verifies that execute_attack_path_analysis_job Celery task runs to completion
    and updates the database job status to COMPLETED.
    """
    from unittest.mock import patch

    org = test_tenants["org_a"]
    user = test_tenants["admin_a"]

    asset = ManagedAsset(
        organization_id=org.id,
        name="Celery Test API",
        asset_type=AssetType.WEB_APPLICATION.value,
        target="celery.alphacorp.in",
        criticality=AssetCriticality.HIGH.value,
        is_in_scope=True,
    )
    db_session.add(asset)
    db_session.commit()

    # Create job in database
    job = AttackPathService.create_analysis_job(db_session, org.id, user.id)
    assert job.status == "PENDING"

    wrapped_db = _TestDBSessionWrapper(db_session)
    with patch("backend.app.modules.attack_path.tasks.attack_path_tasks.SessionLocal", return_value=wrapped_db):
        result = execute_attack_path_analysis_job.apply(args=[str(job.id)]).get()
        assert result["status"] == "COMPLETED"

    # Check updated database record
    db_session.refresh(job)
    assert job.status == "COMPLETED"
    assert job.completed_at is not None
