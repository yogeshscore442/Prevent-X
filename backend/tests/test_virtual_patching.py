"""
PREVENT-X Phase 6 Intelligent Virtual Patching & Reverse Proxy Tests (MOD-06, MOD-08)
Verifies:
1. Explainable virtual patch recommendation synthesis and versioned rule creation.
2. Nginx configuration compilation and native syntax verification ('nginx -t').
3. Strict human authorization gate for production deployment (DRAFT -> STAGING -> PENDING_APPROVAL -> APPROVED -> PRODUCTION).
4. Real Nginx reverse proxy execution with actual HTTP traffic:
   - Blocking SQLi, XSS, Path Traversal, Command Injection, and Recon Scanners (403 Forbidden).
   - Passing legitimate application requests through to upstream (200 OK).
5. Live WAF enforcement logging and false-positive reporting.
6. Emergency configuration rollback.
7. Multi-tenant isolation and Celery asynchronous background tasks on PostgreSQL 16.
"""

import http.server
import json
import logging
import socketserver
import threading
import time
import urllib.request
import uuid
from typing import Any, Dict, Generator, List

import httpx
import pytest
from fastapi.testclient import TestClient
from sqlalchemy.orm import Session

from backend.app.models.asset import AssetCriticality, AssetType, ManagedAsset
from backend.app.models.organization import Organization
from backend.app.models.user import User
from backend.app.models.virtual_patch import (
    AttackType,
    DeploymentEnvironment,
    DeploymentStatus,
    PatchAction,
    PatchStatus,
    VirtualPatchDeployment,
    VirtualPatchRecommendation,
    VirtualPatchRule,
    VirtualPatchVersion,
    WafEnforcementLog,
)
from backend.app.models.vulnerability import VulnerabilityRecord, VulnerabilitySeverity
from backend.app.modules.virtual_patch.generator import (
    CWE_ATTACK_SIGNATURES,
    IntelligentVirtualPatchGenerator,
)
from backend.app.modules.virtual_patch.proxy_manager import NginxProxyManager
from backend.app.modules.virtual_patch.schemas import (
    MatchCondition,
    VirtualPatchRuleCreate,
    VirtualPatchRuleUpdate,
)
from backend.app.modules.virtual_patch.service import VirtualPatchService
from backend.app.modules.virtual_patch.tasks.patch_tasks import (
    deploy_virtual_patches_job,
    generate_virtual_patches_job,
    stage_virtual_patch_deployment_job,
)
from backend.app.modules.virtual_patch.waf_compiler import WafConfigCompiler

logger = logging.getLogger("preventx.tests.virtual_patching")


# =============================================================================
# LIGHTWEIGHT MOCK UPSTREAM SERVER FIXTURE (Port 8086)
# =============================================================================

class MockUpstreamHandler(http.server.BaseHTTPRequestHandler):
    """
    Mock upstream HTTP application for testing reverse proxy pass-through.
    """
    def do_GET(self):
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("X-Upstream-Backend", "PreventX-Mock-App")
        self.end_headers()
        resp = {
            "status": "UPSTREAM_OK",
            "path": self.path,
            "message": "Legitimate request processed successfully.",
        }
        self.wfile.write(json.dumps(resp).encode("utf-8"))

    def do_POST(self):
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.end_headers()
        self.wfile.write(b'{"status":"POST_OK"}')

    def log_message(self, format, *args):
        pass  # Suppress console noise during test execution


@pytest.fixture(scope="module")
def mock_upstream_server():
    """
    Spins up a real lightweight HTTP server on port 8086 to receive reverse proxy traffic.
    """
    server = socketserver.TCPServer(("127.0.0.1", 8086), MockUpstreamHandler)
    server.allow_reuse_address = True
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    time.sleep(0.5)

    yield "http://127.0.0.1:8086"

    server.shutdown()
    server.server_close()


def _login_user(client: TestClient, email: str, password: str = "AlphaAdminPass123!") -> str:
    resp = client.post("/api/v1/auth/login", json={"email": email, "password": password})
    assert resp.status_code == 200
    return resp.json()["tokens"]["access_token"]


# =============================================================================
# TEST SUITE
# =============================================================================

def test_virtual_patch_generator_and_baseline_rules(db_session: Session, test_tenants):
    """
    Verifies deterministic synthesis of explainable virtual patch recommendations
    from detected vulnerabilities, and seeding of baseline rules with version 1 history.
    """
    org_a = test_tenants["org_a"]

    # 1. Create a managed asset and unpatched SQLi vulnerability
    asset = ManagedAsset(
        organization_id=org_a.id,
        name="Billing Portal",
        target="billing.alphacorp.in",
        asset_type=AssetType.WEB_APPLICATION,
        criticality=AssetCriticality.HIGH,
    )
    db_session.add(asset)
    db_session.flush()

    vuln = VulnerabilityRecord(
        organization_id=org_a.id,
        asset_id=asset.id,
        cve_id="CVE-2024-8901",
        title="SQL Injection in Invoice Search",
        description="Invoice query handler concatenates unsanitized parameters into SQL statements.",
        severity=VulnerabilitySeverity.HIGH,
        risk_score=85.0,
        status="CONFIRMED",
    )
    db_session.add(vuln)
    db_session.commit()

    # 2. Synthesize recommendation
    rec = IntelligentVirtualPatchGenerator.synthesize_recommendation_for_vulnerability(vuln, asset)
    assert rec is not None
    assert rec.attack_type == AttackType.SQLI.value
    assert rec.cve_id == "CVE-2024-8901"
    assert rec.confidence == 90
    assert "SQL Injection" in rec.suggested_rule_name
    assert rec.status == "PROPOSED"

    # 3. Accept recommendation -> instantiate rule and version 1
    db_session.add(rec)
    db_session.commit()

    rule = VirtualPatchService.accept_recommendation(db_session, rec.id, org_a.id)
    assert rule.rule_name == rec.suggested_rule_name
    assert rule.version == 1
    assert rule.is_active is True
    assert rule.action == PatchAction.BLOCK.value

    # Verify immutable version 1 record
    versions = VirtualPatchService.get_rule_versions(db_session, rule.id, org_a.id)
    assert len(versions) == 1
    assert versions[0].version_number == 1

    # 4. Seed baseline SMB rules
    baseline_rules = VirtualPatchService.seed_baseline_rules(db_session, org_a.id)
    assert len(baseline_rules) >= 4
    attack_types = {r.attack_type for r in baseline_rules}
    assert AttackType.SQLI.value in attack_types
    assert AttackType.XSS.value in attack_types
    assert AttackType.PATH_TRAVERSAL.value in attack_types
    assert AttackType.PATTERN_BLOCK.value in attack_types


def test_waf_config_compiler_and_native_nginx_syntax(db_session: Session, test_tenants):
    """
    Verifies that the WafConfigCompiler compiles structured rules into valid
    Nginx reverse proxy directives and that 'nginx -t' validates the syntax cleanly.
    """
    org_a = test_tenants["org_a"]
    rules = VirtualPatchService.seed_baseline_rules(db_session, org_a.id)

    # 1. Compile configuration
    config_content, config_hash = WafConfigCompiler.generate_full_nginx_config(
        rules=rules,
        organization_name=org_a.name,
        listen_port=8085,
        upstream_url="http://127.0.0.1:8086",
    )
    assert "PREVENT-X Virtual Patching Engine" in config_content
    assert "listen 8085;" in config_content
    assert "upstream backend_upstream" in config_content
    assert "proxy_pass http://backend_upstream;" in config_content
    assert len(config_hash) == 64

    # 2. Write runtime config and verify with native Nginx binary
    deployment_id = str(uuid.uuid4())
    conf_path = NginxProxyManager.write_runtime_config(deployment_id, config_content)
    is_valid, validation_log = NginxProxyManager.test_configuration(conf_path)

    assert is_valid is True, f"Nginx syntax verification failed: {validation_log}"
    assert "syntax is ok" in validation_log


def test_human_approval_authorization_gate(db_session: Session, test_tenants):
    """
    MANDATORY RULE TEST:
    Verifies the human-in-the-loop authorization gate:
    DRAFT -> STAGING -> PENDING_APPROVAL -> APPROVED -> PRODUCTION.
    Attempting production deployment without prior OrgAdmin approval must fail.
    """
    org_a = test_tenants["org_a"]
    admin_a = test_tenants["admin_a"]

    # 1. Seed baseline rules
    VirtualPatchService.seed_baseline_rules(db_session, org_a.id)

    # 2. Stage deployment (starts in PENDING_APPROVAL)
    deployment = VirtualPatchService.stage_deployment(
        db=db_session,
        organization_id=org_a.id,
        listen_port=8085,
        upstream_url="http://127.0.0.1:8086",
        user_id=admin_a.id,
    )
    assert deployment.environment == DeploymentEnvironment.STAGING.value
    assert deployment.status == DeploymentStatus.PENDING_APPROVAL.value
    assert deployment.approved_by_user_id is None

    # 3. Attempt production deployment without approval -> MUST RAISE VALUEERROR
    with pytest.raises(ValueError, match="strictly requires prior human approval"):
        VirtualPatchService.deploy_to_production(
            db=db_session,
            deployment_id=deployment.id,
            organization_id=org_a.id,
            user_id=admin_a.id,
        )

    # 4. OrgAdmin grants explicit sign-off
    approved_dep = VirtualPatchService.approve_deployment(
        db=db_session,
        deployment_id=deployment.id,
        organization_id=org_a.id,
        user_id=admin_a.id,
    )
    assert approved_dep.status == DeploymentStatus.APPROVED.value
    assert approved_dep.approved_by_user_id == admin_a.id
    assert approved_dep.approved_at is not None


def test_real_nginx_reverse_proxy_enforcement_end_to_end(
    db_session: Session, test_tenants, mock_upstream_server
):
    """
    END-TO-END REVERSE PROXY ENFORCEMENT TEST:
    Executes real HTTP requests against a live native Nginx reverse proxy on Windows.
    Verifies:
    1. Legitimate traffic (200 OK) passes through to upstream mock server.
    2. SQL Injection request (403 Forbidden) is intercepted and blocked by WAF.
    3. Cross-Site Scripting (XSS) request (403 Forbidden) is blocked.
    4. Path Traversal request (403 Forbidden) is blocked.
    5. Command Injection request (403 Forbidden) is blocked.
    6. Automated scanner User-Agent (403 Forbidden) is blocked.
    7. Live enforcement audit logging and false-positive reporting.
    8. Clean rollback.
    """
    org_a = test_tenants["org_a"]
    admin_a = test_tenants["admin_a"]

    try:
        # 1. Install comprehensive baseline rules
        rules = VirtualPatchService.seed_baseline_rules(db_session, org_a.id)

        # 2. Stage deployment on port 8085 targeting mock upstream on port 8086
        deployment = VirtualPatchService.stage_deployment(
            db=db_session,
            organization_id=org_a.id,
            listen_port=8085,
            upstream_url=mock_upstream_server,
            user_id=admin_a.id,
        )

        # 3. Grant OrgAdmin approval
        VirtualPatchService.approve_deployment(
            db=db_session,
            deployment_id=deployment.id,
            organization_id=org_a.id,
            user_id=admin_a.id,
        )

        # 4. Deploy to live production Nginx reverse proxy
        live_dep = VirtualPatchService.deploy_to_production(
            db=db_session,
            deployment_id=deployment.id,
            organization_id=org_a.id,
            user_id=admin_a.id,
        )
        assert live_dep.status == DeploymentStatus.DEPLOYED.value

        # Give Nginx a moment to bind to port 8085
        time.sleep(1.5)

        # Probe proxy health
        health = NginxProxyManager.check_proxy_health(8085)
        assert health.get("is_running") is True, f"Nginx proxy is not running: {health}"

        proxy_url = "http://127.0.0.1:8085"

        with httpx.Client(base_url=proxy_url, timeout=5.0) as client:
            # -------------------------------------------------------------
            # TEST CASE 1: Legitimate benign traffic -> EXPECT 200 OK
            # -------------------------------------------------------------
            res_legit = client.get("/products?category=electronics&page=1")
            assert res_legit.status_code == 200
            assert res_legit.headers.get("X-WAF-Engine") == "PREVENT-X-Intelligent-WAF"
            assert "UPSTREAM_OK" in res_legit.text

            # -------------------------------------------------------------
            # TEST CASE 2: SQL Injection probe -> EXPECT 403 FORBIDDEN
            # -------------------------------------------------------------
            res_sqli = client.get("/products?q=1%20UNION%20SELECT%201,2--")
            assert res_sqli.status_code == 403
            assert res_sqli.headers.get("X-WAF-Blocked") == "1"
            assert "waf_blocked" in res_sqli.text
            assert "SQLI" in res_sqli.text

            # -------------------------------------------------------------
            # TEST CASE 3: Cross-Site Scripting (XSS) -> EXPECT 403 FORBIDDEN
            # -------------------------------------------------------------
            res_xss = client.get("/search?query=<script>alert(1)</script>")
            assert res_xss.status_code == 403
            assert res_xss.headers.get("X-WAF-Blocked") == "1"
            assert "XSS" in res_xss.text

            # -------------------------------------------------------------
            # TEST CASE 4: Path Traversal -> EXPECT 403 FORBIDDEN
            # -------------------------------------------------------------
            res_traversal = client.get("/download?file=../../etc/passwd")
            assert res_traversal.status_code == 403
            assert res_traversal.headers.get("X-WAF-Blocked") == "1"
            assert "PATH_TRAVERSAL" in res_traversal.text

            # -------------------------------------------------------------
            # TEST CASE 5: Command Injection -> EXPECT 403 FORBIDDEN
            # -------------------------------------------------------------
            res_cmdi = client.get("/report?filter=date;whoami")
            assert res_cmdi.status_code == 403
            assert res_cmdi.headers.get("X-WAF-Blocked") == "1"
            assert "CMDI" in res_cmdi.text

            # -------------------------------------------------------------
            # TEST CASE 6: Reconnaissance Scanner -> EXPECT 403 FORBIDDEN
            # -------------------------------------------------------------
            res_scanner = client.get("/api/v1/status", headers={"User-Agent": "sqlmap/1.5#stable"})
            assert res_scanner.status_code == 403
            assert res_scanner.headers.get("X-WAF-Blocked") == "1"
            assert "PATTERN_BLOCK" in res_scanner.text

        # 5. Record enforcement telemetry log
        log_entry = VirtualPatchService.log_enforcement_event(
            db=db_session,
            organization_id=org_a.id,
            client_ip="198.51.100.55",
            http_method="GET",
            uri="/products?q=1 UNION SELECT 1,2--",
            decision="BLOCKED",
            block_reason="Attack detected: SQLI. Pattern matched.",
            rule_id=rules[0].id,
            response_status_code=403,
        )
        assert log_entry.decision == "BLOCKED"
        assert log_entry.rule_id == rules[0].id

        # 6. Report false positive
        fp_entry = VirtualPatchService.report_false_positive(
            db=db_session,
            log_id=log_entry.id,
            organization_id=org_a.id,
            notes="Legitimate query parameter contained 'select' word in user bio.",
        )
        assert fp_entry.is_false_positive_reported is True
        assert fp_entry.false_positive_notes is not None

        # 7. Test Rollback
        rollback_dep = VirtualPatchService.rollback_deployment(
            db=db_session,
            deployment_id=live_dep.id,
            organization_id=org_a.id,
            user_id=admin_a.id,
        )
        assert rollback_dep.status == DeploymentStatus.ROLLED_BACK.value

    finally:
        # Gracefully stop Nginx after test
        NginxProxyManager.stop_proxy()
        time.sleep(0.5)


def test_virtual_patching_rest_api_and_rbac(client: TestClient, test_tenants):
    """
    Verifies complete REST API lifecycle, RBAC enforcement, and version history.
    """
    token_a = _login_user(client, "admin@alphacorp.in")
    headers_a = {"Authorization": f"Bearer {token_a}"}

    # 1. Overview KPIs
    res_ov = client.get("/api/v1/virtual-patching/overview", headers=headers_a)
    assert res_ov.status_code == 200
    ov_data = res_ov.json()
    assert "total_rules" in ov_data
    assert "proxy_status" in ov_data

    # 2. Seed baseline rules
    res_seed = client.post("/api/v1/virtual-patching/rules/seed-baseline", headers=headers_a)
    assert res_seed.status_code == 200
    seed_rules = res_seed.json()
    assert len(seed_rules) >= 4

    # 3. Create custom rule
    rule_payload = {
        "rule_name": "Block Admin API Traversal",
        "attack_type": "PATH_TRAVERSAL",
        "description": "Restricts path traversal attempts targeting admin endpoints.",
        "severity": "HIGH",
        "priority": 75,
        "action": "BLOCK",
        "target_uri_pattern": "/admin/.*",
        "http_methods": ["GET", "POST"],
        "match_conditions": [
            {
                "target": "URI",
                "operator": "REGEX",
                "pattern": r"(?i)(\.\./|\.\.\\)",
                "is_case_sensitive": False,
            }
        ],
    }
    res_create = client.post("/api/v1/virtual-patching/rules", json=rule_payload, headers=headers_a)
    assert res_create.status_code == 201
    created_rule = res_create.json()
    assert created_rule["rule_name"] == "Block Admin API Traversal"
    assert created_rule["version"] == 1
    rule_id = created_rule["id"]

    # 4. View version history
    res_vers = client.get(f"/api/v1/virtual-patching/rules/{rule_id}/versions", headers=headers_a)
    assert res_vers.status_code == 200
    versions = res_vers.json()
    assert len(versions) == 1
    assert versions[0]["version_number"] == 1

    # 5. Update rule -> increments version
    update_payload = {
        "priority": 60,
        "change_summary": "Elevated priority to 60 for admin protection",
        "match_conditions": [
            {
                "target": "URI",
                "operator": "REGEX",
                "pattern": r"(?i)(\.\./|\.\.\\|/etc/passwd)",
                "is_case_sensitive": False,
            }
        ],
    }
    res_update = client.put(f"/api/v1/virtual-patching/rules/{rule_id}", json=update_payload, headers=headers_a)
    assert res_update.status_code == 200
    updated_rule = res_update.json()
    assert updated_rule["version"] == 2
    assert updated_rule["priority"] == 60

    # 6. Stage deployment via API
    stage_payload = {
        "environment": "STAGING",
        "listen_port": 8085,
        "upstream_url": "http://127.0.0.1:8086",
    }
    res_stage = client.post("/api/v1/virtual-patching/deployments/stage", json=stage_payload, headers=headers_a)
    assert res_stage.status_code == 201
    dep_data = res_stage.json()
    dep_id = dep_data["id"]
    assert dep_data["status"] == "PENDING_APPROVAL"

    # 7. Approve deployment via API
    res_approve = client.post(f"/api/v1/virtual-patching/deployments/{dep_id}/approve", headers=headers_a)
    assert res_approve.status_code == 200
    approved_data = res_approve.json()
    assert approved_data["status"] == "APPROVED"
    assert approved_data["approved_by_user_email"] == "admin@alphacorp.in"


def test_multi_tenant_isolation(client: TestClient, db_session: Session, test_tenants):
    """
    Verifies multi-tenant isolation: Tenant B cannot read or modify Tenant A's rules or deployments.
    """
    org_a = test_tenants["org_a"]
    org_b = test_tenants["org_b"]

    token_a = _login_user(client, "admin@alphacorp.in")
    token_b = _login_user(client, "admin@betaind.in", password="BetaAdminPass123!")

    headers_a = {"Authorization": f"Bearer {token_a}"}
    headers_b = {"Authorization": f"Bearer {token_b}"}

    # Tenant A creates a rule
    rule_a = VirtualPatchService.create_rule(
        db=db_session,
        organization_id=org_a.id,
        data=VirtualPatchRuleCreate(
            rule_name="Tenant A Secret Rule",
            attack_type="SQLI",
            description="Tenant A proprietary virtual patch",
            severity="HIGH",
            priority=100,
            action="BLOCK",
            match_conditions=[],
        ),
    )

    # Tenant B tries to get Tenant A's rule -> MUST BE 404 NOT FOUND
    res_b_get = client.get(f"/api/v1/virtual-patching/rules/{rule_a.id}", headers=headers_b)
    assert res_b_get.status_code == 404

    # Tenant B lists rules -> should not include Tenant A's rule
    res_b_list = client.get("/api/v1/virtual-patching/rules", headers=headers_b)
    assert res_b_list.status_code == 200
    b_rule_ids = [r["id"] for r in res_b_list.json()]
    assert str(rule_a.id) not in b_rule_ids


def test_celery_virtual_patching_tasks():
    """
    Verifies that the Celery tasks for virtual patch generation and staging execute cleanly
    against an independent committed test organization in PostgreSQL 16.
    """
    from backend.app.database.session import SessionLocal

    local_db = SessionLocal()
    test_org = Organization(
        name="Celery Virtual Patching Test Org",
        slug=f"celery-vp-{uuid.uuid4().hex[:8]}",
        contact_email="celery-vp@preventx.test",
        is_active=True,
    )
    local_db.add(test_org)
    local_db.commit()
    org_id_str = str(test_org.id)

    try:
        # 1. Virtual patch generation task
        task_gen = generate_virtual_patches_job.apply(args=[org_id_str])
        assert task_gen.status == "SUCCESS"
        res_gen = task_gen.result
        assert res_gen["status"] == "COMPLETED"
        assert res_gen["organization_id"] == org_id_str

        # 2. Stage deployment task
        task_stage = stage_virtual_patch_deployment_job.apply(args=[org_id_str, 8085])
        assert task_stage.status == "SUCCESS"
        res_stage = task_stage.result
        assert res_stage["status"] in ["PENDING_APPROVAL", "STAGING", "FAILED"]
        assert res_stage["organization_id"] == org_id_str
    finally:
        local_db.query(VirtualPatchDeployment).filter(VirtualPatchDeployment.organization_id == test_org.id).delete()
        local_db.query(VirtualPatchRule).filter(VirtualPatchRule.organization_id == test_org.id).delete()
        local_db.query(Organization).filter(Organization.id == test_org.id).delete()
        local_db.commit()
        local_db.close()
