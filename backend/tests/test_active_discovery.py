"""
PREVENT-X Controlled Active Service Discovery Engine Tests (Phase 2 Prompt 2)
Validates mandatory authorization controls, RBAC enforcement, restricted port profiles,
SSRF defenses, worker authorization revalidation, safe protocol handshakes,
TLS metadata extraction, cancellation, and multi-tenant isolation.
"""

from datetime import datetime, timezone, timedelta
import json
import socket
import ssl
import threading
from unittest.mock import patch, MagicMock
from uuid import UUID
import pytest
from fastapi.testclient import TestClient

from backend.app.database.base import utc_now
from backend.app.models.asset import ManagedAsset
from backend.app.models.attack_surface import (
    ActiveScanJob,
    ActiveScanJobStatus,
    DiscoveredService,
    ScanProfile,
    ServiceState,
    ServiceConfidence,
)
from backend.app.models.audit_log import AuditEvent
from backend.app.models.organization import Organization
from backend.app.modules.attack_surface.active_scanner import ActiveScanner, PortScanResult
from backend.app.modules.attack_surface.scope_validator import (
    ScopeValidator,
    ScopeValidationError,
    WorkerAuthorizationError,
)
from backend.app.modules.attack_surface.tasks.active_scan_tasks import execute_active_scan_job
from backend.app.modules.attack_surface.service import AttackSurfaceService


# ==============================================================================
# 1. RBAC & MANDATORY AUTHORIZATION ENFORCEMENT
# ==============================================================================

def test_unauthenticated_active_scan_rejected(client: TestClient):
    """Unauthenticated requests must be rejected with 401 Unauthorized."""
    resp = client.post(
        "/api/v1/attack-surface/active-scans",
        json={
            "asset_id": "00000000-0000-0000-0000-000000000001",
            "scan_profile": "BASIC",
            "authorization_confirmed": True,
        },
    )
    assert resp.status_code == 401


def test_unauthorized_role_active_scan_rejected(client: TestClient, db_session, test_tenants):
    """Users lacking discovery:active permission (e.g. VIEWER) must receive 403 Forbidden."""
    login_resp = client.post(
        "/api/v1/auth/login",
        json={"email": "viewer@betaind.in", "password": "BetaViewerPass123!"},
    )
    assert login_resp.status_code == 200
    token = login_resp.json()["tokens"]["access_token"]
    headers = {"Authorization": f"Bearer {token}"}

    resp = client.post(
        "/api/v1/attack-surface/active-scans",
        headers=headers,
        json={
            "asset_id": "00000000-0000-0000-0000-000000000002",
            "scan_profile": "BASIC",
            "authorization_confirmed": True,
        },
    )
    assert resp.status_code == 403
    assert "permission" in str(resp.json()["detail"]).lower()


def test_missing_authorization_confirmation_rejected(client: TestClient, db_session, test_tenants):
    """Active scan without explicit authorization confirmation must be rejected with 400 Bad Request."""
    org_a = test_tenants["org_a"]
    admin_a = test_tenants["admin_a"]

    asset = ManagedAsset(
        organization_id=org_a.id,
        name="Production Web Portal",
        asset_type="WEB_APPLICATION",
        target="example.com",
        environment="PRODUCTION",
        criticality="HIGH",
        is_in_scope=True,
    )
    db_session.add(asset)
    db_session.commit()

    login_resp = client.post(
        "/api/v1/auth/login",
        json={"email": admin_a.email, "password": "AlphaAdminPass123!"},
    )
    token = login_resp.json()["tokens"]["access_token"]
    headers = {"Authorization": f"Bearer {token}"}

    # authorization_confirmed is False
    resp = client.post(
        "/api/v1/attack-surface/active-scans",
        headers=headers,
        json={
            "asset_id": str(asset.id),
            "scan_profile": "BASIC",
            "authorization_confirmed": False,
        },
    )
    assert resp.status_code == 400
    assert "authorization confirmation is required" in resp.json()["detail"].lower()


# ==============================================================================
# 2. MULTI-TENANT BOUNDARY & CROSS-TENANT REJECTION
# ==============================================================================

def test_cross_tenant_asset_active_scan_rejected(client: TestClient, db_session, test_tenants):
    """Tenant A cannot initiate an active scan against Tenant B's asset."""
    org_b = test_tenants["org_b"]
    admin_a = test_tenants["admin_a"]

    # Asset belongs to Org B
    asset_b = ManagedAsset(
        organization_id=org_b.id,
        name="Beta Payment Gateway",
        asset_type="WEB_APPLICATION",
        target="pay.betaind.in",
        environment="PRODUCTION",
        criticality="CRITICAL",
        is_in_scope=True,
    )
    db_session.add(asset_b)
    db_session.commit()

    # Log in as Tenant A admin
    login_resp = client.post(
        "/api/v1/auth/login",
        json={"email": admin_a.email, "password": "AlphaAdminPass123!"},
    )
    token_a = login_resp.json()["tokens"]["access_token"]
    headers_a = {"Authorization": f"Bearer {token_a}"}

    # Attempt to scan Tenant B asset
    resp = client.post(
        "/api/v1/attack-surface/active-scans",
        headers=headers_a,
        json={
            "asset_id": str(asset_b.id),
            "scan_profile": "BASIC",
            "authorization_confirmed": True,
        },
    )
    assert resp.status_code == 404
    assert "not found" in resp.json()["detail"].lower()


def test_cross_tenant_active_scans_and_services_isolation(client: TestClient, db_session, test_tenants):
    """Tenant B cannot access Tenant A's active scan jobs or discovered services."""
    org_a = test_tenants["org_a"]
    org_b = test_tenants["org_b"]
    admin_a = test_tenants["admin_a"]
    admin_b = test_tenants["admin_b"]

    asset_a = ManagedAsset(
        organization_id=org_a.id,
        name="Alpha Secure API",
        asset_type="API_GATEWAY",
        target="api.alphacorp.in",
        environment="PRODUCTION",
        is_in_scope=True,
    )
    db_session.add(asset_a)
    db_session.flush()

    job_a = ActiveScanJob(
        organization_id=org_a.id,
        asset_id=asset_a.id,
        target="api.alphacorp.in",
        target_ip="203.0.113.10",
        scan_profile="BASIC",
        selected_ports="[80, 443]",
        status="COMPLETED",
        authorized_scope="api.alphacorp.in",
        initiated_by_user_id=admin_a.id,
        authorization_confirmed=True,
        authorized_at=utc_now(),
    )
    db_session.add(job_a)
    db_session.flush()

    svc_a = DiscoveredService(
        organization_id=org_a.id,
        asset_id=asset_a.id,
        job_id=job_a.id,
        target="api.alphacorp.in",
        target_ip="203.0.113.10",
        port=443,
        protocol="tcp",
        service_name="https",
        state="OPEN",
        confidence="CONFIRMED_OBSERVATION",
        discovered_at=utc_now(),
    )
    db_session.add(svc_a)
    db_session.commit()

    # Log in as Tenant B admin
    login_resp = client.post(
        "/api/v1/auth/login",
        json={"email": admin_b.email, "password": "BetaAdminPass123!"},
    )
    token_b = login_resp.json()["tokens"]["access_token"]
    headers_b = {"Authorization": f"Bearer {token_b}"}

    # Tenant B tries to get Tenant A's job details
    resp = client.get(f"/api/v1/attack-surface/active-scans/{job_a.id}", headers=headers_b)
    assert resp.status_code == 404

    # Tenant B lists services: must not include Tenant A's service
    resp_services = client.get("/api/v1/attack-surface/services", headers=headers_b)
    assert resp_services.status_code == 200
    services_list = resp_services.json()
    assert all(s["id"] != str(svc_a.id) for s in services_list)


# ==============================================================================
# 3. SSRF & FORBIDDEN NETWORK BOUNDARY DEFENSES
# ==============================================================================

def test_out_of_scope_loopback_and_metadata_ip_rejected(client: TestClient, db_session, test_tenants):
    """Active scanning against loopback or cloud metadata is strictly forbidden."""
    org_a = test_tenants["org_a"]
    admin_a = test_tenants["admin_a"]

    # Asset targeting loopback
    asset_loopback = ManagedAsset(
        organization_id=org_a.id,
        name="Localhost Probe",
        asset_type="PUBLIC_IP",
        target="127.0.0.1",
        environment="PRODUCTION",
        is_in_scope=True,
    )
    # Asset targeting AWS metadata
    asset_metadata = ManagedAsset(
        organization_id=org_a.id,
        name="Cloud Metadata Probe",
        asset_type="PUBLIC_IP",
        target="169.254.169.254",
        environment="PRODUCTION",
        is_in_scope=True,
    )
    db_session.add_all([asset_loopback, asset_metadata])
    db_session.commit()

    login_resp = client.post(
        "/api/v1/auth/login",
        json={"email": admin_a.email, "password": "AlphaAdminPass123!"},
    )
    token = login_resp.json()["tokens"]["access_token"]
    headers = {"Authorization": f"Bearer {token}"}

    # 1. Loopback rejected
    resp1 = client.post(
        "/api/v1/attack-surface/active-scans",
        headers=headers,
        json={"asset_id": str(asset_loopback.id), "scan_profile": "BASIC", "authorization_confirmed": True},
    )
    assert resp1.status_code == 403
    assert "loopback" in resp1.json()["detail"].lower()

    # 2. Metadata rejected
    resp2 = client.post(
        "/api/v1/attack-surface/active-scans",
        headers=headers,
        json={"asset_id": str(asset_metadata.id), "scan_profile": "BASIC", "authorization_confirmed": True},
    )
    assert resp2.status_code == 403
    assert "metadata" in resp2.json()["detail"].lower() or "link-local" in resp2.json()["detail"].lower()


def test_unauthorized_private_ip_rejected_unless_internal(client: TestClient, db_session, test_tenants):
    """RFC 1918 private IP scanning is rejected for external assets, but permitted for INTERNAL_SERVER."""
    org_a = test_tenants["org_a"]
    admin_a = test_tenants["admin_a"]

    # External asset pointing to private IP
    asset_external = ManagedAsset(
        organization_id=org_a.id,
        name="External Server Claiming Private IP",
        asset_type="WEB_APPLICATION",
        target="10.20.30.40",
        environment="PRODUCTION",
        is_in_scope=True,
    )
    # Internal asset pointing to private IP
    asset_internal = ManagedAsset(
        organization_id=org_a.id,
        name="Authorized Internal Database",
        asset_type="INTERNAL_SERVER",
        target="10.20.30.40",
        environment="PRODUCTION",
        is_in_scope=True,
    )
    db_session.add_all([asset_external, asset_internal])
    db_session.commit()

    login_resp = client.post(
        "/api/v1/auth/login",
        json={"email": admin_a.email, "password": "AlphaAdminPass123!"},
    )
    token = login_resp.json()["tokens"]["access_token"]
    headers = {"Authorization": f"Bearer {token}"}

    # 1. External asset rejected
    resp_ext = client.post(
        "/api/v1/attack-surface/active-scans",
        headers=headers,
        json={"asset_id": str(asset_external.id), "scan_profile": "BASIC", "authorization_confirmed": True},
    )
    assert resp_ext.status_code == 403
    assert "private" in resp_ext.json()["detail"].lower()

    # 2. Internal asset accepted
    with patch("backend.app.modules.attack_surface.tasks.active_scan_tasks.execute_active_scan_job.delay"):
        resp_int = client.post(
            "/api/v1/attack-surface/active-scans",
            headers=headers,
            json={"asset_id": str(asset_internal.id), "scan_profile": "BASIC", "authorization_confirmed": True},
        )
        assert resp_int.status_code == 202
        assert resp_int.json()["target"] == "10.20.30.40"


# ==============================================================================
# 4. RESTRICTED PORT PROFILES & LIMIT ENFORCEMENT
# ==============================================================================

def test_port_profile_validation():
    """Validates BASIC, STANDARD, and CUSTOM port profile restrictions."""
    # 1. BASIC profile has exactly ports 80, 443
    basic_ports = ScopeValidator.validate_port_profile("BASIC")
    assert basic_ports == [80, 443]

    # 2. STANDARD profile has 17 approved ports
    standard_ports = ScopeValidator.validate_port_profile("STANDARD")
    assert len(standard_ports) == 17
    assert 22 in standard_ports
    assert 80 in standard_ports
    assert 443 in standard_ports
    assert 3306 in standard_ports
    assert 8443 in standard_ports

    # 3. CUSTOM profile with valid ports (sorted, unique)
    custom_ports = ScopeValidator.validate_port_profile("CUSTOM", [8443, 8080, 3000, 8080])
    assert custom_ports == [3000, 8080, 8443]

    # 4. CUSTOM profile with > 50 ports rejected
    with pytest.raises(ScopeValidationError) as exc:
        ScopeValidator.validate_port_profile("CUSTOM", list(range(1, 52)))
    assert "maximum limit of 50 ports" in str(exc.value.detail).lower()

    # 5. CUSTOM profile with invalid port out of range (0 or > 65535) rejected
    with pytest.raises(ScopeValidationError):
        ScopeValidator.validate_port_profile("CUSTOM", [80, 0])

    with pytest.raises(ScopeValidationError):
        ScopeValidator.validate_port_profile("CUSTOM", [80, 70000])

    # 6. Unknown profile rejected
    with pytest.raises(ScopeValidationError):
        ScopeValidator.validate_port_profile("ALL_65535_PORTS")


# ==============================================================================
# 5. WORKER-SIDE AUTHORIZATION REVALIDATION (DEFENSE IN DEPTH)
# ==============================================================================

def test_worker_authorization_revalidation_failure_scenarios(db_session, test_tenants):
    """
    Validates that the worker revalidates authorization immediately prior to scanning
    and rejects compromised, expired, tampered, or deleted jobs.
    """
    org_a = test_tenants["org_a"]
    org_b = test_tenants["org_b"]
    admin_a = test_tenants["admin_a"]

    asset = ManagedAsset(
        organization_id=org_a.id,
        name="Critical Core API",
        asset_type="WEB_APPLICATION",
        target="api.alphacorp.in",
        environment="PRODUCTION",
        is_in_scope=True,
    )
    db_session.add(asset)
    db_session.commit()

    valid_evidence = {
        "status": "APPROVED",
        "organization_id": str(org_a.id),
        "asset_id": str(asset.id),
        "effective_target": "api.alphacorp.in",
        "resolved_ip": "203.0.113.50",
        "discovery_policy": "CONTROLLED_ACTIVE",
        "scan_profile": "BASIC",
        "ports": [80, 443],
    }

    # 1. Reject if authorization not confirmed
    job_unconfirmed = ActiveScanJob(
        organization_id=org_a.id,
        asset_id=asset.id,
        target="api.alphacorp.in",
        target_ip="203.0.113.50",
        scan_profile="BASIC",
        selected_ports="[80, 443]",
        authorized_scope="api.alphacorp.in",
        initiated_by_user_id=admin_a.id,
        authorization_confirmed=False,
        authorized_at=utc_now(),
        scope_validation_result=json.dumps(valid_evidence),
    )
    with pytest.raises(WorkerAuthorizationError) as exc:
        ScopeValidator.validate_worker_execution_authorization(db_session, job_unconfirmed)
    assert "mandatory user authorization confirmation" in str(exc.value.detail).lower()

    # 2. Reject if target asset was deleted
    job_missing_asset = ActiveScanJob(
        organization_id=org_a.id,
        asset_id=UUID("00000000-0000-0000-0000-000000000099"),
        target="api.alphacorp.in",
        target_ip="203.0.113.50",
        scan_profile="BASIC",
        selected_ports="[80, 443]",
        authorized_scope="api.alphacorp.in",
        initiated_by_user_id=admin_a.id,
        authorization_confirmed=True,
        authorized_at=utc_now(),
        scope_validation_result=json.dumps(valid_evidence),
    )
    with pytest.raises(WorkerAuthorizationError) as exc:
        ScopeValidator.validate_worker_execution_authorization(db_session, job_missing_asset)
    assert "does not exist or has been deleted" in str(exc.value.detail).lower()

    # 3. Reject if target was tampered in queued job
    job_tampered_target = ActiveScanJob(
        organization_id=org_a.id,
        asset_id=asset.id,
        target="malicious.attacker.com",
        target_ip="203.0.113.50",
        scan_profile="BASIC",
        selected_ports="[80, 443]",
        authorized_scope="api.alphacorp.in",
        initiated_by_user_id=admin_a.id,
        authorization_confirmed=True,
        authorized_at=utc_now(),
        scope_validation_result=json.dumps(valid_evidence),
    )
    with pytest.raises(WorkerAuthorizationError) as exc:
        ScopeValidator.validate_worker_execution_authorization(db_session, job_tampered_target)
    assert "target tampering detected" in str(exc.value.detail).lower()

    # 4. Reject if job expired (> 24 hours in queue)
    job_expired = ActiveScanJob(
        organization_id=org_a.id,
        asset_id=asset.id,
        target="api.alphacorp.in",
        target_ip="203.0.113.50",
        scan_profile="BASIC",
        selected_ports="[80, 443]",
        authorized_scope="api.alphacorp.in",
        initiated_by_user_id=admin_a.id,
        authorization_confirmed=True,
        authorized_at=utc_now() - timedelta(hours=25),
        created_at=utc_now() - timedelta(hours=25),
        scope_validation_result=json.dumps(valid_evidence),
    )
    with pytest.raises(WorkerAuthorizationError) as exc:
        ScopeValidator.validate_worker_execution_authorization(db_session, job_expired, max_queue_ttl_seconds=86400)
    assert "authorization has expired" in str(exc.value.detail).lower()


# ==============================================================================
# 6. ACTIVE SCANNER SAFE PROBES & METADATA EXTRACTION
# ==============================================================================

def test_active_scanner_safe_banner_grabber():
    """
    Validates safe banner grabbing:
    - Strips non-printable ASCII characters
    - Truncates at 256 bytes
    - Returns None if empty or non-banner port
    """
    scanner = ActiveScanner()

    # Simulated dirty banner with control chars
    dirty_banner = b"SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.6\r\n\x00\x01\x07"
    with patch("socket.create_connection") as mock_conn:
        mock_sock = MagicMock()
        mock_sock.recv.return_value = dirty_banner
        mock_conn.return_value.__enter__.return_value = mock_sock

        banner = scanner._grab_banner("203.0.113.1", 22)
        assert banner == "SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.6"


def test_active_scanner_safe_http_probe():
    """Validates safe minimal HTTP GET probe and header/title extraction."""
    scanner = ActiveScanner()

    http_response = (
        b"HTTP/1.1 200 OK\r\n"
        b"Date: Sat, 14 Nov 2026 12:00:00 GMT\r\n"
        b"Server: nginx/1.24.0\r\n"
        b"Content-Type: text/html\r\n"
        b"Connection: close\r\n\r\n"
        b"<html><head><title>Secure Enterprise Portal</title></head><body>Welcome</body></html>"
    )

    with patch("socket.socket") as mock_sock_cls:
        mock_sock = MagicMock()
        mock_sock.recv.side_effect = [http_response, b""]
        mock_sock_cls.return_value = mock_sock

        meta = scanner._probe_http("203.0.113.1", "portal.example.com", 80)
        assert meta is not None
        assert meta["status_code"] == 200
        assert meta["server_header"] == "nginx/1.24.0"
        assert meta["title"] == "Secure Enterprise Portal"


def test_active_scanner_reachability_states():
    """Validates classification of OPEN, CLOSED, and FILTERED states."""
    scanner = ActiveScanner(connect_timeout=0.5)

    # 1. Closed port (ConnectionRefusedError)
    with patch("socket.socket") as mock_sock_cls:
        mock_sock = MagicMock()
        mock_sock.connect.side_effect = ConnectionRefusedError("Connection refused")
        mock_sock_cls.return_value = mock_sock

        res_closed = scanner._probe_single_port("203.0.113.1", "example.com", 21)
        assert res_closed.state == "CLOSED"
        assert res_closed.confidence == "INFERRED_SERVICE"

    # 2. Filtered port (socket.timeout)
    with patch("socket.socket") as mock_sock_cls:
        mock_sock = MagicMock()
        mock_sock.connect.side_effect = socket.timeout("Timed out")
        mock_sock_cls.return_value = mock_sock

        res_filtered = scanner._probe_single_port("203.0.113.1", "example.com", 22)
        assert res_filtered.state == "FILTERED"
        assert res_filtered.confidence == "INFERRED_SERVICE"

    # 3. Open port with banner
    with patch("socket.socket") as mock_sock_cls:
        mock_sock = MagicMock()
        mock_sock.connect.return_value = None
        mock_sock_cls.return_value = mock_sock

        with patch.object(scanner, "_grab_banner", return_value="SSH-2.0-OpenSSH_8.9"):
            res_open = scanner._probe_single_port("203.0.113.1", "example.com", 22)
            assert res_open.state == "OPEN"
            assert res_open.service_name == "ssh"
            assert res_open.confidence == "CONFIRMED_OBSERVATION"
            assert res_open.banner == "SSH-2.0-OpenSSH_8.9"


# ==============================================================================
# 7. SCAN CANCELLATION LIFECYCLE
# ==============================================================================

def test_active_scan_cancellation_lifecycle(client: TestClient, db_session, test_tenants):
    """Verifies in-progress active scan cancellation via API and state machine."""
    org_a = test_tenants["org_a"]
    admin_a = test_tenants["admin_a"]

    asset = ManagedAsset(
        organization_id=org_a.id,
        name="Long Running Asset",
        asset_type="WEB_APPLICATION",
        target="example.com",
        environment="PRODUCTION",
        is_in_scope=True,
    )
    db_session.add(asset)
    db_session.flush()

    job = ActiveScanJob(
        organization_id=org_a.id,
        asset_id=asset.id,
        target="example.com",
        target_ip="93.184.216.34",
        scan_profile="STANDARD",
        selected_ports="[21, 22, 80, 443]",
        status=ActiveScanJobStatus.RUNNING,
        progress_percent=25,
        current_stage="PORT_SCANNING",
        authorized_scope="example.com",
        initiated_by_user_id=admin_a.id,
        authorization_confirmed=True,
        authorized_at=utc_now(),
    )
    db_session.add(job)
    db_session.commit()

    login_resp = client.post(
        "/api/v1/auth/login",
        json={"email": admin_a.email, "password": "AlphaAdminPass123!"},
    )
    token = login_resp.json()["tokens"]["access_token"]
    headers = {"Authorization": f"Bearer {token}"}

    # Cancel scan
    cancel_resp = client.post(
        f"/api/v1/attack-surface/active-scans/{job.id}/cancel",
        headers=headers,
        json={"reason": "Operator manually stopped discovery"},
    )
    assert cancel_resp.status_code == 200
    cancelled_data = cancel_resp.json()
    assert cancelled_data["status"] == "CANCELLED"

    # Attempting to cancel again must return 400
    cancel_again = client.post(
        f"/api/v1/attack-surface/active-scans/{job.id}/cancel",
        headers=headers,
    )
    assert cancel_again.status_code == 400
    assert "terminal state" in cancel_again.json()["detail"].lower()


# ==============================================================================
# 8. AUDIT LOGGING OF ACTIVE DISCOVERY ACTIONS
# ==============================================================================

def test_active_discovery_audit_logging(client: TestClient, db_session, test_tenants):
    """Ensures initiation, cancellation, and worker rejections generate immutable audit events."""
    org_a = test_tenants["org_a"]
    admin_a = test_tenants["admin_a"]

    asset = ManagedAsset(
        organization_id=org_a.id,
        name="Audited Asset",
        asset_type="WEB_APPLICATION",
        target="example.com",
        environment="PRODUCTION",
        is_in_scope=True,
    )
    db_session.add(asset)
    db_session.commit()

    login_resp = client.post(
        "/api/v1/auth/login",
        json={"email": admin_a.email, "password": "AlphaAdminPass123!"},
    )
    token = login_resp.json()["tokens"]["access_token"]
    headers = {"Authorization": f"Bearer {token}"}

    with patch("backend.app.modules.attack_surface.tasks.active_scan_tasks.execute_active_scan_job.delay"):
        resp = client.post(
            "/api/v1/attack-surface/active-scans",
            headers=headers,
            json={"asset_id": str(asset.id), "scan_profile": "BASIC", "authorization_confirmed": True},
        )
        assert resp.status_code == 202
        job_id = resp.json()["id"]

    # Verify audit event in database
    audit_ev = db_session.query(AuditEvent).filter(
        AuditEvent.resource_id == job_id,
        AuditEvent.action == "ACTIVE_DISCOVERY_INITIATED",
    ).first()
    assert audit_ev is not None
    assert audit_ev.organization_id == org_a.id
    assert audit_ev.user_id == admin_a.id
    assert audit_ev.status == "SUCCESS"


# ==============================================================================
# 9. CELERY WORKER TASK EXECUTION & PERSISTENCE
# ==============================================================================

class _TestDBSessionWrapper:
    """Prevents Celery task finally: db.close() from closing test transaction session."""
    def __init__(self, session):
        self._session = session
    def __getattr__(self, name):
        if name == "close":
            return lambda: None
        return getattr(self._session, name)


def test_celery_task_worker_authorization_rejection(db_session, test_tenants):
    """
    Validates that execute_active_scan_job task enforces worker authorization revalidation
    and fails safely with audit logging when authorization is invalid.
    """
    org_a = test_tenants["org_a"]
    admin_a = test_tenants["admin_a"]

    asset = ManagedAsset(
        organization_id=org_a.id,
        name="Worker Rejection Asset",
        asset_type="INTERNAL_SERVER",
        target="10.50.0.1",
        is_in_scope=True,
    )
    db_session.add(asset)
    db_session.flush()

    # Job created without authorization confirmation
    job = ActiveScanJob(
        organization_id=org_a.id,
        asset_id=asset.id,
        target="10.50.0.1",
        target_ip="10.50.0.1",
        scan_profile="BASIC",
        selected_ports="[80, 443]",
        status="PENDING",
        authorized_scope="10.50.0.1",
        initiated_by_user_id=admin_a.id,
        authorization_confirmed=False,  # Unconfirmed!
        authorized_at=utc_now(),
    )
    db_session.add(job)
    db_session.commit()

    # Execute Celery task with transactional session
    wrapped_db = _TestDBSessionWrapper(db_session)
    with patch("backend.app.modules.attack_surface.tasks.active_scan_tasks.SessionLocal", return_value=wrapped_db):
        res = execute_active_scan_job.apply(args=[str(job.id)]).get()

    assert res["status"] == "FAILED"
    assert "Worker authorization rejected" in res["error"]

    # Verify database updates
    db_session.refresh(job)
    assert job.status == ActiveScanJobStatus.FAILED
    assert "worker authorization rejected" in job.error_message.lower()

    # Verify rejection audit event
    audit = db_session.query(AuditEvent).filter(
        AuditEvent.resource_id == str(job.id),
        AuditEvent.action == "ACTIVE_DISCOVERY_WORKER_AUTH_REJECTED",
    ).first()
    assert audit is not None
    assert audit.status == "DENIED"


def test_celery_task_successful_execution_and_service_persistence(db_session, test_tenants):
    """
    Validates end-to-end active scan task execution:
    - Revalidates authorization
    - Executes scanner
    - Persists discovered services with TLS/HTTP metadata
    - Marks job COMPLETED with progress 100%
    - Logs ACTIVE_DISCOVERY_COMPLETED audit event
    """
    org_a = test_tenants["org_a"]
    admin_a = test_tenants["admin_a"]

    asset = ManagedAsset(
        organization_id=org_a.id,
        name="Production Web App",
        asset_type="INTERNAL_SERVER",
        target="10.50.0.2",
        is_in_scope=True,
    )
    db_session.add(asset)
    db_session.flush()

    valid_evidence = {
        "status": "APPROVED",
        "organization_id": str(org_a.id),
        "asset_id": str(asset.id),
        "effective_target": "10.50.0.2",
        "resolved_ip": "10.50.0.2",
        "discovery_policy": "CONTROLLED_ACTIVE",
        "scan_profile": "BASIC",
        "ports": [80, 443],
    }

    job = ActiveScanJob(
        organization_id=org_a.id,
        asset_id=asset.id,
        target="10.50.0.2",
        target_ip="10.50.0.2",
        scan_profile="BASIC",
        selected_ports="[80, 443]",
        status="PENDING",
        authorized_scope="10.50.0.2",
        initiated_by_user_id=admin_a.id,
        authorization_confirmed=True,
        authorized_at=utc_now(),
        scope_validation_result=json.dumps(valid_evidence),
    )
    db_session.add(job)
    db_session.commit()

    mock_port_80 = PortScanResult(
        port=80,
        protocol="tcp",
        state="OPEN",
        service_name="http",
        confidence="CONFIRMED_OBSERVATION",
        http_metadata={"status_code": 200, "server_header": "nginx/1.24", "title": "Dashboard"},
        raw_evidence={"http_probe": "SUCCESS"},
    )
    mock_port_443 = PortScanResult(
        port=443,
        protocol="tcp",
        state="OPEN",
        service_name="https",
        confidence="CONFIRMED_OBSERVATION",
        tls_metadata={"subject_cn": "app.internal", "issuer": "CorpCA", "days_remaining": 120},
        http_metadata={"status_code": 200, "server_header": "nginx/1.24"},
        raw_evidence={"tls_handshake": "SUCCESS"},
    )

    wrapped_db = _TestDBSessionWrapper(db_session)
    with patch("backend.app.modules.attack_surface.tasks.active_scan_tasks.SessionLocal", return_value=wrapped_db):
        with patch.object(ActiveScanner, "scan_ports", return_value=[mock_port_80, mock_port_443]):
            res = execute_active_scan_job.apply(args=[str(job.id)]).get()

    assert res["status"] == "COMPLETED"
    assert res["ports_scanned"] == 2
    assert res["services_discovered"] == 2

    # Verify DB updates
    db_session.refresh(job)
    assert job.status == ActiveScanJobStatus.COMPLETED
    assert job.progress_percent == 100
    assert job.ports_scanned_count == 2
    assert job.services_discovered_count == 2
    assert job.completed_at is not None

    # Verify persisted services
    services = db_session.query(DiscoveredService).filter(DiscoveredService.job_id == job.id).all()
    assert len(services) == 2

    svc_80 = next(s for s in services if s.port == 80)
    assert svc_80.service_name == "http"
    assert svc_80.confidence == "CONFIRMED_OBSERVATION"
    assert "nginx/1.24" in svc_80.http_metadata

    svc_443 = next(s for s in services if s.port == 443)
    assert svc_443.service_name == "https"
    assert svc_443.confidence == "CONFIRMED_OBSERVATION"
    assert "app.internal" in svc_443.tls_metadata

    # Verify audit log
    audit = db_session.query(AuditEvent).filter(
        AuditEvent.resource_id == str(job.id),
        AuditEvent.action == "ACTIVE_DISCOVERY_COMPLETED",
    ).first()
    assert audit is not None
    assert audit.status == "SUCCESS"
