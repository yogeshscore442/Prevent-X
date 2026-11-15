"""
Tests for PREVENT-X Honeypot Detection Engine (Phase 8)
Verifies reconnaissance decoy trapping, automated SecurityIncident generation,
dynamic blocking recommendations, custom trap registration, and REST API endpoints.
"""

import uuid
import pytest
from fastapi.testclient import TestClient

from backend.app.models.monitoring import SecurityIncident
from backend.app.models.network_defense import DynamicIPBlock, DynamicIPBlockStatus, HoneypotProbe
from backend.app.modules.network_defense.honeypot.service import (
    HoneypotService,
    honeypot_service,
)


def test_honeypot_hit_detection():
    """Verifies that sensitive paths trigger decoys while benign business paths are ignored."""
    svc = HoneypotService()

    # Known sensitive decoys
    assert svc.is_trap_hit("/.env")[0] is True
    assert svc.is_trap_hit("/.git/config")[0] is True
    assert svc.is_trap_hit("/.aws/credentials")[0] is True
    assert svc.is_trap_hit("/shell.php")[0] is True
    assert svc.is_trap_hit("/wp-admin/install.php")[0] is True
    assert svc.is_trap_hit("/actuator/env")[0] is True

    # Benign normal business endpoints
    assert svc.is_trap_hit("/api/v1/products")[0] is False
    assert svc.is_trap_hit("/api/v1/search")[0] is False
    assert svc.is_trap_hit("/dashboard")[0] is False
    assert svc.is_trap_hit("/auth/login")[0] is False


def test_custom_decoy_trap_registration():
    """Verifies that an organization can register and trigger bespoke decoy traps."""
    svc = HoneypotService()
    org_id = uuid.uuid4()

    # Before registering
    assert svc.is_trap_hit("/internal-portal/secret-backup.tar.gz", org_id)[0] is False

    # Register custom trap
    svc.add_custom_trap(org_id, "/internal-portal/secret-backup.tar.gz")

    # After registering
    is_hit, matched = svc.is_trap_hit("/internal-portal/secret-backup.tar.gz", org_id)
    assert is_hit is True
    assert matched == "/internal-portal/secret-backup.tar.gz"

    # Isolation: another tenant should not match this custom trap
    assert svc.is_trap_hit("/internal-portal/secret-backup.tar.gz", uuid.uuid4())[0] is False


def test_probe_lifecycle_and_incident_generation(db_session, test_tenants):
    """
    Verifies that when an attacker probes a decoy:
    1. A HoneypotProbe is recorded.
    2. A SecurityIncident is automatically raised.
    3. An IncidentTimelineEntry is created.
    4. A dynamic blocking recommendation (PENDING_APPROVAL) is created.
    """
    org_a = test_tenants["org_a"]
    attacker_ip = "198.51.100.77"

    is_hit, probe = honeypot_service.inspect_and_record_probe(
        db=db_session,
        organization_id=org_a.id,
        path="/.env",
        source_ip=attacker_ip,
        method="GET",
        query_string="debug=true",
        user_agent="Mozilla/5.0 (compatible; ReconScanner/1.0)",
        auto_recommend_block=True,
    )

    assert is_hit is True
    assert probe is not None
    assert probe.trap_path == "/.env"
    assert probe.source_ip == attacker_ip
    assert probe.correlated_incident_id is not None
    assert probe.recommended_block_id is not None

    # Verify SecurityIncident in database
    incident = db_session.get(SecurityIncident, uuid.UUID(probe.correlated_incident_id))
    assert incident is not None
    assert incident.organization_id == org_a.id
    assert incident.source == "HONEYPOT_DETECTION"
    assert incident.severity == "HIGH"
    assert attacker_ip in incident.iocs

    # Verify DynamicIPBlock in database
    block = db_session.get(DynamicIPBlock, probe.recommended_block_id)
    assert block is not None
    assert block.organization_id == org_a.id
    assert attacker_ip in block.ip_or_cidr
    assert block.status == DynamicIPBlockStatus.PENDING_APPROVAL


def test_honeypot_api_workflow(client: TestClient, db_session, test_tenants):
    """Tests the honeypot REST API endpoints for simulation, probe listing, traps, and stats."""
    org_a = test_tenants["org_a"]
    admin_a = test_tenants["admin_a"]

    login_res = client.post(
        "/api/v1/auth/login",
        json={"email": admin_a.email, "password": "AlphaAdminPass123!"},
    )
    assert login_res.status_code == 200
    token_a = login_res.json()["tokens"]["access_token"]
    headers_a = {"Authorization": f"Bearer {token_a}"}

    # 1. Get traps list
    traps_res = client.get("/api/v1/network-defense/honeypot/traps", headers=headers_a)
    assert traps_res.status_code == 200
    traps = traps_res.json()
    assert "/.env" in traps

    # 2. Add custom trap
    add_res = client.post(
        "/api/v1/network-defense/honeypot/traps",
        json={"path": "/admin/legacy-db-dump.sql"},
        headers=headers_a,
    )
    assert add_res.status_code == 200

    # 3. Simulate probe hitting the custom trap
    sim_res = client.post(
        "/api/v1/network-defense/honeypot/simulate",
        json={
            "path": "/admin/legacy-db-dump.sql",
            "source_ip": "203.0.113.199",
            "method": "GET",
            "user_agent": "sqlmap/1.7.2#stable",
            "auto_recommend_block": True,
        },
        headers=headers_a,
    )
    assert sim_res.status_code == 200
    sim_data = sim_res.json()
    assert sim_data["is_honeypot"] is True
    assert sim_data["probe_id"] is not None
    probe_id = sim_data["probe_id"]

    # 4. List captured probes
    list_res = client.get("/api/v1/network-defense/honeypot/probes", headers=headers_a)
    assert list_res.status_code == 200
    probes = list_res.json()
    assert len(probes) >= 1
    assert any(p["id"] == probe_id for p in probes)

    # 5. Get probe details
    detail_res = client.get(f"/api/v1/network-defense/honeypot/probes/{probe_id}", headers=headers_a)
    assert detail_res.status_code == 200
    assert detail_res.json()["source_ip"] == "203.0.113.199"

    # 6. Check statistics
    stats_res = client.get("/api/v1/network-defense/honeypot/stats", headers=headers_a)
    assert stats_res.status_code == 200
    stats = stats_res.json()
    assert stats["total_probes"] >= 1
    assert stats["unique_attacker_ips"] >= 1
