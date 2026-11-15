"""
Tests for PREVENT-X Honeypot Detection Engine (Phase 8)
Verifies reconnaissance decoy trapping, automated SecurityIncident generation,
dynamic blocking recommendations, custom trap registration, and REST API endpoints.
"""

import uuid
import pytest
from fastapi.testclient import TestClient

from backend.app.models.monitoring import (
    IncidentSeverity,
    IncidentStatus,
    IncidentTimelineEntry,
    SecurityIncident,
)
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
    assert isinstance(incident.iocs, dict)
    assert attacker_ip in incident.iocs.get("ip", [])
    assert incident.iocs.get("trap_path") == "/.env"

    # Verify DynamicIPBlock in database
    block = db_session.get(DynamicIPBlock, probe.recommended_block_id)
    assert block is not None
    assert block.organization_id == org_a.id
    assert attacker_ip in block.ip_or_cidr
    assert block.status == DynamicIPBlockStatus.PENDING_APPROVAL

    # Verify IncidentTimelineEntry in database (DEF-02)
    timeline = db_session.query(IncidentTimelineEntry).filter_by(
        incident_id=incident.id, entry_type="HONEYPOT_TRAP_TRIGGERED"
    ).first()
    assert timeline is not None
    assert isinstance(timeline.evidence_data, dict)
    assert timeline.evidence_data.get("probe_id") == str(probe.id)
    assert timeline.evidence_data.get("trap_path") == "/.env"
    assert timeline.evidence_data.get("source_ip") == attacker_ip
    assert timeline.evidence_data.get("user_agent") == "Mozilla/5.0 (compatible; ReconScanner/1.0)"


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


def test_honeypot_incident_iocs_serialization_and_monitoring_endpoint(client: TestClient, db_session, test_tenants):
    """
    Focused regression test for DEF-01:
    Verifies that:
    1. A honeypot trap creates a SecurityIncident.
    2. The stored iocs value is a Python dictionary when loaded through SQLAlchemy.
    3. GET /api/v1/monitoring/incidents returns HTTP 200 after a honeypot incident is created.
    4. The response contains the correct source IP and trap path in its iocs field.
    5. Existing incident records without iocs (or with string iocs) still serialize correctly.
    6. Existing monitoring incident functionality remains unaffected.
    7. Multi-tenant isolation and RBAC remain intact.
    """
    org_a = test_tenants["org_a"]
    admin_a = test_tenants["admin_a"]
    org_b = test_tenants["org_b"]
    admin_b = test_tenants["admin_b"]

    login_a = client.post(
        "/api/v1/auth/login",
        json={"email": admin_a.email, "password": "AlphaAdminPass123!"},
    )
    assert login_a.status_code == 200
    token_a = login_a.json()["tokens"]["access_token"]
    headers_a = {"Authorization": f"Bearer {token_a}"}

    # 1. Trigger honeypot trap to create an incident
    source_ip = "198.51.100.99"
    trap_path = "/wp-admin/*"
    is_hit, probe = honeypot_service.inspect_and_record_probe(
        db=db_session,
        organization_id=org_a.id,
        path="/wp-admin/install.php",
        source_ip=source_ip,
        method="GET",
        query_string="step=1",
        user_agent="BadBot/2.0",
        auto_recommend_block=True,
    )
    assert is_hit is True
    assert probe.correlated_incident_id is not None

    # 2. Check loaded incident through SQLAlchemy - iocs MUST be a dict
    inc_db = db_session.get(SecurityIncident, uuid.UUID(probe.correlated_incident_id))
    assert inc_db is not None
    assert isinstance(inc_db.iocs, dict)
    assert inc_db.iocs.get("ip") == [source_ip]
    assert inc_db.iocs.get("trap_path") == trap_path

    # 3. Add an incident without iocs (iocs=None) to verify null handling
    null_iocs_incident = SecurityIncident(
        organization_id=org_a.id,
        incident_number=f"INC-{uuid.uuid4().hex[:8].upper()}",
        title="Incident Without IOCs",
        description="Historical incident that has no IOCs associated.",
        severity=IncidentSeverity.LOW,
        status=IncidentStatus.OPEN,
        source="SYSTEM",
        iocs=None,
    )
    db_session.add(null_iocs_incident)

    # 4. Add a legacy incident with string-encoded iocs to verify backward-compatibility coercion
    legacy_str_incident = SecurityIncident(
        organization_id=org_a.id,
        incident_number=f"INC-{uuid.uuid4().hex[:8].upper()}",
        title="Historical Incident With String IOCs",
        description="Historical incident stored before DEF-01 fix.",
        severity=IncidentSeverity.MEDIUM,
        status=IncidentStatus.INVESTIGATING,
        source="HONEYPOT_DETECTION",
        iocs='{"ip": ["198.51.100.201"], "trap_path": "/.env"}',
    )
    db_session.add(legacy_str_incident)
    db_session.commit()

    # 5. Call GET /api/v1/monitoring/incidents as Org A Admin
    res = client.get("/api/v1/monitoring/incidents", headers=headers_a)
    assert res.status_code == 200
    data = res.json()
    assert "items" in data
    items = data["items"]

    # Verify honeypot incident is in list and properly serialized
    honeypot_items = [it for it in items if it["id"] == str(inc_db.id)]
    assert len(honeypot_items) == 1
    hp_item = honeypot_items[0]
    assert isinstance(hp_item["iocs"], dict)
    assert source_ip in hp_item["iocs"].get("ip", [])
    assert hp_item["iocs"].get("trap_path") == trap_path

    # Verify incident without iocs serialized without crashing
    null_items = [it for it in items if it["id"] == str(null_iocs_incident.id)]
    assert len(null_items) == 1
    assert null_items[0]["iocs"] is None or null_items[0]["iocs"] == {}

    # Verify legacy string-iocs incident coerced cleanly into dict
    legacy_items = [it for it in items if it["id"] == str(legacy_str_incident.id)]
    assert len(legacy_items) == 1
    assert isinstance(legacy_items[0]["iocs"], dict)
    assert "198.51.100.201" in legacy_items[0]["iocs"].get("ip", [])

    # 6. Verify Tenant Isolation: Org B cannot see Org A's incidents
    login_b = client.post(
        "/api/v1/auth/login",
        json={"email": admin_b.email, "password": "BetaAdminPass123!"},
    )
    assert login_b.status_code == 200
    token_b = login_b.json()["tokens"]["access_token"]
    headers_b = {"Authorization": f"Bearer {token_b}"}

    res_b = client.get("/api/v1/monitoring/incidents", headers=headers_b)
    assert res_b.status_code == 200
    items_b = res_b.json()["items"]
    org_b_incident_ids = {it["id"] for it in items_b}
    assert str(inc_db.id) not in org_b_incident_ids
    assert str(null_iocs_incident.id) not in org_b_incident_ids
    assert str(legacy_str_incident.id) not in org_b_incident_ids

    # 7. Verify RBAC / Unauthenticated denial
    client.cookies.clear()
    unauth_res = client.get("/api/v1/monitoring/incidents")
    assert unauth_res.status_code == 401


def test_honeypot_timeline_evidence_serialization_and_detail_endpoint(client: TestClient, db_session, test_tenants):
    """
    Focused regression test for DEF-02:
    Verifies that:
    1. Honeypot probe creates an IncidentTimelineEntry.
    2. evidence_data loads as a native Python dictionary through SQLAlchemy.
    3. Existing incident detail / timeline API (GET /api/v1/monitoring/incidents/{incident_id}) returns HTTP 200.
    4. Response timeline includes probe_id, trap_path, source_ip, and user_agent.
    5. Null evidence_data remains supported without crashing serialization.
    6. Historical string-encoded records are safely coerced to dictionaries.
    7. Multi-tenant isolation and RBAC are enforced on incident detail.
    """
    org_a = test_tenants["org_a"]
    admin_a = test_tenants["admin_a"]
    org_b = test_tenants["org_b"]
    admin_b = test_tenants["admin_b"]

    login_a = client.post(
        "/api/v1/auth/login",
        json={"email": admin_a.email, "password": "AlphaAdminPass123!"},
    )
    assert login_a.status_code == 200
    token_a = login_a.json()["tokens"]["access_token"]
    headers_a = {"Authorization": f"Bearer {token_a}"}

    # 1. Trigger honeypot probe
    source_ip = "198.51.100.111"
    trap_path = "/wp-admin/*"
    is_hit, probe = honeypot_service.inspect_and_record_probe(
        db=db_session,
        organization_id=org_a.id,
        path="/wp-admin/install.php",
        source_ip=source_ip,
        method="GET",
        query_string="step=2",
        user_agent="AttackBot/1.0",
        auto_recommend_block=True,
    )
    assert is_hit is True
    assert probe.correlated_incident_id is not None
    inc_id = uuid.UUID(probe.correlated_incident_id)

    # 2. Check timeline in SQLAlchemy - evidence_data MUST be a dict
    timeline = db_session.query(IncidentTimelineEntry).filter_by(
        incident_id=inc_id, entry_type="HONEYPOT_TRAP_TRIGGERED"
    ).first()
    assert timeline is not None
    assert isinstance(timeline.evidence_data, dict)
    assert timeline.evidence_data.get("probe_id") == str(probe.id)
    assert timeline.evidence_data.get("trap_path") == trap_path
    assert timeline.evidence_data.get("source_ip") == source_ip
    assert timeline.evidence_data.get("user_agent") == "AttackBot/1.0"

    # 3. Add a timeline entry with null evidence_data
    null_entry = IncidentTimelineEntry(
        id=uuid.uuid4(),
        incident_id=inc_id,
        organization_id=org_a.id,
        entry_type="ANALYST_NOTE",
        message="Analyst reviewed honeypot activity.",
        evidence_data=None,
    )
    db_session.add(null_entry)

    # 4. Add a historical timeline entry with string-encoded evidence_data
    legacy_entry = IncidentTimelineEntry(
        id=uuid.uuid4(),
        incident_id=inc_id,
        organization_id=org_a.id,
        entry_type="HISTORICAL_EVIDENCE",
        message="Legacy timeline entry with string-encoded evidence_data.",
        evidence_data='{"source_ip": "198.51.100.99", "legacy": true}',
    )
    db_session.add(legacy_entry)
    db_session.commit()

    # 5. Call GET /api/v1/monitoring/incidents/{incident_id} as Org A Admin
    res = client.get(f"/api/v1/monitoring/incidents/{inc_id}", headers=headers_a)
    assert res.status_code == 200
    detail = res.json()
    assert "timeline_entries" in detail
    entries = detail["timeline_entries"]

    # Verify honeypot timeline entry in response
    hp_entry = next((e for e in entries if e["id"] == str(timeline.id)), None)
    assert hp_entry is not None
    assert isinstance(hp_entry["evidence_data"], dict)
    assert hp_entry["evidence_data"]["probe_id"] == str(probe.id)
    assert hp_entry["evidence_data"]["trap_path"] == trap_path
    assert hp_entry["evidence_data"]["source_ip"] == source_ip
    assert hp_entry["evidence_data"]["user_agent"] == "AttackBot/1.0"

    # Verify null evidence_data serialized safely
    null_res_entry = next((e for e in entries if e["id"] == str(null_entry.id)), None)
    assert null_res_entry is not None
    assert null_res_entry["evidence_data"] is None or null_res_entry["evidence_data"] == {}

    # Verify legacy string evidence_data coerced safely to dict
    legacy_res_entry = next((e for e in entries if e["id"] == str(legacy_entry.id)), None)
    assert legacy_res_entry is not None
    assert isinstance(legacy_res_entry["evidence_data"], dict)
    assert legacy_res_entry["evidence_data"]["source_ip"] == "198.51.100.99"
    assert legacy_res_entry["evidence_data"]["legacy"] is True

    # 6. Tenant isolation: Org B Admin cannot access Org A incident detail
    login_b = client.post(
        "/api/v1/auth/login",
        json={"email": admin_b.email, "password": "BetaAdminPass123!"},
    )
    assert login_b.status_code == 200
    token_b = login_b.json()["tokens"]["access_token"]
    headers_b = {"Authorization": f"Bearer {token_b}"}

    res_b = client.get(f"/api/v1/monitoring/incidents/{inc_id}", headers=headers_b)
    assert res_b.status_code == 404

    # 7. Unauthenticated access rejected
    client.cookies.clear()
    unauth_res = client.get(f"/api/v1/monitoring/incidents/{inc_id}")
    assert unauth_res.status_code == 401
