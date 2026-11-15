"""
PREVENT-X Phase 3: Dynamic IP Blocking Integration Tests
Verifies temporary bans, auto-expiration, manual unblock, approval workflow,
incident linkage, duplicate prevention, threat-intel recommendations,
and multi-tenant isolation.
"""

import uuid
from datetime import datetime, timedelta, timezone
import pytest

from backend.app.models.monitoring import IncidentSeverity, IncidentStatus, SecurityIncident
from backend.app.models.network_defense import DynamicIPBlock, DynamicIPBlockStatus
from backend.app.models.zero_trust import ThreatIntelRecord
from backend.app.modules.network_defense.blocking.service import (
    DynamicIPBlockingService,
    dynamic_blocking_service,
)


def test_dynamic_block_creation_and_expiration_calculation(db_session, test_tenants):
    """Verifies that temporary bans compute accurate future expiration times."""
    org_a = test_tenants["org_a"]
    admin_a = test_tenants["admin_a"]

    block = dynamic_blocking_service.create_block(
        db=db_session,
        organization_id=org_a.id,
        ip_or_cidr="198.51.100.55",
        reason="Rapid SSH brute force attempt",
        duration_minutes=45,
        user_id=admin_a.id,
    )

    assert block.id is not None
    assert block.ip_or_cidr == "198.51.100.55/32"
    assert block.status == DynamicIPBlockStatus.ACTIVE
    now = datetime.now(timezone.utc)
    assert block.expires_at > now
    assert block.expires_at <= now + timedelta(minutes=46)


def test_approval_workflow_and_enforcement(db_session, test_tenants):
    """Verifies that require_approval places block in PENDING_APPROVAL until approved."""
    org_a = test_tenants["org_a"]
    admin_a = test_tenants["admin_a"]

    block = dynamic_blocking_service.create_block(
        db=db_session,
        organization_id=org_a.id,
        ip_or_cidr="203.0.113.44",
        reason="Suspicious API scanning",
        duration_minutes=30,
        require_approval=True,
        user_id=admin_a.id,
    )

    assert block.status == DynamicIPBlockStatus.PENDING_APPROVAL
    assert block.firewall_rule_id is None

    # Approve block
    approved_block = dynamic_blocking_service.approve_block(
        db=db_session,
        block_id=block.id,
        organization_id=org_a.id,
        approver_id=admin_a.id,
    )
    assert approved_block.status == DynamicIPBlockStatus.ACTIVE
    assert approved_block.approved_by_id == admin_a.id
    assert approved_block.firewall_rule_id is not None


def test_incident_linkage_and_containment(db_session, test_tenants):
    """Verifies that blocking an IP linked to an incident creates a timeline event."""
    org_a = test_tenants["org_a"]
    admin_a = test_tenants["admin_a"]

    # Create an open incident
    incident = SecurityIncident(
        organization_id=org_a.id,
        incident_number="INC-2026-001",
        title="Active Credential Stuffing Campaign",
        description="Suspicious automated credential stuffing detected",
        severity=IncidentSeverity.HIGH.value,
        status=IncidentStatus.OPEN.value,
        iocs={"source_ip": "198.51.100.77"},
    )
    db_session.add(incident)
    db_session.commit()
    db_session.refresh(incident)

    block = dynamic_blocking_service.create_block(
        db=db_session,
        organization_id=org_a.id,
        ip_or_cidr="198.51.100.77",
        reason="Automated containment for credential stuffing",
        duration_minutes=120,
        incident_id=str(incident.id),
        user_id=admin_a.id,
    )

    db_session.refresh(incident)
    assert incident.status == IncidentStatus.INVESTIGATING.value
    assert len(incident.timeline_entries) >= 1
    assert "Dynamic block" in incident.timeline_entries[0].message


def test_duplicate_prevention(db_session, test_tenants):
    """Verifies that subsequent block calls for the same IP return the existing active block."""
    org_a = test_tenants["org_a"]
    admin_a = test_tenants["admin_a"]

    b1 = dynamic_blocking_service.create_block(
        db=db_session,
        organization_id=org_a.id,
        ip_or_cidr="198.51.100.12",
        reason="Initial block",
        duration_minutes=60,
        user_id=admin_a.id,
    )
    b2 = dynamic_blocking_service.create_block(
        db=db_session,
        organization_id=org_a.id,
        ip_or_cidr="198.51.100.12",
        reason="Duplicate block attempt",
        duration_minutes=60,
        user_id=admin_a.id,
    )
    assert b1.id == b2.id


def test_manual_unblock_lifecycle(db_session, test_tenants):
    """Verifies that manual unblock transitions state and records audit reason."""
    org_a = test_tenants["org_a"]
    admin_a = test_tenants["admin_a"]

    block = dynamic_blocking_service.create_block(
        db=db_session,
        organization_id=org_a.id,
        ip_or_cidr="198.51.100.33",
        reason="Temp block for testing",
        duration_minutes=60,
        user_id=admin_a.id,
    )

    unblocked = dynamic_blocking_service.unblock_ip(
        db=db_session,
        block_id=block.id,
        organization_id=org_a.id,
        unblock_reason="False positive confirmed by customer",
        user_id=admin_a.id,
    )

    assert unblocked.status == DynamicIPBlockStatus.UNBLOCKED
    assert unblocked.unblocked_at is not None
    assert unblocked.unblocked_reason == "False positive confirmed by customer"


def test_process_expired_blocks(db_session, test_tenants):
    """Verifies that expired blocks are swept and marked EXPIRED."""
    org_a = test_tenants["org_a"]
    admin_a = test_tenants["admin_a"]

    past_time = datetime.now(timezone.utc) - timedelta(minutes=5)
    expired_block = DynamicIPBlock(
        organization_id=org_a.id,
        ip_or_cidr="198.51.100.88/32",
        reason="Past test ban",
        status=DynamicIPBlockStatus.ACTIVE,
        expires_at=past_time,
        created_by_id=admin_a.id,
    )
    db_session.add(expired_block)
    db_session.commit()

    processed_count = dynamic_blocking_service.process_expired_blocks(db_session)
    assert processed_count >= 1

    db_session.refresh(expired_block)
    assert expired_block.status == DynamicIPBlockStatus.EXPIRED


def test_threat_intel_recommendations(db_session, test_tenants):
    """Verifies that threat intel records generate actionable blocking recommendations."""
    org_a = test_tenants["org_a"]

    threat = ThreatIntelRecord(
        indicator_type="IP",
        indicator_value="198.51.100.111",
        confidence=92,
        source="CISA-Known-Exploited",
        description="Active C2 node probing Indian banking APIs",
        is_active=True,
    )
    db_session.add(threat)
    db_session.commit()

    recs = dynamic_blocking_service.get_recommendations(db_session, org_a.id)
    assert any(r["ip_or_cidr"] == "198.51.100.111" for r in recs)


def test_dynamic_blocking_api_and_tenant_isolation(client, db_session, test_tenants):
    """Verifies API endpoints and multi-tenant isolation for dynamic blocking."""
    org_a = test_tenants["org_a"]
    org_b = test_tenants["org_b"]
    admin_a = test_tenants["admin_a"]
    admin_b = test_tenants["admin_b"]

    # Log in as Tenant A
    login_a = client.post("/api/v1/auth/login", json={"email": admin_a.email, "password": "AlphaAdminPass123!"})
    token_a = login_a.json()["tokens"]["access_token"]
    headers_a = {"Authorization": f"Bearer {token_a}"}

    # Create block
    create_res = client.post(
        "/api/v1/network-defense/blocking/blocks",
        json={
            "ip_or_cidr": "198.51.100.222",
            "reason": "Hostile port scan detected",
            "duration_minutes": 180,
            "threat_intel_score": 85.0,
            "require_approval": False,
        },
        headers=headers_a,
    )
    assert create_res.status_code == 201
    block_id = create_res.json()["id"]

    # List blocks as Tenant A
    list_a = client.get("/api/v1/network-defense/blocking/blocks", headers=headers_a)
    assert list_a.status_code == 200
    ids_a = [b["id"] for b in list_a.json()]
    assert block_id in ids_a

    # Log in as Tenant B and verify isolation
    login_b = client.post("/api/v1/auth/login", json={"email": admin_b.email, "password": "BetaAdminPass123!"})
    token_b = login_b.json()["tokens"]["access_token"]
    headers_b = {"Authorization": f"Bearer {token_b}"}

    list_b = client.get("/api/v1/network-defense/blocking/blocks", headers=headers_b)
    ids_b = [b["id"] for b in list_b.json()]
    assert block_id not in ids_b

    # Tenant B cannot access or unblock Tenant A's block
    get_cross = client.get(f"/api/v1/network-defense/blocking/blocks/{block_id}", headers=headers_b)
    assert get_cross.status_code == 404

    # Unblock as Tenant A
    unblock_res = client.post(
        f"/api/v1/network-defense/blocking/blocks/{block_id}/unblock",
        json={"reason": "Manual operator relief"},
        headers=headers_a,
    )
    assert unblock_res.status_code == 200
    assert unblock_res.json()["status"] == "UNBLOCKED"
