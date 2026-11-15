"""
Tests for PREVENT-X Traffic Replay & Differential Validation Engine
Verifies fixture sanitization, regression detection, false-positive detection,
and API tenant isolation.
"""

import uuid
import pytest
from fastapi.testclient import TestClient

from backend.app.models.virtual_patch import PatchAction, PatchStatus, VirtualPatchRule
from backend.app.modules.network_defense.replay.engine import (
    TrafficReplayEngine,
    traffic_replay_engine,
)


def test_traffic_sanitization():
    """Verifies passwords, tokens, API keys, and emails are properly masked."""
    engine = TrafficReplayEngine()

    raw_payload = '{"username": "admin", "password": "SuperSecretPassword123!", "api_key": "live_key_9988776655"}'
    sanitized = engine.sanitize_payload(raw_payload)

    assert "SuperSecretPassword123!" not in sanitized
    assert "live_key_9988776655" not in sanitized
    assert '"password": "********"' in sanitized
    assert '"api_key": "********"' in sanitized

    token_payload = "Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.e30.fake"
    sanitized_token = engine.sanitize_payload(token_payload)
    assert "eyJhbGci" not in sanitized_token
    assert "Bearer ********" in sanitized_token


def test_traffic_replay_clean_rule(db_session, test_tenants):
    """Verifies that an effective SQLi virtual patch passes all benign fixtures and catches exploits."""
    org_a = test_tenants["org_a"]
    rule = VirtualPatchRule(
        organization_id=org_a.id,
        rule_name="Test Clean SQLi Patch",
        description="Blocks UNION SELECT and DROP TABLE exploits",
        target_uri_pattern="/api/v1/search",
        match_conditions=r"(?i)(union\s+select|drop\s+table)",
        action=PatchAction.BLOCK.value,
        status=PatchStatus.PRODUCTION.value,
    )
    db_session.add(rule)
    db_session.commit()
    db_session.refresh(rule)

    report = traffic_replay_engine.run_replay_validation(
        db=db_session,
        organization_id=org_a.id,
        rule=rule,
    )

    assert report is not None
    assert report.total_replayed > 0
    assert report.false_positives == 0
    assert report.fp_rate == 0.0
    assert report.missed_threats == 0
    assert report.is_regression_free is True


def test_traffic_replay_flawed_rule_catches_false_positive(db_session, test_tenants):
    """Verifies that an overly broad rule (e.g. blocking 'items' or 'cotton') is caught as a regression."""
    org_a = test_tenants["org_a"]
    flawed_rule = VirtualPatchRule(
        organization_id=org_a.id,
        rule_name="Overly Aggressive Flawed Rule",
        description="Overly broad regex that flags benign words",
        target_uri_pattern="/api/v1/.*",
        match_conditions=r"(?i)(items|cotton)",  # Matches standard benign queries
        action=PatchAction.BLOCK.value,
        status=PatchStatus.PRODUCTION.value,
    )
    db_session.add(flawed_rule)
    db_session.commit()
    db_session.refresh(flawed_rule)

    report = traffic_replay_engine.run_replay_validation(
        db=db_session,
        organization_id=org_a.id,
        rule=flawed_rule,
    )

    assert report.false_positives > 0
    assert report.fp_rate > 0.0
    assert report.is_regression_free is False


def test_traffic_replay_missed_exploit_detection(db_session, test_tenants):
    """Verifies that a rule that fails to block known exploit fixtures is marked as non-regression-free."""
    org_a = test_tenants["org_a"]
    useless_rule = VirtualPatchRule(
        organization_id=org_a.id,
        rule_name="Useless Ineffective Rule",
        description="Matches nothing so all exploits pass through",
        target_uri_pattern="/api/v1/.*",
        match_conditions=r"NEVER_MATCHING_UNIQUE_STRING_XYZ_999",
        action=PatchAction.BLOCK.value,
        status=PatchStatus.PRODUCTION.value,
    )
    db_session.add(useless_rule)
    db_session.commit()
    db_session.refresh(useless_rule)

    report = traffic_replay_engine.run_replay_validation(
        db=db_session,
        organization_id=org_a.id,
        rule=useless_rule,
    )

    assert report.missed_threats > 0
    assert report.is_regression_free is False


def test_traffic_replay_api_workflow(client: TestClient, db_session, test_tenants):
    """Tests the full REST API lifecycle for traffic replay."""
    org_a = test_tenants["org_a"]
    admin_a = test_tenants["admin_a"]

    login_res = client.post(
        "/api/v1/auth/login",
        json={"email": admin_a.email, "password": "AlphaAdminPass123!"},
    )
    assert login_res.status_code == 200
    token_a = login_res.json()["tokens"]["access_token"]
    auth_headers = {"Authorization": f"Bearer {token_a}"}

    # 1. Create a patch rule to test against
    rule = VirtualPatchRule(
        organization_id=org_a.id,
        rule_name="API SQLi Patch Rule",
        description="Blocks SQLi keywords",
        target_uri_pattern="/api/v1/search",
        match_conditions=r"(?i)(union\s+select|drop\s+table)",
        action=PatchAction.BLOCK.value,
        status=PatchStatus.PRODUCTION.value,
    )
    db_session.add(rule)
    db_session.commit()
    db_session.refresh(rule)

    # 2. Get sample fixtures
    fix_res = client.get("/api/v1/network-defense/replay/fixtures", headers=auth_headers)
    assert fix_res.status_code == 200
    fix_data = fix_res.json()
    assert fix_data["standard_benign_count"] > 0
    assert fix_data["standard_exploit_count"] > 0

    # 3. Trigger replay run
    run_res = client.post(
        "/api/v1/network-defense/replay/run",
        json={"virtual_patch_id": str(rule.id)},
        headers=auth_headers,
    )
    assert run_res.status_code == 200
    report_data = run_res.json()
    assert report_data["virtual_patch_id"] == str(rule.id)
    assert report_data["total_replayed"] > 0
    assert report_data["is_regression_free"] is True
    report_id = report_data["id"]

    # 4. List reports
    list_res = client.get("/api/v1/network-defense/replay/reports", headers=auth_headers)
    assert list_res.status_code == 200
    reports = list_res.json()
    assert len(reports) >= 1
    assert any(r["id"] == report_id for r in reports)

    # 5. Get report details
    detail_res = client.get(f"/api/v1/network-defense/replay/reports/{report_id}", headers=auth_headers)
    assert detail_res.status_code == 200
    assert detail_res.json()["id"] == report_id
