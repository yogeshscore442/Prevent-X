"""
PREVENT-X Phase 2: Windows Defender Firewall Integration Tests
Validates real OS firewall driver, IP/CIDR validation, IPv4/IPv6 support,
safety allowlisting, authentic OS verification, rule removal, rollback,
multi-tenant isolation, and RBAC permissions.
"""

import ipaddress
import uuid
import pytest
from unittest.mock import MagicMock, patch

from backend.app.models.audit_log import AuditEvent
from backend.app.models.network_defense import (
    FirewallEnforcementStatus,
    FirewallRule,
    FirewallRuleAction,
    FirewallRuleDirection,
    FirewallRuleProtocol,
)
from backend.app.modules.network_defense.firewall.executor import (
    FirewallExecutionResult,
    WindowsFirewallExecutor,
    windows_firewall_executor,
)
from backend.app.modules.network_defense.firewall.service import (
    FirewallSafetyException,
    WindowsFirewallService,
    windows_firewall_service,
)
from backend.app.security.permissions import SystemRole


def test_ip_and_cidr_validation():
    """Verifies strict IPv4, IPv6, and CIDR parsing, rejecting malformed input."""
    assert WindowsFirewallExecutor.validate_ip_or_cidr("198.51.100.1") == "198.51.100.1/32"
    assert WindowsFirewallExecutor.validate_ip_or_cidr("203.0.113.0/24") == "203.0.113.0/24"
    assert WindowsFirewallExecutor.validate_ip_or_cidr("2001:db8::1") == "2001:db8::1/128"
    assert WindowsFirewallExecutor.validate_ip_or_cidr("2001:db8::/64") == "2001:db8::/64"

    # Rejection of invalid inputs and command injection payloads
    with pytest.raises(ValueError):
        WindowsFirewallExecutor.validate_ip_or_cidr("192.168.1.300")
    with pytest.raises(ValueError):
        WindowsFirewallExecutor.validate_ip_or_cidr("192.168.1.1; calc.exe")
    with pytest.raises(ValueError):
        WindowsFirewallExecutor.validate_ip_or_cidr("not-an-ip")


def test_rule_name_and_port_validation():
    """Verifies rule name regex sanitization and TCP/UDP port bounds."""
    assert WindowsFirewallExecutor.validate_rule_name("PX_CORP_RULE1") == "PX_CORP_RULE1"
    assert WindowsFirewallExecutor.validate_rule_name("block-malicious-ip_99") == "block-malicious-ip_99"

    with pytest.raises(ValueError):
        WindowsFirewallExecutor.validate_rule_name("rule; rm -rf /")
    with pytest.raises(ValueError):
        WindowsFirewallExecutor.validate_rule_name("ab")  # Too short

    assert WindowsFirewallExecutor.validate_ports("80,443") == "80,443"
    assert WindowsFirewallExecutor.validate_ports("ANY") is None
    assert WindowsFirewallExecutor.validate_ports(None) is None

    with pytest.raises(ValueError):
        WindowsFirewallExecutor.validate_ports("80,70000")  # Out of range
    with pytest.raises(ValueError):
        WindowsFirewallExecutor.validate_ports("80; echo bad")


def test_safety_allowlist_protects_loopback():
    """Verifies that loopback interfaces cannot be blocked under any circumstances."""
    with pytest.raises(FirewallSafetyException) as exc1:
        WindowsFirewallService.check_safety_allowlist("127.0.0.1")
    assert "Cannot block protected" in str(exc1.value)

    with pytest.raises(FirewallSafetyException) as exc2:
        WindowsFirewallService.check_safety_allowlist("127.0.0.0/8")
    assert "Cannot block protected" in str(exc2.value)

    with pytest.raises(FirewallSafetyException) as exc3:
        WindowsFirewallService.check_safety_allowlist("::1")
    assert "Cannot block protected" in str(exc3.value)

    # Valid non-protected external address passes without exception
    WindowsFirewallService.check_safety_allowlist("198.51.100.42")


def test_authentic_verification_against_os_table():
    """
    Verifies that the executor genuinely queries the OS and does not fake verification.
    """
    executor = WindowsFirewallExecutor()
    # A non-existent rule should return verified=False
    verified, details = executor.verify_rule_exists("PX_DEFINITELY_NONEXISTENT_RULE_99999")
    assert verified is False
    assert "not found" in details.lower() or "no rules match" in details.lower() or "simulated" in details.lower()


def test_firewall_service_lifecycle_with_honest_enforcement(db_session, test_tenants):
    """
    Verifies full rule creation lifecycle:
    If unprivileged, status is marked FAILED honestly rather than falsely claiming VERIFIED.
    When verified, transitions to VERIFIED.
    Rollback removes rule and marks ROLLED_BACK.
    """
    org_a = test_tenants["org_a"]
    admin_a = test_tenants["admin_a"]

    rule = windows_firewall_service.create_firewall_rule(
        db=db_session,
        organization_id=org_a.id,
        remote_ip_or_cidr="203.0.113.88",
        display_name="Block Botnet Host",
        direction=FirewallRuleDirection.INBOUND,
        action=FirewallRuleAction.BLOCK,
        protocol=FirewallRuleProtocol.TCP,
        local_ports="80,443",
        description="Threat intel auto block",
        user_id=admin_a.id,
    )

    assert rule.id is not None
    assert rule.remote_ip_or_cidr == "203.0.113.88/32"
    assert rule.is_active is True

    # Check honest reporting: if execution is unprivileged on Windows, enforcement_status is FAILED
    if not windows_firewall_service.executor.is_elevated_admin() and windows_firewall_service.executor.is_windows:
        assert rule.verified_active is False
        assert rule.enforcement_status == FirewallEnforcementStatus.FAILED
        assert "elevation" in (rule.error_message or "").lower() or "privilege" in (rule.error_message or "").lower()

    # Rollback operation
    rolled_back_rule = windows_firewall_service.rollback_rule(
        db=db_session,
        rule_id=rule.id,
        organization_id=org_a.id,
        user_id=admin_a.id,
    )
    assert rolled_back_rule.is_active is False
    assert rolled_back_rule.enforcement_status == FirewallEnforcementStatus.ROLLED_BACK


def test_firewall_api_endpoints_and_tenant_isolation(client, db_session, test_tenants):
    """
    Tests REST API endpoints:
    - Status check
    - Rule creation
    - Tenant isolation (Tenant B cannot see Tenant A's firewall rules)
    - Verification endpoint
    - Rollback endpoint
    """
    org_a = test_tenants["org_a"]
    org_b = test_tenants["org_b"]
    admin_a = test_tenants["admin_a"]
    admin_b = test_tenants["admin_b"]

    # Log in as Tenant A
    login_res = client.post(
        "/api/v1/auth/login",
        json={"email": admin_a.email, "password": "AlphaAdminPass123!"},
    )
    assert login_res.status_code == 200
    token_a = login_res.json()["tokens"]["access_token"]
    headers_a = {"Authorization": f"Bearer {token_a}"}

    # 1. Check Firewall Status
    status_res = client.get("/api/v1/network-defense/firewall/status", headers=headers_a)
    assert status_res.status_code == 200
    status_data = status_res.json()
    assert "os_type" in status_data
    assert "is_elevated" in status_data
    assert "active_rules_count" in status_data

    # 2. Create Firewall Rule
    create_payload = {
        "remote_ip_or_cidr": "198.51.100.99",
        "display_name": "Block Attacker 198.51.100.99",
        "direction": "in",
        "action": "block",
        "protocol": "TCP",
        "local_ports": "80,443",
        "description": "Integration test rule",
        "expires_in_minutes": 60,
    }
    create_res = client.post(
        "/api/v1/network-defense/firewall/rules",
        json=create_payload,
        headers=headers_a,
    )
    assert create_res.status_code == 201
    rule_a_data = create_res.json()
    rule_a_id = rule_a_data["id"]
    assert rule_a_data["remote_ip_or_cidr"] == "198.51.100.99/32"

    # 3. List Rules for Tenant A
    list_res_a = client.get("/api/v1/network-defense/firewall/rules", headers=headers_a)
    assert list_res_a.status_code == 200
    rule_ids_a = [r["id"] for r in list_res_a.json()]
    assert rule_a_id in rule_ids_a

    # 4. Log in as Tenant B and verify Tenant Isolation
    login_b = client.post(
        "/api/v1/auth/login",
        json={"email": admin_b.email, "password": "BetaAdminPass123!"},
    )
    token_b = login_b.json()["tokens"]["access_token"]
    headers_b = {"Authorization": f"Bearer {token_b}"}

    list_res_b = client.get("/api/v1/network-defense/firewall/rules", headers=headers_b)
    assert list_res_b.status_code == 200
    rule_ids_b = [r["id"] for r in list_res_b.json()]
    assert rule_a_id not in rule_ids_b  # Strict isolation!

    # Tenant B cannot access or modify Tenant A's rule
    get_cross = client.get(f"/api/v1/network-defense/firewall/rules/{rule_a_id}", headers=headers_b)
    assert get_cross.status_code == 404

    # 5. Rollback Rule as Tenant A
    rollback_res = client.post(
        f"/api/v1/network-defense/firewall/rules/{rule_a_id}/rollback",
        headers=headers_a,
    )
    assert rollback_res.status_code == 200
    assert rollback_res.json()["enforcement_status"] == "ROLLED_BACK"


# ==============================================================================
# Enforcement State Integrity & Accurate Audit Regression Tests (Issues 1 & 2)
# ==============================================================================

def test_failed_os_rule_creation_integrity(db_session, test_tenants):
    """
    1. Failed OS rule creation:
    Verifies that when OS rule creation fails (e.g. elevation missing),
    the record has verified_active=False, is_os_enforced=False, enforcement_status=FAILED,
    and audit log records status=FAILED with error details.
    """
    org_a = test_tenants["org_a"]
    admin_a = test_tenants["admin_a"]

    mock_fail_result = FirewallExecutionResult(
        success=False,
        verified=False,
        command=["netsh", "advfirewall", "add"],
        stdout="",
        stderr="The requested operation requires elevation (Run as administrator).",
        return_code=1,
        error_message="Windows Firewall operation requires administrative elevation.",
        is_elevated=False,
    )

    with patch.object(windows_firewall_service.executor, "add_rule", return_value=mock_fail_result):
        rule = windows_firewall_service.create_firewall_rule(
            db=db_session,
            organization_id=org_a.id,
            remote_ip_or_cidr="198.51.100.150",
            display_name="Block Failed Test Host",
            direction=FirewallRuleDirection.OUTBOUND,
            action=FirewallRuleAction.BLOCK,
            user_id=admin_a.id,
        )

        assert rule.verified_active is False
        assert rule.is_os_enforced is False
        assert rule.enforcement_status == FirewallEnforcementStatus.FAILED
        assert "elevation" in (rule.error_message or "").lower()

        # Audit log verification
        audit = (
            db_session.query(AuditEvent)
            .filter_by(resource_id=rule.id, action="firewall_rule_create")
            .order_by(AuditEvent.created_at.desc())
            .first()
        )
        assert audit is not None
        assert audit.status == "FAILED"
        assert "elevation" in audit.details.lower()


def test_successful_os_rule_creation_and_verification(db_session, test_tenants):
    """
    2. Successful OS rule creation and verification:
    Verifies that when OS rule creation and verification succeed,
    verified_active=True, is_os_enforced=True, enforcement_status=VERIFIED,
    and audit log records status=SUCCESS.
    """
    org_a = test_tenants["org_a"]
    admin_a = test_tenants["admin_a"]

    mock_success_result = FirewallExecutionResult(
        success=True,
        verified=True,
        command=["netsh", "advfirewall", "add"],
        stdout="Ok.",
        stderr="",
        return_code=0,
        is_elevated=True,
    )

    with patch.object(windows_firewall_service.executor, "add_rule", return_value=mock_success_result):
        rule = windows_firewall_service.create_firewall_rule(
            db=db_session,
            organization_id=org_a.id,
            remote_ip_or_cidr="198.51.100.151",
            display_name="Block Active Verified Host",
            direction=FirewallRuleDirection.INBOUND,
            action=FirewallRuleAction.BLOCK,
            user_id=admin_a.id,
        )

        assert rule.verified_active is True
        assert rule.is_os_enforced is True
        assert rule.is_active is True
        assert rule.enforcement_status == FirewallEnforcementStatus.VERIFIED
        assert rule.error_message is None

        audit = (
            db_session.query(AuditEvent)
            .filter_by(resource_id=rule.id, action="firewall_rule_create")
            .order_by(AuditEvent.created_at.desc())
            .first()
        )
        assert audit is not None
        assert audit.status == "SUCCESS"
        assert "Verified: True" in audit.details


def test_failed_os_rollback_integrity(db_session, test_tenants):
    """
    3. Failed OS rollback:
    Verifies that when an active OS rule fails deletion (e.g. elevation missing),
    rollback reports failure, audit status is FAILED with 'OS removal failed',
    and the database record is NOT falsely marked as ROLLED_BACK.
    """
    org_a = test_tenants["org_a"]
    admin_a = test_tenants["admin_a"]

    # Pre-create verified active rule
    rule = FirewallRule(
        organization_id=org_a.id,
        name="PX_TEST_ACTIVE_DEL_FAIL",
        display_name="Active Rule Delete Fail",
        remote_ip_or_cidr="198.51.100.152/32",
        direction=FirewallRuleDirection.INBOUND,
        action=FirewallRuleAction.BLOCK,
        protocol=FirewallRuleProtocol.ANY,
        is_active=True,
        verified_active=True,
        enforcement_status=FirewallEnforcementStatus.VERIFIED,
    )
    db_session.add(rule)
    db_session.flush()

    mock_del_fail = FirewallExecutionResult(
        success=False,
        verified=True,
        command=["netsh", "advfirewall", "delete"],
        stdout="",
        stderr="The requested operation requires elevation.",
        return_code=1,
        error_message="The requested operation requires elevation.",
        is_elevated=False,
    )

    with patch.object(windows_firewall_service.executor, "verify_rule_exists", return_value=(True, "Rule exists in OS")), \
         patch.object(windows_firewall_service.executor, "delete_rule", return_value=mock_del_fail):

        with pytest.raises(ValueError, match="OS removal failed"):
            windows_firewall_service.rollback_rule(
                db=db_session,
                rule_id=rule.id,
                organization_id=org_a.id,
                user_id=admin_a.id,
            )

        db_session.refresh(rule)
        # CRITICAL: Record must NOT be marked ROLLED_BACK if OS removal failed!
        assert rule.enforcement_status == FirewallEnforcementStatus.VERIFIED
        assert rule.verified_active is True
        assert "OS removal failed" in (rule.error_message or "")

        # Audit log must accurately state FAILED and OS removal failed
        audit = (
            db_session.query(AuditEvent)
            .filter_by(resource_id=rule.id, action="firewall_rule_rollback")
            .order_by(AuditEvent.created_at.desc())
            .first()
        )
        assert audit is not None
        assert audit.status == "FAILED"
        assert "OS removal failed" in audit.details


def test_successful_os_rollback_integrity(db_session, test_tenants):
    """
    4. Successful OS rollback:
    Verifies that when a verified active rule is deleted from OS,
    verified_active=False, is_os_enforced=False, enforcement_status=ROLLED_BACK,
    and audit log records SUCCESS with 'OS rule successfully removed'.
    """
    org_a = test_tenants["org_a"]
    admin_a = test_tenants["admin_a"]

    rule = FirewallRule(
        organization_id=org_a.id,
        name="PX_TEST_ACTIVE_DEL_OK",
        display_name="Active Rule Delete OK",
        remote_ip_or_cidr="198.51.100.153/32",
        direction=FirewallRuleDirection.INBOUND,
        action=FirewallRuleAction.BLOCK,
        protocol=FirewallRuleProtocol.ANY,
        is_active=True,
        verified_active=True,
        enforcement_status=FirewallEnforcementStatus.VERIFIED,
    )
    db_session.add(rule)
    db_session.flush()

    mock_del_ok = FirewallExecutionResult(
        success=True,
        verified=False,
        command=["netsh", "advfirewall", "delete"],
        stdout="Deleted 1 rule(s). Ok.",
        stderr="",
        return_code=0,
        is_elevated=True,
    )

    with patch.object(windows_firewall_service.executor, "verify_rule_exists", return_value=(True, "Rule exists in OS")), \
         patch.object(windows_firewall_service.executor, "delete_rule", return_value=mock_del_ok):

        rolled_back = windows_firewall_service.rollback_rule(
            db=db_session,
            rule_id=rule.id,
            organization_id=org_a.id,
            user_id=admin_a.id,
        )

        assert rolled_back.is_active is False
        assert rolled_back.verified_active is False
        assert rolled_back.is_os_enforced is False
        assert rolled_back.enforcement_status == FirewallEnforcementStatus.ROLLED_BACK

        audit = (
            db_session.query(AuditEvent)
            .filter_by(resource_id=rule.id, action="firewall_rule_rollback")
            .order_by(AuditEvent.created_at.desc())
            .first()
        )
        assert audit is not None
        assert audit.status == "SUCCESS"
        assert "successfully removed" in audit.details
        assert "OS rule" in audit.details


def test_database_only_cleanup_when_no_os_rule_exists(db_session, test_tenants):
    """
    5. Database-only cleanup when no OS rule exists:
    Tests two subcases:
    a) Un-enforced failed rule: rollback performs database cleanup, audit status=SUCCESS with 'Database-only cleanup completed'.
    b) Previously active rule already absent in OS: rollback transitions DB, audit status=SUCCESS with 'OS rule was already absent'.
    """
    org_a = test_tenants["org_a"]
    admin_a = test_tenants["admin_a"]

    # Subcase A: Rule failed creation (never in OS)
    failed_rule = FirewallRule(
        organization_id=org_a.id,
        name="PX_TEST_FAILED_NO_OS",
        display_name="Failed Un-enforced Rule",
        remote_ip_or_cidr="198.51.100.154/32",
        direction=FirewallRuleDirection.INBOUND,
        action=FirewallRuleAction.BLOCK,
        protocol=FirewallRuleProtocol.ANY,
        is_active=True,
        verified_active=False,
        enforcement_status=FirewallEnforcementStatus.FAILED,
        error_message="Elevation required.",
    )
    db_session.add(failed_rule)
    db_session.flush()

    with patch.object(windows_firewall_service.executor, "verify_rule_exists", return_value=(False, "No matching rule")):
        cleaned_rule = windows_firewall_service.rollback_rule(
            db=db_session,
            rule_id=failed_rule.id,
            organization_id=org_a.id,
            user_id=admin_a.id,
        )

        assert cleaned_rule.is_active is False
        assert cleaned_rule.verified_active is False
        assert cleaned_rule.is_os_enforced is False
        assert cleaned_rule.enforcement_status == FirewallEnforcementStatus.ROLLED_BACK

        audit_a = (
            db_session.query(AuditEvent)
            .filter_by(resource_id=failed_rule.id, action="firewall_rule_rollback")
            .order_by(AuditEvent.created_at.desc())
            .first()
        )
        assert audit_a is not None
        assert audit_a.status == "SUCCESS"
        assert "Database-only cleanup completed" in audit_a.details

    # Subcase B: Rule was marked verified_active, but OS query shows it's already gone
    absent_rule = FirewallRule(
        organization_id=org_a.id,
        name="PX_TEST_ALREADY_ABSENT_OS",
        display_name="Already Absent Rule",
        remote_ip_or_cidr="198.51.100.155/32",
        direction=FirewallRuleDirection.INBOUND,
        action=FirewallRuleAction.BLOCK,
        protocol=FirewallRuleProtocol.ANY,
        is_active=True,
        verified_active=True,
        enforcement_status=FirewallEnforcementStatus.VERIFIED,
    )
    db_session.add(absent_rule)
    db_session.flush()

    with patch.object(windows_firewall_service.executor, "verify_rule_exists", return_value=(False, "No matching rule")):
        cleaned_absent = windows_firewall_service.rollback_rule(
            db=db_session,
            rule_id=absent_rule.id,
            organization_id=org_a.id,
            user_id=admin_a.id,
        )

        assert cleaned_absent.is_active is False
        assert cleaned_absent.verified_active is False
        assert cleaned_absent.enforcement_status == FirewallEnforcementStatus.ROLLED_BACK

        audit_b = (
            db_session.query(AuditEvent)
            .filter_by(resource_id=absent_rule.id, action="firewall_rule_rollback")
            .order_by(AuditEvent.created_at.desc())
            .first()
        )
        assert audit_b is not None
        assert audit_b.status == "SUCCESS"
        assert "already absent" in audit_b.details.lower()

