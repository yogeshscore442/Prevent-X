"""
PREVENT-X Windows Defender Firewall Service
Orchestrates rule lifecycle, safety allowlists, audit logging,
expiration management, authentic verification, and rollback operations.
"""

import ipaddress
import logging
import uuid
from datetime import datetime, timezone
from typing import Dict, List, Optional, Tuple

from sqlalchemy import and_, select
from sqlalchemy.orm import Session

from backend.app.models.audit_log import AuditEvent
from backend.app.models.network_defense import (
    FirewallEnforcementStatus,
    FirewallRule,
    FirewallRuleAction,
    FirewallRuleDirection,
    FirewallRuleProtocol,
)
from backend.app.models.organization import Organization
from backend.app.modules.network_defense.firewall.executor import (
    WindowsFirewallExecutor,
    windows_firewall_executor,
)

logger = logging.getLogger("preventx.network_defense.firewall.service")

# Safety Allowlist: Addresses that MUST NEVER be blocked at the OS firewall
SYSTEM_PROTECTED_NETWORKS = [
    ipaddress.ip_network("127.0.0.0/8"),      # IPv4 loopback
    ipaddress.ip_network("::1/128"),          # IPv6 loopback
]


class FirewallSafetyException(Exception):
    """Raised when an operation attempts to block a protected or critical IP."""
    pass


class WindowsFirewallService:
    def __init__(self, executor: Optional[WindowsFirewallExecutor] = None):
        self.executor = executor or windows_firewall_executor

    @classmethod
    def check_safety_allowlist(cls, target_ip_or_cidr: str) -> None:
        """
        Ensures the requested IP/CIDR is not a protected local/loopback address.
        """
        try:
            target_net = ipaddress.ip_network(target_ip_or_cidr.strip(), strict=False)
        except ValueError as err:
            raise FirewallSafetyException(f"Invalid target IP or CIDR: {err}")

        for protected in SYSTEM_PROTECTED_NETWORKS:
            if target_net.overlaps(protected):
                raise FirewallSafetyException(
                    f"Safety Violation: Cannot block protected loopback/internal network '{protected}'."
                )

    def create_firewall_rule(
        self,
        db: Session,
        organization_id: uuid.UUID,
        remote_ip_or_cidr: str,
        display_name: str,
        direction: FirewallRuleDirection = FirewallRuleDirection.INBOUND,
        action: FirewallRuleAction = FirewallRuleAction.BLOCK,
        protocol: FirewallRuleProtocol = FirewallRuleProtocol.ANY,
        local_ports: Optional[str] = None,
        description: Optional[str] = None,
        expires_at: Optional[datetime] = None,
        user_id: Optional[uuid.UUID] = None,
    ) -> FirewallRule:
        """
        Creates a new firewall rule, enforces it against Windows Firewall, and verifies active state.
        """
        # 1. Safety Allowlist Verification
        self.check_safety_allowlist(remote_ip_or_cidr)

        # 2. Normalize and validate IP/CIDR
        normalized_ip = self.executor.validate_ip_or_cidr(remote_ip_or_cidr)

        # 3. Prevent duplicate active verified rule for the same scope and tenant
        existing = db.execute(
            select(FirewallRule).where(
                and_(
                    FirewallRule.organization_id == organization_id,
                    FirewallRule.remote_ip_or_cidr == normalized_ip,
                    FirewallRule.direction == direction,
                    FirewallRule.action == action,
                    FirewallRule.is_active == True,
                    FirewallRule.enforcement_status == FirewallEnforcementStatus.VERIFIED,
                )
            )
        ).scalar_one_or_none()

        if existing:
            logger.info("Rule for %s already exists for organization %s", normalized_ip, organization_id)
            return existing

        # 4. Generate compliant OS rule name
        org = db.get(Organization, organization_id)
        org_slug = (org.slug if org else "org")[:8].replace("-", "_")
        unique_suffix = uuid.uuid4().hex[:8]
        os_rule_name = f"PX_{org_slug}_{unique_suffix}".upper()

        # 5. Create database record
        rule = FirewallRule(
            organization_id=organization_id,
            name=os_rule_name,
            display_name=display_name,
            description=description,
            direction=direction,
            action=action,
            protocol=protocol,
            remote_ip_or_cidr=normalized_ip,
            local_ports=local_ports,
            is_active=True,
            verified_active=False,
            enforcement_status=FirewallEnforcementStatus.PENDING,
            expires_at=expires_at,
            created_by_id=user_id,
        )
        db.add(rule)
        db.flush()

        # 6. Execute against Windows Defender Firewall
        exec_res = self.executor.add_rule(
            name=os_rule_name,
            remote_ip=normalized_ip,
            direction=direction.value,
            action=action.value,
            protocol=protocol.value,
            local_ports=local_ports,
            description=description,
        )

        now = datetime.now(timezone.utc)
        if exec_res.success and exec_res.verified:
            rule.verified_active = True
            rule.enforcement_status = FirewallEnforcementStatus.VERIFIED
            rule.verification_details = exec_res.stdout
            rule.last_verified_at = now
            rule.error_message = None
        else:
            rule.verified_active = False
            rule.enforcement_status = FirewallEnforcementStatus.FAILED
            rule.error_message = exec_res.error_message or exec_res.stderr or "Enforcement failed."
            rule.verification_details = exec_res.stdout

        # 7. Audit log event
        audit = AuditEvent(
            organization_id=organization_id,
            user_id=user_id,
            action="firewall_rule_create",
            resource_type="firewall_rule",
            resource_id=rule.id,
            status="SUCCESS" if rule.verified_active else "FAILED",
            details=f"Created rule '{rule.name}' for {normalized_ip}. Verified: {rule.verified_active}. Status: {rule.enforcement_status.value}. Error: {rule.error_message}",
        )
        db.add(audit)
        db.commit()
        db.refresh(rule)
        return rule

    def verify_rule(self, db: Session, rule_id: str, organization_id: uuid.UUID) -> FirewallRule:
        """
        Re-verifies whether the rule is currently active in Windows Defender Firewall.
        """
        rule = db.execute(
            select(FirewallRule).where(
                and_(FirewallRule.id == rule_id, FirewallRule.organization_id == organization_id)
            )
        ).scalar_one_or_none()
        if not rule:
            raise ValueError(f"Firewall rule '{rule_id}' not found.")

        is_present, details = self.executor.verify_rule_exists(rule.name)
        now = datetime.now(timezone.utc)
        rule.last_verified_at = now
        rule.verification_details = details

        if is_present:
            rule.verified_active = True
            rule.enforcement_status = FirewallEnforcementStatus.VERIFIED
            rule.error_message = None
        else:
            rule.verified_active = False
            if rule.is_active:
                rule.enforcement_status = FirewallEnforcementStatus.FAILED
                rule.error_message = "Rule is marked active in database but missing in Windows Firewall table."

        db.commit()
        db.refresh(rule)
        return rule

    def rollback_rule(self, db: Session, rule_id: str, organization_id: uuid.UUID, user_id: Optional[uuid.UUID] = None) -> FirewallRule:
        """
        Rolls back / deletes the firewall rule:
        - If verified active in OS, genuinely removes it from Windows Defender Firewall.
        - If removal succeeds, records SUCCESS audit with 'OS rule successfully removed'.
        - If already absent from OS, records SUCCESS audit with 'OS rule already absent'.
        - If never active in OS (e.g. FAILED creation), performs database-only cleanup with 'Database-only cleanup completed'.
        - If OS removal fails, records FAILED audit with 'OS removal failed' and raises ValueError without marking ROLLED_BACK.
        """
        rule = db.execute(
            select(FirewallRule).where(
                and_(FirewallRule.id == rule_id, FirewallRule.organization_id == organization_id)
            )
        ).scalar_one_or_none()
        if not rule:
            raise KeyError(f"Firewall rule '{rule_id}' not found.")

        # Check if the rule actually exists in the OS firewall table
        is_os_present, _ = self.executor.verify_rule_exists(rule.name)

        if not is_os_present:
            # Rule is not in the OS firewall table
            was_verified = rule.verified_active
            rule.is_active = False
            rule.verified_active = False
            rule.enforcement_status = FirewallEnforcementStatus.ROLLED_BACK
            rule.error_message = None

            audit_details = (
                f"OS rule '{rule.name}' was already absent from Windows Defender Firewall. Database record marked rolled back."
                if was_verified
                else f"Database-only cleanup completed for un-enforced rule '{rule.name}'. No OS firewall rule was active."
            )
            audit = AuditEvent(
                organization_id=organization_id,
                user_id=user_id,
                action="firewall_rule_rollback",
                resource_type="firewall_rule",
                resource_id=rule.id,
                status="SUCCESS",
                details=audit_details,
            )
            db.add(audit)
            db.commit()
            db.refresh(rule)
            return rule

        # OS rule is present; execute deletion
        del_res = self.executor.delete_rule(rule.name)

        if del_res.success:
            rule.is_active = False
            rule.verified_active = False
            rule.enforcement_status = FirewallEnforcementStatus.ROLLED_BACK
            rule.error_message = None

            audit_details = (
                f"OS rule '{rule.name}' was already absent from Windows Defender Firewall."
                if "no rules match" in (del_res.stdout + del_res.stderr).lower()
                else f"OS rule '{rule.name}' successfully removed from Windows Defender Firewall."
            )
            audit = AuditEvent(
                organization_id=organization_id,
                user_id=user_id,
                action="firewall_rule_rollback",
                resource_type="firewall_rule",
                resource_id=rule.id,
                status="SUCCESS",
                details=audit_details,
            )
            db.add(audit)
            db.commit()
            db.refresh(rule)
            return rule
        else:
            # OS removal failed - do not mark as rolled back!
            err_msg = del_res.error_message or del_res.stderr or "OS firewall deletion failed."
            rule.error_message = f"OS removal failed: {err_msg}"
            audit = AuditEvent(
                organization_id=organization_id,
                user_id=user_id,
                action="firewall_rule_rollback",
                resource_type="firewall_rule",
                resource_id=rule.id,
                status="FAILED",
                details=f"OS removal failed for rule '{rule.name}': {err_msg}. Rule remains in OS firewall.",
            )
            db.add(audit)
            db.commit()
            db.refresh(rule)
            raise ValueError(f"OS removal failed for rule '{rule.name}': {err_msg}")

    def remove_rule(self, db: Session, rule_id: str, organization_id: uuid.UUID, user_id: Optional[uuid.UUID] = None) -> FirewallRule:
        """
        Permanently deactivates and removes rule with authentic OS removal verification.
        """
        rule = db.execute(
            select(FirewallRule).where(
                and_(FirewallRule.id == rule_id, FirewallRule.organization_id == organization_id)
            )
        ).scalar_one_or_none()
        if not rule:
            raise KeyError(f"Firewall rule '{rule_id}' not found.")

        is_os_present, _ = self.executor.verify_rule_exists(rule.name)

        if not is_os_present:
            was_verified = rule.verified_active
            rule.is_active = False
            rule.verified_active = False
            rule.enforcement_status = FirewallEnforcementStatus.REMOVED
            rule.error_message = None

            audit_details = (
                f"OS rule '{rule.name}' was already absent from Windows Defender Firewall."
                if was_verified
                else f"Database-only cleanup completed for un-enforced rule '{rule.name}'. No OS firewall rule was active."
            )
            audit = AuditEvent(
                organization_id=organization_id,
                user_id=user_id,
                action="firewall_rule_delete",
                resource_type="firewall_rule",
                resource_id=rule.id,
                status="SUCCESS",
                details=audit_details,
            )
            db.add(audit)
            db.commit()
            db.refresh(rule)
            return rule

        del_res = self.executor.delete_rule(rule.name)

        if del_res.success:
            rule.is_active = False
            rule.verified_active = False
            rule.enforcement_status = FirewallEnforcementStatus.REMOVED
            rule.error_message = None

            audit_details = (
                f"OS rule '{rule.name}' was already absent from Windows Defender Firewall."
                if "no rules match" in (del_res.stdout + del_res.stderr).lower()
                else f"OS rule '{rule.name}' successfully removed from Windows Defender Firewall."
            )
            audit = AuditEvent(
                organization_id=organization_id,
                user_id=user_id,
                action="firewall_rule_delete",
                resource_type="firewall_rule",
                resource_id=rule.id,
                status="SUCCESS",
                details=audit_details,
            )
            db.add(audit)
            db.commit()
            db.refresh(rule)
            return rule
        else:
            err_msg = del_res.error_message or del_res.stderr or "OS firewall deletion failed."
            rule.error_message = f"OS removal failed: {err_msg}"
            audit = AuditEvent(
                organization_id=organization_id,
                user_id=user_id,
                action="firewall_rule_delete",
                resource_type="firewall_rule",
                resource_id=rule.id,
                status="FAILED",
                details=f"OS removal failed for rule '{rule.name}': {err_msg}. Rule remains in OS firewall.",
            )
            db.add(audit)
            db.commit()
            db.refresh(rule)
            raise ValueError(f"OS removal failed for rule '{rule.name}': {err_msg}")

    def clean_expired_rules(self, db: Session) -> int:
        """
        Scans for expired firewall rules and automatically removes them.
        """
        now = datetime.now(timezone.utc)
        expired_rules = db.execute(
            select(FirewallRule).where(
                and_(
                    FirewallRule.is_active == True,
                    FirewallRule.expires_at <= now,
                )
            )
        ).scalars().all()

        cleaned_count = 0
        for rule in expired_rules:
            try:
                self.remove_rule(db, rule.id, rule.organization_id)
                cleaned_count += 1
            except Exception as e:
                logger.error("Failed to clean expired rule %s: %s", rule.id, e)
        return cleaned_count


# Global service instance
windows_firewall_service = WindowsFirewallService()
