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

        # 3. Prevent duplicate active rule for the same scope and tenant
        existing = db.execute(
            select(FirewallRule).where(
                and_(
                    FirewallRule.organization_id == organization_id,
                    FirewallRule.remote_ip_or_cidr == normalized_ip,
                    FirewallRule.direction == direction,
                    FirewallRule.action == action,
                    FirewallRule.is_active == True,
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
        Rolls back / deletes the firewall rule from Windows Defender Firewall.
        """
        rule = db.execute(
            select(FirewallRule).where(
                and_(FirewallRule.id == rule_id, FirewallRule.organization_id == organization_id)
            )
        ).scalar_one_or_none()
        if not rule:
            raise ValueError(f"Firewall rule '{rule_id}' not found.")

        # Remove from Windows Defender Firewall
        del_res = self.executor.delete_rule(rule.name)

        rule.is_active = False
        rule.verified_active = False
        rule.enforcement_status = FirewallEnforcementStatus.ROLLED_BACK
        rule.error_message = del_res.error_message

        audit = AuditEvent(
            organization_id=organization_id,
            user_id=user_id,
            action="firewall_rule_rollback",
            resource_type="firewall_rule",
            resource_id=rule.id,
            status="SUCCESS" if del_res.success else "FAILED",
            details=f"Rolled back rule '{rule.name}'. Output: {del_res.stdout}. Error: {del_res.error_message}",
        )
        db.add(audit)
        db.commit()
        db.refresh(rule)
        return rule

    def remove_rule(self, db: Session, rule_id: str, organization_id: uuid.UUID, user_id: Optional[uuid.UUID] = None) -> FirewallRule:
        """
        Permanently deactivates and removes rule.
        """
        rule = db.execute(
            select(FirewallRule).where(
                and_(FirewallRule.id == rule_id, FirewallRule.organization_id == organization_id)
            )
        ).scalar_one_or_none()
        if not rule:
            raise ValueError(f"Firewall rule '{rule_id}' not found.")

        del_res = self.executor.delete_rule(rule.name)

        rule.is_active = False
        rule.verified_active = False
        rule.enforcement_status = FirewallEnforcementStatus.REMOVED
        rule.error_message = del_res.error_message

        audit = AuditEvent(
            organization_id=organization_id,
            user_id=user_id,
            action="firewall_rule_delete",
            resource_type="firewall_rule",
            resource_id=rule.id,
            status="SUCCESS" if del_res.success else "FAILED",
            details=f"Deleted rule '{rule.name}' for {rule.remote_ip_or_cidr}.",
        )
        db.add(audit)
        db.commit()
        db.refresh(rule)
        return rule

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
