"""
PREVENT-X Dynamic IP Blocking Service
Provides automated temporary bans, expiration lifecycle, approval workflows,
incident containment integration, and threat-intelligence-based recommendations.
"""

import ipaddress
import logging
import uuid
from datetime import datetime, timedelta, timezone
from typing import Dict, List, Optional, Tuple

from sqlalchemy import and_, or_, select
from sqlalchemy.orm import Session

from backend.app.models.audit_log import AuditEvent
from backend.app.models.monitoring import (
    IncidentSeverity,
    IncidentStatus,
    IncidentTimelineEntry,
    SecurityIncident,
)
from backend.app.models.network_defense import (
    DynamicIPBlock,
    DynamicIPBlockStatus,
    FirewallEnforcementStatus,
    FirewallRule,
    FirewallRuleAction,
    FirewallRuleDirection,
    FirewallRuleProtocol,
)
from backend.app.models.zero_trust import ThreatIntelRecord
from backend.app.modules.network_defense.firewall.executor import (
    WindowsFirewallExecutor,
    windows_firewall_executor,
)
from backend.app.modules.network_defense.firewall.service import (
    FirewallSafetyException,
    WindowsFirewallService,
    windows_firewall_service,
)

logger = logging.getLogger("preventx.network_defense.blocking")


class DynamicIPBlockingService:
    def __init__(self, fw_service: Optional[WindowsFirewallService] = None):
        self.fw_service = fw_service or windows_firewall_service

    def create_block(
        self,
        db: Session,
        organization_id: uuid.UUID,
        ip_or_cidr: str,
        reason: str,
        duration_minutes: int = 60,
        incident_id: Optional[str] = None,
        threat_intel_score: Optional[float] = None,
        require_approval: bool = False,
        user_id: Optional[uuid.UUID] = None,
    ) -> DynamicIPBlock:
        """
        Creates a dynamic IP block with automatic expiration.
        If approval is required, stays in PENDING_APPROVAL until an analyst approves.
        Otherwise, immediately creates the underlying OS firewall rule.
        """
        # Validate target format and safety
        self.fw_service.check_safety_allowlist(ip_or_cidr)
        normalized_ip = self.fw_service.executor.validate_ip_or_cidr(ip_or_cidr)

        now = datetime.now(timezone.utc)
        expires_at = now + timedelta(minutes=duration_minutes)

        # 1. Duplicate Prevention
        existing = db.execute(
            select(DynamicIPBlock).where(
                and_(
                    DynamicIPBlock.organization_id == organization_id,
                    DynamicIPBlock.ip_or_cidr == normalized_ip,
                    DynamicIPBlock.status.in_([
                        DynamicIPBlockStatus.ACTIVE,
                        DynamicIPBlockStatus.PENDING_APPROVAL,
                    ]),
                )
            )
        ).scalar_one_or_none()

        if existing:
            logger.info("Active or pending block already exists for %s in org %s", normalized_ip, organization_id)
            return existing

        initial_status = DynamicIPBlockStatus.PENDING_APPROVAL if require_approval else DynamicIPBlockStatus.ACTIVE

        block = DynamicIPBlock(
            organization_id=organization_id,
            ip_or_cidr=normalized_ip,
            reason=reason,
            incident_id=incident_id,
            threat_intel_score=threat_intel_score,
            status=initial_status,
            expires_at=expires_at,
            created_by_id=user_id,
        )
        db.add(block)
        db.flush()

        # If immediate enforcement:
        if initial_status == DynamicIPBlockStatus.ACTIVE:
            fw_rule = self.fw_service.create_firewall_rule(
                db=db,
                organization_id=organization_id,
                remote_ip_or_cidr=normalized_ip,
                display_name=f"Dynamic Block: {normalized_ip}",
                direction=FirewallRuleDirection.INBOUND,
                action=FirewallRuleAction.BLOCK,
                protocol=FirewallRuleProtocol.ANY,
                description=f"Auto-block expiring at {expires_at.isoformat()}. Reason: {reason}",
                expires_at=expires_at,
                user_id=user_id,
            )
            block.firewall_rule_id = fw_rule.id

        # 2. Incident Correlation & Timeline Update
        if incident_id:
            incident = db.get(SecurityIncident, incident_id)
            if incident and incident.organization_id == organization_id:
                timeline = IncidentTimelineEntry(
                    incident_id=incident.id,
                    organization_id=organization_id,
                    entry_type="CONTAINMENT_ACTION",
                    actor_user_id=user_id,
                    message=f"Dynamic block placed on hostile IP {normalized_ip} for {duration_minutes}m. Status: {initial_status.value}.",
                )
                db.add(timeline)
                if initial_status == DynamicIPBlockStatus.ACTIVE and incident.status == IncidentStatus.OPEN:
                    incident.status = IncidentStatus.INVESTIGATING

        # 3. Audit Log
        audit = AuditEvent(
            organization_id=organization_id,
            user_id=user_id,
            action="dynamic_ip_block_create",
            resource_type="dynamic_ip_block",
            resource_id=block.id,
            status="SUCCESS",
            details=f"Target: {normalized_ip}, Status: {initial_status.value}, Duration: {duration_minutes}m, Reason: {reason}",
        )
        db.add(audit)
        db.commit()
        db.refresh(block)
        return block

    def approve_block(
        self,
        db: Session,
        block_id: str,
        organization_id: uuid.UUID,
        approver_id: uuid.UUID,
    ) -> DynamicIPBlock:
        """
        Approves a pending block and enforces it in the OS Firewall.
        """
        block = db.execute(
            select(DynamicIPBlock).where(
                and_(DynamicIPBlock.id == block_id, DynamicIPBlock.organization_id == organization_id)
            )
        ).scalar_one_or_none()
        if not block:
            raise ValueError(f"Dynamic block '{block_id}' not found.")

        if block.status != DynamicIPBlockStatus.PENDING_APPROVAL:
            raise ValueError(f"Block is not pending approval (current status: {block.status.value}).")

        # Create OS firewall rule
        fw_rule = self.fw_service.create_firewall_rule(
            db=db,
            organization_id=organization_id,
            remote_ip_or_cidr=block.ip_or_cidr,
            display_name=f"Approved Dynamic Block: {block.ip_or_cidr}",
            direction=FirewallRuleDirection.INBOUND,
            action=FirewallRuleAction.BLOCK,
            protocol=FirewallRuleProtocol.ANY,
            description=f"Approved block expiring at {block.expires_at.isoformat()}. Reason: {block.reason}",
            expires_at=block.expires_at,
            user_id=approver_id,
        )

        block.status = DynamicIPBlockStatus.ACTIVE
        block.approved_by_id = approver_id
        block.firewall_rule_id = fw_rule.id

        if block.incident_id:
            incident = db.get(SecurityIncident, block.incident_id)
            if incident and incident.organization_id == organization_id:
                timeline = IncidentTimelineEntry(
                    incident_id=incident.id,
                    organization_id=organization_id,
                    entry_type="CONTAINMENT_ACTION",
                    actor_user_id=approver_id,
                    message=f"Dynamic block on {block.ip_or_cidr} approved and enforced in OS firewall.",
                )
                db.add(timeline)

        audit = AuditEvent(
            organization_id=organization_id,
            user_id=approver_id,
            action="dynamic_ip_block_approve",
            resource_type="dynamic_ip_block",
            resource_id=block.id,
            status="SUCCESS",
            details=f"Approved and enforced block for {block.ip_or_cidr}",
        )
        db.add(audit)
        db.commit()
        db.refresh(block)
        return block

    def unblock_ip(
        self,
        db: Session,
        block_id: str,
        organization_id: uuid.UUID,
        unblock_reason: str,
        user_id: Optional[uuid.UUID] = None,
    ) -> DynamicIPBlock:
        """
        Manually lifts an active dynamic ban and deletes the associated OS firewall rule.
        """
        block = db.execute(
            select(DynamicIPBlock).where(
                and_(DynamicIPBlock.id == block_id, DynamicIPBlock.organization_id == organization_id)
            )
        ).scalar_one_or_none()
        if not block:
            raise ValueError(f"Dynamic block '{block_id}' not found.")

        # If an active firewall rule was created, remove it
        if block.firewall_rule_id:
            try:
                self.fw_service.remove_rule(db, block.firewall_rule_id, organization_id, user_id)
            except Exception as e:
                logger.warning("Could not remove firewall rule %s during unblock: %s", block.firewall_rule_id, e)

        block.status = DynamicIPBlockStatus.UNBLOCKED
        block.unblocked_at = datetime.now(timezone.utc)
        block.unblocked_reason = unblock_reason

        if block.incident_id:
            incident = db.get(SecurityIncident, block.incident_id)
            if incident and incident.organization_id == organization_id:
                timeline = IncidentTimelineEntry(
                    incident_id=incident.id,
                    organization_id=organization_id,
                    entry_type="CONTAINMENT_ACTION",
                    actor_user_id=user_id,
                    message=f"Manual unblock for {block.ip_or_cidr}: {unblock_reason}",
                )
                db.add(timeline)

        audit = AuditEvent(
            organization_id=organization_id,
            user_id=user_id,
            action="dynamic_ip_unblock",
            resource_type="dynamic_ip_block",
            resource_id=block.id,
            status="SUCCESS",
            details=f"Unblocked {block.ip_or_cidr}. Reason: {unblock_reason}",
        )
        db.add(audit)
        db.commit()
        db.refresh(block)
        return block

    def process_expired_blocks(self, db: Session) -> int:
        """
        Scans for expired dynamic blocks and deactivates their OS firewall rules.
        """
        now = datetime.now(timezone.utc)
        expired = db.execute(
            select(DynamicIPBlock).where(
                and_(
                    DynamicIPBlock.status == DynamicIPBlockStatus.ACTIVE,
                    DynamicIPBlock.expires_at <= now,
                )
            )
        ).scalars().all()

        count = 0
        for block in expired:
            if block.firewall_rule_id:
                try:
                    self.fw_service.remove_rule(db, block.firewall_rule_id, block.organization_id)
                except Exception as ex:
                    logger.error("Failed to remove firewall rule for expired block %s: %s", block.id, ex)

            block.status = DynamicIPBlockStatus.EXPIRED
            block.unblocked_at = now
            block.unblocked_reason = "Automatic ban expiration."
            count += 1

        db.commit()
        return count

    def get_recommendations(self, db: Session, organization_id: uuid.UUID) -> List[Dict]:
        """
        Examines high-confidence threat intel records and open incidents to recommend dynamic bans.
        """
        threats = db.execute(
            select(ThreatIntelRecord).where(
                ThreatIntelRecord.is_active == True,
            ).order_by(ThreatIntelRecord.confidence.desc()).limit(10)
        ).scalars().all()

        active_blocks = {
            b.ip_or_cidr for b in db.execute(
                select(DynamicIPBlock).where(
                    and_(
                        DynamicIPBlock.organization_id == organization_id,
                        DynamicIPBlock.status.in_([DynamicIPBlockStatus.ACTIVE, DynamicIPBlockStatus.PENDING_APPROVAL]),
                    )
                )
            ).scalars().all()
        }

        recommendations = []
        for t in threats:
            val = t.indicator_value
            if not val or val in active_blocks:
                continue
            # Validate if it's an IP
            try:
                ipaddress.ip_network(val, strict=False)
            except ValueError:
                continue  # Not an IP indicator

            recommendations.append({
                "ip_or_cidr": val,
                "threat_score": float(t.confidence),
                "threat_source": t.source or "Global Threat Intel Feed",
                "recommended_action": "TEMPORARY_BLOCK",
                "suggested_duration_minutes": 1440 if t.confidence >= 80 else 120,
                "threat_description": t.description or "Hostile infrastructure probe detected.",
            })

        return recommendations


# Global dynamic blocking service instance
dynamic_blocking_service = DynamicIPBlockingService()
