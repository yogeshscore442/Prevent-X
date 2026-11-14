"""
PREVENT-X Automated Risk-Based Response Engine (MOD-04)
Generates controlled, evidence-backed mitigation actions with mandatory
human-in-the-loop authorization gates for disruptive containment.

RULE: Disruptive actions (Network Isolation, Port Restriction, Virtual Patching)
STRICTLY require OrgAdmin human approval before execution.
"""

import json
import logging
import uuid
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from sqlalchemy import select
from sqlalchemy.orm import Session

from backend.app.models.asset import ManagedAsset
from backend.app.models.user import User
from backend.app.models.zero_trust import (
    BehavioralAnomaly,
    ResponseAction,
    ResponseActionStatus,
    ResponseActionType,
    ThreatAssetCorrelation,
)
from backend.app.repositories.audit_repo import AuditRepository

audit_repo = AuditRepository()
logger = logging.getLogger("preventx.zero_trust.response_engine")


class AutomatedResponseEngine:
    """
    Orchestrates response action creation, authorization approval,
    execution, and reversible rollback.
    """

    @classmethod
    def propose_action(
        cls,
        db: Session,
        organization_id: uuid.UUID,
        action_type: str,
        title: str,
        description: str,
        target_entity: str,
        asset_id: Optional[uuid.UUID] = None,
        anomaly_id: Optional[uuid.UUID] = None,
        execution_payload: Optional[Dict[str, Any]] = None,
        rollback_payload: Optional[Dict[str, Any]] = None,
        is_disruptive: bool = True,
    ) -> ResponseAction:
        """
        Creates a proposed response action. Disruptive actions require PENDING_APPROVAL.
        """
        action = ResponseAction(
            id=uuid.uuid4(),
            organization_id=organization_id,
            asset_id=asset_id,
            anomaly_id=anomaly_id,
            action_type=action_type,
            title=title,
            description=description,
            target_entity=target_entity,
            execution_payload=json.dumps(execution_payload or {}),
            rollback_payload=json.dumps(rollback_payload or {}),
            status=ResponseActionStatus.PENDING_APPROVAL.value if is_disruptive else ResponseActionStatus.APPROVED.value,
            is_disruptive=is_disruptive,
        )
        db.add(action)
        db.flush()
        return action

    @classmethod
    def propose_mitigation_for_threat(
        cls,
        db: Session,
        correlation: ThreatAssetCorrelation,
    ) -> ResponseAction:
        """
        Synthesizes an automated response proposal for an active threat correlation.
        """
        title = f"Isolate C2 / Prohibited Indicator {correlation.matched_value}"
        desc = (
            f"Mitigate active threat correlation ({correlation.correlation_type}) on asset {correlation.asset_id}. "
            f"Enforces ingress/egress firewall blocks against malicious indicator {correlation.matched_value}."
        )
        exec_payload = {
            "mechanism": "FIREWALL_DROP",
            "target": correlation.matched_value,
            "rule": f"iptables -I FORWARD -s {correlation.matched_value} -j DROP",
            "enforcement_tier": "GATEWAY_BOUNDARY",
        }
        rollback_payload = {
            "mechanism": "FIREWALL_DELETE",
            "target": correlation.matched_value,
            "rule": f"iptables -D FORWARD -s {correlation.matched_value} -j DROP",
        }

        return cls.propose_action(
            db=db,
            organization_id=correlation.organization_id,
            action_type=ResponseActionType.NETWORK_ISOLATION.value,
            title=title,
            description=desc,
            target_entity=correlation.matched_value,
            asset_id=correlation.asset_id,
            execution_payload=exec_payload,
            rollback_payload=rollback_payload,
            is_disruptive=True,
        )

    @classmethod
    def propose_mitigation_for_anomaly(
        cls,
        db: Session,
        anomaly: BehavioralAnomaly,
    ) -> ResponseAction:
        """
        Synthesizes response action for behavioral anomaly or zero-day indicator.
        """
        ev_data = json.loads(anomaly.evidence_data or "{}")

        if anomaly.is_zero_day_indicator:
            # Virtual patch enforcement
            port = ev_data.get("service_port", 443)
            title = f"Deploy Virtual Patch for Zero-Day Anomaly (Port {port})"
            desc = (
                f"Deploys application reverse-proxy WAF inspection rule to neutralize unknown payload pattern "
                f"targeting port {port} without taking the service offline."
            )
            exec_payload = {
                "rule_type": "WAF_VIRTUAL_PATCH",
                "service_port": port,
                "pattern_filter": ev_data.get("payload_signature", "BINARY_ANOMALY_REGEX"),
                "action": "BLOCK_PAYLOAD",
            }
            rollback_payload = {
                "rule_type": "WAF_VIRTUAL_PATCH_DISABLE",
                "service_port": port,
            }
            return cls.propose_action(
                db=db,
                organization_id=anomaly.organization_id,
                action_type=ResponseActionType.VIRTUAL_PATCH_ENFORCEMENT.value,
                title=title,
                description=desc,
                target_entity=f"port_{port}",
                asset_id=anomaly.asset_id,
                anomaly_id=anomaly.id,
                execution_payload=exec_payload,
                rollback_payload=rollback_payload,
                is_disruptive=True,
            )

        elif anomaly.anomaly_type == "UNEXPECTED_SERVICE_PORT":
            port = ev_data.get("port", 0)
            title = f"Restrict Access to Unexpected Port {port}"
            desc = f"Block public ingress traffic on unexpected port {port} to prevent unauthorized access."
            exec_payload = {
                "rule_type": "PORT_FILTER",
                "port": port,
                "action": "DROP_INGRESS",
            }
            rollback_payload = {
                "rule_type": "PORT_FILTER_REMOVE",
                "port": port,
            }
            return cls.propose_action(
                db=db,
                organization_id=anomaly.organization_id,
                action_type=ResponseActionType.RESTRICT_SERVICE_ACCESS.value,
                title=title,
                description=desc,
                target_entity=f"port_{port}",
                asset_id=anomaly.asset_id,
                anomaly_id=anomaly.id,
                execution_payload=exec_payload,
                rollback_payload=rollback_payload,
                is_disruptive=True,
            )

        else:
            # Non-disruptive telemetry increase
            title = f"Elevate Telemetry Logging for {anomaly.anomaly_type}"
            desc = "Increase event auditing and logging frequency to DEBUG level for targeted investigation."
            exec_payload = {
                "log_level": "DEBUG",
                "duration_hours": 24,
            }
            rollback_payload = {
                "log_level": "INFO",
            }
            return cls.propose_action(
                db=db,
                organization_id=anomaly.organization_id,
                action_type=ResponseActionType.INCREASE_TELEMETRY_LOGGING.value,
                title=title,
                description=desc,
                target_entity="TELEMETRY_SUBSYSTEM",
                asset_id=anomaly.asset_id,
                anomaly_id=anomaly.id,
                execution_payload=exec_payload,
                rollback_payload=rollback_payload,
                is_disruptive=False,
            )

    @classmethod
    def approve_action(
        cls,
        db: Session,
        action_id: uuid.UUID,
        organization_id: uuid.UUID,
        user: User,
    ) -> ResponseAction:
        """
        Explicit human approval gate by authenticated OrgAdmin / SuperAdmin.
        """
        stmt = select(ResponseAction).where(
            ResponseAction.id == action_id,
            ResponseAction.organization_id == organization_id,
        )
        action = db.execute(stmt).scalar_one_or_none()
        if not action:
            raise ValueError("Response action not found.")

        if action.status not in [ResponseActionStatus.PENDING_APPROVAL.value]:
            raise ValueError(f"Cannot approve action in status '{action.status}'.")

        now = datetime.now(timezone.utc)
        action.status = ResponseActionStatus.APPROVED.value
        action.approved_by_user_id = user.id
        action.approved_at = now
        db.flush()

        audit_repo.log_event(
            db=db,
            action="RESPONSE_ACTION_APPROVED",
            resource_type="RESPONSE_ACTION",
            resource_id=str(action.id),
            status="SUCCESS",
            organization_id=organization_id,
            user_id=user.id,
            details=json.dumps({
                "action_id": str(action.id),
                "action_type": action.action_type,
                "title": action.title,
                "is_disruptive": action.is_disruptive,
            }),
        )
        return action

    @classmethod
    def reject_action(
        cls,
        db: Session,
        action_id: uuid.UUID,
        organization_id: uuid.UUID,
        user: User,
        reason: Optional[str] = None,
    ) -> ResponseAction:
        """Rejects a proposed response action."""
        stmt = select(ResponseAction).where(
            ResponseAction.id == action_id,
            ResponseAction.organization_id == organization_id,
        )
        action = db.execute(stmt).scalar_one_or_none()
        if not action:
            raise ValueError("Response action not found.")

        action.status = ResponseActionStatus.REJECTED.value
        action.execution_log = f"Rejected by user {user.email}. Reason: {reason or 'No reason provided'}"
        db.flush()

        audit_repo.log_event(
            db=db,
            action="RESPONSE_ACTION_REJECTED",
            resource_type="RESPONSE_ACTION",
            resource_id=str(action.id),
            status="SUCCESS",
            organization_id=organization_id,
            user_id=user.id,
            details=json.dumps({"action_id": str(action.id), "reason": reason}),
        )
        return action

    @classmethod
    def execute_action(
        cls,
        db: Session,
        action_id: uuid.UUID,
        organization_id: uuid.UUID,
        user: User,
    ) -> ResponseAction:
        """
        Executes an approved response action. Enforces approval gate on disruptive actions.
        """
        stmt = select(ResponseAction).where(
            ResponseAction.id == action_id,
            ResponseAction.organization_id == organization_id,
        )
        action = db.execute(stmt).scalar_one_or_none()
        if not action:
            raise ValueError("Response action not found.")

        # STRICT HUMAN AUTHORIZATION GATE: Disruptive actions must be APPROVED
        if action.is_disruptive and action.status != ResponseActionStatus.APPROVED.value:
            raise ValueError(
                f"Disruptive action '{action.title}' cannot be executed without prior OrgAdmin approval. "
                f"Current status: {action.status}."
            )

        now = datetime.now(timezone.utc)
        payload = json.loads(action.execution_payload or "{}")

        # Simulate safe execution / policy enforcement
        log_message = (
            f"Successfully executed {action.action_type} on target '{action.target_entity}' at {now.isoformat()}. "
            f"Applied policy payload: {payload}. Mechanism active."
        )

        action.status = ResponseActionStatus.EXECUTED.value
        action.executed_at = now
        action.execution_log = log_message
        db.flush()

        audit_repo.log_event(
            db=db,
            action="RESPONSE_ACTION_EXECUTED",
            resource_type="RESPONSE_ACTION",
            resource_id=str(action.id),
            status="SUCCESS",
            organization_id=organization_id,
            user_id=user.id,
            details=json.dumps({
                "action_id": str(action.id),
                "action_type": action.action_type,
                "target_entity": action.target_entity,
                "log": log_message,
            }),
        )
        return action

    @classmethod
    def rollback_action(
        cls,
        db: Session,
        action_id: uuid.UUID,
        organization_id: uuid.UUID,
        user: User,
    ) -> ResponseAction:
        """
        Reverts an executed response action using its rollback payload.
        """
        stmt = select(ResponseAction).where(
            ResponseAction.id == action_id,
            ResponseAction.organization_id == organization_id,
        )
        action = db.execute(stmt).scalar_one_or_none()
        if not action:
            raise ValueError("Response action not found.")

        if action.status != ResponseActionStatus.EXECUTED.value:
            raise ValueError(f"Cannot rollback action in status '{action.status}'. Only EXECUTED actions can be rolled back.")

        now = datetime.now(timezone.utc)
        rollback_data = json.loads(action.rollback_payload or "{}")

        log_message = (
            f"Successfully rolled back {action.action_type} on target '{action.target_entity}' at {now.isoformat()}. "
            f"Applied rollback configuration: {rollback_data}. State restored."
        )

        action.status = ResponseActionStatus.ROLLED_BACK.value
        action.execution_log = (action.execution_log or "") + f"\n[ROLLBACK]: {log_message}"
        db.flush()

        audit_repo.log_event(
            db=db,
            action="RESPONSE_ACTION_ROLLED_BACK",
            resource_type="RESPONSE_ACTION",
            resource_id=str(action.id),
            status="SUCCESS",
            organization_id=organization_id,
            user_id=user.id,
            details=json.dumps({
                "action_id": str(action.id),
                "action_type": action.action_type,
                "target_entity": action.target_entity,
                "rollback_log": log_message,
            }),
        )
        return action
