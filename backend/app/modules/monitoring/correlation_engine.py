"""
PREVENT-X Intelligent Security Correlation Engine (MOD-09, MOD-12)
Correlates WAF blocks, source IP attack patterns, CVE exposure, attack paths,
and validation failures into evidence-backed Security Incidents.
"""

import logging
import uuid
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List, Optional

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from backend.app.database.base import utc_now
from backend.app.models.asset import ManagedAsset
from backend.app.models.attack_path import AttackPath
from backend.app.models.monitoring import (
    AlertCategory,
    EventCategory,
    EventSeverity,
    EventSource,
    IncidentSeverity,
    IncidentStatus,
    IncidentTimelineEntry,
    SecurityAlert,
    SecurityEvent,
    SecurityIncident,
)
from backend.app.models.vulnerability import VulnerabilityRecord, VulnerabilitySeverity

logger = logging.getLogger("preventx.monitoring.correlation")


class SecurityCorrelationEngine:
    """
    Evidence-backed correlation engine analyzing streaming and ingested events.
    Avoids duplicate incidents from repeated identical attacks.
    """

    @classmethod
    def generate_incident_number(cls, db: Session, organization_id: uuid.UUID) -> str:
        """
        Generates sequential, readable incident numbers (e.g. INC-2026-0001).
        """
        year = datetime.now(timezone.utc).year
        prefix = f"INC-{year}-"

        # Count existing incidents for this organization this year
        count = db.scalar(
            select(func.count(SecurityIncident.id)).where(
                SecurityIncident.organization_id == organization_id,
                SecurityIncident.incident_number.like(f"{prefix}%"),
            )
        ) or 0

        seq = count + 1
        return f"{prefix}{seq:04d}"

    @classmethod
    def correlate_event(
        cls,
        db: Session,
        event: SecurityEvent,
    ) -> Optional[SecurityIncident]:
        """
        Evaluates correlation rules for a single incoming security event.
        Returns the created or updated SecurityIncident, or None if no correlation triggered.
        """
        incident = None

        # Rule 1: Repeated attack patterns from single source IP
        if event.source_ip and event.source in (EventSource.WAF.value, EventSource.NGINX.value):
            incident = cls._correlate_source_ip_attacks(db, event)
            if incident:
                return incident

        # Rule 2: Attacks targeting assets with open critical vulnerabilities
        if event.asset_id and event.severity in (EventSeverity.HIGH.value, EventSeverity.CRITICAL.value):
            incident = cls._correlate_vulnerable_asset_attack(db, event)
            if incident:
                return incident

        # Rule 3: Zero Trust trust-state degradation
        if event.source == EventSource.ZERO_TRUST.value and event.severity in (EventSeverity.HIGH.value, EventSeverity.CRITICAL.value):
            incident = cls._correlate_trust_degradation(db, event)
            if incident:
                return incident

        # Rule 4: Validation / Rollback failure events
        if event.source == EventSource.VALIDATION.value and event.severity in (EventSeverity.HIGH.value, EventSeverity.CRITICAL.value):
            incident = cls._correlate_validation_failure(db, event)
            if incident:
                return incident

        return incident

    evaluate_event = correlate_event

    @classmethod
    def _correlate_source_ip_attacks(
        cls,
        db: Session,
        event: SecurityEvent,
    ) -> Optional[SecurityIncident]:
        """
        CORR-01: Aggregates repeated attack attempts from the same source IP.
        """
        window_start = utc_now() - timedelta(minutes=10)

        # Count recent attacks from this IP
        attack_count = db.scalar(
            select(func.count(SecurityEvent.id)).where(
                SecurityEvent.organization_id == event.organization_id,
                SecurityEvent.source_ip == event.source_ip,
                SecurityEvent.timestamp >= window_start,
                SecurityEvent.severity.in_([EventSeverity.HIGH.value, EventSeverity.CRITICAL.value]),
            )
        ) or 1

        # Threshold: 3 or more attacks in 10 minutes
        if attack_count < 3:
            return None

        # Check for an existing open incident for this source IP to avoid duplicates
        existing_incident = db.scalar(
            select(SecurityIncident).where(
                SecurityIncident.organization_id == event.organization_id,
                SecurityIncident.status.in_([
                    IncidentStatus.OPEN.value,
                    IncidentStatus.ACKNOWLEDGED.value,
                    IncidentStatus.INVESTIGATING.value,
                ]),
                SecurityIncident.title.like(f"%from {event.source_ip}%"),
            )
        )

        if existing_incident:
            # Update existing open incident
            existing_incident.last_seen_at = utc_now()
            rel_events = existing_incident.related_event_ids or []
            if str(event.id) not in rel_events:
                rel_events.append(str(event.id))
                existing_incident.related_event_ids = rel_events

            event.is_correlated = True
            event.incident_id = existing_incident.id

            # Add timeline note
            timeline = IncidentTimelineEntry(
                id=uuid.uuid4(),
                incident_id=existing_incident.id,
                organization_id=event.organization_id,
                entry_type="EVENT_LINKED",
                message=f"Additional hostile request from {event.source_ip} (HTTP {event.status_code} on {event.target_uri}). Total events: {len(rel_events)}.",
                evidence_data={"source_ip": event.source_ip, "target_uri": event.target_uri, "event_id": str(event.id)},
            )
            db.add(timeline)
            db.commit()
            return existing_incident

        # Create new incident
        inc_number = cls.generate_incident_number(db, event.organization_id)
        severity = IncidentSeverity.CRITICAL.value if attack_count >= 10 else IncidentSeverity.HIGH.value

        new_incident = SecurityIncident(
            id=uuid.uuid4(),
            incident_number=inc_number,
            organization_id=event.organization_id,
            title=f"High Frequency Attack from {event.source_ip}",
            description=(
                f"Detected {attack_count} hostile web application requests within a 10-minute window "
                f"originating from {event.source_ip} targeting {event.target_uri or 'web applications'}."
            ),
            severity=severity,
            status=IncidentStatus.OPEN.value,
            source="CORRELATION_ENGINE",
            primary_asset_id=event.asset_id,
            mitre_attack_id="T1190",
            mitre_technique="Exploit Public-Facing Application",
            recommended_action=f"Enforce IP-level block rule at Nginx reverse proxy gateway for {event.source_ip}.",
            containment_requires_approval=True,
            iocs={"source_ips": [event.source_ip], "target_uris": [event.target_uri] if event.target_uri else []},
            related_event_ids=[str(event.id)],
            first_seen_at=event.timestamp,
            last_seen_at=event.timestamp,
        )
        db.add(new_incident)
        db.flush()

        event.is_correlated = True
        event.incident_id = new_incident.id

        # Timeline entry
        timeline = IncidentTimelineEntry(
            id=uuid.uuid4(),
            incident_id=new_incident.id,
            organization_id=event.organization_id,
            entry_type="STATUS_CHANGE",
            message=f"Incident {inc_number} automatically opened by Correlation Engine: threshold exceeded ({attack_count} attacks from {event.source_ip}).",
            evidence_data={"initial_event_id": str(event.id), "source_ip": event.source_ip},
        )
        db.add(timeline)

        # In-app Security Alert
        alert = SecurityAlert(
            id=uuid.uuid4(),
            organization_id=event.organization_id,
            title=f"Repeated Attack Alert: {event.source_ip}",
            message=f"Incident {inc_number} created: {attack_count} attack attempts blocked from {event.source_ip}.",
            category=AlertCategory.REPEATED_WAF_ATTACKS.value,
            severity=severity,
            related_incident_id=new_incident.id,
            related_event_id=event.id,
        )
        db.add(alert)
        db.commit()
        db.refresh(new_incident)

        logger.info("Created SecurityIncident %s for source IP %s", inc_number, event.source_ip)
        return new_incident

    @classmethod
    def _correlate_vulnerable_asset_attack(
        cls,
        db: Session,
        event: SecurityEvent,
    ) -> Optional[SecurityIncident]:
        """
        CORR-02: Correlates attacks directed at assets harboring confirmed critical/high vulnerabilities.
        """
        # Check if asset has active critical vulnerabilities
        vuln_count = db.scalar(
            select(func.count(VulnerabilityRecord.id)).where(
                VulnerabilityRecord.asset_id == event.asset_id,
                VulnerabilityRecord.organization_id == event.organization_id,
                VulnerabilityRecord.severity.in_([VulnerabilitySeverity.CRITICAL.value, VulnerabilitySeverity.HIGH.value]),
            )
        ) or 0

        if vuln_count == 0:
            return None

        # Check existing open incident for this asset
        existing_incident = db.scalar(
            select(SecurityIncident).where(
                SecurityIncident.organization_id == event.organization_id,
                SecurityIncident.primary_asset_id == event.asset_id,
                SecurityIncident.status.in_([
                    IncidentStatus.OPEN.value,
                    IncidentStatus.ACKNOWLEDGED.value,
                    IncidentStatus.INVESTIGATING.value,
                ]),
                SecurityIncident.title.like("%Targeting Vulnerable Asset%"),
            )
        )

        if existing_incident:
            rel_events = existing_incident.related_event_ids or []
            if str(event.id) not in rel_events:
                rel_events.append(str(event.id))
                existing_incident.related_event_ids = rel_events
                existing_incident.last_seen_at = utc_now()
                event.is_correlated = True
                event.incident_id = existing_incident.id
                db.commit()
            return existing_incident

        asset = db.scalar(select(ManagedAsset).where(ManagedAsset.id == event.asset_id))
        asset_name = asset.name if asset else str(event.asset_id)
        inc_number = cls.generate_incident_number(db, event.organization_id)

        incident = SecurityIncident(
            id=uuid.uuid4(),
            incident_number=inc_number,
            organization_id=event.organization_id,
            title=f"Exploit Probing Targeting Vulnerable Asset ({asset_name})",
            description=(
                f"Hostile request targeting {asset_name} which has {vuln_count} unpatched critical/high vulnerabilities. "
                f"Request: {event.http_method} {event.target_uri} from {event.source_ip or 'unknown'}."
            ),
            severity=IncidentSeverity.CRITICAL.value,
            status=IncidentStatus.OPEN.value,
            source="CORRELATION_ENGINE",
            primary_asset_id=event.asset_id,
            mitre_attack_id="T1190",
            mitre_technique="Exploit Public-Facing Application",
            recommended_action="Deploy immediate compensating virtual patch and restrict public network exposure.",
            containment_requires_approval=True,
            iocs={"target_asset": asset_name, "source_ip": event.source_ip},
            related_event_ids=[str(event.id)],
            first_seen_at=event.timestamp,
            last_seen_at=event.timestamp,
        )
        db.add(incident)
        db.flush()

        event.is_correlated = True
        event.incident_id = incident.id

        timeline = IncidentTimelineEntry(
            id=uuid.uuid4(),
            incident_id=incident.id,
            organization_id=event.organization_id,
            entry_type="STATUS_CHANGE",
            message=f"Incident {inc_number} opened: exploit traffic correlated with vulnerable asset {asset_name}.",
        )
        db.add(timeline)

        alert = SecurityAlert(
            id=uuid.uuid4(),
            organization_id=event.organization_id,
            title=f"Critical Exposure Alert: {asset_name}",
            message=f"Hostile traffic detected against vulnerable asset {asset_name} (CVE count: {vuln_count}).",
            category=AlertCategory.CRITICAL_VULNERABILITY.value,
            severity=IncidentSeverity.CRITICAL.value,
            related_incident_id=incident.id,
            related_event_id=event.id,
        )
        db.add(alert)
        db.commit()
        db.refresh(incident)
        return incident

    @classmethod
    def _correlate_trust_degradation(
        cls,
        db: Session,
        event: SecurityEvent,
    ) -> Optional[SecurityIncident]:
        """
        CORR-03: Generates incident on severe Zero Trust posture degradation.
        """
        inc_number = cls.generate_incident_number(db, event.organization_id)
        incident = SecurityIncident(
            id=uuid.uuid4(),
            incident_number=inc_number,
            organization_id=event.organization_id,
            title=f"Zero Trust Posture Degradation: {event.title}",
            description=event.description,
            severity=IncidentSeverity.MEDIUM.value,
            status=IncidentStatus.OPEN.value,
            source="ZERO_TRUST_ENGINE",
            primary_asset_id=event.asset_id,
            mitre_attack_id="T1078",
            mitre_technique="Valid Accounts",
            recommended_action="Review asset identity tokens and perform manual Zero Trust verification.",
            containment_requires_approval=False,
            related_event_ids=[str(event.id)],
            first_seen_at=event.timestamp,
            last_seen_at=event.timestamp,
        )
        db.add(incident)
        db.flush()

        event.is_correlated = True
        event.incident_id = incident.id

        alert = SecurityAlert(
            id=uuid.uuid4(),
            organization_id=event.organization_id,
            title="Zero Trust Degradation Alert",
            message=f"Incident {inc_number}: {event.title}",
            category=AlertCategory.TRUST_DEGRADATION.value,
            severity=IncidentSeverity.MEDIUM.value,
            related_incident_id=incident.id,
            related_event_id=event.id,
        )
        db.add(alert)
        db.commit()
        db.refresh(incident)
        return incident

    @classmethod
    def _correlate_validation_failure(
        cls,
        db: Session,
        event: SecurityEvent,
    ) -> Optional[SecurityIncident]:
        """
        CORR-04: Generates incident on validation failure or rollback error.
        """
        inc_number = cls.generate_incident_number(db, event.organization_id)
        incident = SecurityIncident(
            id=uuid.uuid4(),
            incident_number=inc_number,
            organization_id=event.organization_id,
            title=f"Security Validation Alert: {event.title}",
            description=event.description,
            severity=IncidentSeverity.HIGH.value,
            status=IncidentStatus.OPEN.value,
            source="VALIDATION_ENGINE",
            primary_asset_id=event.asset_id,
            recommended_action="Inspect reverse proxy error logs and verify virtual patch syntax.",
            containment_requires_approval=False,
            related_event_ids=[str(event.id)],
            first_seen_at=event.timestamp,
            last_seen_at=event.timestamp,
        )
        db.add(incident)
        db.flush()

        event.is_correlated = True
        event.incident_id = incident.id

        alert = SecurityAlert(
            id=uuid.uuid4(),
            organization_id=event.organization_id,
            title="Validation / Rollback Failure Alert",
            message=f"Incident {inc_number}: {event.title}",
            category=AlertCategory.DEPLOYMENT_ROLLBACK_FAILURE.value,
            severity=IncidentSeverity.HIGH.value,
            related_incident_id=incident.id,
            related_event_id=event.id,
        )
        db.add(alert)
        db.commit()
        db.refresh(incident)
        return incident
