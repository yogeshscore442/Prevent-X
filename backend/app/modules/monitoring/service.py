"""
PREVENT-X Centralized Monitoring & Incident Management Service (MOD-09, MOD-12)
Orchestrates event ingestion, deduplication, correlation, incident lifecycle,
in-app alerts, retention pruning, and centralized executive SMB posture aggregation.
"""

import hashlib
import logging
import uuid
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List, Optional, Tuple

from sqlalchemy import delete, desc, func, or_, select, update
from sqlalchemy.orm import Session

from backend.app.database.base import utc_now
from backend.app.models.asset import ManagedAsset
from backend.app.models.attack_path import AttackPath, AttackPathStatus
from backend.app.models.monitoring import (
    AlertCategory,
    EventCategory,
    EventRetentionPolicy,
    EventSeverity,
    EventSource,
    IncidentSeverity,
    IncidentStatus,
    IncidentTimelineEntry,
    SecurityAlert,
    SecurityEvent,
    SecurityIncident,
)
from backend.app.models.security_validation import RollbackRecord, ValidationJob, ValidationJobStatus
from backend.app.models.virtual_patch import PatchStatus, VirtualPatchRule, WafEnforcementLog
from backend.app.models.vulnerability import VulnerabilityRecord, VulnerabilitySeverity
from backend.app.models.zero_trust import AssetTrustAssessment, TrustDecision
from backend.app.modules.monitoring.correlation_engine import SecurityCorrelationEngine
from backend.app.modules.monitoring.log_parser import NginxLogParser
from backend.app.modules.monitoring.sanitizer import (
    sanitize_headers,
    sanitize_payload,
    sanitize_string,
)
from backend.app.modules.monitoring.schemas import (
    BatchSecurityEventIngestRequest,
    BatchSecurityEventIngestResponse,
    EventRetentionPolicyUpdate,
    IncidentContainmentRequest,
    IncidentTimelineEntryCreate,
    SecurityCenterOverviewStats,
    SecurityEventCreate,
    SecurityIncidentCreate,
    SecurityIncidentUpdate,
)
from backend.app.modules.monitoring.sse_manager import SSEManager

logger = logging.getLogger("preventx.monitoring.service")

# Event deduplication window
DEDUPLICATION_WINDOW_SECONDS = 60


class MonitoringService:
    """
    Core service powering PREVENT-X real-time monitoring and centralized security operations.
    """

    # =========================================================================
    # EVENT INGESTION & DEDUPLICATION
    # =========================================================================

    @classmethod
    def compute_event_fingerprint(
        cls,
        organization_id: uuid.UUID,
        source: str,
        category: str,
        source_ip: Optional[str],
        target_uri: Optional[str],
        title: str,
    ) -> str:
        """
        Computes SHA-256 fingerprint for deduplicating identical events within a time window.
        """
        raw_key = f"{organization_id}:{source}:{category}:{source_ip or '-'}:{target_uri or '-'}:{title}"
        return hashlib.sha256(raw_key.encode("utf-8")).hexdigest()

    @classmethod
    def ingest_single_event(
        cls,
        db: Session,
        organization_id: uuid.UUID,
        event_data: SecurityEventCreate,
        publish_live: bool = True,
    ) -> Tuple[SecurityEvent, bool]:
        """
        Ingests and sanitizes a single security event.
        Returns: (SecurityEvent, is_duplicate)
        """
        fingerprint = cls.compute_event_fingerprint(
            organization_id=organization_id,
            source=event_data.source.value if hasattr(event_data.source, "value") else str(event_data.source),
            category=event_data.category.value if hasattr(event_data.category, "value") else str(event_data.category),
            source_ip=event_data.source_ip,
            target_uri=event_data.target_uri,
            title=event_data.title,
        )

        event_time = event_data.timestamp or utc_now()
        dedup_threshold = event_time - timedelta(seconds=DEDUPLICATION_WINDOW_SECONDS)

        # Check for duplicate event within window
        existing_event = db.scalar(
            select(SecurityEvent).where(
                SecurityEvent.organization_id == organization_id,
                SecurityEvent.fingerprint == fingerprint,
                SecurityEvent.timestamp >= dedup_threshold,
            )
        )

        if existing_event:
            # Suppress duplicate insertion
            logger.debug("Duplicate event suppressed for fingerprint %s", fingerprint)
            return existing_event, True

        # Sanitize sensitive fields
        clean_title = sanitize_string(event_data.title, max_length=255)
        clean_desc = sanitize_string(event_data.description, max_length=2048, strip_crlf=False)
        clean_ip = sanitize_string(event_data.source_ip, max_length=64) if event_data.source_ip else None
        clean_uri = sanitize_string(event_data.target_uri, max_length=1024) if event_data.target_uri else None
        clean_method = sanitize_string(event_data.http_method, max_length=16) if event_data.http_method else None
        clean_payload = sanitize_payload(event_data.raw_payload) if event_data.raw_payload else None

        source_val = event_data.source.value if hasattr(event_data.source, "value") else str(event_data.source)
        category_val = event_data.category.value if hasattr(event_data.category, "value") else str(event_data.category)
        severity_val = event_data.severity.value if hasattr(event_data.severity, "value") else str(event_data.severity)

        event = SecurityEvent(
            id=uuid.uuid4(),
            organization_id=organization_id,
            asset_id=event_data.asset_id,
            source=source_val,
            category=category_val,
            severity=severity_val,
            confidence=event_data.confidence,
            title=clean_title,
            description=clean_desc,
            source_ip=clean_ip,
            target_uri=clean_uri,
            http_method=clean_method,
            status_code=event_data.status_code,
            fingerprint=fingerprint,
            raw_payload=clean_payload,
            event_metadata=event_data.event_metadata or {},
            is_correlated=False,
            timestamp=event_time,
        )
        db.add(event)
        db.flush()

        # Generate in-app alert for Critical / High events
        if severity_val in (EventSeverity.CRITICAL.value, EventSeverity.HIGH.value):
            alert = SecurityAlert(
                id=uuid.uuid4(),
                organization_id=organization_id,
                title=f"Alert: {clean_title}",
                message=clean_desc,
                category=AlertCategory.CRITICAL_INCIDENT.value,
                severity=severity_val,
                is_acknowledged=False,
                related_event_id=event.id,
            )
            db.add(alert)

        # Run Correlation Engine
        SecurityCorrelationEngine.correlate_event(db, event)

        db.commit()
        db.refresh(event)

        # Broadcast event to live SSE clients
        if publish_live:
            event_dict = {
                "id": str(event.id),
                "organization_id": str(event.organization_id),
                "asset_id": str(event.asset_id) if event.asset_id else None,
                "incident_id": str(event.incident_id) if event.incident_id else None,
                "source": event.source,
                "category": event.category,
                "severity": event.severity,
                "confidence": event.confidence,
                "title": event.title,
                "description": event.description,
                "source_ip": event.source_ip,
                "target_uri": event.target_uri,
                "http_method": event.http_method,
                "status_code": event.status_code,
                "timestamp": event.timestamp.isoformat(),
            }
            SSEManager.publish_event(organization_id, event_dict)

        return event, False

    @classmethod
    def ingest_batch(
        cls,
        db: Session,
        organization_id: uuid.UUID,
        request: BatchSecurityEventIngestRequest,
    ) -> BatchSecurityEventIngestResponse:
        """
        Batch-ingests structured events and/or raw Nginx log strings.
        """
        ingested_ids: List[uuid.UUID] = []
        dup_count = 0
        correlated_count = 0

        # 1. Ingest structured events
        for ev_create in request.events:
            if not ev_create.asset_id and request.asset_id:
                ev_create.asset_id = request.asset_id
            ev, is_dup = cls.ingest_single_event(db, organization_id, ev_create, publish_live=True)
            if is_dup:
                dup_count += 1
            else:
                ingested_ids.append(ev.id)
                if ev.is_correlated:
                    correlated_count += 1

        # 2. Ingest raw Nginx logs if provided
        if request.raw_nginx_logs:
            lines = request.raw_nginx_logs.strip().splitlines()
            for line in lines:
                parsed = NginxLogParser.parse_log_line(line)
                if parsed:
                    ev_create = SecurityEventCreate(
                        source=EventSource.NGINX,
                        category=EventCategory(parsed["category"]),
                        severity=EventSeverity(parsed["severity"]),
                        confidence=parsed.get("confidence", 1.0),
                        title=parsed["title"],
                        description=parsed["description"],
                        source_ip=parsed.get("source_ip"),
                        target_uri=parsed.get("target_uri"),
                        http_method=parsed.get("http_method"),
                        status_code=parsed.get("status_code"),
                        asset_id=request.asset_id,
                        raw_payload=parsed.get("raw_payload"),
                        event_metadata=parsed.get("event_metadata"),
                        timestamp=parsed.get("timestamp"),
                    )
                    ev, is_dup = cls.ingest_single_event(db, organization_id, ev_create, publish_live=True)
                    if is_dup:
                        dup_count += 1
                    else:
                        ingested_ids.append(ev.id)
                        if ev.is_correlated:
                            correlated_count += 1

        return BatchSecurityEventIngestResponse(
            ingested_count=len(ingested_ids),
            deduplicated_count=dup_count,
            correlated_incidents_count=correlated_count,
            event_ids=ingested_ids,
        )

    # =========================================================================
    # EVENT QUERYING
    # =========================================================================

    @classmethod
    def get_events(
        cls,
        db: Session,
        organization_id: uuid.UUID,
        source: Optional[str] = None,
        category: Optional[str] = None,
        severity: Optional[str] = None,
        search: Optional[str] = None,
        start_time: Optional[datetime] = None,
        end_time: Optional[datetime] = None,
        page: int = 1,
        size: int = 50,
    ) -> Tuple[List[SecurityEvent], int]:
        """
        Retrieves paginated, tenant-isolated security events.
        """
        query = select(SecurityEvent).where(SecurityEvent.organization_id == organization_id)

        if source:
            query = query.where(SecurityEvent.source == source)
        if category:
            query = query.where(SecurityEvent.category == category)
        if severity:
            query = query.where(SecurityEvent.severity == severity)
        if start_time:
            query = query.where(SecurityEvent.timestamp >= start_time)
        if end_time:
            query = query.where(SecurityEvent.timestamp <= end_time)
        if search:
            search_pattern = f"%{search.strip()}%"
            query = query.where(
                or_(
                    SecurityEvent.title.ilike(search_pattern),
                    SecurityEvent.description.ilike(search_pattern),
                    SecurityEvent.source_ip.ilike(search_pattern),
                    SecurityEvent.target_uri.ilike(search_pattern),
                )
            )

        total = db.scalar(select(func.count()).select_from(query.subquery())) or 0
        offset = (page - 1) * size
        items = list(db.scalars(query.order_by(SecurityEvent.timestamp.desc()).offset(offset).limit(size)).all())

        return items, total

    # =========================================================================
    # INCIDENT MANAGEMENT
    # =========================================================================

    @classmethod
    def create_incident(
        cls,
        db: Session,
        organization_id: uuid.UUID,
        payload: SecurityIncidentCreate,
        actor_user_id: Optional[uuid.UUID] = None,
    ) -> SecurityIncident:
        """
        Manually creates an audited security incident.
        """
        inc_number = SecurityCorrelationEngine.generate_incident_number(db, organization_id)
        now = utc_now()

        severity_val = payload.severity.value if hasattr(payload.severity, "value") else str(payload.severity)

        incident = SecurityIncident(
            id=uuid.uuid4(),
            incident_number=inc_number,
            organization_id=organization_id,
            title=sanitize_string(payload.title, 255),
            description=sanitize_string(payload.description, 2048, strip_crlf=False),
            severity=severity_val,
            status=IncidentStatus.OPEN.value,
            source="MANUAL_ANALYST",
            primary_asset_id=payload.primary_asset_id,
            mitre_attack_id=sanitize_string(payload.mitre_attack_id, 32) if payload.mitre_attack_id else None,
            mitre_technique=sanitize_string(payload.mitre_technique, 255) if payload.mitre_technique else None,
            recommended_action=sanitize_string(payload.recommended_action, 1024, strip_crlf=False) if payload.recommended_action else None,
            iocs=payload.iocs or {},
            related_event_ids=[],
            first_seen_at=now,
            last_seen_at=now,
        )
        db.add(incident)
        db.flush()

        timeline = IncidentTimelineEntry(
            id=uuid.uuid4(),
            incident_id=incident.id,
            organization_id=organization_id,
            entry_type="STATUS_CHANGE",
            message=f"Incident {inc_number} manually opened by analyst.",
            actor_user_id=actor_user_id,
        )
        db.add(timeline)

        db.commit()
        db.refresh(incident)
        return incident

    @classmethod
    def get_incidents(
        cls,
        db: Session,
        organization_id: uuid.UUID,
        status: Optional[str] = None,
        severity: Optional[str] = None,
        page: int = 1,
        size: int = 50,
    ) -> Tuple[List[SecurityIncident], int]:
        """
        Lists tenant-isolated security incidents.
        """
        query = select(SecurityIncident).where(SecurityIncident.organization_id == organization_id)
        if status:
            query = query.where(SecurityIncident.status == status)
        if severity:
            query = query.where(SecurityIncident.severity == severity)

        total = db.scalar(select(func.count()).select_from(query.subquery())) or 0
        offset = (page - 1) * size
        items = list(db.scalars(query.order_by(SecurityIncident.last_seen_at.desc()).offset(offset).limit(size)).all())

        return items, total

    @classmethod
    def get_incident_detail(
        cls,
        db: Session,
        organization_id: uuid.UUID,
        incident_id: uuid.UUID,
    ) -> Optional[SecurityIncident]:
        """
        Retrieves incident details with timeline and correlated events.
        """
        return db.scalar(
            select(SecurityIncident).where(
                SecurityIncident.id == incident_id,
                SecurityIncident.organization_id == organization_id,
            )
        )

    @classmethod
    def update_incident(
        cls,
        db: Session,
        organization_id: uuid.UUID,
        incident_id: uuid.UUID,
        payload: SecurityIncidentUpdate,
        actor_user_id: Optional[uuid.UUID] = None,
    ) -> SecurityIncident:
        """
        Updates incident status, severity, or assignee with immutable timeline audit history.
        """
        incident = db.scalar(
            select(SecurityIncident).where(
                SecurityIncident.id == incident_id,
                SecurityIncident.organization_id == organization_id,
            )
        )
        if not incident:
            return None

        # Status transition
        if payload.status is not None:
            new_status = payload.status.value if hasattr(payload.status, "value") else str(payload.status)
            if new_status != incident.status:
                old_status = incident.status
                incident.status = new_status
                if new_status == IncidentStatus.RESOLVED.value:
                    incident.resolved_at = utc_now()
                elif new_status == IncidentStatus.CLOSED.value:
                    incident.closed_at = utc_now()

                timeline = IncidentTimelineEntry(
                    id=uuid.uuid4(),
                    incident_id=incident.id,
                    organization_id=organization_id,
                    entry_type="STATUS_CHANGE",
                    message=f"Status changed from {old_status} to {new_status}.",
                    actor_user_id=actor_user_id,
                )
                db.add(timeline)

        # Severity change
        if payload.severity is not None:
            new_sev = payload.severity.value if hasattr(payload.severity, "value") else str(payload.severity)
            if new_sev != incident.severity:
                old_sev = incident.severity
                incident.severity = new_sev
                timeline = IncidentTimelineEntry(
                    id=uuid.uuid4(),
                    incident_id=incident.id,
                    organization_id=organization_id,
                    entry_type="SEVERITY_CHANGE",
                    message=f"Severity updated from {old_sev} to {new_sev}.",
                    actor_user_id=actor_user_id,
                )
                db.add(timeline)

        # Assignee update
        if payload.assigned_user_id is not None:
            incident.assigned_user_id = payload.assigned_user_id
            timeline = IncidentTimelineEntry(
                id=uuid.uuid4(),
                incident_id=incident.id,
                organization_id=organization_id,
                entry_type="ASSIGNMENT_CHANGE",
                message=f"Incident assigned to user {payload.assigned_user_id}.",
                actor_user_id=actor_user_id,
            )
            db.add(timeline)

        # Analyst notes
        if payload.notes:
            timeline = IncidentTimelineEntry(
                id=uuid.uuid4(),
                incident_id=incident.id,
                organization_id=organization_id,
                entry_type="ANALYST_NOTE",
                message=sanitize_string(payload.notes, 2048, strip_crlf=False),
                actor_user_id=actor_user_id,
            )
            db.add(timeline)

        incident.updated_at = utc_now()
        db.commit()
        db.refresh(incident)
        return incident

    @classmethod
    def add_incident_note(
        cls,
        db: Session,
        organization_id: uuid.UUID,
        incident_id: uuid.UUID,
        payload: IncidentTimelineEntryCreate,
        actor_user_id: Optional[uuid.UUID] = None,
    ) -> IncidentTimelineEntry:
        """
        Adds an analyst note or evidence artifact to the incident timeline.
        """
        incident = db.scalar(
            select(SecurityIncident).where(
                SecurityIncident.id == incident_id,
                SecurityIncident.organization_id == organization_id,
            )
        )
        if not incident:
            return None

        entry = IncidentTimelineEntry(
            id=uuid.uuid4(),
            incident_id=incident_id,
            organization_id=organization_id,
            entry_type=payload.entry_type or "ANALYST_NOTE",
            message=sanitize_string(payload.message, 2048, strip_crlf=False),
            evidence_data=payload.evidence_data or {},
            actor_user_id=actor_user_id,
        )
        db.add(entry)
        db.commit()
        db.refresh(entry)
        return entry

    @classmethod
    def execute_containment(
        cls,
        db: Session,
        organization_id: uuid.UUID,
        incident_id: uuid.UUID,
        payload: IncidentContainmentRequest,
        actor_user_id: Optional[uuid.UUID] = None,
        is_admin: bool = False,
    ) -> SecurityIncident:
        """
        Executes or requests incident containment (e.g. IP block, patch deployment).
        Enforces human authorization workflow for disruptive actions.
        """
        incident = db.scalar(
            select(SecurityIncident).where(
                SecurityIncident.id == incident_id,
                SecurityIncident.organization_id == organization_id,
            )
        )
        if not incident:
            return None

        action = sanitize_string(payload.containment_action, 128)

        # If user is admin and approved, execute containment immediately
        if is_admin and payload.is_approved:
            incident.status = IncidentStatus.CONTAINED.value
            incident.containment_action_taken = action
            incident.containment_approved_by = actor_user_id
            incident.containment_executed_at = utc_now()
            incident.containment_requires_approval = False

            timeline = IncidentTimelineEntry(
                id=uuid.uuid4(),
                incident_id=incident.id,
                organization_id=organization_id,
                entry_type="CONTAINMENT_ACTION",
                message=f"Disruptive containment '{action}' authorized and executed by OrgAdmin.",
                actor_user_id=actor_user_id,
                evidence_data={"action": action, "notes": payload.notes},
            )
            db.add(timeline)
        else:
            # Requires human approval from OrgAdmin
            incident.containment_requires_approval = True
            timeline = IncidentTimelineEntry(
                id=uuid.uuid4(),
                incident_id=incident.id,
                organization_id=organization_id,
                entry_type="CONTAINMENT_ACTION",
                message=f"Containment action '{action}' requested. Awaiting OrgAdmin human authorization.",
                actor_user_id=actor_user_id,
                evidence_data={"action": action, "notes": payload.notes},
            )
            db.add(timeline)

        db.commit()
        db.refresh(incident)
        return incident

    # =========================================================================
    # ALERTS & NOTIFICATIONS
    # =========================================================================

    @classmethod
    def get_alerts(
        cls,
        db: Session,
        organization_id: uuid.UUID,
        is_acknowledged: Optional[bool] = None,
        unacknowledged_only: bool = False,
        limit: int = 50,
    ) -> List[SecurityAlert]:
        """
        Lists tenant in-app alerts with optional acknowledgement filtering.
        """
        query = select(SecurityAlert).where(SecurityAlert.organization_id == organization_id)
        if is_acknowledged is not None:
            query = query.where(SecurityAlert.is_acknowledged == is_acknowledged)
        elif unacknowledged_only:
            query = query.where(SecurityAlert.is_acknowledged == False)
        return list(db.scalars(query.order_by(SecurityAlert.created_at.desc()).limit(limit)).all())

    @classmethod
    def acknowledge_alert(
        cls,
        db: Session,
        organization_id: uuid.UUID,
        alert_id: uuid.UUID,
        user_id: Optional[uuid.UUID] = None,
    ) -> Optional[SecurityAlert]:
        """
        Acknowledges an in-app security alert.
        """
        alert = db.scalar(
            select(SecurityAlert).where(
                SecurityAlert.id == alert_id,
                SecurityAlert.organization_id == organization_id,
            )
        )
        if alert:
            alert.is_acknowledged = True
            alert.acknowledged_at = utc_now()
            alert.acknowledged_by_user_id = user_id
            db.commit()
            db.refresh(alert)
        return alert

    # =========================================================================
    # RETENTION POLICY & CLEANUP
    # =========================================================================

    @classmethod
    def get_or_create_retention_policy(
        cls,
        db: Session,
        organization_id: uuid.UUID,
    ) -> EventRetentionPolicy:
        """
        Retrieves or initializes the tenant's event retention policy.
        """
        policy = db.scalar(
            select(EventRetentionPolicy).where(EventRetentionPolicy.organization_id == organization_id)
        )
        if not policy:
            policy = EventRetentionPolicy(
                id=uuid.uuid4(),
                organization_id=organization_id,
                retention_days=30,
                max_stored_events=100000,
                auto_prune_enabled=True,
            )
            db.add(policy)
            db.commit()
            db.refresh(policy)
        return policy

    @classmethod
    def update_retention_policy(
        cls,
        db: Session,
        organization_id: uuid.UUID,
        payload: EventRetentionPolicyUpdate,
    ) -> EventRetentionPolicy:
        """
        Updates retention policy settings.
        """
        policy = cls.get_or_create_retention_policy(db, organization_id)
        if payload.retention_days is not None:
            policy.retention_days = payload.retention_days
        if payload.max_stored_events is not None:
            policy.max_stored_events = payload.max_stored_events
        if payload.auto_prune_enabled is not None:
            policy.auto_prune_enabled = payload.auto_prune_enabled
        policy.updated_at = utc_now()
        db.commit()
        db.refresh(policy)
        return policy

    @classmethod
    def prune_expired_events(
        cls,
        db: Session,
        organization_id: Optional[uuid.UUID] = None,
    ) -> int:
        """
        Prunes security events older than the configured retention days or exceeding max storage limits.
        """
        total_pruned = 0
        policies = []
        if organization_id:
            p = cls.get_or_create_retention_policy(db, organization_id)
            policies = [p]
        else:
            policies = list(db.scalars(select(EventRetentionPolicy).where(EventRetentionPolicy.auto_prune_enabled == True)).all())

        for p in policies:
            cutoff = utc_now() - timedelta(days=p.retention_days)
            # Delete events older than cutoff that are not linked to open incidents
            res = db.execute(
                delete(SecurityEvent).where(
                    SecurityEvent.organization_id == p.organization_id,
                    SecurityEvent.timestamp < cutoff,
                    SecurityEvent.incident_id == None,
                )
            )
            deleted_count = res.rowcount or 0
            total_pruned += deleted_count

            p.last_pruned_at = utc_now()
            db.commit()
            logger.info("Pruned %d expired security events for organization %s", deleted_count, p.organization_id)

        return total_pruned

    # =========================================================================
    # CENTRALIZED SMB DASHBOARD POSTURE OVERVIEW
    # =========================================================================

    @classmethod
    def get_security_center_overview(
        cls,
        db: Session,
        organization_id: uuid.UUID,
    ) -> SecurityCenterOverviewStats:
        """
        Aggregates real-time security posture across all PREVENT-X modules (Phases 1 - 8).
        Every single metric is evidence-backed from actual database records.
        """
        now = utc_now()
        past_24h = now - timedelta(hours=24)

        # 1. Incidents breakdown
        incidents = list(
            db.scalars(
                select(SecurityIncident).where(
                    SecurityIncident.organization_id == organization_id,
                    SecurityIncident.status.in_([
                        IncidentStatus.OPEN.value,
                        IncidentStatus.ACKNOWLEDGED.value,
                        IncidentStatus.INVESTIGATING.value,
                    ]),
                )
            ).all()
        )
        open_incidents_total = len(incidents)
        crit_incidents = sum(1 for i in incidents if i.severity == IncidentSeverity.CRITICAL.value)
        high_incidents = sum(1 for i in incidents if i.severity == IncidentSeverity.HIGH.value)
        med_incidents = sum(1 for i in incidents if i.severity == IncidentSeverity.MEDIUM.value)

        # 2. Events in past 24h
        events_24h = db.scalar(
            select(func.count(SecurityEvent.id)).where(
                SecurityEvent.organization_id == organization_id,
                SecurityEvent.timestamp >= past_24h,
            )
        ) or 0

        # 3. WAF Blocks & Allowed in past 24h
        waf_blocks = db.scalar(
            select(func.count(WafEnforcementLog.id)).where(
                WafEnforcementLog.organization_id == organization_id,
                WafEnforcementLog.decision == "BLOCKED",
                WafEnforcementLog.created_at >= past_24h,
            )
        ) or 0

        # Also add security events with 403 status code
        sec_waf_blocks = db.scalar(
            select(func.count(SecurityEvent.id)).where(
                SecurityEvent.organization_id == organization_id,
                SecurityEvent.status_code == 403,
                SecurityEvent.timestamp >= past_24h,
            )
        ) or 0
        total_waf_blocks = max(waf_blocks, sec_waf_blocks)

        waf_allowed = db.scalar(
            select(func.count(SecurityEvent.id)).where(
                SecurityEvent.organization_id == organization_id,
                SecurityEvent.status_code == 200,
                SecurityEvent.timestamp >= past_24h,
            )
        ) or 0

        # 4. Exposed Assets count
        exposed_assets = db.scalar(
            select(func.count(ManagedAsset.id)).where(
                ManagedAsset.organization_id == organization_id,
                ManagedAsset.is_in_scope == True,
            )
        ) or 0

        # 5. Active Virtual Patches count
        active_patches = db.scalar(
            select(func.count(VirtualPatchRule.id)).where(
                VirtualPatchRule.organization_id == organization_id,
                VirtualPatchRule.status == PatchStatus.PRODUCTION.value,
                VirtualPatchRule.is_active == True,
            )
        ) or 0

        # 6. Zero Trust Trust Distribution
        trust_assessments = list(
            db.scalars(
                select(AssetTrustAssessment).where(
                    AssetTrustAssessment.organization_id == organization_id,
                )
            ).all()
        )
        trust_dist = {"TRUSTED": 0, "RESTRICTED": 0, "UNTRUSTED": 0, "INSUFFICIENT_EVIDENCE": 0}
        for ta in trust_assessments:
            decision = ta.trust_decision or "INSUFFICIENT_EVIDENCE"
            trust_dist[decision] = trust_dist.get(decision, 0) + 1

        # 7. Recent Rollbacks & Validation Failures
        recent_rollbacks = db.scalar(
            select(func.count(RollbackRecord.id)).where(
                RollbackRecord.organization_id == organization_id,
                RollbackRecord.created_at >= past_24h,
            )
        ) or 0

        val_failures = db.scalar(
            select(func.count(ValidationJob.id)).where(
                ValidationJob.organization_id == organization_id,
                ValidationJob.status == ValidationJobStatus.FAILED.value,
                ValidationJob.created_at >= past_24h,
            )
        ) or 0

        # 8. Unacknowledged Alerts
        unack_alerts = db.scalar(
            select(func.count(SecurityAlert.id)).where(
                SecurityAlert.organization_id == organization_id,
                SecurityAlert.is_acknowledged == False,
            )
        ) or 0

        # 9. Dynamic Security Posture Score Calculation (0 - 100)
        # Baseline 100 with evidence-backed deductions:
        # - 15 points per open Critical incident
        # - 8 points per open High incident
        # - 3 points per open Medium incident
        # - 5 points per UNTRUSTED asset
        # - 5 points per recent rollback / validation failure
        score = 100
        score -= crit_incidents * 15
        score -= high_incidents * 8
        score -= med_incidents * 3
        score -= trust_dist.get("UNTRUSTED", 0) * 5
        score -= val_failures * 5
        score = max(10, min(100, score))

        if score >= 90:
            grade = "A"
        elif score >= 80:
            grade = "B"
        elif score >= 70:
            grade = "C"
        elif score >= 60:
            grade = "D"
        else:
            grade = "F"

        return SecurityCenterOverviewStats(
            security_score=score,
            security_grade=grade,
            open_incidents_total=open_incidents_total,
            critical_incidents_count=crit_incidents,
            high_incidents_count=high_incidents,
            medium_incidents_count=med_incidents,
            events_24h_count=events_24h,
            waf_blocked_24h=total_waf_blocks,
            waf_allowed_24h=waf_allowed,
            exposed_assets_count=exposed_assets,
            active_virtual_patches_count=active_patches,
            trust_distribution=trust_dist,
            recent_rollbacks_count=recent_rollbacks,
            validation_failures_24h=val_failures,
            unacknowledged_alerts_count=unack_alerts,
        )
