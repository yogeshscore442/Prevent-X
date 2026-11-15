"""
PREVENT-X Honeypot & Decoy Reconnaissance Detection Engine
Detects unauthorized reconnaissance against deceptive administrative and sensitive file paths,
generates correlated security incidents, and suggests dynamic IP blocking recommendations.
"""

import json
import logging
import uuid
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Set, Tuple

from sqlalchemy import and_, desc, func, select
from sqlalchemy.orm import Session

from backend.app.models.audit_log import AuditEvent
from backend.app.models.monitoring import (
    IncidentSeverity,
    IncidentStatus,
    IncidentTimelineEntry,
    SecurityIncident,
)
from backend.app.models.network_defense import HoneypotProbe
from backend.app.modules.network_defense.blocking.service import (
    dynamic_blocking_service,
)

logger = logging.getLogger("preventx.network_defense.honeypot")

# Default high-fidelity decoy traps representing typical bot and attacker recon targets
DEFAULT_DECOY_EXACT_PATHS: Set[str] = {
    "/.env",
    "/.git/config",
    "/.svn/entries",
    "/.aws/credentials",
    "/wp-config.php",
    "/id_rsa",
    "/.ssh/id_rsa",
    "/config.json",
    "/server-status",
    "/database.sql",
    "/backup.sql",
    "/dump.sql",
    "/shell.php",
    "/c99.php",
    "/r57.php",
    "/cmd.php",
    "/wso.php",
    "/eval-stdin.php",
    "/api/internal/debug",
}

DEFAULT_DECOY_PREFIXES: Tuple[str, ...] = (
    "/wp-admin",
    "/phpmyadmin",
    "/pma",
    "/actuator",
    "/solr/admin",
    "/jenkins",
    "/geoserver",
    "/debug/vars",
)


class HoneypotService:
    """
    Manages decoy trap definitions, inspects live traffic for deceptive traps,
    records reconnaissance probes, generates incidents, and recommends blocking.
    """

    def __init__(self):
        # Per-tenant custom decoy path cache: organization_id -> set of custom paths
        self._custom_traps: Dict[str, Set[str]] = {}

    def get_all_traps(self, organization_id: Optional[uuid.UUID] = None) -> List[str]:
        """Returns all configured decoy trap paths for an organization."""
        traps = set(DEFAULT_DECOY_EXACT_PATHS)
        for prefix in DEFAULT_DECOY_PREFIXES:
            traps.add(f"{prefix}/*")

        if organization_id:
            org_str = str(organization_id)
            if org_str in self._custom_traps:
                traps.update(self._custom_traps[org_str])

        return sorted(list(traps))

    def add_custom_trap(self, organization_id: uuid.UUID, path: str) -> None:
        """Registers a custom decoy trap path for an organization."""
        org_str = str(organization_id)
        if org_str not in self._custom_traps:
            self._custom_traps[org_str] = set()
        clean_path = path.strip().lower()
        if not clean_path.startswith("/"):
            clean_path = f"/{clean_path}"
        self._custom_traps[org_str].add(clean_path)
        logger.info("Added custom decoy trap '%s' for tenant %s", clean_path, org_str)

    def is_trap_hit(self, path: str, organization_id: Optional[uuid.UUID] = None) -> Tuple[bool, Optional[str]]:
        """
        Determines whether a requested path hits a decoy trap.
        Returns (is_hit, matched_trap_pattern).
        """
        if not path:
            return False, None

        norm_path = path.strip().lower()
        # Remove query parameters if present
        if "?" in norm_path:
            norm_path = norm_path.split("?")[0]
        # Remove trailing slash unless root
        if len(norm_path) > 1 and norm_path.endswith("/"):
            norm_path = norm_path.rstrip("/")

        # 1. Exact match check against default traps
        if norm_path in DEFAULT_DECOY_EXACT_PATHS:
            return True, norm_path

        # 2. Prefix check against default decoy directories
        for prefix in DEFAULT_DECOY_PREFIXES:
            if norm_path == prefix or norm_path.startswith(f"{prefix}/"):
                return True, f"{prefix}/*"

        # 3. Check custom traps
        if organization_id:
            org_str = str(organization_id)
            custom_set = self._custom_traps.get(org_str, set())
            if norm_path in custom_set:
                return True, norm_path
            for custom_trap in custom_set:
                if custom_trap.endswith("/*"):
                    prefix = custom_trap[:-2]
                    if norm_path == prefix or norm_path.startswith(f"{prefix}/"):
                        return True, custom_trap

        return False, None

    def inspect_and_record_probe(
        self,
        db: Session,
        organization_id: uuid.UUID,
        path: str,
        source_ip: str,
        method: str = "GET",
        query_string: Optional[str] = None,
        user_agent: Optional[str] = None,
        payload_preview: Optional[str] = None,
        auto_recommend_block: bool = True,
    ) -> Tuple[bool, Optional[HoneypotProbe]]:
        """
        Evaluates a request against honeypot decoys.
        If a trap is tripped:
        1. Logs HoneypotProbe in DB.
        2. Automatically creates a SecurityIncident.
        3. Appends an IncidentTimelineEntry.
        4. Issues a dynamic blocking recommendation if enabled.
        """
        is_hit, matched_trap = self.is_trap_hit(path, organization_id)
        if not is_hit:
            return False, None

        logger.warning(
            "HONEYPOT TRAP TRIPPED: %s %s from IP %s (matched: %s)",
            method,
            path,
            source_ip,
            matched_trap,
        )

        # 1. Create HoneypotProbe record
        probe = HoneypotProbe(
            id=str(uuid.uuid4()),
            organization_id=organization_id,
            trap_path=matched_trap or path,
            source_ip=source_ip,
            http_method=method.upper(),
            user_agent=user_agent[:1024] if user_agent else None,
            query_string=query_string[:4096] if query_string else None,
            payload_preview=payload_preview[:2048] if payload_preview else None,
        )
        db.add(probe)

        # 2. Correlate with SecurityIncident (MOD-09 / MOD-11)
        severity = IncidentSeverity.HIGH.value if any(
            x in (matched_trap or "") for x in [".env", "id_rsa", "shell", "actuator"]
        ) else IncidentSeverity.MEDIUM.value

        incident_num = f"INC-HP-{uuid.uuid4().hex[:8].upper()}"
        incident = SecurityIncident(
            incident_number=incident_num,
            organization_id=organization_id,
            title=f"Honeypot Decoy Trap Triggered: {matched_trap or path} from {source_ip}",
            description=(
                f"Unauthorized reconnaissance activity detected. Attacker probed deceptive honeypot "
                f"endpoint '{matched_trap or path}'. Source IP: {source_ip}, HTTP Method: {method.upper()}."
            ),
            severity=severity,
            status=IncidentStatus.OPEN.value,
            source="HONEYPOT_DETECTION",
            mitre_attack_id="T1595.002",
            mitre_technique="Active Scanning: Vulnerability Scanning",
            recommended_action=f"Review host activity and enforce dynamic IP block on {source_ip}.",
            containment_action_taken=False,
            containment_requires_approval=True,
            iocs={"ip": [source_ip], "trap_path": matched_trap or path},
        )
        db.add(incident)
        db.flush()

        probe.correlated_incident_id = str(incident.id)

        # 3. Add Incident Timeline Entry
        timeline = IncidentTimelineEntry(
            incident_id=incident.id,
            organization_id=organization_id,
            entry_type="HONEYPOT_TRAP_TRIGGERED",
            message=f"Host {source_ip} probed honeypot trap {matched_trap or path} using {method.upper()}.",
            evidence_data={
                "probe_id": str(probe.id),
                "trap_path": matched_trap or path,
                "source_ip": source_ip,
                "path": path,
                "method": method,
                "query": query_string,
                "user_agent": user_agent,
            },
        )
        db.add(timeline)

        # 4. Issue Dynamic Blocking Recommendation if enabled
        if auto_recommend_block:
            try:
                block = dynamic_blocking_service.create_block(
                    db=db,
                    organization_id=organization_id,
                    ip_or_cidr=source_ip,
                    reason=f"Honeypot Decoy Tripwire: Probed {matched_trap or path}",
                    duration_minutes=120,
                    require_approval=True,  # Safer default: requires approval
                    incident_id=incident.id,
                )
                probe.recommended_block_id = block.id
            except Exception as ex:
                logger.warning("Could not create dynamic block recommendation for %s: %s", source_ip, ex)

        # 5. Audit Log
        audit = AuditEvent(
            organization_id=organization_id,
            action="honeypot_probe_captured",
            resource_type="honeypot_probe",
            resource_id=probe.id,
            status="WARNING",
            details=f"Source: {source_ip}, Trap: {matched_trap or path}, Incident: {incident_num}",
        )
        db.add(audit)
        db.commit()
        db.refresh(probe)

        return True, probe

    def list_probes(
        self,
        db: Session,
        organization_id: uuid.UUID,
        source_ip: Optional[str] = None,
        limit: int = 50,
    ) -> List[HoneypotProbe]:
        """Lists captured honeypot probes for an organization."""
        query = select(HoneypotProbe).where(HoneypotProbe.organization_id == organization_id)
        if source_ip:
            query = query.where(HoneypotProbe.source_ip == source_ip)
        query = query.order_by(desc(HoneypotProbe.created_at)).limit(limit)
        return db.execute(query).scalars().all()

    def get_probe(
        self,
        db: Session,
        probe_id: str,
        organization_id: uuid.UUID,
    ) -> Optional[HoneypotProbe]:
        """Retrieves a specific probe by ID."""
        return db.execute(
            select(HoneypotProbe).where(
                and_(HoneypotProbe.id == probe_id, HoneypotProbe.organization_id == organization_id)
            )
        ).scalar_one_or_none()

    def get_statistics(self, db: Session, organization_id: uuid.UUID) -> Dict[str, Any]:
        """Computes summary metrics for honeypot telemetry."""
        total_probes = db.execute(
            select(func.count(HoneypotProbe.id)).where(HoneypotProbe.organization_id == organization_id)
        ).scalar() or 0

        unique_ips = db.execute(
            select(func.count(func.distinct(HoneypotProbe.source_ip))).where(
                HoneypotProbe.organization_id == organization_id
            )
        ).scalar() or 0

        # Top 5 probed traps
        top_traps_query = (
            select(HoneypotProbe.trap_path, func.count(HoneypotProbe.id).label("hits"))
            .where(HoneypotProbe.organization_id == organization_id)
            .group_by(HoneypotProbe.trap_path)
            .order_by(desc("hits"))
            .limit(5)
        )
        top_traps_rows = db.execute(top_traps_query).all()
        top_traps = [{"trap_path": row[0], "hits": row[1]} for row in top_traps_rows]

        all_traps = self.get_all_traps(organization_id)

        return {
            "total_probes": total_probes,
            "unique_attacker_ips": unique_ips,
            "top_traps": top_traps,
            "active_decoy_count": len(all_traps),
        }


# Global instance
honeypot_service = HoneypotService()
