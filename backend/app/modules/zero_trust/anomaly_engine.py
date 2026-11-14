"""
PREVENT-X Behavioral Anomaly Detection & Zero-Day Resilience Engine (MOD-04)
Analyzes telemetry for statistical baseline deviations, unexpected service ports,
lateral communication links, authentication bursts, and unknown protocol payloads.

DISTINCTION:
- Anomaly: Statistical/heuristic departure from normal baseline.
- Confirmed Attack: Corroborated with verified exploitation or threat IOC.
- Zero-Day Indicator: Behavioral exploitation attempt without known CVE match.
"""

import json
import logging
import math
import uuid
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List, Optional, Tuple

from sqlalchemy import select
from sqlalchemy.orm import Session

from backend.app.models.asset import ManagedAsset
from backend.app.models.attack_surface import DiscoveredService
from backend.app.models.audit_log import AuditEvent
from backend.app.models.session import UserSession
from backend.app.models.zero_trust import (
    AnomalyConfidence,
    AnomalySeverity,
    AnomalyStatus,
    AnomalyType,
    BehavioralAnomaly,
)

logger = logging.getLogger("preventx.zero_trust.anomaly_engine")

# Known suspicious backdoor / exploit ports
SUSPICIOUS_UNEXPECTED_PORTS = {
    4444: ("Metasploit default listener port", AnomalySeverity.CRITICAL.value, 95.0),
    1337: ("Hacker / backdoor shell port", AnomalySeverity.HIGH.value, 85.0),
    6667: ("IRC botnet command channel", AnomalySeverity.HIGH.value, 80.0),
    31337: ("Elite / Back Orifice backdoor", AnomalySeverity.CRITICAL.value, 95.0),
    8008: ("Alternate unencrypted management interface", AnomalySeverity.MEDIUM.value, 60.0),
    8888: ("Unsecured proxy / development listener", AnomalySeverity.MEDIUM.value, 60.0),
    9999: ("Urgent debug daemon port", AnomalySeverity.HIGH.value, 75.0),
}


class BehavioralAnomalyEngine:
    """
    Evaluates behavioral baseline drifts, port deviations, authentication bursts,
    and unknown zero-day payload indicators.
    """

    @classmethod
    def evaluate_all_anomalies(
        cls,
        db: Session,
        organization_id: uuid.UUID,
    ) -> List[BehavioralAnomaly]:
        """
        Executes full suite of behavioral detection checks across tenant assets.
        """
        stmt_assets = select(ManagedAsset).where(
            ManagedAsset.organization_id == organization_id,
        )
        assets = db.execute(stmt_assets).scalars().all()

        detected: List[BehavioralAnomaly] = []

        for asset in assets:
            # 1. Unexpected Service Ports
            anom_ports = cls.detect_unexpected_ports(db, asset, organization_id)
            detected.extend(anom_ports)

            # 2. Authentication Bursts / Failures
            anom_auth = cls.detect_authentication_bursts(db, asset, organization_id)
            if anom_auth:
                detected.append(anom_auth)

        db.commit()
        return detected

    @classmethod
    def detect_unexpected_ports(
        cls,
        db: Session,
        asset: ManagedAsset,
        organization_id: uuid.UUID,
    ) -> List[BehavioralAnomaly]:
        """
        Identifies ports that deviate substantially from expected SMB server profiles.
        """
        stmt = select(DiscoveredService).where(
            DiscoveredService.asset_id == asset.id,
            DiscoveredService.organization_id == organization_id,
        )
        services = db.execute(stmt).scalars().all()
        anomalies: List[BehavioralAnomaly] = []

        for svc in services:
            if svc.port in SUSPICIOUS_UNEXPECTED_PORTS:
                desc, sev, score = SUSPICIOUS_UNEXPECTED_PORTS[svc.port]

                # Check if already logged and active
                existing = cls._find_existing_anomaly(
                    db=db,
                    organization_id=organization_id,
                    asset_id=asset.id,
                    anomaly_type=AnomalyType.UNEXPECTED_SERVICE_PORT.value,
                    evidence_key=f"port_{svc.port}",
                )
                if not existing:
                    anomaly = BehavioralAnomaly(
                        id=uuid.uuid4(),
                        organization_id=organization_id,
                        asset_id=asset.id,
                        anomaly_type=AnomalyType.UNEXPECTED_SERVICE_PORT.value,
                        severity=sev,
                        confidence=AnomalyConfidence.CONFIRMED.value,
                        anomaly_score=score,
                        description=(
                            f"Unexpected service port {svc.port} detected on asset '{asset.name}'. "
                            f"{desc} indicates non-standard software or potential backdoor presence."
                        ),
                        evidence_data=json.dumps({
                            "evidence_key": f"port_{svc.port}",
                            "port": svc.port,
                            "service_name": svc.service_name,
                            "banner": svc.banner,
                            "target_ip": svc.target_ip,
                        }),
                        status=AnomalyStatus.OPEN.value,
                        is_zero_day_indicator=False,
                    )
                    db.add(anomaly)
                    anomalies.append(anomaly)

        return anomalies

    @classmethod
    def detect_authentication_bursts(
        cls,
        db: Session,
        asset: ManagedAsset,
        organization_id: uuid.UUID,
    ) -> Optional[BehavioralAnomaly]:
        """
        Detects anomalous bursts in authentication activity or session churn.
        """
        now = datetime.now(timezone.utc)
        ten_mins_ago = now - timedelta(minutes=10)

        # Count recent sessions created in the last 10 minutes
        stmt_sessions = select(UserSession).where(
            UserSession.created_at >= ten_mins_ago,
        )
        recent_sessions = db.execute(stmt_sessions).scalars().all()

        # Check audit log for login failures or rapid events
        stmt_audit = select(AuditEvent).where(
            AuditEvent.organization_id == organization_id,
            AuditEvent.created_at >= ten_mins_ago,
            AuditEvent.action.ilike("%login%"),
        )
        recent_logins = db.execute(stmt_audit).scalars().all()

        # Threshold: > 15 auth events in 10 minutes for SMB tenant is anomalous
        if len(recent_logins) > 15 or len(recent_sessions) > 20:
            existing = cls._find_existing_anomaly(
                db=db,
                organization_id=organization_id,
                asset_id=asset.id,
                anomaly_type=AnomalyType.AUTHENTICATION_BURST.value,
                evidence_key="recent_auth_burst",
            )
            if not existing:
                count = len(recent_logins) + len(recent_sessions)
                anomaly = BehavioralAnomaly(
                    id=uuid.uuid4(),
                    organization_id=organization_id,
                    asset_id=asset.id,
                    anomaly_type=AnomalyType.AUTHENTICATION_BURST.value,
                    severity=AnomalySeverity.HIGH.value,
                    confidence=AnomalyConfidence.LIKELY.value,
                    anomaly_score=75.0,
                    description=(
                        f"Authentication burst anomaly detected: {count} authentication attempts "
                        f"recorded within 10 minutes. Indicates potential credential stuffing or brute force."
                    ),
                    evidence_data=json.dumps({
                        "evidence_key": "recent_auth_burst",
                        "audit_login_count": len(recent_logins),
                        "recent_session_count": len(recent_sessions),
                        "window_minutes": 10,
                    }),
                    status=AnomalyStatus.OPEN.value,
                    is_zero_day_indicator=False,
                )
                db.add(anomaly)
                return anomaly

        return None

    @classmethod
    def evaluate_connection_rate_anomaly(
        cls,
        db: Session,
        asset: ManagedAsset,
        organization_id: uuid.UUID,
        observed_rate: float,
        baseline_mean: float,
        baseline_std: float,
    ) -> Optional[BehavioralAnomaly]:
        """
        Evaluates statistical Z-score deviation against established baseline.
        Z = (observed - mean) / std. Triggers when Z >= 2.5 (99% confidence interval).
        """
        if baseline_std <= 0:
            baseline_std = 1.0

        z_score = (observed_rate - baseline_mean) / baseline_std

        if z_score >= 2.5:
            score = min(95.0, 50.0 + (z_score * 10.0))
            existing = cls._find_existing_anomaly(
                db=db,
                organization_id=organization_id,
                asset_id=asset.id,
                anomaly_type=AnomalyType.UNUSUAL_CONNECTION_RATE.value,
                evidence_key="z_score_conn_rate",
            )
            if not existing:
                anomaly = BehavioralAnomaly(
                    id=uuid.uuid4(),
                    organization_id=organization_id,
                    asset_id=asset.id,
                    anomaly_type=AnomalyType.UNUSUAL_CONNECTION_RATE.value,
                    severity=AnomalySeverity.HIGH.value if z_score >= 3.5 else AnomalySeverity.MEDIUM.value,
                    confidence=AnomalyConfidence.CONFIRMED.value if z_score >= 4.0 else AnomalyConfidence.LIKELY.value,
                    anomaly_score=round(score, 1),
                    description=(
                        f"Statistical connection rate anomaly (Z-score: {z_score:.2f}). "
                        f"Observed rate {observed_rate:.1f} req/s significantly deviates from "
                        f"baseline mean {baseline_mean:.1f} ± {baseline_std:.1f}."
                    ),
                    evidence_data=json.dumps({
                        "evidence_key": "z_score_conn_rate",
                        "observed_rate": observed_rate,
                        "baseline_mean": baseline_mean,
                        "baseline_std": baseline_std,
                        "z_score": round(z_score, 2),
                    }),
                    status=AnomalyStatus.OPEN.value,
                    is_zero_day_indicator=False,
                )
                db.add(anomaly)
                db.flush()
                return anomaly

        return None

    @classmethod
    def record_zero_day_payload_indicator(
        cls,
        db: Session,
        asset: ManagedAsset,
        organization_id: uuid.UUID,
        service_port: int,
        payload_signature: str,
        heuristic_evidence: str,
    ) -> BehavioralAnomaly:
        """
        Records a behavioral zero-day exploitation indicator for non-standard,
        unmapped shellcode or malformed protocol manipulation.
        Sets is_zero_day_indicator = True.
        """
        anomaly = BehavioralAnomaly(
            id=uuid.uuid4(),
            organization_id=organization_id,
            asset_id=asset.id,
            anomaly_type=AnomalyType.UNKNOWN_PROTOCOL_PAYLOAD.value,
            severity=AnomalySeverity.CRITICAL.value,
            confidence=AnomalyConfidence.CONFIRMED.value,
            anomaly_score=92.0,
            description=(
                f"Zero-Day Resilience Alert: Unmapped binary/protocol payload anomaly detected on port {service_port}. "
                f"Payload does not match documented CVE signatures, indicating potential novel exploitation."
            ),
            evidence_data=json.dumps({
                "service_port": service_port,
                "payload_signature": payload_signature[:200],
                "heuristic_evidence": heuristic_evidence,
                "classification": "ZERO_DAY_BEHAVIORAL_RESILIENCE",
            }),
            status=AnomalyStatus.OPEN.value,
            is_zero_day_indicator=True,
        )
        db.add(anomaly)
        db.flush()
        return anomaly

    @classmethod
    def _find_existing_anomaly(
        cls,
        db: Session,
        organization_id: uuid.UUID,
        asset_id: uuid.UUID,
        anomaly_type: str,
        evidence_key: str,
    ) -> Optional[BehavioralAnomaly]:
        """Checks for existing open anomaly with matching key to avoid duplicate alerts."""
        stmt = select(BehavioralAnomaly).where(
            BehavioralAnomaly.organization_id == organization_id,
            BehavioralAnomaly.asset_id == asset_id,
            BehavioralAnomaly.anomaly_type == anomaly_type,
            BehavioralAnomaly.status.in_([AnomalyStatus.OPEN.value, AnomalyStatus.INVESTIGATING.value]),
        )
        results = db.execute(stmt).scalars().all()
        for r in results:
            if r.evidence_data and evidence_key in r.evidence_data:
                return r
        return None
