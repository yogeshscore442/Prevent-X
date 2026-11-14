"""
PREVENT-X Zero Trust Posture & Continuous Identity Evaluation Engine (MOD-04)
Evaluates tenant assets against dynamic security telemetry, exposure metrics,
vulnerability findings, and behavioral signals to generate an explainable trust decision.

CRUCIAL RULE: Never mark an asset TRUSTED merely because it is registered.
Requires positive verification of least-privilege, clean posture, and valid telemetry.
"""

import json
import logging
import uuid
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple

from sqlalchemy import select
from sqlalchemy.orm import Session

from backend.app.models.asset import ManagedAsset
from backend.app.models.attack_surface import DiscoveredService, ServiceState
from backend.app.models.vulnerability import VulnerabilityRecord, VulnerabilitySeverity
from backend.app.models.zero_trust import (
    AssetTrustAssessment,
    BehavioralAnomaly,
    ThreatAssetCorrelation,
    TrustDecision,
)

logger = logging.getLogger("preventx.zero_trust.trust_engine")

# Sensitive ports that should not be exposed to public networks without strict controls
HIGH_RISK_PORTS = {
    21: "FTP (Unencrypted file transfer)",
    22: "SSH (Remote administrative shell)",
    23: "Telnet (Insecure plaintext terminal)",
    3389: "RDP (Windows Remote Desktop)",
    445: "SMB (Server Message Block / EternalBlue vector)",
    139: "NetBIOS (Legacy file sharing)",
    1433: "MSSQL (Database port)",
    3306: "MySQL (Database port)",
    5432: "PostgreSQL (Database port)",
    27017: "MongoDB (NoSQL database port)",
    6379: "Redis (In-memory datastore)",
    9200: "Elasticsearch (Search engine API)",
}


class ZeroTrustEvaluationEngine:
    """
    Evaluates zero-trust state for an asset, enforcing continuous verification
    and least-privilege principles.
    """

    @classmethod
    def evaluate_asset_trust(
        cls,
        db: Session,
        asset: ManagedAsset,
        organization_id: uuid.UUID,
    ) -> AssetTrustAssessment:
        """
        Calculates trust decision, score (0.0 - 100.0), positive factors,
        risk factors, and least-privilege recommendations for a managed asset.
        """
        # 1. Fetch discovered services for this asset
        stmt_services = select(DiscoveredService).where(
            DiscoveredService.asset_id == asset.id,
            DiscoveredService.organization_id == organization_id,
        )
        services = db.execute(stmt_services).scalars().all()

        # 2. Fetch vulnerability findings for this asset
        stmt_vulns = select(VulnerabilityRecord).where(
            VulnerabilityRecord.asset_id == asset.id,
            VulnerabilityRecord.organization_id == organization_id,
        )
        vulnerabilities = db.execute(stmt_vulns).scalars().all()

        # 3. Fetch active threat correlations
        stmt_correlations = select(ThreatAssetCorrelation).where(
            ThreatAssetCorrelation.asset_id == asset.id,
            ThreatAssetCorrelation.organization_id == organization_id,
            ThreatAssetCorrelation.status == "ACTIVE",
        )
        correlations = db.execute(stmt_correlations).scalars().all()

        # 4. Fetch unresolved behavioral anomalies
        stmt_anomalies = select(BehavioralAnomaly).where(
            BehavioralAnomaly.asset_id == asset.id,
            BehavioralAnomaly.organization_id == organization_id,
            BehavioralAnomaly.status.in_(["OPEN", "INVESTIGATING"]),
        )
        anomalies = db.execute(stmt_anomalies).scalars().all()

        # Check for insufficient evidence first
        # An asset with zero services, zero discovery scans, and zero telemetry
        # CANNOT be marked TRUSTED. It must receive INSUFFICIENT_EVIDENCE.
        has_telemetry = len(services) > 0 or len(vulnerabilities) > 0 or len(anomalies) > 0

        if not has_telemetry:
            return cls._build_insufficient_evidence_assessment(
                db=db,
                asset=asset,
                organization_id=organization_id,
            )

        # Compute factor scores
        positive_factors: List[Dict[str, Any]] = []
        risk_factors: List[Dict[str, Any]] = []
        recommendations: List[str] = []

        base_score = 50.0  # Baseline neutral evaluation start

        # --- A. Service Exposure Analysis ---
        open_services = [s for s in services if s.state == ServiceState.OPEN]
        tls_verified = False
        high_risk_open = []

        for s in open_services:
            if s.port in HIGH_RISK_PORTS:
                high_risk_open.append((s.port, HIGH_RISK_PORTS[s.port]))

            # Check TLS configuration
            if s.tls_metadata:
                try:
                    tls_data = json.loads(s.tls_metadata) if isinstance(s.tls_metadata, str) else s.tls_metadata
                    if tls_data.get("valid") is True or tls_data.get("status") == "VALID":
                        tls_verified = True
                except Exception:
                    pass

        if high_risk_open:
            port_desc = ", ".join(f"{p} ({desc})" for p, desc in high_risk_open[:3])
            penalty = min(40.0, len(high_risk_open) * 15.0)
            base_score -= penalty
            risk_factors.append({
                "category": "NETWORK_EXPOSURE",
                "factor": f"Exposed high-risk administrative or datastore port(s): {port_desc}",
                "impact": "NEGATIVE",
                "score_delta": -penalty,
                "description": "Sensitive administrative interfaces are exposed without network boundary isolation.",
            })
            for p, desc in high_risk_open:
                recommendations.append(
                    f"Isolate port {p} ({desc}) behind a Zero-Trust Network Access (ZTNA) or VPN boundary."
                )

        if tls_verified:
            base_score += 15.0
            positive_factors.append({
                "category": "TRANSPORT_SECURITY",
                "factor": "Valid TLS encryption verified on service endpoints",
                "impact": "POSITIVE",
                "score_delta": 15.0,
                "description": "Traffic in transit is encrypted using validated cryptographic certificates.",
            })
        elif any(s.port in [443, 8443] for s in open_services):
            recommendations.append("Enforce modern TLS 1.3 encryption with strict HSTS headers on web services.")

        # If services are strictly non-administrative (e.g. only 80, 443)
        if open_services and not high_risk_open:
            base_score += 10.0
            positive_factors.append({
                "category": "SERVICE_SURFACE",
                "factor": "Service attack surface is limited to standard web protocols",
                "impact": "POSITIVE",
                "score_delta": 10.0,
                "description": "No legacy or unauthenticated management ports are publicly reachable.",
            })

        # --- B. Vulnerability Analysis ---
        active_vulns = [v for v in vulnerabilities if v.status in ["DETECTED", "IN_TRIAGE"]]
        crit_vulns = [v for v in active_vulns if v.severity == VulnerabilitySeverity.CRITICAL.value]
        high_vulns = [v for v in active_vulns if v.severity == VulnerabilitySeverity.HIGH.value]
        med_vulns = [v for v in active_vulns if v.severity == VulnerabilitySeverity.MEDIUM.value]

        if crit_vulns:
            penalty = min(50.0, len(crit_vulns) * 25.0)
            base_score -= penalty
            risk_factors.append({
                "category": "VULNERABILITY_POSTURE",
                "factor": f"{len(crit_vulns)} Critical severity vulnerability finding(s) detected",
                "impact": "NEGATIVE",
                "score_delta": -penalty,
                "description": f"Asset is exposed to confirmed critical CVEs: {', '.join(v.cve_id or v.title for v in crit_vulns[:2])}",
            })
            recommendations.append("Apply emergency virtual patching or software updates for critical CVEs immediately.")

        if high_vulns:
            penalty = min(30.0, len(high_vulns) * 10.0)
            base_score -= penalty
            risk_factors.append({
                "category": "VULNERABILITY_POSTURE",
                "factor": f"{len(high_vulns)} High severity vulnerability finding(s) detected",
                "impact": "NEGATIVE",
                "score_delta": -penalty,
                "description": "High severity security flaws increase likelihood of unauthorized privilege escalation.",
            })
            recommendations.append("Remediate high severity CVEs within standard SLA window.")

        if med_vulns and not crit_vulns and not high_vulns:
            base_score -= min(15.0, len(med_vulns) * 5.0)
            risk_factors.append({
                "category": "VULNERABILITY_POSTURE",
                "factor": f"{len(med_vulns)} Medium severity vulnerability finding(s)",
                "impact": "NEGATIVE",
                "score_delta": -min(15.0, len(med_vulns) * 5.0),
                "description": "Non-critical vulnerabilities present, requiring scheduled remediation.",
            })

        if not active_vulns and has_telemetry:
            base_score += 15.0
            positive_factors.append({
                "category": "VULNERABILITY_POSTURE",
                "factor": "Zero active critical or high vulnerability findings",
                "impact": "POSITIVE",
                "score_delta": 15.0,
                "description": "Scans show no known unpatched CVEs or missing security fixes.",
            })

        # --- C. Threat Intelligence Correlations ---
        if correlations:
            penalty = min(50.0, len(correlations) * 25.0)
            base_score -= penalty
            risk_factors.append({
                "category": "THREAT_INTELLIGENCE",
                "factor": f"Asset correlates with {len(correlations)} active threat intelligence indicator(s)",
                "impact": "NEGATIVE",
                "score_delta": -penalty,
                "description": "Matched known malicious C2 IP, phishing infrastructure, or malware indicators.",
            })
            recommendations.append("Trigger automated host isolation and initiate incident investigation for threat IOCs.")

        # --- D. Behavioral Anomalies & Zero-Day Indicators ---
        zero_day_alerts = [a for a in anomalies if a.is_zero_day_indicator]
        other_anomalies = [a for a in anomalies if not a.is_zero_day_indicator]

        if zero_day_alerts:
            base_score -= 35.0
            risk_factors.append({
                "category": "ZERO_DAY_RESILIENCE",
                "factor": f"{len(zero_day_alerts)} Zero-day behavioral anomaly indicator(s) triggered",
                "impact": "NEGATIVE",
                "score_delta": -35.0,
                "description": "Payload pattern or execution drift indicates potential novel attack or zero-day behavior.",
            })
            recommendations.append("Activate virtual patch enforcement and packet capture inspection for anomalous payload.")

        if other_anomalies:
            base_score -= min(25.0, len(other_anomalies) * 8.0)
            risk_factors.append({
                "category": "BEHAVIORAL_BASELINE",
                "factor": f"{len(other_anomalies)} Baseline behavioral anomaly deviation(s) active",
                "impact": "NEGATIVE",
                "score_delta": -min(25.0, len(other_anomalies) * 8.0),
                "description": "Statistical deviation in connection rates or authentication burst detected.",
            })
            recommendations.append("Investigate unusual traffic volume and review recent authentication logs.")

        # --- E. Identity & Scope Hygiene ---
        if getattr(asset, "criticality", "").upper() == "CRITICAL":
            recommendations.append("Enforce multi-factor authentication (MFA) and hardware token verification for access.")
            recommendations.append("Implement micro-segmentation policies restricting lateral traversal to this crown-jewel asset.")
        else:
            recommendations.append("Enforce principle of least-privilege (PoLP) on service-to-service access bindings.")

        # Clamp trust score strictly to [0.0, 100.0]
        final_score = max(0.0, min(100.0, round(base_score, 1)))

        # Determine Trust Decision
        # Decision Boundaries:
        # UNTRUSTED: score < 30.0 OR active critical vulns OR threat correlations OR zero-day alerts
        # RESTRICTED: score 30.0 - 69.9 OR high risk open ports OR active high vulns
        # TRUSTED: score >= 70.0 AND zero critical/high vulns AND zero high-risk ports AND zero correlations
        if final_score < 30.0 or crit_vulns or correlations:
            decision = TrustDecision.UNTRUSTED.value
            reason = (
                f"Asset is classified UNTRUSTED (Score: {final_score}/100) due to severe security exposure: "
                f"{len(crit_vulns)} critical CVEs, {len(correlations)} threat IOC correlations, "
                f"and {len(high_risk_open)} open sensitive ports."
            )
        elif final_score < 70.0 or high_risk_open or high_vulns or other_anomalies:
            decision = TrustDecision.RESTRICTED.value
            reason = (
                f"Asset is classified RESTRICTED (Score: {final_score}/100). Access requires constrained privilege "
                f"due to {len(high_risk_open)} open management ports, {len(high_vulns)} high vulnerabilities, "
                f"or active behavioral anomalies."
            )
        else:
            decision = TrustDecision.TRUSTED.value
            reason = (
                f"Asset is positively verified and classified TRUSTED (Score: {final_score}/100). "
                f"Service attack surface is clean, transport encryption is verified, and zero high/critical vulnerabilities exist."
            )

        return cls._upsert_assessment(
            db=db,
            asset=asset,
            organization_id=organization_id,
            decision=decision,
            score=final_score,
            positive_factors=positive_factors,
            risk_factors=risk_factors,
            recommendations=recommendations,
            reason=reason,
        )

    @classmethod
    def _build_insufficient_evidence_assessment(
        cls,
        db: Session,
        asset: ManagedAsset,
        organization_id: uuid.UUID,
    ) -> AssetTrustAssessment:
        """
        Builds assessment when insufficient security telemetry is available.
        Under Zero Trust, unverified assets CANNOT be trusted.
        """
        score = 20.0
        decision = TrustDecision.INSUFFICIENT_EVIDENCE.value
        positive_factors: List[Dict[str, Any]] = []
        risk_factors: List[Dict[str, Any]] = [{
            "category": "TELEMETRY_GAP",
            "factor": "No active scan telemetry or vulnerability records available",
            "impact": "NEGATIVE",
            "score_delta": -30.0,
            "description": "Zero Trust principle requires continuous verification before granting trust.",
        }]
        recommendations = [
            "Execute an active service discovery scan to collect endpoint telemetry.",
            "Run a vulnerability assessment job to evaluate CVE exposure.",
            "Verify asset network boundary before granting elevated access.",
        ]
        reason = (
            f"Asset has insufficient telemetry to establish verified trust (Score: {score}/100). "
            f"Zero Trust posture mandates empirical discovery verification prior to granting TRUSTED status."
        )

        return cls._upsert_assessment(
            db=db,
            asset=asset,
            organization_id=organization_id,
            decision=decision,
            score=score,
            positive_factors=positive_factors,
            risk_factors=risk_factors,
            recommendations=recommendations,
            reason=reason,
        )

    @classmethod
    def _upsert_assessment(
        cls,
        db: Session,
        asset: ManagedAsset,
        organization_id: uuid.UUID,
        decision: str,
        score: float,
        positive_factors: List[Dict[str, Any]],
        risk_factors: List[Dict[str, Any]],
        recommendations: List[str],
        reason: str,
    ) -> AssetTrustAssessment:
        """Upserts the trust assessment for the asset."""
        stmt = select(AssetTrustAssessment).where(
            AssetTrustAssessment.asset_id == asset.id,
            AssetTrustAssessment.organization_id == organization_id,
        )
        assessment = db.execute(stmt).scalar_one_or_none()

        now = datetime.now(timezone.utc)
        if not assessment:
            assessment = AssetTrustAssessment(
                id=uuid.uuid4(),
                organization_id=organization_id,
                asset_id=asset.id,
                trust_decision=decision,
                trust_score=score,
                positive_factors=json.dumps(positive_factors),
                risk_factors=json.dumps(risk_factors),
                least_privilege_recommendations=json.dumps(recommendations),
                decision_reason=reason,
                last_evaluated_at=now,
                is_stale=False,
            )
            db.add(assessment)
        else:
            assessment.trust_decision = decision
            assessment.trust_score = score
            assessment.positive_factors = json.dumps(positive_factors)
            assessment.risk_factors = json.dumps(risk_factors)
            assessment.least_privilege_recommendations = json.dumps(recommendations)
            assessment.decision_reason = reason
            assessment.last_evaluated_at = now
            assessment.is_stale = False

        db.flush()
        return assessment
