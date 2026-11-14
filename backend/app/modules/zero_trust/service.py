"""
PREVENT-X Zero Trust & Threat Intelligence Service (MOD-04, MOD-05)
High-level orchestration service for trust evaluations, threat intelligence,
behavioral anomaly detection, and automated mitigation workflows.
"""

import json
import logging
import uuid
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple

from sqlalchemy import func, or_, select
from sqlalchemy.orm import Session

from backend.app.models.asset import ManagedAsset
from backend.app.models.user import User
from backend.app.models.zero_trust import (
    AnomalyStatus,
    AssetTrustAssessment,
    BehavioralAnomaly,
    ResponseAction,
    ResponseActionStatus,
    ThreatAssetCorrelation,
    ThreatIntelRecord,
    TrustDecision,
)
from backend.app.modules.zero_trust.anomaly_engine import BehavioralAnomalyEngine
from backend.app.modules.zero_trust.response_engine import AutomatedResponseEngine
from backend.app.modules.zero_trust.schemas import (
    AssetTrustAssessmentRead,
    BehavioralAnomalyRead,
    ResponseActionCreate,
    ResponseActionRead,
    ThreatAssetCorrelationRead,
    ThreatIntelCreate,
    ThreatIntelRead,
    ZeroTrustOverviewStats,
)
from backend.app.modules.zero_trust.threat_intel_engine import ThreatIntelligenceEngine
from backend.app.modules.zero_trust.trust_engine import ZeroTrustEvaluationEngine

logger = logging.getLogger("preventx.zero_trust.service")


class ZeroTrustService:
    """Service facade coordinating Zero Trust, Threat Intel, Anomalies, and Responses."""

    @classmethod
    def evaluate_asset(
        cls,
        db: Session,
        asset_id: uuid.UUID,
        organization_id: uuid.UUID,
    ) -> AssetTrustAssessment:
        stmt = select(ManagedAsset).where(
            ManagedAsset.id == asset_id,
            ManagedAsset.organization_id == organization_id,
        )
        asset = db.execute(stmt).scalar_one_or_none()
        if not asset:
            raise ValueError(f"Managed asset {asset_id} not found in organization.")

        assessment = ZeroTrustEvaluationEngine.evaluate_asset_trust(
            db=db,
            asset=asset,
            organization_id=organization_id,
        )
        db.commit()
        return assessment

    @classmethod
    def evaluate_all_assets(
        cls,
        db: Session,
        organization_id: uuid.UUID,
    ) -> List[AssetTrustAssessment]:
        stmt = select(ManagedAsset).where(
            ManagedAsset.organization_id == organization_id,
        )
        assets = db.execute(stmt).scalars().all()
        assessments = []
        for asset in assets:
            ass = ZeroTrustEvaluationEngine.evaluate_asset_trust(
                db=db,
                asset=asset,
                organization_id=organization_id,
            )
            assessments.append(ass)
        db.commit()
        return assessments

    @classmethod
    def get_assessments(
        cls,
        db: Session,
        organization_id: uuid.UUID,
        decision: Optional[str] = None,
        skip: int = 0,
        limit: int = 100,
    ) -> List[AssetTrustAssessmentRead]:
        stmt = (
            select(AssetTrustAssessment, ManagedAsset)
            .join(ManagedAsset, AssetTrustAssessment.asset_id == ManagedAsset.id)
            .where(AssetTrustAssessment.organization_id == organization_id)
        )
        if decision:
            stmt = stmt.where(AssetTrustAssessment.trust_decision == decision.upper())

        stmt = stmt.order_by(AssetTrustAssessment.trust_score.asc()).offset(skip).limit(limit)
        results = db.execute(stmt).all()

        output = []
        for assessment, asset in results:
            pos_factors = json.loads(assessment.positive_factors or "[]")
            risk_factors = json.loads(assessment.risk_factors or "[]")
            recs = json.loads(assessment.least_privilege_recommendations or "[]")

            output.append(
                AssetTrustAssessmentRead(
                    id=assessment.id,
                    organization_id=assessment.organization_id,
                    asset_id=assessment.asset_id,
                    asset_name=asset.name,
                    asset_target=asset.target,
                    asset_type=asset.asset_type,
                    asset_criticality=asset.criticality,
                    trust_decision=assessment.trust_decision,
                    trust_score=assessment.trust_score,
                    positive_factors=pos_factors,
                    risk_factors=risk_factors,
                    least_privilege_recommendations=recs,
                    decision_reason=assessment.decision_reason,
                    last_evaluated_at=assessment.last_evaluated_at,
                    is_stale=assessment.is_stale,
                    created_at=assessment.created_at,
                    updated_at=assessment.updated_at,
                )
            )
        return output

    @classmethod
    def get_threat_indicators(
        cls,
        db: Session,
        organization_id: uuid.UUID,
        indicator_type: Optional[str] = None,
        is_active: Optional[bool] = None,
        skip: int = 0,
        limit: int = 100,
    ) -> List[ThreatIntelRead]:
        now = datetime.now(timezone.utc)
        stmt = select(ThreatIntelRecord).where(
            or_(
                ThreatIntelRecord.organization_id == organization_id,
                ThreatIntelRecord.organization_id.is_(None),
            )
        )
        if indicator_type:
            stmt = stmt.where(ThreatIntelRecord.indicator_type == indicator_type.upper())
        if is_active is not None:
            stmt = stmt.where(ThreatIntelRecord.is_active == is_active)

        stmt = stmt.order_by(ThreatIntelRecord.created_at.desc()).offset(skip).limit(limit)
        records = db.execute(stmt).scalars().all()

        output = []
        for r in records:
            tactics = json.loads(r.mitre_tactics or "[]")
            techniques = json.loads(r.mitre_techniques or "[]")
            tags = json.loads(r.tags or "[]")
            is_expired = bool(r.expires_at and r.expires_at <= now)

            output.append(
                ThreatIntelRead(
                    id=r.id,
                    organization_id=r.organization_id,
                    indicator_type=r.indicator_type,
                    indicator_value=r.indicator_value,
                    confidence=r.confidence,
                    source=r.source,
                    threat_actor=r.threat_actor,
                    description=r.description,
                    severity=r.severity,
                    tlp=r.tlp,
                    is_active=r.is_active,
                    expires_at=r.expires_at,
                    last_seen_at=r.last_seen_at,
                    mitre_tactics=tactics,
                    mitre_techniques=techniques,
                    tags=tags,
                    is_expired=is_expired,
                    created_at=r.created_at,
                    updated_at=r.updated_at,
                )
            )
        return output

    @classmethod
    def create_threat_indicator(
        cls,
        db: Session,
        organization_id: uuid.UUID,
        data: ThreatIntelCreate,
    ) -> ThreatIntelRecord:
        record = ThreatIntelligenceEngine.ingest_indicator(
            db=db,
            indicator_type=data.indicator_type,
            indicator_value=data.indicator_value,
            confidence=data.confidence,
            source=data.source,
            organization_id=organization_id,
            threat_actor=data.threat_actor,
            description=data.description,
            severity=data.severity,
            tlp=data.tlp,
            expires_at=data.expires_at,
            mitre_tactics=data.mitre_tactics,
            mitre_techniques=data.mitre_techniques,
            tags=data.tags,
        )
        db.commit()
        return record

    @classmethod
    def sync_threat_intel(cls, db: Session, organization_id: uuid.UUID) -> int:
        return ThreatIntelligenceEngine.seed_threat_intelligence(db, organization_id)

    @classmethod
    def run_threat_correlation(cls, db: Session, organization_id: uuid.UUID) -> Dict[str, Any]:
        return ThreatIntelligenceEngine.correlate_threats(db, organization_id)

    @classmethod
    def get_correlations(
        cls,
        db: Session,
        organization_id: uuid.UUID,
        status: Optional[str] = None,
        skip: int = 0,
        limit: int = 100,
    ) -> List[ThreatAssetCorrelationRead]:
        stmt = (
            select(ThreatAssetCorrelation, ManagedAsset, ThreatIntelRecord)
            .join(ManagedAsset, ThreatAssetCorrelation.asset_id == ManagedAsset.id)
            .join(ThreatIntelRecord, ThreatAssetCorrelation.threat_intel_id == ThreatIntelRecord.id)
            .where(ThreatAssetCorrelation.organization_id == organization_id)
        )
        if status:
            stmt = stmt.where(ThreatAssetCorrelation.status == status.upper())

        stmt = stmt.order_by(ThreatAssetCorrelation.created_at.desc()).offset(skip).limit(limit)
        results = db.execute(stmt).all()

        output = []
        for corr, asset, ioc in results:
            output.append(
                ThreatAssetCorrelationRead(
                    id=corr.id,
                    organization_id=corr.organization_id,
                    threat_intel_id=corr.threat_intel_id,
                    asset_id=corr.asset_id,
                    asset_name=asset.name,
                    asset_target=asset.target,
                    threat_indicator=ioc.indicator_value,
                    threat_type=ioc.indicator_type,
                    correlation_type=corr.correlation_type,
                    matched_value=corr.matched_value,
                    severity=corr.severity,
                    confidence=corr.confidence,
                    details=corr.details,
                    status=corr.status,
                    created_at=corr.created_at,
                    updated_at=corr.updated_at,
                )
            )
        return output

    @classmethod
    def get_anomalies(
        cls,
        db: Session,
        organization_id: uuid.UUID,
        status: Optional[str] = None,
        is_zero_day: Optional[bool] = None,
        skip: int = 0,
        limit: int = 100,
    ) -> List[BehavioralAnomalyRead]:
        stmt = (
            select(BehavioralAnomaly, ManagedAsset)
            .join(ManagedAsset, BehavioralAnomaly.asset_id == ManagedAsset.id)
            .where(BehavioralAnomaly.organization_id == organization_id)
        )
        if status:
            stmt = stmt.where(BehavioralAnomaly.status == status.upper())
        if is_zero_day is not None:
            stmt = stmt.where(BehavioralAnomaly.is_zero_day_indicator == is_zero_day)

        stmt = stmt.order_by(BehavioralAnomaly.anomaly_score.desc()).offset(skip).limit(limit)
        results = db.execute(stmt).all()

        output = []
        for anom, asset in results:
            ev_data = json.loads(anom.evidence_data or "{}") if anom.evidence_data else None
            output.append(
                BehavioralAnomalyRead(
                    id=anom.id,
                    organization_id=anom.organization_id,
                    asset_id=anom.asset_id,
                    asset_name=asset.name,
                    asset_target=asset.target,
                    anomaly_type=anom.anomaly_type,
                    severity=anom.severity,
                    confidence=anom.confidence,
                    anomaly_score=anom.anomaly_score,
                    description=anom.description,
                    evidence_data=ev_data,
                    status=anom.status,
                    is_zero_day_indicator=anom.is_zero_day_indicator,
                    created_at=anom.created_at,
                    updated_at=anom.updated_at,
                )
            )
        return output

    @classmethod
    def update_anomaly_status(
        cls,
        db: Session,
        anomaly_id: uuid.UUID,
        organization_id: uuid.UUID,
        new_status: str,
        user: User,
    ) -> BehavioralAnomaly:
        stmt = select(BehavioralAnomaly).where(
            BehavioralAnomaly.id == anomaly_id,
            BehavioralAnomaly.organization_id == organization_id,
        )
        anomaly = db.execute(stmt).scalar_one_or_none()
        if not anomaly:
            raise ValueError(f"Behavioral anomaly {anomaly_id} not found.")

        anomaly.status = new_status.upper()
        db.commit()
        return anomaly

    @classmethod
    def run_behavioral_evaluation(
        cls,
        db: Session,
        organization_id: uuid.UUID,
    ) -> List[BehavioralAnomaly]:
        return BehavioralAnomalyEngine.evaluate_all_anomalies(db, organization_id)

    @classmethod
    def get_response_actions(
        cls,
        db: Session,
        organization_id: uuid.UUID,
        status: Optional[str] = None,
        skip: int = 0,
        limit: int = 100,
    ) -> List[ResponseActionRead]:
        stmt = (
            select(
                ResponseAction,
                ManagedAsset.name.label("asset_name"),
                BehavioralAnomaly.anomaly_type.label("anomaly_type"),
                User.email.label("approved_by_user_name"),
            )
            .outerjoin(ManagedAsset, ResponseAction.asset_id == ManagedAsset.id)
            .outerjoin(BehavioralAnomaly, ResponseAction.anomaly_id == BehavioralAnomaly.id)
            .outerjoin(User, ResponseAction.approved_by_user_id == User.id)
            .where(ResponseAction.organization_id == organization_id)
        )
        if status:
            stmt = stmt.where(ResponseAction.status == status.upper())

        stmt = stmt.order_by(ResponseAction.created_at.desc()).offset(skip).limit(limit)
        results = db.execute(stmt).all()

        output = []
        for action, asset_name, anomaly_type, approved_by_user_name in results:
            exec_payload = json.loads(action.execution_payload or "{}") if action.execution_payload else None
            rollback_payload = json.loads(action.rollback_payload or "{}") if action.rollback_payload else None

            output.append(
                ResponseActionRead(
                    id=action.id,
                    organization_id=action.organization_id,
                    asset_id=action.asset_id,
                    asset_name=asset_name,
                    anomaly_id=action.anomaly_id,
                    anomaly_type=anomaly_type,
                    action_type=action.action_type,
                    title=action.title,
                    description=action.description,
                    target_entity=action.target_entity,
                    execution_payload=exec_payload,
                    rollback_payload=rollback_payload,
                    status=action.status,
                    is_disruptive=action.is_disruptive,
                    approved_by_user_id=action.approved_by_user_id,
                    approved_by_user_name=approved_by_user_name,
                    approved_at=action.approved_at,
                    executed_at=action.executed_at,
                    execution_log=action.execution_log,
                    created_at=action.created_at,
                    updated_at=action.updated_at,
                )
            )
        return output

    @classmethod
    def propose_response_action(
        cls,
        db: Session,
        organization_id: uuid.UUID,
        data: ResponseActionCreate,
    ) -> ResponseAction:
        action = AutomatedResponseEngine.propose_action(
            db=db,
            organization_id=organization_id,
            action_type=data.action_type,
            title=data.title,
            description=data.description,
            target_entity=data.target_entity,
            asset_id=data.asset_id,
            anomaly_id=data.anomaly_id,
            execution_payload=data.execution_payload,
            rollback_payload=data.rollback_payload,
            is_disruptive=data.is_disruptive,
        )
        db.commit()
        return action

    @classmethod
    def approve_response_action(
        cls,
        db: Session,
        action_id: uuid.UUID,
        organization_id: uuid.UUID,
        user: User,
    ) -> ResponseAction:
        action = AutomatedResponseEngine.approve_action(db, action_id, organization_id, user)
        db.commit()
        return action

    @classmethod
    def reject_response_action(
        cls,
        db: Session,
        action_id: uuid.UUID,
        organization_id: uuid.UUID,
        user: User,
        reason: Optional[str] = None,
    ) -> ResponseAction:
        action = AutomatedResponseEngine.reject_action(db, action_id, organization_id, user, reason)
        db.commit()
        return action

    @classmethod
    def execute_response_action(
        cls,
        db: Session,
        action_id: uuid.UUID,
        organization_id: uuid.UUID,
        user: User,
    ) -> ResponseAction:
        action = AutomatedResponseEngine.execute_action(db, action_id, organization_id, user)
        db.commit()
        return action

    @classmethod
    def rollback_response_action(
        cls,
        db: Session,
        action_id: uuid.UUID,
        organization_id: uuid.UUID,
        user: User,
    ) -> ResponseAction:
        action = AutomatedResponseEngine.rollback_action(db, action_id, organization_id, user)
        db.commit()
        return action

    @classmethod
    def get_overview_stats(cls, db: Session, organization_id: uuid.UUID) -> ZeroTrustOverviewStats:
        """Aggregates high-level posture KPIs."""
        # Assets count
        total_assets = db.execute(
            select(func.count(ManagedAsset.id)).where(ManagedAsset.organization_id == organization_id)
        ).scalar() or 0

        # Assessments by decision
        stmt_decisions = (
            select(AssetTrustAssessment.trust_decision, func.count(AssetTrustAssessment.id))
            .where(AssetTrustAssessment.organization_id == organization_id)
            .group_by(AssetTrustAssessment.trust_decision)
        )
        decision_counts = dict(db.execute(stmt_decisions).all())

        # Average score
        avg_score = db.execute(
            select(func.avg(AssetTrustAssessment.trust_score)).where(
                AssetTrustAssessment.organization_id == organization_id
            )
        ).scalar() or 0.0

        # Threat intel counts
        now = datetime.now(timezone.utc)
        active_indicators = db.execute(
            select(func.count(ThreatIntelRecord.id)).where(
                ThreatIntelRecord.is_active == True,
                or_(
                    ThreatIntelRecord.expires_at.is_(None),
                    ThreatIntelRecord.expires_at > now,
                ),
                or_(
                    ThreatIntelRecord.organization_id == organization_id,
                    ThreatIntelRecord.organization_id.is_(None),
                ),
            )
        ).scalar() or 0

        correlations_count = db.execute(
            select(func.count(ThreatAssetCorrelation.id)).where(
                ThreatAssetCorrelation.organization_id == organization_id,
                ThreatAssetCorrelation.status == "ACTIVE",
            )
        ).scalar() or 0

        # Anomalies count
        active_anomalies = db.execute(
            select(func.count(BehavioralAnomaly.id)).where(
                BehavioralAnomaly.organization_id == organization_id,
                BehavioralAnomaly.status.in_([AnomalyStatus.OPEN.value, AnomalyStatus.INVESTIGATING.value]),
            )
        ).scalar() or 0

        zero_day_indicators = db.execute(
            select(func.count(BehavioralAnomaly.id)).where(
                BehavioralAnomaly.organization_id == organization_id,
                BehavioralAnomaly.is_zero_day_indicator == True,
                BehavioralAnomaly.status.in_([AnomalyStatus.OPEN.value, AnomalyStatus.INVESTIGATING.value]),
            )
        ).scalar() or 0

        # Actions counts
        pending_actions = db.execute(
            select(func.count(ResponseAction.id)).where(
                ResponseAction.organization_id == organization_id,
                ResponseAction.status == ResponseActionStatus.PENDING_APPROVAL.value,
            )
        ).scalar() or 0

        executed_actions = db.execute(
            select(func.count(ResponseAction.id)).where(
                ResponseAction.organization_id == organization_id,
                ResponseAction.status == ResponseActionStatus.EXECUTED.value,
            )
        ).scalar() or 0

        return ZeroTrustOverviewStats(
            total_assets=total_assets,
            trusted_count=decision_counts.get(TrustDecision.TRUSTED.value, 0),
            restricted_count=decision_counts.get(TrustDecision.RESTRICTED.value, 0),
            untrusted_count=decision_counts.get(TrustDecision.UNTRUSTED.value, 0),
            insufficient_evidence_count=decision_counts.get(TrustDecision.INSUFFICIENT_EVIDENCE.value, 0),
            average_trust_score=round(float(avg_score), 1),
            active_threat_indicators=active_indicators,
            correlated_threats_count=correlations_count,
            active_anomalies_count=active_anomalies,
            zero_day_indicators_count=zero_day_indicators,
            pending_approval_actions=pending_actions,
            executed_actions=executed_actions,
        )
