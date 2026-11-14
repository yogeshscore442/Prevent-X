"""
Attack Path and Prevention Engine Service (MOD-03)
Manages CRUD operations, graph execution, trust relationships, recommendation ranking,
and multi-tenant audit-logged operations.
"""

import json
import logging
import uuid
from datetime import datetime
from typing import Any, Dict, List, Optional, Tuple
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from backend.app.models.asset import ManagedAsset
from backend.app.models.attack_path import (
    AssetTrustRelationship,
    AttackPath,
    AttackPathAnalysisJob,
    AttackPathConfidence,
    AttackPathSeverity,
    AttackPathStatus,
    PreventionRecommendation,
)
from backend.app.models.audit_log import AuditEvent
from backend.app.modules.attack_path.graph_engine import AttackPathGraphEngine
from backend.app.modules.attack_path.recommendation_engine import PreventionRecommendationEngine
from backend.app.modules.attack_path.schemas import (
    AssetTrustRelationshipCreate,
    AttackPathOverviewStats,
    AttackPathRead,
    PreventionRecommendationRead,
)

logger = logging.getLogger(__name__)


class AttackPathService:
    """
    Business logic and storage service for Attack Path Analysis & Prevention.
    """

    @classmethod
    def get_overview(cls, db: Session, org_id: uuid.UUID) -> AttackPathOverviewStats:
        """
        Computes high-level overview metrics and KPI aggregations for an organization.
        """
        paths: List[AttackPath] = (
            db.execute(select(AttackPath).where(AttackPath.organization_id == org_id))
            .scalars()
            .all()
        )

        total_paths = len(paths)
        critical_paths = sum(1 for p in paths if p.severity == AttackPathSeverity.CRITICAL.value)
        high_paths = sum(1 for p in paths if p.severity == AttackPathSeverity.HIGH.value)
        medium_paths = sum(1 for p in paths if p.severity == AttackPathSeverity.MEDIUM.value)
        low_paths = sum(1 for p in paths if p.severity == AttackPathSeverity.LOW.value)

        entry_asset_ids = {p.entry_point_asset_id for p in paths}
        target_asset_ids = {p.target_asset_id for p in paths}

        avg_risk = (
            round(sum(p.risk_score for p in paths) / total_paths, 1)
            if total_paths > 0
            else 0.0
        )

        # Recommendations metrics
        recs: List[PreventionRecommendation] = (
            db.execute(
                select(PreventionRecommendation).where(
                    PreventionRecommendation.organization_id == org_id
                )
            )
            .scalars()
            .all()
        )
        total_recs = len(recs)
        impl_recs = sum(1 for r in recs if r.status == "IMPLEMENTED")

        # Top MITRE Tactics aggregation
        tactic_counts: Dict[str, int] = {}
        for p in paths:
            if p.mitre_tactics:
                try:
                    tactics = json.loads(p.mitre_tactics)
                    for t in tactics:
                        tactic_counts[t] = tactic_counts.get(t, 0) + 1
                except Exception:
                    pass

        top_tactics = [
            {"tactic": k, "count": v}
            for k, v in sorted(tactic_counts.items(), key=lambda item: item[1], reverse=True)
        ]

        return AttackPathOverviewStats(
            total_paths=total_paths,
            critical_paths=critical_paths,
            high_paths=high_paths,
            medium_paths=medium_paths,
            low_paths=low_paths,
            entry_points_count=len(entry_asset_ids),
            crown_jewels_at_risk_count=len(target_asset_ids),
            average_risk_score=avg_risk,
            total_recommendations=total_recs,
            implemented_recommendations=impl_recs,
            top_mitre_tactics=top_tactics[:6],
        )

    @classmethod
    def list_paths(
        cls,
        db: Session,
        org_id: uuid.UUID,
        severity: Optional[str] = None,
        confidence: Optional[str] = None,
        status: Optional[str] = None,
        entry_point_id: Optional[uuid.UUID] = None,
        target_id: Optional[uuid.UUID] = None,
        limit: int = 50,
        offset: int = 0,
    ) -> Tuple[List[AttackPath], int]:
        """
        Lists attack paths with optional filters and total count.
        """
        query = select(AttackPath).where(AttackPath.organization_id == org_id)

        if severity:
            query = query.where(AttackPath.severity == severity.upper())
        if confidence:
            query = query.where(AttackPath.confidence == confidence.upper())
        if status:
            query = query.where(AttackPath.status == status.upper())
        if entry_point_id:
            query = query.where(AttackPath.entry_point_asset_id == entry_point_id)
        if target_id:
            query = query.where(AttackPath.target_asset_id == target_id)

        # Count total
        count_query = select(func.count()).select_from(query.subquery())
        total = db.execute(count_query).scalar_one()

        # Fetch page ordered by risk score descending
        results = (
            db.execute(
                query.order_by(AttackPath.risk_score.desc())
                .limit(limit)
                .offset(offset)
            )
            .scalars()
            .all()
        )

        return results, total

    @classmethod
    def get_path(cls, db: Session, org_id: uuid.UUID, path_id: uuid.UUID) -> Optional[AttackPath]:
        """
        Fetches an attack path by ID scoped to the tenant organization.
        """
        return db.execute(
            select(AttackPath).where(
                AttackPath.id == path_id,
                AttackPath.organization_id == org_id,
            )
        ).scalar_one_or_none()

    @classmethod
    def update_path_status(
        cls,
        db: Session,
        org_id: uuid.UUID,
        path_id: uuid.UUID,
        status: str,
        user_id: Optional[uuid.UUID] = None,
    ) -> Optional[AttackPath]:
        """
        Updates the status of an attack path with audit logging.
        """
        path = cls.get_path(db, org_id, path_id)
        if not path:
            return None

        old_status = path.status
        path.status = status.upper()
        path.updated_at = datetime.utcnow()

        audit = AuditEvent(
            organization_id=org_id,
            user_id=user_id,
            action="UPDATE_ATTACK_PATH_STATUS",
            resource_type="attack_path",
            resource_id=str(path.id),
            status="SUCCESS",
            details=json.dumps({"old_status": old_status, "new_status": path.status}),
        )
        db.add(audit)
        db.commit()
        db.refresh(path)
        return path

    @classmethod
    def list_recommendations(
        cls,
        db: Session,
        org_id: uuid.UUID,
        category: Optional[str] = None,
        status: Optional[str] = None,
        attack_path_id: Optional[uuid.UUID] = None,
        limit: int = 50,
        offset: int = 0,
    ) -> Tuple[List[PreventionRecommendation], int]:
        """
        Lists prevention recommendations ordered by priority rank.
        """
        query = select(PreventionRecommendation).where(
            PreventionRecommendation.organization_id == org_id
        )

        if category:
            query = query.where(PreventionRecommendation.category == category.upper())
        if status:
            query = query.where(PreventionRecommendation.status == status.upper())
        if attack_path_id:
            query = query.where(PreventionRecommendation.attack_path_id == attack_path_id)

        count_query = select(func.count()).select_from(query.subquery())
        total = db.execute(count_query).scalar_one()

        results = (
            db.execute(
                query.order_by(PreventionRecommendation.priority_rank.asc())
                .limit(limit)
                .offset(offset)
            )
            .scalars()
            .all()
        )

        return results, total

    @classmethod
    def update_recommendation_status(
        cls,
        db: Session,
        org_id: uuid.UUID,
        recommendation_id: uuid.UUID,
        status: str,
        user_id: Optional[uuid.UUID] = None,
    ) -> Optional[PreventionRecommendation]:
        """
        Updates recommendation status with audit trail.
        """
        rec = db.execute(
            select(PreventionRecommendation).where(
                PreventionRecommendation.id == recommendation_id,
                PreventionRecommendation.organization_id == org_id,
            )
        ).scalar_one_or_none()

        if not rec:
            return None

        old_status = rec.status
        rec.status = status.upper()
        rec.updated_at = datetime.utcnow()

        audit = AuditEvent(
            organization_id=org_id,
            user_id=user_id,
            action="UPDATE_PREVENTION_RECOMMENDATION_STATUS",
            resource_type="prevention_recommendation",
            resource_id=str(rec.id),
            status="SUCCESS",
            details=json.dumps({"old_status": old_status, "new_status": rec.status}),
        )
        db.add(audit)
        db.commit()
        db.refresh(rec)
        return rec

    @classmethod
    def list_trust_relationships(
        cls, db: Session, org_id: uuid.UUID
    ) -> List[AssetTrustRelationship]:
        """
        Lists verified asset trust relationships for an organization.
        """
        return (
            db.execute(
                select(AssetTrustRelationship).where(
                    AssetTrustRelationship.organization_id == org_id
                )
            )
            .scalars()
            .all()
        )

    @classmethod
    def create_trust_relationship(
        cls,
        db: Session,
        org_id: uuid.UUID,
        data: AssetTrustRelationshipCreate,
        user_id: Optional[uuid.UUID] = None,
    ) -> AssetTrustRelationship:
        """
        Creates an explicit, evidence-backed trust link between two assets.
        """
        rel = AssetTrustRelationship(
            organization_id=org_id,
            source_asset_id=data.source_asset_id,
            target_asset_id=data.target_asset_id,
            relationship_type=data.relationship_type.upper(),
            port=data.port,
            evidence_source=data.evidence_source,
            is_verified=data.is_verified,
        )
        db.add(rel)

        audit = AuditEvent(
            organization_id=org_id,
            user_id=user_id,
            action="CREATE_ASSET_TRUST_RELATIONSHIP",
            resource_type="asset_trust_relationship",
            resource_id=str(rel.id),
            status="SUCCESS",
            details=json.dumps({
                "source_asset_id": str(data.source_asset_id),
                "target_asset_id": str(data.target_asset_id),
                "relationship_type": data.relationship_type,
            }),
        )
        db.add(audit)
        db.commit()
        db.refresh(rel)
        return rel

    @classmethod
    def delete_trust_relationship(
        cls,
        db: Session,
        org_id: uuid.UUID,
        rel_id: uuid.UUID,
        user_id: Optional[uuid.UUID] = None,
    ) -> bool:
        """
        Deletes a trust relationship.
        """
        rel = db.execute(
            select(AssetTrustRelationship).where(
                AssetTrustRelationship.id == rel_id,
                AssetTrustRelationship.organization_id == org_id,
            )
        ).scalar_one_or_none()

        if not rel:
            return False

        db.delete(rel)
        audit = AuditEvent(
            organization_id=org_id,
            user_id=user_id,
            action="DELETE_ASSET_TRUST_RELATIONSHIP",
            resource_type="asset_trust_relationship",
            resource_id=str(rel_id),
            status="SUCCESS",
        )
        db.add(audit)
        db.commit()
        return True

    @classmethod
    def run_analysis_sync(
        cls, db: Session, org_id: uuid.UUID, user_id: Optional[uuid.UUID] = None
    ) -> Dict[str, Any]:
        """
        Synchronously runs graph analysis, detects paths, generates recommendations,
        and saves them to the database.
        """
        engine = AttackPathGraphEngine(db=db, organization_id=org_id)
        raw_paths = engine.analyze_paths()

        persisted_paths: List[AttackPath] = []
        total_recs = 0

        for p_data in raw_paths:
            entry_asset = p_data.pop("_entry_asset")
            target_asset = p_data.pop("_target_asset")
            intermediate_assets = p_data.pop("_intermediate_assets")
            vulns = p_data.pop("_all_path_vulns")
            mitre_techniques = p_data.pop("_mitre_techniques")

            # Check if path already exists for this entry/target/step_count
            existing_path = db.execute(
                select(AttackPath).where(
                    AttackPath.organization_id == org_id,
                    AttackPath.entry_point_asset_id == p_data["entry_point_asset_id"],
                    AttackPath.target_asset_id == p_data["target_asset_id"],
                    AttackPath.step_count == p_data["step_count"],
                )
            ).scalar_one_or_none()

            if existing_path:
                for k, v in p_data.items():
                    setattr(existing_path, k, v)
                existing_path.updated_at = datetime.utcnow()
                path_obj = existing_path
            else:
                path_obj = AttackPath(**p_data)
                db.add(path_obj)

            db.flush()  # Ensure path_obj.id is available

            # Generate and persist recommendations for this path
            recs_data = PreventionRecommendationEngine.generate_recommendations(
                attack_path_id=path_obj.id,
                entry_asset=entry_asset,
                target_asset=target_asset,
                intermediate_assets=intermediate_assets,
                vulnerabilities=vulns,
                mitre_techniques=mitre_techniques,
                path_severity=path_obj.severity,
            )

            # Avoid duplicate recommendations
            for r in recs_data:
                existing_rec = db.execute(
                    select(PreventionRecommendation).where(
                        PreventionRecommendation.organization_id == org_id,
                        PreventionRecommendation.attack_path_id == path_obj.id,
                        PreventionRecommendation.title == r["title"],
                    )
                ).scalar_one_or_none()

                if not existing_rec:
                    rec_obj = PreventionRecommendation(
                        organization_id=org_id,
                        attack_path_id=path_obj.id,
                        target_asset_id=r.get("target_asset_id"),
                        title=r["title"],
                        category=r["category"],
                        description=r["description"],
                        risk_reduction=r["risk_reduction"],
                        implementation_complexity=r["implementation_complexity"],
                        smb_operational_impact=r["smb_operational_impact"],
                        priority_rank=r["priority_rank"],
                        mitre_technique_id=r.get("mitre_technique_id"),
                        status="PROPOSED",
                    )
                    db.add(rec_obj)
                    total_recs += 1

            persisted_paths.append(path_obj)

        audit = AuditEvent(
            organization_id=org_id,
            user_id=user_id,
            action="EXECUTE_ATTACK_PATH_ANALYSIS",
            resource_type="attack_path_job",
            status="SUCCESS",
            details=json.dumps({
                "paths_discovered": len(persisted_paths),
                "recommendations_created": total_recs,
            }),
        )
        db.add(audit)
        db.commit()

        for p in persisted_paths:
            db.refresh(p)

        return {
            "paths_count": len(persisted_paths),
            "recommendations_count": total_recs,
            "paths": persisted_paths,
        }

    @classmethod
    def create_analysis_job(
        cls, db: Session, org_id: uuid.UUID, user_id: Optional[uuid.UUID] = None
    ) -> AttackPathAnalysisJob:
        """
        Creates an asynchronous analysis job record.
        """
        job = AttackPathAnalysisJob(
            organization_id=org_id,
            initiated_by_user_id=user_id,
            status="PENDING",
            paths_discovered_count=0,
            recommendations_count=0,
        )
        db.add(job)
        db.commit()
        db.refresh(job)
        return job

    @classmethod
    def execute_job(cls, db: Session, job_id: uuid.UUID) -> AttackPathAnalysisJob:
        """
        Executes an analysis job (invoked by Celery worker).
        """
        job = db.execute(
            select(AttackPathAnalysisJob).where(AttackPathAnalysisJob.id == job_id)
        ).scalar_one_or_none()

        if not job:
            raise ValueError(f"Job {job_id} not found.")

        job.status = "RUNNING"
        db.commit()

        try:
            res = cls.run_analysis_sync(
                db=db,
                org_id=job.organization_id,
                user_id=job.initiated_by_user_id,
            )
            job.status = "COMPLETED"
            job.paths_discovered_count = res["paths_count"]
            job.recommendations_count = res["recommendations_count"]
            job.completed_at = datetime.utcnow()
        except Exception as exc:
            logger.error(f"Failed to execute attack path analysis job {job_id}: {exc}", exc_info=True)
            job.status = "FAILED"
            job.error_message = str(exc)
            job.completed_at = datetime.utcnow()

        db.commit()
        db.refresh(job)
        return job
