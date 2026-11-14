"""
PREVENT-X Celery Background Tasks for Zero Trust & Threat Intelligence (MOD-04, MOD-05)
"""

import logging
import uuid
from typing import Any, Dict, Optional

from backend.app.database.session import SessionLocal
from backend.app.modules.zero_trust.service import ZeroTrustService
from backend.app.workers.celery_app import celery_app

logger = logging.getLogger("preventx.tasks.zero_trust")


@celery_app.task(name="preventx.tasks.evaluate_zero_trust_job", bind=True)
def evaluate_zero_trust_job(
    self,
    organization_id: str,
    asset_id: Optional[str] = None,
) -> Dict[str, Any]:
    """
    Background worker task to continuously evaluate Zero Trust posture,
    execute threat correlations, and run behavioral anomaly detection.
    """
    org_uuid = uuid.UUID(organization_id)
    asset_uuid = uuid.UUID(asset_id) if asset_id else None

    logger.info("Starting Zero Trust evaluation task for org %s (asset: %s)", org_uuid, asset_uuid)

    db = SessionLocal()
    try:
        # 1. Run behavioral anomaly checks
        anomalies = ZeroTrustService.run_behavioral_evaluation(db, org_uuid)

        # 2. Run threat correlation
        corr_result = ZeroTrustService.run_threat_correlation(db, org_uuid)

        # 3. Evaluate Zero Trust posture
        if asset_uuid:
            assessment = ZeroTrustService.evaluate_asset(db, asset_uuid, org_uuid)
            assessed_count = 1
        else:
            assessments = ZeroTrustService.evaluate_all_assets(db, org_uuid)
            assessed_count = len(assessments)

        return {
            "status": "COMPLETED",
            "organization_id": str(org_uuid),
            "assets_evaluated": assessed_count,
            "anomalies_detected": len(anomalies),
            "threat_correlations": corr_result,
        }
    except Exception as exc:
        logger.exception("Failed Zero Trust evaluation task: %s", exc)
        raise
    finally:
        db.close()


@celery_app.task(name="preventx.tasks.sync_threat_intel_job", bind=True)
def sync_threat_intel_job(
    self,
    organization_id: Optional[str] = None,
) -> Dict[str, Any]:
    """
    Background worker task to sync threat intelligence feeds and re-correlate indicators.
    """
    org_uuid = uuid.UUID(organization_id) if organization_id else None
    logger.info("Starting Threat Intelligence sync task for org %s", org_uuid)

    db = SessionLocal()
    try:
        seeded_count = ZeroTrustService.sync_threat_intel(db, org_uuid)
        corr_summary = None
        if org_uuid:
            corr_summary = ZeroTrustService.run_threat_correlation(db, org_uuid)

        return {
            "status": "COMPLETED",
            "indicators_synced": seeded_count,
            "correlation_summary": corr_summary,
        }
    except Exception as exc:
        logger.exception("Failed Threat Intelligence sync task: %s", exc)
        raise
    finally:
        db.close()
