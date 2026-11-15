"""
PREVENT-X Celery Background Tasks for Intelligent Virtual Patching & Reverse Proxy (MOD-06, MOD-08)
"""

import logging
import uuid
from typing import Any, Dict, Optional

from backend.app.database.session import SessionLocal
from backend.app.modules.virtual_patch.service import VirtualPatchService
from backend.app.workers.celery_app import celery_app

logger = logging.getLogger("preventx.tasks.virtual_patch")


@celery_app.task(name="preventx.tasks.generate_virtual_patches_job", bind=True)
def generate_virtual_patches_job(
    self,
    organization_id: str,
) -> Dict[str, Any]:
    """
    Background worker task to analyze unpatched vulnerabilities and synthesize virtual patch recommendations.
    """
    org_uuid = uuid.UUID(organization_id)
    logger.info("Starting virtual patch generation job for organization %s", org_uuid)

    db = SessionLocal()
    try:
        recs = VirtualPatchService.generate_recommendations_for_organization(db, org_uuid)
        return {
            "status": "COMPLETED",
            "organization_id": str(org_uuid),
            "recommendations_generated": len(recs),
        }
    except Exception as exc:
        logger.exception("Failed virtual patch recommendation synthesis: %s", exc)
        raise
    finally:
        db.close()


@celery_app.task(name="preventx.tasks.stage_virtual_patch_deployment_job", bind=True)
def stage_virtual_patch_deployment_job(
    self,
    organization_id: str,
    listen_port: int = 8085,
    upstream_url: str = "http://127.0.0.1:8086",
    user_id: Optional[str] = None,
) -> Dict[str, Any]:
    """
    Background worker task to compile virtual patch rules and validate syntax in staging.
    """
    org_uuid = uuid.UUID(organization_id)
    user_uuid = uuid.UUID(user_id) if user_id else None
    logger.info("Staging virtual patch deployment for organization %s on port %s", org_uuid, listen_port)

    db = SessionLocal()
    try:
        deployment = VirtualPatchService.stage_deployment(
            db=db,
            organization_id=org_uuid,
            listen_port=listen_port,
            upstream_url=upstream_url,
            user_id=user_uuid,
        )
        return {
            "status": deployment.status,
            "deployment_id": str(deployment.id),
            "organization_id": str(org_uuid),
            "deployed_rules_count": deployment.deployed_rules_count,
            "config_hash": deployment.config_hash,
        }
    except Exception as exc:
        logger.exception("Failed to stage virtual patch deployment: %s", exc)
        raise
    finally:
        db.close()


@celery_app.task(name="preventx.tasks.deploy_virtual_patches_job", bind=True)
def deploy_virtual_patches_job(
    self,
    organization_id: str,
    deployment_id: str,
    user_id: str,
) -> Dict[str, Any]:
    """
    Background worker task to enforce approved virtual patches on the live Nginx reverse proxy.
    Strictly enforces human approval requirement.
    """
    org_uuid = uuid.UUID(organization_id)
    dep_uuid = uuid.UUID(deployment_id)
    u_uuid = uuid.UUID(user_id)
    logger.info("Deploying approved virtual patches for org %s (dep: %s, user: %s)", org_uuid, dep_uuid, u_uuid)

    db = SessionLocal()
    try:
        deployment = VirtualPatchService.deploy_to_production(
            db=db,
            deployment_id=dep_uuid,
            organization_id=org_uuid,
            user_id=u_uuid,
        )
        return {
            "status": deployment.status,
            "deployment_id": str(deployment.id),
            "environment": deployment.environment,
            "deployed_rules_count": deployment.deployed_rules_count,
        }
    except Exception as exc:
        logger.exception("Failed production deployment: %s", exc)
        raise
    finally:
        db.close()

