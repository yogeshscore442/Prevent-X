"""
PREVENT-X Reliable Rollback Orchestrator (MOD-10, MOD-08)
Safely reverts reverse proxy configurations to known-good snapshots,
enforces pre-reload syntax validation, performs live verification, and prevents race conditions.
"""

import hashlib
import logging
import threading
import time
import uuid
from pathlib import Path
from typing import Any, Dict, Optional, Tuple

from sqlalchemy import select
from sqlalchemy.orm import Session

from backend.app.database.base import utc_now
from backend.app.models.security_validation import (
    RollbackRecord,
    RollbackStatus,
    RollbackTriggerSource,
)
from backend.app.models.virtual_patch import (
    DeploymentStatus,
    VirtualPatchDeployment,
)
from backend.app.modules.virtual_patch.proxy_manager import NginxProxyManager

logger = logging.getLogger("preventx.security_validation.rollback")

# In-process concurrency lock preventing race conditions between deployments & rollbacks
_DEPLOYMENT_LOCK = threading.Lock()


class RollbackOrchestrator:
    """
    Executes atomic, verified rollbacks with pre-reload syntax testing and empirical verification.
    """

    @classmethod
    def execute_atomic_rollback(
        cls,
        db: Session,
        organization_id: uuid.UUID,
        deployment_id: uuid.UUID,
        rollback_reason: str,
        target_deployment_id: Optional[uuid.UUID] = None,
        operator_user_id: Optional[uuid.UUID] = None,
        trigger_source: str = RollbackTriggerSource.MANUAL.value,
    ) -> RollbackRecord:
        """
        Orchestrates safe rollback:
        1. Acquires deployment lock to prevent concurrent modifications.
        2. Retrieves previous known-good deployment snapshot and verifies SHA-256 integrity.
        3. Tests Nginx syntax before reload.
        4. Applies configuration atomically.
        5. Verifies restored reverse proxy with real HTTP health probes.
        6. Marks ROLLBACK_FAILED if restoration or verification fails.
        """
        # Concurrency protection
        acquired = _DEPLOYMENT_LOCK.acquire(blocking=True, timeout=10.0)
        if not acquired:
            raise RuntimeError("Concurrent deployment or rollback operation currently in progress. Lock acquisition timed out.")

        try:
            # 1. Fetch current deployment
            current_dep = db.scalar(
                select(VirtualPatchDeployment).where(
                    VirtualPatchDeployment.id == deployment_id,
                    VirtualPatchDeployment.organization_id == organization_id,
                )
            )
            if not current_dep:
                raise ValueError("Current deployment record not found.")

            prev_hash = current_dep.config_hash

            # 2. Locate target known-good deployment
            if target_deployment_id:
                target_dep = db.scalar(
                    select(VirtualPatchDeployment).where(
                        VirtualPatchDeployment.id == target_deployment_id,
                        VirtualPatchDeployment.organization_id == organization_id,
                    )
                )
            else:
                # Find the most recent stable deployment prior to current
                target_dep = db.scalar(
                    select(VirtualPatchDeployment)
                    .where(
                        VirtualPatchDeployment.organization_id == organization_id,
                        VirtualPatchDeployment.id != deployment_id,
                        VirtualPatchDeployment.status == DeploymentStatus.DEPLOYED.value,
                    )
                    .order_by(VirtualPatchDeployment.deployed_at.desc().nullslast())
                    .limit(1)
                )

            restored_hash = target_dep.config_hash if target_dep else "NO_PRIOR_DEPLOYMENT"

            # Create Rollback Record
            record = RollbackRecord(
                id=uuid.uuid4(),
                organization_id=organization_id,
                deployment_id=current_dep.id,
                target_deployment_id=target_dep.id if target_dep else None,
                trigger_source=trigger_source,
                rollback_reason=rollback_reason,
                previous_config_hash=prev_hash,
                restored_config_hash=restored_hash,
                status=RollbackStatus.INITIATED.value,
                is_restoration_verified=False,
                operator_user_id=operator_user_id,
                started_at=utc_now(),
            )
            db.add(record)
            db.commit()

            # If no target deployment exists, stop the reverse proxy safely
            if not target_dep or not target_dep.nginx_config_path:
                logger.warning("No prior deployment available for rollback. Gracefully stopping Nginx reverse proxy.")
                NginxProxyManager.stop_proxy()
                record.status = RollbackStatus.COMPLETED.value
                record.is_restoration_verified = True
                record.verification_evidence = "No prior deployment found. Reverse proxy terminated safely to protect upstream."
                record.completed_at = utc_now()
                current_dep.status = DeploymentStatus.ROLLED_BACK.value
                db.commit()
                db.refresh(record)
                return record

            # 3. Read target configuration & verify SHA-256 checksum
            target_conf_path = Path(target_dep.nginx_config_path)
            if not target_conf_path.is_file():
                error_msg = f"Target configuration file {target_dep.nginx_config_path} missing from disk."
                record.status = RollbackStatus.ROLLBACK_FAILED.value
                record.error_details = error_msg
                record.completed_at = utc_now()
                db.commit()
                logger.error(error_msg)
                raise RuntimeError(error_msg)

            config_content = target_conf_path.read_text(encoding="utf-8")
            computed_hash = hashlib.sha256(config_content.encode("utf-8")).hexdigest()
            if computed_hash != target_dep.config_hash:
                error_msg = f"Config snapshot integrity check failed! Expected hash {target_dep.config_hash}, found {computed_hash}."
                record.status = RollbackStatus.ROLLBACK_FAILED.value
                record.error_details = error_msg
                record.completed_at = utc_now()
                db.commit()
                logger.critical(error_msg)
                raise RuntimeError(error_msg)

            # 4. Pre-reload syntax validation
            record.status = RollbackStatus.VALIDATING_SYNTAX.value
            db.commit()

            is_valid, validation_log = NginxProxyManager.test_configuration(str(target_conf_path))
            if not is_valid:
                error_msg = f"Pre-reload Nginx syntax validation failed: {validation_log}"
                record.status = RollbackStatus.ROLLBACK_FAILED.value
                record.error_details = error_msg
                record.completed_at = utc_now()
                db.commit()
                logger.critical(error_msg)
                raise RuntimeError(error_msg)

            # 5. Restore configuration onto live Nginx
            record.status = RollbackStatus.RESTORING.value
            db.commit()

            applied, apply_log = NginxProxyManager.apply_deployment(
                deployment_id=str(target_dep.id),
                config_content=config_content,
                listen_port=target_dep.listen_port,
                upstream_url=target_dep.upstream_url,
            )

            if not applied:
                error_msg = f"Nginx configuration application failed: {apply_log}"
                record.status = RollbackStatus.ROLLBACK_FAILED.value
                record.error_details = error_msg
                record.completed_at = utc_now()
                db.commit()
                logger.critical(error_msg)
                raise RuntimeError(error_msg)

            # 6. Verify restored configuration with live HTTP probe
            time.sleep(1.0)
            health = NginxProxyManager.check_proxy_health(target_dep.listen_port)
            if not health.get("is_running"):
                error_msg = f"Post-restoration health check failed on port {target_dep.listen_port}: {health.get('error')}"
                record.status = RollbackStatus.ROLLBACK_FAILED.value
                record.error_details = error_msg
                record.completed_at = utc_now()
                db.commit()
                logger.critical(error_msg)
                raise RuntimeError(error_msg)

            # Rollback successful
            record.status = RollbackStatus.COMPLETED.value
            record.is_restoration_verified = True
            record.verification_evidence = (
                f"Successfully restored deployment {target_dep.id} (SHA-256: {restored_hash[:12]}...). "
                f"Gateway healthy on port {target_dep.listen_port} (Status code: {health.get('status_code')})."
            )
            record.completed_at = utc_now()

            # Update deployment statuses
            current_dep.status = DeploymentStatus.ROLLED_BACK.value
            current_dep.rollback_target_deployment_id = target_dep.id
            target_dep.status = DeploymentStatus.DEPLOYED.value

            db.commit()
            db.refresh(record)
            logger.info("Rollback completed successfully for deployment %s to %s", deployment_id, target_dep.id)
            return record

        finally:
            _DEPLOYMENT_LOCK.release()

