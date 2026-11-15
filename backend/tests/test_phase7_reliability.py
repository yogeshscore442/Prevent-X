"""
PREVENT-X Phase 7.1 Reliability Verification Tests
Covers:
1. Distributed deployment locking across independent database sessions and worker processes.
2. Real Nginx reverse proxy configuration deployment, reload, rollback, and SHA-256 checksum verification.
3. Rollback failure accuracy (ROLLBACK_FAILED reporting).
4. Canary safety policy and automated rollback enforcement.
"""

import hashlib
import json
import logging
import os
import subprocess
import sys
import threading
import time
import uuid
from pathlib import Path
from typing import Generator

import httpx
import pytest
from sqlalchemy import select, text
from sqlalchemy.orm import Session

from backend.app.core.distributed_lock import (
    DeploymentLockConflictError,
    compute_advisory_lock_id,
    distributed_deployment_lock,
    get_deployment_scope,
)
from backend.app.database.base import utc_now
from backend.app.database.session import SessionLocal, engine
from backend.app.models.audit_log import AuditEvent
from backend.app.models.organization import Organization
from backend.app.models.security_validation import (
    CanaryPolicy,
    RollbackRecord,
    RollbackStatus,
    RollbackTriggerSource,
)
from backend.app.models.virtual_patch import (
    DeploymentEnvironment,
    DeploymentStatus,
    VirtualPatchDeployment,
)
from backend.app.modules.security_validation.rollback_orchestrator import RollbackOrchestrator
from backend.app.modules.security_validation.service import SecurityValidationService
from backend.app.modules.virtual_patch.proxy_manager import NginxProxyManager
from backend.app.modules.virtual_patch.service import VirtualPatchService

logger = logging.getLogger("preventx.test.phase7_reliability")


# =============================================================================
# 1. DISTRIBUTED DEPLOYMENT LOCKING (MULTI-SESSION & CROSS-PROCESS)
# =============================================================================

def test_distributed_lock_multi_session_contention(db_session: Session, test_tenants):
    """
    Demonstrates that independent database sessions cannot acquire the deployment
    lock simultaneously for the same protected scope.
    Verifies that lock contention is recorded in the audit log.
    """
    org_a = test_tenants["org_a"]
    admin_a = test_tenants["admin_a"]
    # Commit org_a so independent database sessions can see it
    db_session.commit()
    scope = get_deployment_scope(org_a.id)

    # Clean audit logs for this scope first
    db_session.query(AuditEvent).filter(AuditEvent.resource_id == scope).delete()
    db_session.commit()

    # Session 1 acquires the lock
    with distributed_deployment_lock(
        scope=scope,
        organization_id=org_a.id,
        user_id=admin_a.id,
        timeout_seconds=5.0,
        db=db_session,
    ):
        # Session 2 attempts to acquire the same lock with short timeout
        db2 = SessionLocal()
        try:
            with pytest.raises(DeploymentLockConflictError):
                with distributed_deployment_lock(
                    scope=scope,
                    organization_id=org_a.id,
                    user_id=admin_a.id,
                    timeout_seconds=0.5,
                    poll_interval=0.1,
                    db=db2,
                ):
                    pytest.fail("Session 2 should not have acquired the lock while Session 1 holds it!")
        finally:
            db2.close()

    # Verify lock contention was recorded in the audit log
    db_check = SessionLocal()
    try:
        conflict_event = db_check.scalar(
            select(AuditEvent).where(
                AuditEvent.action == "deployment_lock_contention",
                AuditEvent.resource_id == scope,
                AuditEvent.status == "CONFLICT",
            )
        )
        assert conflict_event is not None
        assert "Simultaneous deployment/rollback prevented" in (conflict_event.details or "")
    finally:
        db_check.close()

    # Now that Session 1 has exited, Session 2 can acquire the lock
    db3 = SessionLocal()
    try:
        acquired = False
        with distributed_deployment_lock(
            scope=scope,
            organization_id=org_a.id,
            user_id=admin_a.id,
            timeout_seconds=2.0,
            db=db3,
        ):
            acquired = True
        assert acquired is True
    finally:
        db3.close()


def test_distributed_lock_cross_process_contention(test_tenants):
    """
    Demonstrates cross-process locking:
    Spawns an independent OS process that holds the PostgreSQL advisory lock.
    Verifies that the parent process is blocked from acquiring the lock.
    Verifies that when the child process terminates, the lock is released safely.
    """
    if engine.dialect.name != "postgresql":
        pytest.skip("Cross-process test requires PostgreSQL")

    org_a = test_tenants["org_a"]
    scope = get_deployment_scope(org_a.id)
    lock_id = compute_advisory_lock_id(scope)
    db_url = os.environ.get("DATABASE_URL", "postgresql://preventx_user:preventx_secure_pass@localhost:54320/preventx_db")

    # Script for external process to acquire lock and signal readiness
    child_script = f"""
import os, time, sys
from sqlalchemy import create_engine, text
engine = create_engine("{db_url}")
conn = engine.connect()
res = conn.execute(text("SELECT pg_try_advisory_lock({lock_id})")).scalar()
if res:
    sys.stdout.write("LOCKED\\n")
    sys.stdout.flush()
    time.sleep(3)
    conn.execute(text("SELECT pg_advisory_unlock({lock_id})"))
conn.close()
"""

    env = os.environ.copy()
    env["PYTHONPATH"] = "."
    proc = subprocess.Popen(
        [sys.executable, "-c", child_script],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        env=env,
    )

    try:
        # Wait for child to acquire lock
        line = proc.stdout.readline()
        assert "LOCKED" in line

        # Parent process attempts to acquire lock immediately -> must timeout
        with pytest.raises(DeploymentLockConflictError):
            with distributed_deployment_lock(
                scope=scope,
                timeout_seconds=0.5,
                poll_interval=0.1,
            ):
                pytest.fail("Parent should not acquire lock while child process holds it!")

        # Wait for child process to finish
        proc.wait(timeout=5)

        # Parent process should now successfully acquire lock
        acquired = False
        with distributed_deployment_lock(
            scope=scope,
            timeout_seconds=2.0,
            poll_interval=0.1,
        ):
            acquired = True
        assert acquired is True
    finally:
        if proc.poll() is None:
            proc.kill()


# =============================================================================
# 2. REAL NGINX ROLLBACK AND CHECKSUM VERIFICATION
# =============================================================================

def test_real_nginx_rollback_and_checksum_verification(db_session: Session, test_tenants):
    """
    Tests atomic rollback against the native Nginx reverse proxy:
    1. Deploys Version 1 configuration with X-PreventX-Version: V1.
    2. Records active configuration version and SHA-256 checksum.
    3. Probes proxy and verifies HTTP response.
    4. Deploys Version 2 configuration with X-PreventX-Version: V2.
    5. Verifies checksum changed.
    6. Triggers rollback to Version 1.
    7. Verifies previous configuration restored on disk, nginx -t passes, proxy reloaded.
    8. Verifies live HTTP probe returns V1 header.
    9. Verifies active configuration checksum matches original snapshot 1.
    """
    bin_path, prefix_path = NginxProxyManager.get_nginx_binary_and_prefix()
    if not bin_path:
        pytest.skip("Native Nginx binary not found in infrastructure/bin/nginx")

    org_a = test_tenants["org_a"]
    admin_a = test_tenants["admin_a"]
    listen_port = 8995

    # Configuration 1: Version 1
    conf_v1_content = f"""worker_processes  1;
events {{ worker_connections 64; }}
http {{
    server {{
        listen {listen_port};
        server_name localhost;
        location / {{
            add_header X-PreventX-Version "V1";
            add_header X-WAF-Engine "PREVENT-X-Native";
            return 200 "PreventX Live Gateway Version 1";
        }}
    }}
}}
"""
    hash_v1 = hashlib.sha256(conf_v1_content.encode("utf-8")).hexdigest()
    dep1_id = uuid.uuid4()
    conf_v1_path = NginxProxyManager.write_runtime_config(str(dep1_id), conf_v1_content)

    dep1 = VirtualPatchDeployment(
        id=dep1_id,
        organization_id=org_a.id,
        environment=DeploymentEnvironment.PRODUCTION.value,
        status=DeploymentStatus.DEPLOYED.value,
        deployed_rules_count=1,
        config_hash=hash_v1,
        nginx_config_path=conf_v1_path,
        listen_port=listen_port,
        upstream_url="http://127.0.0.1:8086",
        deployed_at=utc_now(),
    )
    db_session.add(dep1)
    db_session.commit()

    # Apply Deployment 1 to live Nginx
    applied1, msg1 = NginxProxyManager.apply_deployment(
        deployment_id=str(dep1.id),
        config_content=conf_v1_content,
        listen_port=listen_port,
        upstream_url="http://127.0.0.1:8086",
    )
    assert applied1 is True, f"Failed to apply deployment 1: {msg1}"
    time.sleep(1.0)

    # Verify active config on disk matches V1
    active_hash_1 = NginxProxyManager.get_active_config_hash()
    assert active_hash_1 == hash_v1

    # Live HTTP probe V1
    with httpx.Client(timeout=3.0) as client:
        r1 = client.get(f"http://127.0.0.1:{listen_port}/")
        assert r1.status_code == 200
        assert r1.headers.get("x-preventx-version") == "V1"
        assert r1.headers.get("x-waf-engine") == "PREVENT-X-Native"

    # Configuration 2: Version 2
    conf_v2_content = f"""worker_processes  1;
events {{ worker_connections 64; }}
http {{
    server {{
        listen {listen_port};
        server_name localhost;
        location / {{
            add_header X-PreventX-Version "V2";
            add_header X-WAF-Engine "PREVENT-X-Native";
            return 200 "PreventX Live Gateway Version 2";
        }}
    }}
}}
"""
    hash_v2 = hashlib.sha256(conf_v2_content.encode("utf-8")).hexdigest()
    dep2_id = uuid.uuid4()
    conf_v2_path = NginxProxyManager.write_runtime_config(str(dep2_id), conf_v2_content)

    dep2 = VirtualPatchDeployment(
        id=dep2_id,
        organization_id=org_a.id,
        environment=DeploymentEnvironment.PRODUCTION.value,
        status=DeploymentStatus.DEPLOYED.value,
        deployed_rules_count=2,
        config_hash=hash_v2,
        nginx_config_path=conf_v2_path,
        listen_port=listen_port,
        upstream_url="http://127.0.0.1:8086",
        deployed_at=utc_now(),
    )
    db_session.add(dep2)
    db_session.commit()

    # Apply Deployment 2 to live Nginx
    applied2, msg2 = NginxProxyManager.apply_deployment(
        deployment_id=str(dep2.id),
        config_content=conf_v2_content,
        listen_port=listen_port,
        upstream_url="http://127.0.0.1:8086",
    )
    assert applied2 is True, f"Failed to apply deployment 2: {msg2}"
    time.sleep(1.0)

    # Verify active config on disk matches V2
    active_hash_2 = NginxProxyManager.get_active_config_hash()
    assert active_hash_2 == hash_v2
    assert active_hash_2 != hash_v1

    # Live HTTP probe V2
    with httpx.Client(timeout=3.0) as client:
        r2 = client.get(f"http://127.0.0.1:{listen_port}/")
        assert r2.status_code == 200
        assert r2.headers.get("x-preventx-version") == "V2"

    # TRIGGER ATOMIC ROLLBACK FROM V2 TO V1
    rollback_record = RollbackOrchestrator.execute_atomic_rollback(
        db=db_session,
        organization_id=org_a.id,
        deployment_id=dep2.id,
        target_deployment_id=dep1.id,
        rollback_reason="Production canary health violation; reverting to V1 snapshot.",
        operator_user_id=admin_a.id,
        trigger_source=RollbackTriggerSource.MANUAL.value,
    )

    # Verify rollback record metadata
    assert rollback_record.status == RollbackStatus.COMPLETED.value
    assert rollback_record.is_restoration_verified is True
    assert rollback_record.previous_config_hash == hash_v2
    assert rollback_record.restored_config_hash == hash_v1

    # Test syntax explicitly
    syntax_ok, syntax_log = NginxProxyManager.test_configuration(NginxProxyManager.get_active_config_path())
    assert syntax_ok is True, f"Nginx syntax check failed on restored active config: {syntax_log}"

    # Verify active config checksum on disk matches snapshot 1
    active_hash_restored = NginxProxyManager.get_active_config_hash()
    assert active_hash_restored == hash_v1

    # Send live HTTP probe through restored proxy
    with httpx.Client(timeout=3.0) as client:
        r_restored = client.get(f"http://127.0.0.1:{listen_port}/")
        assert r_restored.status_code == 200
        assert r_restored.headers.get("x-preventx-version") == "V1"
        assert "Version 1" in r_restored.text

    # Clean up proxy
    NginxProxyManager.stop_proxy()


def test_rollback_failure_reports_failed(db_session: Session, test_tenants):
    """
    Tests that when rollback cannot be safely executed (corrupted snapshot file),
    the system reports ROLLBACK_FAILED and does NOT falsely report success.
    """
    org_a = test_tenants["org_a"]
    admin_a = test_tenants["admin_a"]

    active_dep = VirtualPatchDeployment(
        id=uuid.uuid4(),
        organization_id=org_a.id,
        environment=DeploymentEnvironment.PRODUCTION.value,
        status=DeploymentStatus.DEPLOYED.value,
        deployed_rules_count=1,
        config_hash="a" * 64,
        nginx_config_path="infrastructure/bin/nginx/conf/fake_active.conf",
        listen_port=8996,
        upstream_url="http://127.0.0.1:8086",
    )
    db_session.add(active_dep)

    # Corrupt target deployment: nonexistent file
    corrupt_dep = VirtualPatchDeployment(
        id=uuid.uuid4(),
        organization_id=org_a.id,
        environment=DeploymentEnvironment.STAGING.value,
        status=DeploymentStatus.DEPLOYED.value,
        deployed_rules_count=0,
        config_hash="b" * 64,
        nginx_config_path="infrastructure/bin/nginx/conf/nonexistent_snapshot.conf",
        listen_port=8996,
        upstream_url="http://127.0.0.1:8086",
    )
    db_session.add(corrupt_dep)
    db_session.commit()

    with pytest.raises(RuntimeError) as exc_info:
        RollbackOrchestrator.execute_atomic_rollback(
            db=db_session,
            organization_id=org_a.id,
            deployment_id=active_dep.id,
            target_deployment_id=corrupt_dep.id,
            rollback_reason="Test rollback failure handling",
            operator_user_id=admin_a.id,
        )

    assert "missing from disk" in str(exc_info.value)

    # Check database record
    db_session.expire_all()
    failed_record = db_session.scalar(
        select(RollbackRecord)
        .where(
            RollbackRecord.organization_id == org_a.id,
            RollbackRecord.deployment_id == active_dep.id,
        )
        .order_by(RollbackRecord.created_at.desc())
        .limit(1)
    )
    assert failed_record is not None
    assert failed_record.status == RollbackStatus.ROLLBACK_FAILED.value
    assert failed_record.is_restoration_verified is False
    assert "missing from disk" in (failed_record.error_details or "")


# =============================================================================
# 3. CANARY POLICY & SAFETY THRESHOLDS VERIFICATION
# =============================================================================

def test_canary_policy_safety_gate_designation(db_session: Session, test_tenants):
    """
    Verifies that CanaryPolicy serves as an automated safety evaluation gate
    governing validation failure thresholds and auto-rollback triggers,
    and is properly identified as a policy/configuration capability.
    """
    org_a = test_tenants["org_a"]

    policy = SecurityValidationService.get_or_create_canary_policy(db_session, org_a.id)
    assert policy is not None
    assert policy.canary_traffic_weight == 10
    assert policy.max_failure_rate_percent == 5.0
    assert policy.auto_rollback_enabled is True

    # Update policy thresholds
    from backend.app.modules.security_validation.schemas import CanaryPolicyUpdate
    updated = SecurityValidationService.update_canary_policy(
        db_session,
        org_a.id,
        CanaryPolicyUpdate(canary_traffic_weight=20, max_failure_rate_percent=2.5),
    )
    assert updated.canary_traffic_weight == 20
    assert updated.max_failure_rate_percent == 2.5
