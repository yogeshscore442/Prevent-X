"""
PREVENT-X Distributed Deployment Locking (MOD-08, MOD-10)
Cross-process distributed locking using PostgreSQL advisory locks (with threading fallback for SQLite).
Guarantees mutually exclusive deployments, rollbacks, and configuration reloads across FastAPI and Celery workers.
"""

import hashlib
import logging
import threading
import time
import uuid
from contextlib import contextmanager
from typing import Dict, Generator, Optional

from sqlalchemy import text
from sqlalchemy.engine import Engine
from sqlalchemy.orm import Session

from backend.app.database.session import SessionLocal, engine
from backend.app.repositories.audit_repo import audit_repo

logger = logging.getLogger("preventx.distributed_lock")

# Process-local fallback locks for non-PostgreSQL dialects (e.g. SQLite memory in unit tests)
_FALLBACK_LOCKS: Dict[str, threading.Lock] = {}
_FALLBACK_MAP_LOCK = threading.Lock()


class DeploymentLockConflictError(RuntimeError):
    """Raised when a deployment or rollback operation cannot acquire the distributed lock due to concurrency contention."""
    pass


def compute_advisory_lock_id(scope: str) -> int:
    """
    Deterministically computes a signed 64-bit integer lock ID from a scope string.
    Suitable for PostgreSQL pg_try_advisory_lock(bigint).
    """
    digest = hashlib.sha256(scope.encode("utf-8")).digest()
    return int.from_bytes(digest[:8], byteorder="big", signed=True)


def get_deployment_scope(
    organization_id: uuid.UUID,
    app_id: Optional[str] = "default",
) -> str:
    """
    Generates a canonical scope string identifying a protected application within a tenant.
    """
    return f"preventx:org:{organization_id}:app:{app_id or 'default'}"


@contextmanager
def distributed_deployment_lock(
    scope: str,
    organization_id: Optional[uuid.UUID] = None,
    user_id: Optional[uuid.UUID] = None,
    timeout_seconds: float = 10.0,
    poll_interval: float = 0.25,
    db: Optional[Session] = None,
    custom_engine: Optional[Engine] = None,
) -> Generator[None, None, None]:
    """
    Distributed lock context manager for deployment and rollback operations.
    Shares lock state across FastAPI web threads and independent Celery worker processes.

    - Scope: Uniquely identifies tenant and target application.
    - Mechanism: PostgreSQL 64-bit session advisory locks (`pg_try_advisory_lock`).
    - Safety: Automatically released on completion, error, or process/socket termination.
    - Contention: Emits an audited conflict event when acquisition times out.
    """
    target_engine = custom_engine
    if target_engine is None:
        if db is not None:
            bind = db.get_bind()
            if hasattr(bind, "engine"):
                target_engine = bind.engine
            else:
                target_engine = bind
        else:
            target_engine = engine

    dialect_name = getattr(getattr(target_engine, "dialect", None), "name", None)
    is_postgres = dialect_name == "postgresql"

    if not is_postgres:
        # Fallback for SQLite / non-PostgreSQL test environments
        with _FALLBACK_MAP_LOCK:
            if scope not in _FALLBACK_LOCKS:
                _FALLBACK_LOCKS[scope] = threading.Lock()
            local_lock = _FALLBACK_LOCKS[scope]

        acquired = local_lock.acquire(blocking=True, timeout=timeout_seconds)
        if not acquired:
            _record_lock_conflict(db, scope, organization_id, user_id)
            raise DeploymentLockConflictError(
                f"Concurrent deployment or rollback in progress for scope '{scope}'. Lock acquisition timed out."
            )
        try:
            yield
        finally:
            local_lock.release()
        return

    # Native PostgreSQL 64-bit Advisory Locking via dedicated connection
    lock_id = compute_advisory_lock_id(scope)
    owns_conn = False
    if hasattr(target_engine, "connect"):
        conn = target_engine.connect()
        owns_conn = True
    else:
        conn = target_engine
        owns_conn = False

    deadline = time.time() + timeout_seconds
    acquired = False

    try:
        while time.time() < deadline:
            res = conn.execute(
                text("SELECT pg_try_advisory_lock(:lock_id)"),
                {"lock_id": lock_id},
            ).scalar()
            if res:
                acquired = True
                break
            time.sleep(poll_interval)

        if not acquired:
            logger.warning(
                "Lock contention detected for scope %s (lock_id=%s) after %.1fs timeout",
                scope,
                lock_id,
                timeout_seconds,
            )
            _record_lock_conflict(db, scope, organization_id, user_id)
            raise DeploymentLockConflictError(
                f"Concurrent deployment or rollback in progress for scope '{scope}'. Distributed lock acquisition timed out."
            )

        logger.debug("Successfully acquired distributed advisory lock for scope %s (lock_id=%s)", scope, lock_id)
        yield

    finally:
        if acquired:
            try:
                conn.execute(
                    text("SELECT pg_advisory_unlock(:lock_id)"),
                    {"lock_id": lock_id},
                )
                logger.debug("Released distributed advisory lock for scope %s (lock_id=%s)", scope, lock_id)
            except Exception as exc:
                logger.warning("Error releasing PostgreSQL advisory lock %s: %s", lock_id, exc)
        if owns_conn:
            try:
                conn.close()
            except Exception:
                pass


def _record_lock_conflict(
    db: Optional[Session],
    scope: str,
    organization_id: Optional[uuid.UUID],
    user_id: Optional[uuid.UUID],
) -> None:
    """
    Persists a deployment lock contention event to the immutable audit log.
    """
    try:
        close_db = False
        target_db = db
        if target_db is None:
            target_db = SessionLocal()
            close_db = True
        try:
            try:
                audit_repo.log_event(
                    db=target_db,
                    action="deployment_lock_contention",
                    resource_type="deployment_lock",
                    status="CONFLICT",
                    organization_id=organization_id,
                    user_id=user_id,
                    resource_id=scope,
                    details=f"Distributed lock conflict detected for scope '{scope}'. Simultaneous deployment/rollback prevented.",
                )
            except Exception:
                # Fallback without organization_id/user_id if not yet committed in outer test transactions
                target_db.rollback()
                audit_repo.log_event(
                    db=target_db,
                    action="deployment_lock_contention",
                    resource_type="deployment_lock",
                    status="CONFLICT",
                    organization_id=None,
                    user_id=None,
                    resource_id=scope,
                    details=f"Distributed lock conflict detected for scope '{scope}' (org={organization_id}). Simultaneous deployment/rollback prevented.",
                )
        finally:
            if close_db:
                target_db.close()
    except Exception as exc:
        logger.error("Failed to write lock contention event to audit log: %s", exc)
