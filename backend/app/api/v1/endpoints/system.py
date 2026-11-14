"""
PREVENT-X System Health and Telemetry Endpoints
"""

import sys
import time
from datetime import datetime, timezone
from fastapi import APIRouter, Depends, status
from sqlalchemy import text
from sqlalchemy.orm import Session
from backend.app.core.config import settings
from backend.app.database.session import get_db
from backend.app.integrations.redis_client import ping_redis
from backend.app.modules.registry import module_registry
from backend.app.schemas.system import (
    HealthResponse,
    ReadinessResponse,
    ServiceHealth,
    SystemInfoResponse,
)

router = APIRouter(tags=["System"])


@router.get(
    "/health",
    response_model=HealthResponse,
    summary="Liveness check returning service heartbeat",
)
def get_liveness():
    return HealthResponse(
        status="HEALTHY",
        version=settings.APP_VERSION,
        environment=settings.ENVIRONMENT,
        timestamp=datetime.now(timezone.utc).isoformat(),
    )


@router.get(
    "/ready",
    response_model=ReadinessResponse,
    summary="Readiness check evaluating database and cache dependencies",
)
def get_readiness(db: Session = Depends(get_db)):
    # 1. Database check
    db_start = time.perf_counter()
    db_status = "UP"
    db_details = "Database connection verified"
    try:
        db.execute(text("SELECT 1"))
        db_latency = (time.perf_counter() - db_start) * 1000.0
    except Exception as e:
        db_status = "DOWN"
        db_latency = (time.perf_counter() - db_start) * 1000.0
        db_details = f"Database query failed: {str(e)}"

    # 2. Redis check
    redis_up, redis_latency, redis_msg = ping_redis()
    redis_status = "UP" if redis_up else "DOWN"

    is_ready = db_status == "UP"  # Database is hard dependency; Redis is cache/queue

    return ReadinessResponse(
        ready=is_ready,
        database=ServiceHealth(
            status=db_status,
            latency_ms=round(db_latency, 2),
            details=db_details,
        ),
        redis=ServiceHealth(
            status=redis_status,
            latency_ms=redis_latency,
            details=redis_msg,
        ),
        timestamp=datetime.now(timezone.utc).isoformat(),
    )


@router.get(
    "/system/info",
    response_model=SystemInfoResponse,
    summary="Platform metadata and security module availability catalog",
)
def get_system_info(db: Session = Depends(get_db)):
    db_backend = db.bind.dialect.name if db.bind else "unknown"
    modules = module_registry.get_all_statuses()

    return SystemInfoResponse(
        app_name=settings.APP_NAME,
        app_version=settings.APP_VERSION,
        phase="PHASE 1: ENTERPRISE-GRADE FOUNDATION & ARCHITECTURE",
        environment=settings.ENVIRONMENT,
        python_version=sys.version.split(" ")[0],
        database_backend=db_backend,
        modules=modules,
    )
