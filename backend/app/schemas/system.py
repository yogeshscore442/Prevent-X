"""
PREVENT-X System Health and Information Schemas
"""

from typing import Dict, Any, List
from pydantic import BaseModel


class HealthResponse(BaseModel):
    status: str
    version: str
    environment: str
    timestamp: str


class ServiceHealth(BaseModel):
    status: str  # UP, DOWN, DEGRADED
    latency_ms: float
    details: str


class ReadinessResponse(BaseModel):
    ready: bool
    database: ServiceHealth
    redis: ServiceHealth
    timestamp: str


class ModuleStatus(BaseModel):
    module_id: str
    name: str
    status: str  # OPERATIONAL, ARCHITECTURAL_STUB, PLANNED_PHASE_2_PLUS
    phase: int
    description: str


class SystemInfoResponse(BaseModel):
    app_name: str
    app_version: str
    phase: str
    environment: str
    python_version: str
    database_backend: str
    modules: List[ModuleStatus]

