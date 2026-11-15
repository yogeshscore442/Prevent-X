"""
PREVENT-X Automated Security Validation Pydantic Schemas (MOD-10, MOD-08)
"""

import json
import uuid
from datetime import datetime
from typing import Any, Dict, List, Optional
from pydantic import BaseModel, ConfigDict, Field, field_validator


class ValidationJobCreate(BaseModel):
    deployment_id: Optional[uuid.UUID] = None
    environment: str = "STAGING"  # STAGING, PRODUCTION
    target_url: str = "http://127.0.0.1:8085"
    canary_percentage: int = Field(default=0, ge=0, le=100)
    trigger_type: str = "MANUAL"


class ValidationTestResultRead(BaseModel):
    id: uuid.UUID
    job_id: uuid.UUID
    organization_id: uuid.UUID
    test_id: str
    test_category: str
    test_name: str
    description: str
    target_endpoint: str
    http_method: str
    request_headers_redacted: Optional[str] = None
    request_payload_redacted: Optional[str] = None
    expected_status_code: int
    actual_status_code: Optional[int] = None
    expected_decision: str
    actual_decision: Optional[str] = None
    result: str
    latency_ms: float
    evidence_snippet: Optional[str] = None
    confidence: int
    error_message: Optional[str] = None
    created_at: datetime

    model_config = ConfigDict(from_attributes=True)


class ValidationJobRead(BaseModel):
    id: uuid.UUID
    organization_id: uuid.UUID
    deployment_id: Optional[uuid.UUID] = None
    environment: str
    target_url: str
    status: str
    trigger_type: str
    canary_percentage: int
    total_tests: int
    passed_tests: int
    failed_tests: int
    blocked_attacks: int
    allowed_legitimate: int
    false_positives_detected: int
    bypasses_detected: int
    pass_rate_percentage: float
    active_config_hash: Optional[str] = None
    summary_report: Optional[str] = None
    initiated_by_user_id: Optional[uuid.UUID] = None
    started_at: Optional[datetime] = None
    completed_at: Optional[datetime] = None
    created_at: datetime
    updated_at: datetime

    model_config = ConfigDict(from_attributes=True)


class RollbackRequest(BaseModel):
    deployment_id: uuid.UUID
    target_deployment_id: Optional[uuid.UUID] = None
    rollback_reason: str = Field(..., min_length=5, description="Audited operational reason for configuration rollback")


class RollbackRecordRead(BaseModel):
    id: uuid.UUID
    organization_id: uuid.UUID
    deployment_id: uuid.UUID
    target_deployment_id: Optional[uuid.UUID] = None
    trigger_source: str
    rollback_reason: str
    previous_config_hash: str
    restored_config_hash: str
    status: str
    is_restoration_verified: bool
    verification_evidence: Optional[str] = None
    operator_user_id: Optional[uuid.UUID] = None
    error_details: Optional[str] = None
    started_at: datetime
    completed_at: Optional[datetime] = None
    created_at: datetime

    model_config = ConfigDict(from_attributes=True)


class CanaryPolicyCreate(BaseModel):
    name: str = "Default SMB Canary Safety Policy"
    canary_traffic_weight: int = Field(default=10, ge=0, le=100)
    max_failure_rate_percent: float = Field(default=5.0, ge=0.0, le=100.0)
    max_latency_ms: float = Field(default=1000.0, ge=10.0)
    max_false_positive_count: int = Field(default=1, ge=0)
    auto_rollback_enabled: bool = True
    auto_promotion_enabled: bool = False


class CanaryPolicyUpdate(BaseModel):
    name: Optional[str] = None
    canary_traffic_weight: Optional[int] = Field(default=None, ge=0, le=100)
    max_failure_rate_percent: Optional[float] = Field(default=None, ge=0.0, le=100.0)
    max_latency_ms: Optional[float] = None
    max_false_positive_count: Optional[int] = None
    auto_rollback_enabled: Optional[bool] = None
    auto_promotion_enabled: Optional[bool] = None
    is_active: Optional[bool] = None


class CanaryPolicyRead(BaseModel):
    id: uuid.UUID
    organization_id: uuid.UUID
    name: str
    canary_traffic_weight: int
    max_failure_rate_percent: float
    max_latency_ms: float
    max_false_positive_count: int
    auto_rollback_enabled: bool
    auto_promotion_enabled: bool
    is_active: bool
    created_at: datetime
    updated_at: datetime

    model_config = ConfigDict(from_attributes=True)


class CategoryCoverageStats(BaseModel):
    category: str
    total_tests: int
    passed_tests: int
    failed_tests: int
    pass_rate_percentage: float


class SecurityValidationOverviewStats(BaseModel):
    total_validation_jobs: int
    passed_validation_jobs: int
    failed_validation_jobs: int
    overall_pass_rate_percent: float
    total_attacks_tested: int
    attacks_blocked_percent: float
    legitimate_traffic_allowed_percent: float
    active_canary_weight: int
    last_rollback_status: Optional[str] = None
    last_rollback_time: Optional[datetime] = None
    active_proxy_port: int
    active_proxy_healthy: bool
    coverage_by_category: List[CategoryCoverageStats] = Field(default_factory=list)

