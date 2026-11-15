"""
PREVENT-X Automated Security Validation & Reliable Rollback Models (MOD-10, MOD-08)
Relational models for validation jobs, granular test results, regression matrices,
atomic rollback records, and canary safety policies.
"""

import enum
import uuid
from datetime import datetime
from typing import Any, Dict, List, Optional
from sqlalchemy import (
    Boolean,
    DateTime,
    Float,
    ForeignKey,
    Index,
    Integer,
    String,
    Text,
)
from sqlalchemy.orm import Mapped, mapped_column, relationship

from backend.app.database.base import Base, TimestampMixin, utc_now
from backend.app.database.guid import GUID


class ValidationJobStatus(str, enum.Enum):
    PENDING = "PENDING"
    RUNNING = "RUNNING"
    PASSED = "PASSED"
    FAILED = "FAILED"
    CANCELLED = "CANCELLED"


class ValidationTriggerType(str, enum.Enum):
    MANUAL = "MANUAL"
    PRE_DEPLOYMENT = "PRE_DEPLOYMENT"
    POST_DEPLOYMENT = "POST_DEPLOYMENT"
    CANARY_GATE = "CANARY_GATE"
    SCHEDULED = "SCHEDULED"


class ValidationTestCategory(str, enum.Enum):
    SQLI = "SQLI"
    XSS = "XSS"
    PATH_TRAVERSAL = "PATH_TRAVERSAL"
    CMDI = "CMDI"
    METHOD_RESTRICTION = "METHOD_RESTRICTION"
    REGRESSION_ENCODING = "REGRESSION_ENCODING"
    LEGITIMATE_TRAFFIC = "LEGITIMATE_TRAFFIC"
    UPSTREAM_CONNECTIVITY = "UPSTREAM_CONNECTIVITY"
    AUTHENTICATION_GATE = "AUTHENTICATION_GATE"


class TestResultStatus(str, enum.Enum):
    PASSED = "PASSED"
    FAILED = "FAILED"
    ERROR = "ERROR"


class RollbackStatus(str, enum.Enum):
    INITIATED = "INITIATED"
    VALIDATING_SYNTAX = "VALIDATING_SYNTAX"
    RESTORING = "RESTORING"
    COMPLETED = "COMPLETED"
    ROLLBACK_FAILED = "ROLLBACK_FAILED"


class RollbackTriggerSource(str, enum.Enum):
    MANUAL = "MANUAL"
    AUTOMATIC_HEALTH_FAILURE = "AUTOMATIC_HEALTH_FAILURE"
    AUTOMATIC_VALIDATION_FAILURE = "AUTOMATIC_VALIDATION_FAILURE"
    CANARY_BREACH = "CANARY_BREACH"


class ValidationJob(Base, TimestampMixin):
    """
    Automated security validation run against staged or deployed virtual patch configurations.
    """
    __tablename__ = "validation_jobs"

    id: Mapped[uuid.UUID] = mapped_column(GUID(), primary_key=True, default=uuid.uuid4)
    organization_id: Mapped[uuid.UUID] = mapped_column(
        GUID(), ForeignKey("organizations.id", ondelete="CASCADE"), index=True, nullable=False
    )
    deployment_id: Mapped[Optional[uuid.UUID]] = mapped_column(
        GUID(), ForeignKey("virtual_patch_deployments.id", ondelete="SET NULL"), index=True, nullable=True
    )
    environment: Mapped[str] = mapped_column(String(30), default="STAGING", nullable=False, index=True)
    target_url: Mapped[str] = mapped_column(String(255), default="http://127.0.0.1:8085", nullable=False)
    status: Mapped[str] = mapped_column(
        String(30), default=ValidationJobStatus.PENDING.value, nullable=False, index=True
    )
    trigger_type: Mapped[str] = mapped_column(
        String(30), default=ValidationTriggerType.MANUAL.value, nullable=False, index=True
    )
    canary_percentage: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    total_tests: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    passed_tests: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    failed_tests: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    blocked_attacks: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    allowed_legitimate: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    false_positives_detected: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    bypasses_detected: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    pass_rate_percentage: Mapped[float] = mapped_column(Float, default=0.0, nullable=False)
    active_config_hash: Mapped[Optional[str]] = mapped_column(String(64), nullable=True)
    summary_report: Mapped[Optional[str]] = mapped_column(Text, nullable=True)  # JSON summary
    initiated_by_user_id: Mapped[Optional[uuid.UUID]] = mapped_column(
        GUID(), ForeignKey("users.id", ondelete="SET NULL"), nullable=True
    )
    started_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)
    completed_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)

    # Relationships
    organization: Mapped["Organization"] = relationship("Organization")
    deployment: Mapped[Optional["VirtualPatchDeployment"]] = relationship("VirtualPatchDeployment")
    initiated_by_user: Mapped[Optional["User"]] = relationship("User")
    test_results: Mapped[List["ValidationTestResult"]] = relationship(
        "ValidationTestResult", back_populates="job", cascade="all, delete-orphan", order_by="ValidationTestResult.created_at"
    )


class ValidationTestResult(Base):
    """
    Granular evidence record for each non-destructive security test executed.
    """
    __tablename__ = "validation_test_results"

    id: Mapped[uuid.UUID] = mapped_column(GUID(), primary_key=True, default=uuid.uuid4)
    job_id: Mapped[uuid.UUID] = mapped_column(
        GUID(), ForeignKey("validation_jobs.id", ondelete="CASCADE"), index=True, nullable=False
    )
    organization_id: Mapped[uuid.UUID] = mapped_column(
        GUID(), ForeignKey("organizations.id", ondelete="CASCADE"), index=True, nullable=False
    )
    test_id: Mapped[str] = mapped_column(String(100), nullable=False, index=True)
    test_category: Mapped[str] = mapped_column(
        String(50), default=ValidationTestCategory.SQLI.value, nullable=False, index=True
    )
    test_name: Mapped[str] = mapped_column(String(255), nullable=False)
    description: Mapped[str] = mapped_column(Text, nullable=False)
    target_endpoint: Mapped[str] = mapped_column(String(500), nullable=False)
    http_method: Mapped[str] = mapped_column(String(10), default="GET", nullable=False)
    request_headers_redacted: Mapped[Optional[str]] = mapped_column(Text, nullable=True)  # JSON
    request_payload_redacted: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    expected_status_code: Mapped[int] = mapped_column(Integer, nullable=False)
    actual_status_code: Mapped[Optional[int]] = mapped_column(Integer, nullable=True)
    expected_decision: Mapped[str] = mapped_column(String(20), default="BLOCKED", nullable=False)
    actual_decision: Mapped[Optional[str]] = mapped_column(String(20), nullable=True)
    result: Mapped[str] = mapped_column(
        String(20), default=TestResultStatus.PASSED.value, nullable=False, index=True
    )
    latency_ms: Mapped[float] = mapped_column(Float, default=0.0, nullable=False)
    evidence_snippet: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    confidence: Mapped[int] = mapped_column(Integer, default=95, nullable=False)
    error_message: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utc_now, nullable=False, index=True)

    # Relationships
    job: Mapped["ValidationJob"] = relationship("ValidationJob", back_populates="test_results")
    organization: Mapped["Organization"] = relationship("Organization")


class RollbackRecord(Base, TimestampMixin):
    """
    Audited record tracking atomic rollback of reverse proxy configurations to a known-good state.
    """
    __tablename__ = "rollback_records"

    id: Mapped[uuid.UUID] = mapped_column(GUID(), primary_key=True, default=uuid.uuid4)
    organization_id: Mapped[uuid.UUID] = mapped_column(
        GUID(), ForeignKey("organizations.id", ondelete="CASCADE"), index=True, nullable=False
    )
    deployment_id: Mapped[uuid.UUID] = mapped_column(
        GUID(), ForeignKey("virtual_patch_deployments.id", ondelete="CASCADE"), index=True, nullable=False
    )
    target_deployment_id: Mapped[Optional[uuid.UUID]] = mapped_column(
        GUID(), ForeignKey("virtual_patch_deployments.id", ondelete="SET NULL"), index=True, nullable=True
    )
    trigger_source: Mapped[str] = mapped_column(
        String(50), default=RollbackTriggerSource.MANUAL.value, nullable=False, index=True
    )
    rollback_reason: Mapped[str] = mapped_column(Text, nullable=False)
    previous_config_hash: Mapped[str] = mapped_column(String(64), nullable=False)
    restored_config_hash: Mapped[str] = mapped_column(String(64), nullable=False)
    status: Mapped[str] = mapped_column(
        String(30), default=RollbackStatus.INITIATED.value, nullable=False, index=True
    )
    is_restoration_verified: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    verification_evidence: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    operator_user_id: Mapped[Optional[uuid.UUID]] = mapped_column(
        GUID(), ForeignKey("users.id", ondelete="SET NULL"), nullable=True
    )
    error_details: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    started_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utc_now, nullable=False)
    completed_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)

    # Relationships
    organization: Mapped["Organization"] = relationship("Organization")
    deployment: Mapped["VirtualPatchDeployment"] = relationship(
        "VirtualPatchDeployment", foreign_keys=[deployment_id]
    )
    target_deployment: Mapped[Optional["VirtualPatchDeployment"]] = relationship(
        "VirtualPatchDeployment", foreign_keys=[target_deployment_id]
    )
    operator_user: Mapped[Optional["User"]] = relationship("User")


class CanaryPolicy(Base, TimestampMixin):
    """
    Configurable safety thresholds and canary routing rules for progressive virtual patch rollouts.
    """
    __tablename__ = "canary_policies"

    id: Mapped[uuid.UUID] = mapped_column(GUID(), primary_key=True, default=uuid.uuid4)
    organization_id: Mapped[uuid.UUID] = mapped_column(
        GUID(), ForeignKey("organizations.id", ondelete="CASCADE"), index=True, nullable=False
    )
    name: Mapped[str] = mapped_column(String(255), default="Default SMB Canary Safety Policy", nullable=False)
    canary_traffic_weight: Mapped[int] = mapped_column(Integer, default=10, nullable=False)  # 10%
    max_failure_rate_percent: Mapped[float] = mapped_column(Float, default=5.0, nullable=False)  # 5% max errors
    max_latency_ms: Mapped[float] = mapped_column(Float, default=1000.0, nullable=False)
    max_false_positive_count: Mapped[int] = mapped_column(Integer, default=1, nullable=False)
    auto_rollback_enabled: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)
    auto_promotion_enabled: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)  # Human approval mandate
    is_active: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False, index=True)

    # Relationships
    organization: Mapped["Organization"] = relationship("Organization")

