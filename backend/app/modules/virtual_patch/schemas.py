"""
PREVENT-X Intelligent Virtual Patching Pydantic Schemas (MOD-06, MOD-08)
"""

import json
import uuid
from datetime import datetime
from typing import Any, Dict, List, Optional
from pydantic import BaseModel, ConfigDict, Field, field_validator


class MatchCondition(BaseModel):
    target: str  # URI, QUERY, HEADER, BODY
    header_name: Optional[str] = None
    operator: str  # REGEX, CONTAINS, EQUALS, STARTS_WITH
    pattern: str
    is_case_sensitive: bool = False


class VirtualPatchRuleCreate(BaseModel):
    rule_name: str
    attack_type: str = "SQLI"  # SQLI, XSS, PATH_TRAVERSAL, CMDI, METHOD_RESTRICTION, RATE_LIMIT, PATTERN_BLOCK, API_PROTECTION
    description: str
    severity: str = "HIGH"
    priority: int = Field(default=100, ge=1, le=1000)
    action: str = "BLOCK"  # BLOCK, ALLOW, LOG_ONLY
    target_uri_pattern: Optional[str] = None
    http_methods: List[str] = Field(default_factory=lambda: ["GET", "POST", "PUT", "DELETE", "PATCH"])
    match_conditions: List[MatchCondition] = Field(default_factory=list)
    asset_id: Optional[uuid.UUID] = None
    vulnerability_id: Optional[uuid.UUID] = None
    cve_id: Optional[str] = None
    cwe_id: Optional[str] = None
    expires_at: Optional[datetime] = None


class VirtualPatchRuleUpdate(BaseModel):
    rule_name: Optional[str] = None
    description: Optional[str] = None
    severity: Optional[str] = None
    priority: Optional[int] = Field(default=None, ge=1, le=1000)
    action: Optional[str] = None
    target_uri_pattern: Optional[str] = None
    http_methods: Optional[List[str]] = None
    match_conditions: Optional[List[MatchCondition]] = None
    is_active: Optional[bool] = None
    expires_at: Optional[datetime] = None
    change_summary: Optional[str] = None


class VirtualPatchRuleRead(BaseModel):
    id: uuid.UUID
    organization_id: uuid.UUID
    asset_id: Optional[uuid.UUID] = None
    asset_name: Optional[str] = None
    vulnerability_id: Optional[uuid.UUID] = None
    cve_id: Optional[str] = None
    cwe_id: Optional[str] = None
    rule_name: str
    attack_type: str
    description: str
    severity: str
    priority: int
    action: str
    target_uri_pattern: Optional[str] = None
    http_methods: List[str] = Field(default_factory=list)
    match_conditions: List[MatchCondition] = Field(default_factory=list)
    status: str
    is_active: bool
    is_system_rule: bool
    version: int
    expires_at: Optional[datetime] = None
    false_positive_count: int
    enforcement_count: int
    config_snippet: Optional[str] = None
    created_at: datetime
    updated_at: datetime

    model_config = ConfigDict(from_attributes=True)

    @field_validator("http_methods", mode="before")
    @classmethod
    def parse_http_methods(cls, v: Any) -> Any:
        if isinstance(v, str):
            try:
                return json.loads(v)
            except Exception:
                return [v]
        return v or []

    @field_validator("match_conditions", mode="before")
    @classmethod
    def parse_match_conditions(cls, v: Any) -> Any:
        if isinstance(v, str):
            try:
                return json.loads(v)
            except Exception:
                return []
        return v or []


class VirtualPatchVersionRead(BaseModel):
    id: uuid.UUID
    rule_id: uuid.UUID
    version_number: int
    rule_name: str
    action: str
    target_uri_pattern: Optional[str] = None
    match_conditions: List[MatchCondition] = Field(default_factory=list)
    config_snippet: Optional[str] = None
    change_summary: Optional[str] = None
    created_by_user_id: Optional[uuid.UUID] = None
    created_at: datetime

    model_config = ConfigDict(from_attributes=True)

    @field_validator("match_conditions", mode="before")
    @classmethod
    def parse_version_match_conditions(cls, v: Any) -> Any:
        if isinstance(v, str):
            try:
                return json.loads(v)
            except Exception:
                return []
        return v or []


class VirtualPatchRecommendationRead(BaseModel):
    id: uuid.UUID
    organization_id: uuid.UUID
    vulnerability_id: uuid.UUID
    asset_id: uuid.UUID
    asset_name: Optional[str] = None
    cve_id: Optional[str] = None
    cwe_id: Optional[str] = None
    attack_type: str
    suggested_rule_name: str
    suggested_pattern: str
    target_uri_pattern: Optional[str] = None
    rationale: str
    confidence: int
    status: str
    generated_rule_id: Optional[uuid.UUID] = None
    created_at: datetime
    updated_at: datetime

    model_config = ConfigDict(from_attributes=True)


class VirtualPatchDeploymentCreate(BaseModel):
    environment: str = "STAGING"  # STAGING, PRODUCTION
    listen_port: int = 8085
    upstream_url: str = "http://127.0.0.1:8086"


class VirtualPatchDeploymentRead(BaseModel):
    id: uuid.UUID
    organization_id: uuid.UUID
    environment: str
    status: str
    deployed_rules_count: int
    config_hash: str
    nginx_config_path: Optional[str] = None
    listen_port: int
    upstream_url: str
    approved_by_user_id: Optional[uuid.UUID] = None
    approved_by_user_email: Optional[str] = None
    approved_at: Optional[datetime] = None
    deployed_at: Optional[datetime] = None
    rollback_target_deployment_id: Optional[uuid.UUID] = None
    deployment_log: Optional[str] = None
    created_at: datetime
    updated_at: datetime

    model_config = ConfigDict(from_attributes=True)


class WafEnforcementLogRead(BaseModel):
    id: uuid.UUID
    organization_id: uuid.UUID
    rule_id: Optional[uuid.UUID] = None
    rule_name: Optional[str] = None
    client_ip: str
    http_method: str
    uri: str
    query_string: Optional[str] = None
    headers_snippet: Optional[str] = None
    body_snippet: Optional[str] = None
    decision: str
    matched_pattern: Optional[str] = None
    block_reason: str
    response_status_code: int
    is_false_positive_reported: bool
    false_positive_notes: Optional[str] = None
    created_at: datetime

    model_config = ConfigDict(from_attributes=True)


class FalsePositiveReportRequest(BaseModel):
    notes: str


class VirtualPatchOverviewStats(BaseModel):
    total_rules: int
    active_rules: int
    staging_deployments: int
    production_deployments: int
    pending_approval_deployments: int
    total_blocks_recorded: int
    false_positives_reported: int
    active_recommendations_count: int
    proxy_status: str
    proxy_listen_port: int
    upstream_url: str
