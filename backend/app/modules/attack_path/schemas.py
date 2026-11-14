"""
Pydantic Schemas for Attack Path and Prevention Engine (MOD-03)
"""

import uuid
from datetime import datetime
from typing import Any, Dict, List, Optional
from pydantic import BaseModel, ConfigDict, Field


class GraphNode(BaseModel):
    id: str
    name: str
    asset_type: str
    criticality: str
    is_entry_point: bool = False
    is_crown_jewel: bool = False
    ip_address: Optional[str] = None
    technologies: List[str] = Field(default_factory=list)
    vulnerabilities_count: int = 0
    max_cvss: Optional[float] = None


class GraphEdge(BaseModel):
    source: str
    target: str
    hop_type: str
    port: Optional[int] = None
    protocol: Optional[str] = None
    mitre_technique: Optional[str] = None
    mitre_technique_id: Optional[str] = None
    evidence_source: str
    justification: str


class GraphData(BaseModel):
    nodes: List[GraphNode] = Field(default_factory=list)
    edges: List[GraphEdge] = Field(default_factory=list)


class MitreTechniqueDetail(BaseModel):
    technique_id: str
    technique_name: str
    tactic: str
    description: str


class AttackPathBase(BaseModel):
    name: str
    title: Optional[str] = None
    description: Optional[str] = None
    severity: str = "MEDIUM"
    confidence: str = "POTENTIAL"
    step_count: int = 1
    risk_score: float = 0.0
    status: str = "IDENTIFIED"


class AttackPathRead(AttackPathBase):
    id: uuid.UUID
    organization_id: uuid.UUID
    entry_point_asset_id: uuid.UUID
    target_asset_id: uuid.UUID
    entry_point_asset_name: Optional[str] = None
    target_asset_name: Optional[str] = None
    target_asset_criticality: Optional[str] = None
    path_narrative: Optional[str] = None
    graph_data: Optional[Dict[str, Any]] = None
    mitre_tactics: List[str] = Field(default_factory=list)
    mitre_techniques: List[Dict[str, Any]] = Field(default_factory=list)
    prerequisites: List[str] = Field(default_factory=list)
    evidence_references: List[str] = Field(default_factory=list)
    recommendations_count: int = 0
    created_at: datetime
    updated_at: datetime

    model_config = ConfigDict(from_attributes=True)


class AttackPathStatusUpdate(BaseModel):
    status: str  # IDENTIFIED, UNDER_REVIEW, MITIGATED, ACCEPTED


class AssetTrustRelationshipCreate(BaseModel):
    source_asset_id: uuid.UUID
    target_asset_id: uuid.UUID
    relationship_type: str = "SAME_SUBNET"  # DATABASE_LINK, SSH_ADMIN_ACCESS, ACTIVE_DIRECTORY_TRUST, SAME_SUBNET, API_DEPENDENCY
    port: Optional[int] = None
    evidence_source: str = "MANUAL_VERIFIED"
    is_verified: bool = True


class AssetTrustRelationshipRead(BaseModel):
    id: uuid.UUID
    organization_id: uuid.UUID
    source_asset_id: uuid.UUID
    target_asset_id: uuid.UUID
    source_asset_name: Optional[str] = None
    target_asset_name: Optional[str] = None
    relationship_type: str
    port: Optional[int] = None
    evidence_source: str
    is_verified: bool
    created_at: datetime
    updated_at: datetime

    model_config = ConfigDict(from_attributes=True)


class PreventionRecommendationRead(BaseModel):
    id: uuid.UUID
    organization_id: uuid.UUID
    attack_path_id: Optional[uuid.UUID] = None
    attack_path_title: Optional[str] = None
    target_asset_id: Optional[uuid.UUID] = None
    target_asset_name: Optional[str] = None
    title: str
    category: str
    description: str
    risk_reduction: str
    implementation_complexity: str
    smb_operational_impact: str
    priority_rank: int
    mitre_technique_id: Optional[str] = None
    status: str
    created_at: datetime
    updated_at: datetime

    model_config = ConfigDict(from_attributes=True)


class PreventionRecommendationStatusUpdate(BaseModel):
    status: str  # PROPOSED, ACCEPTED, IMPLEMENTED, DISMISSED


class AttackPathAnalysisJobRead(BaseModel):
    id: uuid.UUID
    organization_id: uuid.UUID
    initiated_by_user_id: Optional[uuid.UUID] = None
    status: str
    paths_discovered_count: int
    recommendations_count: int
    error_message: Optional[str] = None
    completed_at: Optional[datetime] = None
    created_at: datetime
    updated_at: datetime

    model_config = ConfigDict(from_attributes=True)


class AttackPathAnalyzeRequest(BaseModel):
    target_asset_id: Optional[uuid.UUID] = None
    include_potential: bool = True
    sync: bool = False


class AttackPathOverviewStats(BaseModel):
    total_paths: int
    critical_paths: int
    high_paths: int
    medium_paths: int
    low_paths: int
    entry_points_count: int
    crown_jewels_at_risk_count: int
    average_risk_score: float
    total_recommendations: int
    implemented_recommendations: int
    top_mitre_tactics: List[Dict[str, Any]]
