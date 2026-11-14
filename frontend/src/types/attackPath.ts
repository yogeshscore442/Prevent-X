export interface GraphNode {
  id: string;
  name: string;
  asset_type: string;
  criticality: string;
  is_entry_point: boolean;
  is_crown_jewel: boolean;
  ip_address?: string;
  technologies: string[];
  vulnerabilities_count: number;
  max_cvss?: number;
}

export interface GraphEdge {
  source: string;
  target: string;
  hop_type: string;
  port?: number;
  protocol?: string;
  mitre_technique?: string;
  mitre_technique_id?: string;
  evidence_source: string;
  justification: string;
}

export interface GraphData {
  nodes: GraphNode[];
  edges: GraphEdge[];
}

export interface MitreTechnique {
  id: string;
  name: string;
  tactic_id: string;
  tactic: string;
  description: string;
  prerequisites?: string[];
}

export interface AttackPath {
  id: string;
  organization_id: string;
  name: string;
  title?: string;
  description?: string;
  severity: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW';
  confidence: 'CONFIRMED' | 'LIKELY' | 'POTENTIAL';
  step_count: number;
  risk_score: number;
  status: 'IDENTIFIED' | 'UNDER_REVIEW' | 'MITIGATED' | 'ACCEPTED';
  entry_point_asset_id: string;
  target_asset_id: string;
  entry_point_asset_name?: string;
  target_asset_name?: string;
  target_asset_criticality?: string;
  path_narrative?: string;
  graph_data?: GraphData;
  mitre_tactics: string[];
  mitre_techniques: MitreTechnique[];
  prerequisites: string[];
  evidence_references: string[];
  recommendations_count: number;
  created_at: string;
  updated_at: string;
}

export interface PreventionRecommendation {
  id: string;
  organization_id: string;
  attack_path_id?: string;
  attack_path_title?: string;
  target_asset_id?: string;
  target_asset_name?: string;
  title: string;
  category: 'SERVICE_HARDENING' | 'NETWORK_SEGMENTATION' | 'MFA_ACCESS_CONTROL' | 'VIRTUAL_PATCH' | 'LEAST_PRIVILEGE' | 'LOGGING_MONITORING';
  description: string;
  risk_reduction: 'HIGH' | 'MEDIUM' | 'LOW';
  implementation_complexity: 'LOW' | 'MEDIUM' | 'HIGH';
  smb_operational_impact: 'MINIMAL' | 'LOW' | 'MEDIUM' | 'HIGH';
  priority_rank: number;
  mitre_technique_id?: string;
  status: 'PROPOSED' | 'ACCEPTED' | 'IMPLEMENTED' | 'DISMISSED';
  created_at: string;
  updated_at: string;
}

export interface AssetTrustRelationship {
  id: string;
  organization_id: string;
  source_asset_id: string;
  target_asset_id: string;
  source_asset_name?: string;
  target_asset_name?: string;
  relationship_type: string;
  port?: number;
  evidence_source: string;
  is_verified: boolean;
  created_at: string;
  updated_at: string;
}

export interface AttackPathOverviewStats {
  total_paths: number;
  critical_paths: number;
  high_paths: number;
  medium_paths: number;
  low_paths: number;
  entry_points_count: number;
  crown_jewels_at_risk_count: number;
  average_risk_score: number;
  total_recommendations: number;
  implemented_recommendations: number;
  top_mitre_tactics: { tactic: string; count: number }[];
}

export interface AttackPathAnalysisJob {
  id: string;
  organization_id: string;
  status: 'PENDING' | 'RUNNING' | 'COMPLETED' | 'FAILED';
  paths_discovered_count: number;
  recommendations_count: number;
  error_message?: string;
  completed_at?: string;
  created_at: string;
}

