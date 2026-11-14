export type TrustDecision = 'TRUSTED' | 'RESTRICTED' | 'UNTRUSTED' | 'INSUFFICIENT_EVIDENCE';

export interface TrustFactor {
  category: string;
  factor: string;
  impact: 'POSITIVE' | 'NEGATIVE';
  score_delta: number;
  description: string;
}

export interface AssetTrustAssessment {
  id: string;
  organization_id: string;
  asset_id: string;
  asset_name?: string;
  asset_target?: string;
  asset_type?: string;
  asset_criticality?: string;
  trust_decision: TrustDecision;
  trust_score: number;
  positive_factors: TrustFactor[];
  risk_factors: TrustFactor[];
  least_privilege_recommendations: string[];
  decision_reason: string;
  last_evaluated_at: string;
  is_stale: boolean;
  created_at: string;
  updated_at: string;
}

export interface ThreatIntelRecord {
  id: string;
  organization_id?: string;
  indicator_type: string;
  indicator_value: string;
  confidence: number;
  source: string;
  threat_actor?: string;
  description?: string;
  severity: string;
  tlp: string;
  is_active: boolean;
  expires_at?: string;
  last_seen_at?: string;
  mitre_tactics: string[];
  mitre_techniques: string[];
  tags: string[];
  is_expired: boolean;
  created_at: string;
  updated_at: string;
}

export interface ThreatAssetCorrelation {
  id: string;
  organization_id: string;
  threat_intel_id: string;
  asset_id: string;
  asset_name?: string;
  asset_target?: string;
  threat_indicator?: string;
  threat_type?: string;
  correlation_type: string;
  matched_value: string;
  severity: string;
  confidence: number;
  details: string;
  status: string;
  created_at: string;
  updated_at: string;
}

export interface BehavioralAnomaly {
  id: string;
  organization_id: string;
  asset_id: string;
  asset_name?: string;
  asset_target?: string;
  anomaly_type: string;
  severity: string;
  confidence: string;
  anomaly_score: number;
  description: string;
  evidence_data?: Record<string, any>;
  status: string;
  is_zero_day_indicator: boolean;
  created_at: string;
  updated_at: string;
}

export interface ResponseAction {
  id: string;
  organization_id: string;
  asset_id?: string;
  asset_name?: string;
  anomaly_id?: string;
  anomaly_type?: string;
  action_type: string;
  title: string;
  description: string;
  target_entity: string;
  execution_payload?: Record<string, any>;
  rollback_payload?: Record<string, any>;
  status: 'PENDING_APPROVAL' | 'APPROVED' | 'EXECUTED' | 'REJECTED' | 'ROLLED_BACK';
  is_disruptive: boolean;
  approved_by_user_id?: string;
  approved_by_user_name?: string;
  approved_at?: string;
  executed_at?: string;
  execution_log?: string;
  created_at: string;
  updated_at: string;
}

export interface ZeroTrustOverviewStats {
  total_assets: number;
  trusted_count: number;
  restricted_count: number;
  untrusted_count: number;
  insufficient_evidence_count: number;
  average_trust_score: number;
  active_threat_indicators: number;
  correlated_threats_count: number;
  active_anomalies_count: number;
  zero_day_indicators_count: number;
  pending_approval_actions: number;
  executed_actions: number;
}
