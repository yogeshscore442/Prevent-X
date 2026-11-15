/**
 * PREVENT-X Advanced Network Defense & Detection Layer Type Definitions
 */

export type FirewallDirection = 'in' | 'out';
export type FirewallAction = 'allow' | 'block';
export type FirewallProtocol = 'TCP' | 'UDP' | 'ICMPv4' | 'ICMPv6' | 'ANY';
export type FirewallEnforcementStatus = 'PENDING' | 'VERIFIED' | 'FAILED' | 'REMOVED' | 'ROLLED_BACK';

export interface FirewallRule {
  id: string;
  organization_id: string;
  name: string;
  display_name: string;
  remote_ip_or_cidr: string;
  direction: FirewallDirection;
  action: FirewallAction;
  protocol: FirewallProtocol;
  local_ports?: string | null;
  remote_ports?: string | null;
  is_active: boolean;
  verified_active: boolean;
  enforcement_status: FirewallEnforcementStatus;
  error_message?: string | null;
  expires_at?: string | null;
  last_verified_at?: string | null;
  created_at: string;
  updated_at: string;
}

export interface FirewallStatus {
  os_type: string;
  is_elevated: boolean;
  is_operational: boolean;
  active_rules_count: number;
  verified_rules_count: number;
  failed_rules_count: number;
  pending_rules_count: number;
  execution_mode: string;
  managed_os_rules: string[];
  notice?: string | null;
}

export type DynamicBlockStatus = 'PENDING_APPROVAL' | 'ACTIVE' | 'EXPIRED' | 'UNBLOCKED' | 'FAILED';

export interface DynamicIPBlock {
  id: string;
  organization_id: string;
  ip_or_cidr: string;
  reason: string;
  duration_minutes?: number | null;
  status: DynamicBlockStatus;
  firewall_rule_id?: string | null;
  incident_id?: string | null;
  threat_intel_score?: number | null;
  expires_at: string;
  unblocked_at?: string | null;
  created_at: string;
  updated_at: string;
}

export type RateLimitScope = 'IP' | 'ENDPOINT' | 'TENANT' | 'API_KEY';
export type RateLimitAlgorithm = 'SLIDING_WINDOW' | 'TOKEN_BUCKET';

export interface RateLimitPolicy {
  id: string;
  organization_id: string;
  name: string;
  endpoint_pattern: string;
  scope: RateLimitScope;
  algorithm: RateLimitAlgorithm;
  max_requests: number;
  window_seconds: number;
  burst_capacity: number;
  refill_rate_per_sec: number;
  is_active: boolean;
  created_at: string;
  updated_at: string;
}

export interface NormalizationResult {
  raw_text: string;
  normalized_text: string;
  obfuscation_detected: boolean;
  detected_techniques: string[];
  extracted_base64_fragments: string[];
}

export interface AttackDetectionResult {
  detected: boolean;
  category?: string | null;
  confidence: number;
  severity: string;
  cwe_id?: string | null;
  mitre_attack_id?: string | null;
  explanation: string;
  matched_pattern?: string | null;
  obfuscation_detected: boolean;
  detected_techniques: string[];
}

export interface TrafficReplayReport {
  id: string;
  organization_id: string;
  virtual_patch_id?: string | null;
  total_replayed: number;
  passed_benign: number;
  false_positives: number;
  missed_threats: number;
  fp_rate: number;
  is_regression_free: boolean;
  report_details?: string | null;
  created_at: string;
}

export interface HoneypotProbe {
  id: string;
  organization_id: string;
  trap_path: string;
  source_ip: string;
  http_method: string;
  user_agent?: string | null;
  query_string?: string | null;
  payload_preview?: string | null;
  correlated_incident_id?: string | null;
  recommended_block_id?: string | null;
  created_at: string;
}

export interface HoneypotStats {
  total_probes: number;
  unique_attacker_ips: number;
  top_traps: { trap_path: string; hits: number }[];
  active_decoy_count: number;
}

export interface GeoIPPolicy {
  id: string;
  organization_id: string;
  country_code: string;
  country_name: string;
  action: 'ALLOW' | 'DENY';
  exception_cidrs?: string | null;
  risk_score_modifier: number;
  is_active: boolean;
  created_at: string;
  updated_at: string;
}

export interface GeoIPLookupResult {
  ip_address: string;
  country_code: string;
  country_name: string;
  is_denied: boolean;
  policy_action?: string | null;
  risk_score_modifier: number;
  is_exception_cidr: boolean;
  database_version: string;
  is_advisory_only: boolean;
}

export interface MLModelStatus {
  model_version: string;
  algorithm: string;
  training_sample_count: number;
  features_count: number;
  is_ready: boolean;
  precision: number;
  recall: number;
  f1_score: number;
  advisory_mode: boolean;
}

export interface MLClassificationResult {
  is_anomalous: boolean;
  anomaly_score: number;
  predicted_class: string;
  model_version: string;
  is_advisory_only: boolean;
  top_feature_importances: Record<string, number>;
  recommendation: string;
}
