export type AttackType =
  | 'SQLI'
  | 'XSS'
  | 'PATH_TRAVERSAL'
  | 'CMDI'
  | 'METHOD_RESTRICTION'
  | 'RATE_LIMIT'
  | 'PATTERN_BLOCK'
  | 'API_PROTECTION';

export type PatchAction = 'BLOCK' | 'ALLOW' | 'LOG_ONLY';

export type PatchStatus =
  | 'DRAFT'
  | 'VALIDATING'
  | 'STAGING'
  | 'PENDING_APPROVAL'
  | 'APPROVED'
  | 'PRODUCTION'
  | 'DISABLED'
  | 'ROLLED_BACK';

export type DeploymentEnvironment = 'STAGING' | 'PRODUCTION';

export type DeploymentStatus =
  | 'PENDING_APPROVAL'
  | 'APPROVED'
  | 'DEPLOYED'
  | 'FAILED'
  | 'ROLLED_BACK';

export interface MatchCondition {
  target: string;
  header_name?: string;
  operator: string;
  pattern: string;
  is_case_sensitive?: boolean;
}

export interface VirtualPatchRule {
  id: string;
  organization_id: string;
  asset_id?: string;
  asset_name?: string;
  vulnerability_id?: string;
  cve_id?: string;
  cwe_id?: string;
  rule_name: string;
  attack_type: AttackType;
  description: string;
  severity: string;
  priority: number;
  action: PatchAction;
  target_uri_pattern?: string;
  http_methods: string[];
  match_conditions: MatchCondition[];
  status: PatchStatus;
  is_active: boolean;
  is_system_rule: boolean;
  version: number;
  expires_at?: string;
  false_positive_count: number;
  enforcement_count: number;
  config_snippet?: string;
  created_at: string;
  updated_at: string;
}

export interface VirtualPatchVersion {
  id: string;
  rule_id: string;
  version_number: number;
  rule_name: string;
  action: string;
  target_uri_pattern?: string;
  match_conditions: MatchCondition[];
  config_snippet?: string;
  change_summary?: string;
  created_by_user_id?: string;
  created_at: string;
}

export interface VirtualPatchRecommendation {
  id: string;
  organization_id: string;
  vulnerability_id: string;
  asset_id: string;
  asset_name?: string;
  cve_id?: string;
  cwe_id?: string;
  attack_type: AttackType;
  suggested_rule_name: string;
  suggested_pattern: string;
  target_uri_pattern?: string;
  rationale: string;
  confidence: number;
  status: 'PROPOSED' | 'ACCEPTED' | 'REJECTED';
  generated_rule_id?: string;
  created_at: string;
  updated_at: string;
}

export interface VirtualPatchDeployment {
  id: string;
  organization_id: string;
  environment: DeploymentEnvironment;
  status: DeploymentStatus;
  deployed_rules_count: number;
  config_hash: string;
  nginx_config_path?: string;
  listen_port: number;
  upstream_url: string;
  approved_by_user_id?: string;
  approved_by_user_email?: string;
  approved_at?: string;
  deployed_at?: string;
  rollback_target_deployment_id?: string;
  deployment_log?: string;
  created_at: string;
  updated_at: string;
}

export interface WafEnforcementLog {
  id: string;
  organization_id: string;
  rule_id?: string;
  rule_name?: string;
  client_ip: string;
  http_method: string;
  uri: string;
  query_string?: string;
  headers_snippet?: string;
  body_snippet?: string;
  decision: 'BLOCKED' | 'ALLOWED';
  matched_pattern?: string;
  block_reason: string;
  response_status_code: number;
  is_false_positive_reported: boolean;
  false_positive_notes?: string;
  created_at: string;
}

export interface VirtualPatchOverviewStats {
  total_rules: number;
  active_rules: number;
  staging_deployments: number;
  production_deployments: number;
  pending_approval_deployments: number;
  total_blocks_recorded: number;
  false_positives_reported: number;
  active_recommendations_count: number;
  proxy_status: 'ACTIVE' | 'STOPPED';
  proxy_listen_port: number;
  upstream_url: string;
}

export interface VirtualPatchRuleCreatePayload {
  rule_name: string;
  attack_type: string;
  description: string;
  severity: string;
  priority: number;
  action: string;
  target_uri_pattern?: string;
  http_methods: string[];
  match_conditions: MatchCondition[];
  asset_id?: string;
  vulnerability_id?: string;
  cve_id?: string;
  cwe_id?: string;
}

export interface VirtualPatchDeploymentCreatePayload {
  environment: string;
  listen_port: number;
  upstream_url: string;
}

