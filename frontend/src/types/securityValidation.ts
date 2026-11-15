export type ValidationJobStatus =
  | 'PENDING'
  | 'RUNNING'
  | 'PASSED'
  | 'FAILED'
  | 'ERROR'
  | 'CANCELLED';

export type ValidationTriggerType =
  | 'MANUAL'
  | 'POST_DEPLOY'
  | 'CANARY_EVAL'
  | 'SCHEDULED';

export type ValidationTestCategory =
  | 'SQLI'
  | 'XSS'
  | 'PATH_TRAVERSAL'
  | 'CMDI'
  | 'METHOD_RESTRICTION'
  | 'REGRESSION_ENCODING'
  | 'LEGITIMATE_TRAFFIC'
  | 'UPSTREAM_CONNECTIVITY'
  | 'AUTHENTICATION_GATE';

export type TestResultStatus = 'PASSED' | 'FAILED' | 'ERROR';

export type RollbackStatus =
  | 'INITIATED'
  | 'VALIDATING_SYNTAX'
  | 'RESTORING'
  | 'COMPLETED'
  | 'ROLLBACK_FAILED';

export type RollbackTriggerSource =
  | 'MANUAL'
  | 'AUTOMATIC_HEALTH_FAILURE'
  | 'AUTOMATIC_VALIDATION_FAILURE'
  | 'CANARY_BREACH';

export interface ValidationTestResult {
  id: string;
  job_id: string;
  organization_id: string;
  test_id: string;
  test_category: ValidationTestCategory | string;
  test_name: string;
  description: string;
  target_endpoint: string;
  http_method: string;
  request_headers_redacted?: string;
  request_payload_redacted?: string;
  expected_status_code: number;
  actual_status_code?: number;
  expected_decision: 'BLOCKED' | 'ALLOWED';
  actual_decision?: 'BLOCKED' | 'ALLOWED';
  result: TestResultStatus;
  latency_ms: number;
  evidence_snippet?: string;
  confidence: number;
  error_message?: string;
  created_at: string;
}

export interface ValidationJob {
  id: string;
  organization_id: string;
  deployment_id?: string;
  environment: 'STAGING' | 'PRODUCTION' | string;
  target_url: string;
  status: ValidationJobStatus;
  trigger_type: ValidationTriggerType;
  canary_percentage: number;
  total_tests: number;
  passed_tests: number;
  failed_tests: number;
  blocked_attacks: number;
  allowed_legitimate: number;
  false_positives_detected: number;
  bypasses_detected: number;
  pass_rate_percentage: number;
  active_config_hash?: string;
  summary_report?: string;
  initiated_by_user_id?: string;
  started_at?: string;
  completed_at?: string;
  created_at: string;
  updated_at: string;
}

export interface RollbackRecord {
  id: string;
  organization_id: string;
  deployment_id: string;
  target_deployment_id?: string;
  trigger_source: RollbackTriggerSource | string;
  rollback_reason: string;
  previous_config_hash: string;
  restored_config_hash: string;
  status: RollbackStatus;
  is_restoration_verified: boolean;
  verification_evidence?: string;
  operator_user_id?: string;
  error_details?: string;
  started_at: string;
  completed_at?: string;
  created_at: string;
}

export interface CanaryPolicy {
  id: string;
  organization_id: string;
  name: string;
  canary_traffic_weight: number;
  max_failure_rate_percent: number;
  max_latency_ms: number;
  max_false_positive_count: number;
  auto_rollback_enabled: boolean;
  auto_promotion_enabled: boolean;
  is_active: boolean;
  created_at: string;
  updated_at: string;
}

export interface CategoryCoverageStats {
  category: string;
  total_tests: number;
  passed_tests: number;
  failed_tests: number;
  pass_rate_percentage: number;
}

export interface SecurityValidationOverviewStats {
  total_validation_jobs: number;
  passed_validation_jobs: number;
  failed_validation_jobs: number;
  overall_pass_rate_percent: number;
  total_attacks_tested: number;
  attacks_blocked_percent: number;
  legitimate_traffic_allowed_percent: number;
  active_canary_weight: number;
  last_rollback_status?: string;
  last_rollback_time?: string;
  active_proxy_port: number;
  active_proxy_healthy: boolean;
  coverage_by_category: CategoryCoverageStats[];
}

export interface ValidationJobCreatePayload {
  deployment_id?: string;
  environment?: string;
  target_url?: string;
  canary_percentage?: number;
  trigger_type?: string;
}

export interface RollbackRequestPayload {
  deployment_id: string;
  target_deployment_id?: string;
  rollback_reason: string;
}

export interface CanaryPolicyUpdatePayload {
  name?: string;
  canary_traffic_weight?: number;
  max_failure_rate_percent?: number;
  max_latency_ms?: number;
  max_false_positive_count?: number;
  auto_rollback_enabled?: boolean;
  auto_promotion_enabled?: boolean;
  is_active?: boolean;
}

