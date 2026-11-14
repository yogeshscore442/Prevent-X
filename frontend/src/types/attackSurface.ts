/**
 * PREVENT-X Attack Surface TypeScript Types
 */

export interface RiskFactorDetail {
  name: string;
  factor_key: string;
  score: number;
  max_weight: number;
  impact: string;
  description: string;
}

export interface RiskScoreBreakdown {
  total_score: number;
  risk_level: 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL';
  factors: RiskFactorDetail[];
  interpretation: string;
}

export interface DiscoveryJob {
  id: string;
  organization_id: string;
  asset_id: string;
  target_domain: string;
  status: 'PENDING' | 'QUEUED' | 'RUNNING' | 'COMPLETED' | 'PARTIALLY_COMPLETED' | 'FAILED' | 'CANCELLED';
  progress_percent: number;
  current_stage: string;
  authorized_scope: string;
  initiated_by_user_id?: string;
  authorization_confirmed: boolean;
  authorized_at: string;
  started_at?: string;
  completed_at?: string;
  error_message?: string;
  stage_errors?: string;
  domains_discovered_count: number;
  findings_count: number;
  initial_exposure_score?: number;
  risk_score_details?: string;
  created_at: string;
  updated_at: string;
}

export interface DNSRecord {
  id: string;
  domain_id: string;
  domain_name: string;
  record_type: string;
  record_value: string;
  ttl?: number;
  source: string;
  resolution_status: string;
  collected_at: string;
}

export interface CertificateEvidence {
  id: string;
  domain_id: string;
  issuer_name?: string;
  common_name?: string;
  subject_alt_names?: string;
  not_before?: string;
  not_after?: string;
  is_expired: boolean;
  is_wildcard: boolean;
  serial_number?: string;
  source: string;
  logged_at?: string;
}

export interface RDAPRecord {
  id: string;
  domain_id: string;
  handle?: string;
  registrar_name?: string;
  whois_server?: string;
  registration_date?: string;
  expiration_date?: string;
  last_updated_date?: string;
  nameservers?: string;
  status_codes?: string;
  asn?: string;
}

export interface DiscoveredDomain {
  id: string;
  organization_id: string;
  asset_id: string;
  job_id: string;
  domain_name: string;
  parent_domain?: string;
  is_subdomain: boolean;
  discovery_source: string;
  confidence_score: number;
  first_observed_at: string;
  last_observed_at: string;
  dns_records?: DNSRecord[];
  certificates?: CertificateEvidence[];
  rdap?: RDAPRecord;
}

export interface ExposureFinding {
  id: string;
  organization_id: string;
  asset_id: string;
  job_id: string;
  target: string;
  finding_category: string;
  severity: 'INFO' | 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL';
  confidence: string;
  title: string;
  description: string;
  evidence: string;
  discovery_source: string;
  first_observed_at: string;
  last_observed_at: string;
  current_status: string;
}

export interface AttackSurfaceOverview {
  total_discovered_domains: number;
  total_public_ips: number;
  average_exposure_score: number;
  active_findings_count: number;
  findings_by_severity: Record<string, number>;
  findings_by_category: Record<string, number>;
  recent_jobs: DiscoveryJob[];
}

export interface DiscoveryJobCreatePayload {
  asset_id: string;
  target_domain?: string;
  authorization_confirmed: boolean;
}
