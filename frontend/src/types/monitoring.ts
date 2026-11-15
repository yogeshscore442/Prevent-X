export type EventSource = 'NGINX_ACCESS' | 'NGINX_ERROR' | 'WAF_ENFORCEMENT' | 'SYSTEM' | 'AUTH' | 'VALIDATION';

export type EventCategory = 'SECURITY' | 'TRAFFIC' | 'ERROR' | 'AUTH' | 'SYSTEM' | 'ROLLBACK';

export type EventSeverity = 'INFO' | 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL';

export type IncidentStatus = 'OPEN' | 'ACKNOWLEDGED' | 'INVESTIGATING' | 'CONTAINED' | 'RESOLVED' | 'CLOSED';

export type IncidentSeverity = 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL';

export type AlertCategory = 'INCIDENT' | 'SYSTEM_ERROR' | 'WAF_BLOCK_SPIKE' | 'ROLLBACK_TRIGGERED' | 'TRUST_DEGRADATION';

export interface SecurityEvent {
  id: string;
  organization_id: string;
  asset_id?: string;
  incident_id?: string;
  source: EventSource | string;
  category: EventCategory | string;
  severity: EventSeverity | string;
  confidence: number;
  title: string;
  description: string;
  source_ip?: string;
  target_uri?: string;
  http_method?: string;
  status_code?: number;
  fingerprint: string;
  raw_payload?: string;
  event_metadata?: Record<string, any>;
  is_correlated: boolean;
  timestamp: string;
  created_at: string;
}

export interface SecurityEventListResponse {
  items: SecurityEvent[];
  total: number;
  page: number;
  size: number;
}

export interface IncidentTimelineEntry {
  id: string;
  incident_id: string;
  organization_id: string;
  entry_type: string;
  message: string;
  evidence_data?: Record<string, any>;
  actor_user_id?: string;
  created_at: string;
}

export interface SecurityIncident {
  id: string;
  incident_number: string;
  organization_id: string;
  title: string;
  description: string;
  severity: IncidentSeverity | string;
  status: IncidentStatus | string;
  source: string;
  primary_asset_id?: string;
  mitre_attack_id?: string;
  mitre_technique?: string;
  recommended_action?: string;
  containment_action_taken?: string;
  containment_requires_approval: boolean;
  containment_approved_by?: string;
  containment_executed_at?: string;
  assigned_user_id?: string;
  iocs?: Record<string, any>;
  related_event_ids?: string[];
  first_seen_at: string;
  last_seen_at: string;
  resolved_at?: string;
  closed_at?: string;
  created_at: string;
  updated_at: string;
}

export interface SecurityIncidentDetail extends SecurityIncident {
  timeline_entries: IncidentTimelineEntry[];
  events: SecurityEvent[];
}

export interface SecurityIncidentListResponse {
  items: SecurityIncident[];
  total: number;
  page: number;
  size: number;
}

export interface SecurityAlert {
  id: string;
  organization_id: string;
  title: string;
  message: string;
  category: AlertCategory | string;
  severity: EventSeverity | string;
  is_acknowledged: boolean;
  acknowledged_at?: string;
  acknowledged_by_user_id?: string;
  related_incident_id?: string;
  related_event_id?: string;
  created_at: string;
}

export interface EventRetentionPolicy {
  id: string;
  organization_id: string;
  retention_days: number;
  max_stored_events: number;
  auto_prune_enabled: boolean;
  last_pruned_at?: string;
  created_at: string;
  updated_at: string;
}

export interface SecurityCenterOverviewStats {
  security_score: number;
  security_grade: string;
  open_incidents_total: number;
  critical_incidents_count: number;
  high_incidents_count: number;
  medium_incidents_count: number;
  events_24h_count: number;
  waf_blocked_24h: number;
  waf_allowed_24h: number;
  exposed_assets_count: number;
  active_virtual_patches_count: number;
  trust_distribution: Record<string, number>;
  recent_rollbacks_count: number;
  validation_failures_24h: number;
  unacknowledged_alerts_count: number;
}
