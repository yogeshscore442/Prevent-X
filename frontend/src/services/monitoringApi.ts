import { api } from '@/services/api';
import {
  EventRetentionPolicy,
  IncidentTimelineEntry,
  SecurityCenterOverviewStats,
  SecurityAlert,
  SecurityEventListResponse,
  SecurityIncident,
  SecurityIncidentDetail,
  SecurityIncidentListResponse,
} from '@/types/monitoring';

export const monitoringApi = {
  async getOverview(): Promise<SecurityCenterOverviewStats> {
    const res = await api.get<SecurityCenterOverviewStats>('/monitoring/overview');
    return res.data;
  },

  async getEvents(params?: {
    source?: string;
    category?: string;
    severity?: string;
    search?: string;
    start_time?: string;
    end_time?: string;
    page?: number;
    size?: number;
  }): Promise<SecurityEventListResponse> {
    const res = await api.get<SecurityEventListResponse>('/monitoring/events', { params });
    return res.data;
  },

  async ingestBatch(payload: {
    events?: any[];
    raw_nginx_logs?: string;
    asset_id?: string;
  }): Promise<{
    ingested_count: number;
    deduplicated_count: number;
    correlated_incidents_count: number;
    event_ids: string[];
  }> {
    const res = await api.post('/monitoring/events/ingest', payload);
    return res.data;
  },

  async getIncidents(params?: {
    status?: string;
    severity?: string;
    page?: number;
    size?: number;
  }): Promise<SecurityIncidentListResponse> {
    const res = await api.get<SecurityIncidentListResponse>('/monitoring/incidents', { params });
    return res.data;
  },

  async createIncident(payload: {
    title: string;
    description: string;
    severity?: string;
    primary_asset_id?: string;
    mitre_attack_id?: string;
    mitre_technique?: string;
    recommended_action?: string;
  }): Promise<SecurityIncident> {
    const res = await api.post<SecurityIncident>('/monitoring/incidents', payload);
    return res.data;
  },

  async getIncidentDetail(id: string): Promise<SecurityIncidentDetail> {
    const res = await api.get<SecurityIncidentDetail>(`/monitoring/incidents/${id}`);
    return res.data;
  },

  async updateIncident(
    id: string,
    payload: {
      status?: string;
      severity?: string;
      assigned_user_id?: string;
      notes?: string;
    }
  ): Promise<SecurityIncident> {
    const res = await api.patch<SecurityIncident>(`/monitoring/incidents/${id}`, payload);
    return res.data;
  },

  async addIncidentNote(
    id: string,
    payload: { message: string; entry_type?: string; evidence_data?: Record<string, any> }
  ): Promise<IncidentTimelineEntry> {
    const res = await api.post<IncidentTimelineEntry>(`/monitoring/incidents/${id}/notes`, payload);
    return res.data;
  },

  async executeContainment(
    id: string,
    payload: { containment_action: string; notes?: string; is_approved?: boolean }
  ): Promise<SecurityIncident> {
    const res = await api.post<SecurityIncident>(`/monitoring/incidents/${id}/contain`, payload);
    return res.data;
  },

  async getAlerts(params?: { is_acknowledged?: boolean; limit?: number }): Promise<SecurityAlert[]> {
    const res = await api.get<SecurityAlert[]>('/monitoring/alerts', { params });
    return res.data;
  },

  async acknowledgeAlert(alertId: string): Promise<SecurityAlert> {
    const res = await api.post<SecurityAlert>(`/monitoring/alerts/${alertId}/acknowledge`);
    return res.data;
  },

  async getRetentionPolicy(): Promise<EventRetentionPolicy> {
    const res = await api.get<EventRetentionPolicy>('/monitoring/retention');
    return res.data;
  },

  async updateRetentionPolicy(payload: {
    retention_days?: number;
    max_stored_events?: number;
    auto_prune_enabled?: boolean;
  }): Promise<EventRetentionPolicy> {
    const res = await api.put<EventRetentionPolicy>('/monitoring/retention', payload);
    return res.data;
  },

  async pruneEventsNow(): Promise<{ status: string; organization_id: string; deleted_events_count: number }> {
    const res = await api.post('/monitoring/retention/prune');
    return res.data;
  },

  getSSEUrl(lastEventId?: string): string {
    const token = localStorage.getItem('preventx_access_token') || localStorage.getItem('access_token') || '';
    const baseUrl = '/api/v1/monitoring/events/stream';
    const params = new URLSearchParams();
    if (token) params.set('token', token);
    if (lastEventId) params.set('last_event_id', lastEventId);
    const queryString = params.toString();
    return queryString ? `${baseUrl}?${queryString}` : baseUrl;
  },
};
