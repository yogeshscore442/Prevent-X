import { api } from '@/services/api';
import {
  AssetTrustAssessment,
  BehavioralAnomaly,
  ResponseAction,
  ThreatAssetCorrelation,
  ThreatIntelRecord,
  ZeroTrustOverviewStats,
} from '@/types/zeroTrust';

export const zeroTrustApi = {
  async getOverview(): Promise<ZeroTrustOverviewStats> {
    const res = await api.get<ZeroTrustOverviewStats>('/zero-trust/overview');
    return res.data;
  },

  async listAssessments(params?: {
    decision?: string;
    skip?: number;
    limit?: number;
  }): Promise<AssetTrustAssessment[]> {
    const res = await api.get<AssetTrustAssessment[]>('/zero-trust/assessments', { params });
    return res.data;
  },

  async evaluatePosture(payload?: {
    asset_id?: string;
    force_refresh?: boolean;
  }): Promise<any> {
    const res = await api.post('/zero-trust/evaluate', payload || {});
    return res.data;
  },

  async listThreatIndicators(params?: {
    indicator_type?: string;
    is_active?: boolean;
    skip?: number;
    limit?: number;
  }): Promise<ThreatIntelRecord[]> {
    const res = await api.get<ThreatIntelRecord[]>('/zero-trust/threat-intel', { params });
    return res.data;
  },

  async syncThreatFeed(): Promise<any> {
    const res = await api.post('/zero-trust/threat-intel/sync');
    return res.data;
  },

  async correlateThreats(): Promise<any> {
    const res = await api.post('/zero-trust/threat-intel/correlate');
    return res.data;
  },

  async listThreatCorrelations(params?: {
    status?: string;
    skip?: number;
    limit?: number;
  }): Promise<ThreatAssetCorrelation[]> {
    const res = await api.get<ThreatAssetCorrelation[]>('/zero-trust/threat-correlations', { params });
    return res.data;
  },

  async listAnomalies(params?: {
    status?: string;
    is_zero_day?: boolean;
    skip?: number;
    limit?: number;
  }): Promise<BehavioralAnomaly[]> {
    const res = await api.get<BehavioralAnomaly[]>('/zero-trust/anomalies', { params });
    return res.data;
  },

  async detectAnomalies(): Promise<any> {
    const res = await api.post('/zero-trust/anomalies/detect');
    return res.data;
  },

  async updateAnomalyStatus(anomalyId: string, status: string): Promise<any> {
    const res = await api.patch(`/zero-trust/anomalies/${anomalyId}/status`, { status });
    return res.data;
  },

  async listResponseActions(params?: {
    status?: string;
    skip?: number;
    limit?: number;
  }): Promise<ResponseAction[]> {
    const res = await api.get<ResponseAction[]>('/zero-trust/response-actions', { params });
    return res.data;
  },

  async approveResponseAction(actionId: string): Promise<any> {
    const res = await api.post(`/zero-trust/response-actions/${actionId}/approve`);
    return res.data;
  },

  async rejectResponseAction(actionId: string, reason?: string): Promise<any> {
    const res = await api.post(`/zero-trust/response-actions/${actionId}/reject`, null, {
      params: { reason },
    });
    return res.data;
  },

  async executeResponseAction(actionId: string): Promise<any> {
    const res = await api.post(`/zero-trust/response-actions/${actionId}/execute`);
    return res.data;
  },

  async rollbackResponseAction(actionId: string): Promise<any> {
    const res = await api.post(`/zero-trust/response-actions/${actionId}/rollback`);
    return res.data;
  },
};

