import { api } from '@/services/api';
import {
  AssetTrustRelationship,
  AttackPath,
  AttackPathAnalysisJob,
  AttackPathOverviewStats,
  PreventionRecommendation,
} from '@/types/attackPath';

export interface AttackPathListResponse {
  total: number;
  items: AttackPath[];
  limit: number;
  offset: number;
}

export interface PreventionRecommendationListResponse {
  total: number;
  items: PreventionRecommendation[];
  limit: number;
  offset: number;
}

export const attackPathApi = {
  async getOverview(): Promise<AttackPathOverviewStats> {
    const res = await api.get<AttackPathOverviewStats>('/attack-paths/overview');
    return res.data;
  },

  async listPaths(params?: {
    severity?: string;
    confidence?: string;
    status?: string;
    entry_point_id?: string;
    target_id?: string;
    limit?: number;
    offset?: number;
  }): Promise<AttackPathListResponse> {
    const res = await api.get<AttackPathListResponse>('/attack-paths/paths', { params });
    return res.data;
  },

  async getPath(pathId: string): Promise<AttackPath> {
    const res = await api.get<AttackPath>(`/attack-paths/paths/${pathId}`);
    return res.data;
  },

  async updatePathStatus(pathId: string, status: string): Promise<AttackPath> {
    const res = await api.patch<AttackPath>(`/attack-paths/paths/${pathId}/status`, { status });
    return res.data;
  },

  async triggerAnalysis(payload?: {
    target_asset_id?: string;
    include_potential?: boolean;
    sync?: boolean;
  }): Promise<any> {
    const res = await api.post('/attack-paths/analyze', payload || {});
    return res.data;
  },

  async listJobs(limit = 20, offset = 0): Promise<AttackPathAnalysisJob[]> {
    const res = await api.get<AttackPathAnalysisJob[]>('/attack-paths/jobs', {
      params: { limit, offset },
    });
    return res.data;
  },

  async getJob(jobId: string): Promise<AttackPathAnalysisJob> {
    const res = await api.get<AttackPathAnalysisJob>(`/attack-paths/jobs/${jobId}`);
    return res.data;
  },

  async listRecommendations(params?: {
    category?: string;
    status?: string;
    attack_path_id?: string;
    limit?: number;
    offset?: number;
  }): Promise<PreventionRecommendationListResponse> {
    const res = await api.get<PreventionRecommendationListResponse>(
      '/attack-paths/recommendations',
      { params }
    );
    return res.data;
  },

  async updateRecommendationStatus(
    recId: string,
    status: string
  ): Promise<PreventionRecommendation> {
    const res = await api.patch<PreventionRecommendation>(
      `/attack-paths/recommendations/${recId}/status`,
      { status }
    );
    return res.data;
  },

  async listTrustRelationships(): Promise<AssetTrustRelationship[]> {
    const res = await api.get<AssetTrustRelationship[]>('/attack-paths/trust-relationships');
    return res.data;
  },

  async createTrustRelationship(payload: {
    source_asset_id: string;
    target_asset_id: string;
    relationship_type: string;
    port?: number;
    evidence_source?: string;
    is_verified?: boolean;
  }): Promise<AssetTrustRelationship> {
    const res = await api.post<AssetTrustRelationship>(
      '/attack-paths/trust-relationships',
      payload
    );
    return res.data;
  },

  async deleteTrustRelationship(relId: string): Promise<void> {
    await api.delete(`/attack-paths/trust-relationships/${relId}`);
  },
};
