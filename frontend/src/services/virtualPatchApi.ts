import { api } from '@/services/api';
import {
  VirtualPatchDeployment,
  VirtualPatchDeploymentCreatePayload,
  VirtualPatchOverviewStats,
  VirtualPatchRecommendation,
  VirtualPatchRule,
  VirtualPatchRuleCreatePayload,
  VirtualPatchVersion,
  WafEnforcementLog,
} from '@/types/virtualPatch';

export const virtualPatchApi = {
  async getOverview(): Promise<VirtualPatchOverviewStats> {
    const res = await api.get<VirtualPatchOverviewStats>('/virtual-patching/overview');
    return res.data;
  },

  async listRecommendations(status?: string): Promise<VirtualPatchRecommendation[]> {
    const res = await api.get<VirtualPatchRecommendation[]>('/virtual-patching/recommendations', {
      params: status ? { status } : undefined,
    });
    return res.data;
  },

  async generateRecommendations(): Promise<VirtualPatchRecommendation[]> {
    const res = await api.post<VirtualPatchRecommendation[]>('/virtual-patching/recommendations/generate');
    return res.data;
  },

  async acceptRecommendation(id: string): Promise<VirtualPatchRule> {
    const res = await api.post<VirtualPatchRule>(`/virtual-patching/recommendations/${id}/accept`);
    return res.data;
  },

  async rejectRecommendation(id: string): Promise<VirtualPatchRecommendation> {
    const res = await api.post<VirtualPatchRecommendation>(`/virtual-patching/recommendations/${id}/reject`);
    return res.data;
  },

  async listRules(params?: { is_active?: boolean; attack_type?: string }): Promise<VirtualPatchRule[]> {
    const res = await api.get<VirtualPatchRule[]>('/virtual-patching/rules', { params });
    return res.data;
  },

  async createRule(payload: VirtualPatchRuleCreatePayload): Promise<VirtualPatchRule> {
    const res = await api.post<VirtualPatchRule>('/virtual-patching/rules', payload);
    return res.data;
  },

  async seedBaselineRules(): Promise<VirtualPatchRule[]> {
    const res = await api.post<VirtualPatchRule[]>('/virtual-patching/rules/seed-baseline');
    return res.data;
  },

  async getRule(id: string): Promise<VirtualPatchRule> {
    const res = await api.get<VirtualPatchRule>(`/virtual-patching/rules/${id}`);
    return res.data;
  },

  async updateRule(id: string, payload: Partial<VirtualPatchRuleCreatePayload> & { is_active?: boolean; change_summary?: string }): Promise<VirtualPatchRule> {
    const res = await api.put<VirtualPatchRule>(`/virtual-patching/rules/${id}`, payload);
    return res.data;
  },

  async deleteRule(id: string): Promise<{ status: string; rule_id: string }> {
    const res = await api.delete<{ status: string; rule_id: string }>(`/virtual-patching/rules/${id}`);
    return res.data;
  },

  async listRuleVersions(ruleId: string): Promise<VirtualPatchVersion[]> {
    const res = await api.get<VirtualPatchVersion[]>(`/virtual-patching/rules/${ruleId}/versions`);
    return res.data;
  },

  async listDeployments(): Promise<VirtualPatchDeployment[]> {
    const res = await api.get<VirtualPatchDeployment[]>('/virtual-patching/deployments');
    return res.data;
  },

  async stageDeployment(payload: VirtualPatchDeploymentCreatePayload): Promise<VirtualPatchDeployment> {
    const res = await api.post<VirtualPatchDeployment>('/virtual-patching/deployments/stage', payload);
    return res.data;
  },

  async approveDeployment(id: string): Promise<VirtualPatchDeployment> {
    const res = await api.post<VirtualPatchDeployment>(`/virtual-patching/deployments/${id}/approve`);
    return res.data;
  },

  async deployToProduction(id: string): Promise<VirtualPatchDeployment> {
    const res = await api.post<VirtualPatchDeployment>(`/virtual-patching/deployments/${id}/deploy`);
    return res.data;
  },

  async rollbackDeployment(id: string): Promise<VirtualPatchDeployment> {
    const res = await api.post<VirtualPatchDeployment>(`/virtual-patching/deployments/${id}/rollback`);
    return res.data;
  },

  async listEnforcementLogs(params?: { limit?: number; decision?: string }): Promise<WafEnforcementLog[]> {
    const res = await api.get<WafEnforcementLog[]>('/virtual-patching/logs', { params });
    return res.data;
  },

  async reportFalsePositive(id: string, notes: string): Promise<WafEnforcementLog> {
    const res = await api.post<WafEnforcementLog>(`/virtual-patching/logs/${id}/false-positive`, { notes });
    return res.data;
  },
};

