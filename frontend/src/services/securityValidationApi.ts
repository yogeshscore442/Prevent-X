import { api } from '@/services/api';
import {
  CanaryPolicy,
  CanaryPolicyUpdatePayload,
  RollbackRecord,
  RollbackRequestPayload,
  SecurityValidationOverviewStats,
  ValidationJob,
  ValidationJobCreatePayload,
  ValidationTestResult,
} from '@/types/securityValidation';

export const securityValidationApi = {
  async getOverview(): Promise<SecurityValidationOverviewStats> {
    const res = await api.get<SecurityValidationOverviewStats>('/security-validation/overview');
    return res.data;
  },

  async listJobs(params?: {
    limit?: number;
    environment?: string;
    status?: string;
  }): Promise<ValidationJob[]> {
    const res = await api.get<ValidationJob[]>('/security-validation/jobs', { params });
    return res.data;
  },

  async getJob(id: string): Promise<ValidationJob> {
    const res = await api.get<ValidationJob>(`/security-validation/jobs/${id}`);
    return res.data;
  },

  async getJobResults(
    id: string,
    params?: { category?: string; result?: string }
  ): Promise<ValidationTestResult[]> {
    const res = await api.get<ValidationTestResult[]>(`/security-validation/jobs/${id}/results`, {
      params,
    });
    return res.data;
  },

  async runValidation(
    payload: ValidationJobCreatePayload,
    asyncMode: boolean = false
  ): Promise<ValidationJob> {
    const res = await api.post<ValidationJob>('/security-validation/jobs/run', payload, {
      params: { async_mode: asyncMode },
    });
    return res.data;
  },

  async executeRollback(
    payload: RollbackRequestPayload,
    asyncMode: boolean = false
  ): Promise<RollbackRecord> {
    const res = await api.post<RollbackRecord>('/security-validation/rollback', payload, {
      params: { async_mode: asyncMode },
    });
    return res.data;
  },

  async listRollbacks(limit: number = 50): Promise<RollbackRecord[]> {
    const res = await api.get<RollbackRecord[]>('/security-validation/rollback/history', {
      params: { limit },
    });
    return res.data;
  },

  async getCanaryPolicy(): Promise<CanaryPolicy> {
    const res = await api.get<CanaryPolicy>('/security-validation/canary-policies');
    return res.data;
  },

  async updateCanaryPolicy(payload: CanaryPolicyUpdatePayload): Promise<CanaryPolicy> {
    const res = await api.put<CanaryPolicy>('/security-validation/canary-policies', payload);
    return res.data;
  },
};

