import { api } from '@/services/api';
import {
  AttackSurfaceOverview,
  DiscoveryJob,
  DiscoveryJobCreatePayload,
  DiscoveredDomain,
  ExposureFinding,
  ActiveScanJob,
  ActiveScanCreatePayload,
  DiscoveredService,
} from '@/types/attackSurface';

export const attackSurfaceApi = {
  async getOverview(): Promise<AttackSurfaceOverview> {
    const res = await api.get<AttackSurfaceOverview>('/attack-surface/overview');
    return res.data;
  },

  async listJobs(assetId?: string): Promise<DiscoveryJob[]> {
    const params = assetId ? { asset_id: assetId } : {};
    const res = await api.get<DiscoveryJob[]>('/attack-surface/jobs', { params });
    return res.data;
  },

  async getJob(jobId: string): Promise<DiscoveryJob> {
    const res = await api.get<DiscoveryJob>(`/attack-surface/jobs/${jobId}`);
    return res.data;
  },

  async createJob(payload: DiscoveryJobCreatePayload): Promise<DiscoveryJob> {
    const res = await api.post<DiscoveryJob>('/attack-surface/discovery', payload);
    return res.data;
  },

  async cancelJob(jobId: string, reason?: string): Promise<DiscoveryJob> {
    const res = await api.post<DiscoveryJob>(`/attack-surface/jobs/${jobId}/cancel`, { reason });
    return res.data;
  },

  async listDomains(params?: {
    asset_id?: string;
    job_id?: string;
    search?: string;
  }): Promise<DiscoveredDomain[]> {
    const res = await api.get<DiscoveredDomain[]>('/attack-surface/domains', { params });
    return res.data;
  },

  async getDomainDetail(domainId: string): Promise<DiscoveredDomain> {
    const res = await api.get<DiscoveredDomain>(`/attack-surface/domains/${domainId}`);
    return res.data;
  },

  async listFindings(params?: {
    asset_id?: string;
    job_id?: string;
    severity?: string;
    category?: string;
  }): Promise<ExposureFinding[]> {
    const res = await api.get<ExposureFinding[]>('/attack-surface/findings', { params });
    return res.data;
  },

  async listActiveScans(assetId?: string): Promise<ActiveScanJob[]> {
    const params = assetId ? { asset_id: assetId } : {};
    const res = await api.get<ActiveScanJob[]>('/attack-surface/active-scans', { params });
    return res.data;
  },

  async getActiveScan(jobId: string): Promise<ActiveScanJob> {
    const res = await api.get<ActiveScanJob>(`/attack-surface/active-scans/${jobId}`);
    return res.data;
  },

  async createActiveScan(payload: ActiveScanCreatePayload): Promise<ActiveScanJob> {
    const res = await api.post<ActiveScanJob>('/attack-surface/active-scans', payload);
    return res.data;
  },

  async cancelActiveScan(jobId: string, reason?: string): Promise<ActiveScanJob> {
    const res = await api.post<ActiveScanJob>(`/attack-surface/active-scans/${jobId}/cancel`, { reason });
    return res.data;
  },

  async listScanServices(jobId: string): Promise<DiscoveredService[]> {
    const res = await api.get<DiscoveredService[]>(`/attack-surface/active-scans/${jobId}/services`);
    return res.data;
  },

  async listServices(params?: {
    asset_id?: string;
    port?: number;
    service_name?: string;
    state?: string;
  }): Promise<DiscoveredService[]> {
    const res = await api.get<DiscoveredService[]>('/attack-surface/services', { params });
    return res.data;
  },
};

