/**
 * PREVENT-X Network Defense API Client
 * Wraps REST endpoints for OS Firewall, Dynamic Blocking, Rate Limiting,
 * Normalization, Detection, Replay, Honeypots, GeoIP, and ML Classification.
 */

import { api } from '@/services/api';
import {
  AttackDetectionResult,
  DynamicIPBlock,
  FirewallRule,
  FirewallStatus,
  GeoIPLookupResult,
  GeoIPPolicy,
  HoneypotProbe,
  HoneypotStats,
  MLClassificationResult,
  MLModelStatus,
  NormalizationResult,
  RateLimitPolicy,
  TrafficReplayReport,
} from '@/types/networkDefense';

export const networkDefenseApi = {
  // 1. OS Firewall
  getFirewallStatus: async (): Promise<FirewallStatus> => {
    const res = await api.get('/network-defense/firewall/status');
    return res.data;
  },
  getFirewallRules: async (): Promise<FirewallRule[]> => {
    const res = await api.get('/network-defense/firewall/rules');
    return res.data;
  },
  createFirewallRule: async (payload: {
    remote_ip_or_cidr: string;
    display_name: string;
    direction?: string;
    action?: string;
    protocol?: string;
    local_ports?: string;
    description?: string;
    expires_in_minutes?: number;
  }): Promise<FirewallRule> => {
    const res = await api.post('/network-defense/firewall/rules', payload);
    return res.data;
  },
  rollbackFirewallRule: async (ruleId: string): Promise<FirewallRule> => {
    const res = await api.post(`/network-defense/firewall/rules/${ruleId}/rollback`);
    return res.data;
  },

  // 2. Dynamic IP Blocking
  getDynamicBlocks: async (status?: string): Promise<DynamicIPBlock[]> => {
    const res = await api.get('/network-defense/blocking/blocks', {
      params: status ? { status_filter: status } : {},
    });
    return res.data;
  },
  createDynamicBlock: async (payload: {
    ip_or_cidr: string;
    reason: string;
    duration_minutes?: number;
    require_approval?: boolean;
  }): Promise<DynamicIPBlock> => {
    const res = await api.post('/network-defense/blocking/blocks', payload);
    return res.data;
  },
  approveDynamicBlock: async (blockId: string, notes?: string): Promise<DynamicIPBlock> => {
    const res = await api.post(`/network-defense/blocking/blocks/${blockId}/approve`, { notes });
    return res.data;
  },
  unblockDynamicIP: async (blockId: string, reason?: string): Promise<DynamicIPBlock> => {
    const res = await api.post(`/network-defense/blocking/blocks/${blockId}/unblock`, { reason });
    return res.data;
  },

  // 3. Rate Limiting
  getRateLimitPolicies: async (): Promise<RateLimitPolicy[]> => {
    const res = await api.get('/network-defense/rate-limiting/policies');
    return res.data;
  },
  createRateLimitPolicy: async (payload: Partial<RateLimitPolicy>): Promise<RateLimitPolicy> => {
    const res = await api.post('/network-defense/rate-limiting/policies', payload);
    return res.data;
  },
  testRateLimit: async (client_ip: string, path: string): Promise<any> => {
    const res = await api.post('/network-defense/rate-limiting/test', { client_ip, path });
    return res.data;
  },

  // 4. Payload Normalization
  normalizePayload: async (payload: string): Promise<NormalizationResult> => {
    const res = await api.post('/network-defense/normalization/inspect', { payload });
    return res.data;
  },

  // 5. Advanced Attack Detection
  detectAttack: async (payload: {
    method: string;
    path: string;
    query_string?: string;
    body?: string;
    headers?: Record<string, string>;
  }): Promise<AttackDetectionResult> => {
    const res = await api.post('/network-defense/detection/inspect', payload);
    return res.data;
  },

  // 6. Traffic Replay
  getReplayFixtures: async (): Promise<any> => {
    const res = await api.get('/network-defense/replay/fixtures');
    return res.data;
  },
  runTrafficReplay: async (payload: {
    virtual_patch_id?: string;
    max_fixtures?: number;
  }): Promise<TrafficReplayReport> => {
    const res = await api.post('/network-defense/replay/run', payload);
    return res.data;
  },
  getReplayReports: async (): Promise<TrafficReplayReport[]> => {
    const res = await api.get('/network-defense/replay/reports');
    return res.data;
  },

  // 7. Honeypot Detection
  getHoneypotStats: async (): Promise<HoneypotStats> => {
    const res = await api.get('/network-defense/honeypot/stats');
    return res.data;
  },
  getHoneypotProbes: async (limit: number = 50): Promise<HoneypotProbe[]> => {
    const res = await api.get('/network-defense/honeypot/probes', { params: { limit } });
    return res.data;
  },
  getHoneypotTraps: async (): Promise<string[]> => {
    const res = await api.get('/network-defense/honeypot/traps');
    return res.data;
  },
  addHoneypotTrap: async (path: string): Promise<any> => {
    const res = await api.post('/network-defense/honeypot/traps', { path });
    return res.data;
  },
  simulateHoneypotProbe: async (payload: {
    path: string;
    source_ip: string;
    method?: string;
    auto_recommend_block?: boolean;
  }): Promise<any> => {
    const res = await api.post('/network-defense/honeypot/simulate', payload);
    return res.data;
  },

  // 8. GeoIP Policies
  getGeoIPPolicies: async (): Promise<GeoIPPolicy[]> => {
    const res = await api.get('/network-defense/geoip/policies');
    return res.data;
  },
  createGeoIPPolicy: async (payload: {
    country_code: string;
    country_name: string;
    action: 'ALLOW' | 'DENY';
    exception_cidrs?: string;
    risk_score_modifier?: number;
  }): Promise<GeoIPPolicy> => {
    const res = await api.post('/network-defense/geoip/policies', payload);
    return res.data;
  },
  deleteGeoIPPolicy: async (policyId: string): Promise<any> => {
    const res = await api.delete(`/network-defense/geoip/policies/${policyId}`);
    return res.data;
  },
  evaluateGeoIP: async (ip_address: string): Promise<GeoIPLookupResult> => {
    const res = await api.post('/network-defense/geoip/evaluate', { ip_address });
    return res.data;
  },

  // 9. ML Traffic Classification
  getMLStatus: async (): Promise<MLModelStatus> => {
    const res = await api.get('/network-defense/ml/status');
    return res.data;
  },
  classifyTraffic: async (payload: {
    method: string;
    path: string;
    query_string?: string;
    body?: string;
  }): Promise<MLClassificationResult> => {
    const res = await api.post('/network-defense/ml/classify', payload);
    return res.data;
  },
};
