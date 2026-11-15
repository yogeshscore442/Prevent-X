import { render, screen, fireEvent, waitFor } from '@testing-library/react';
import { describe, it, expect, vi, beforeEach } from 'vitest';
import { BrowserRouter } from 'react-router-dom';
import { NetworkDefensePage } from '@/pages/NetworkDefensePage';
import { networkDefenseApi } from '@/services/networkDefenseApi';

vi.mock('@/services/networkDefenseApi', () => ({
  networkDefenseApi: {
    getFirewallStatus: vi.fn(),
    getFirewallRules: vi.fn(),
    createFirewallRule: vi.fn(),
    rollbackFirewallRule: vi.fn(),
    getDynamicBlocks: vi.fn(),
    createDynamicBlock: vi.fn(),
    approveDynamicBlock: vi.fn(),
    unblockDynamicIP: vi.fn(),
    getRateLimitPolicies: vi.fn(),
    createRateLimitPolicy: vi.fn(),
    testRateLimit: vi.fn(),
    normalizePayload: vi.fn(),
    detectAttack: vi.fn(),
    getReplayFixtures: vi.fn(),
    runTrafficReplay: vi.fn(),
    getReplayReports: vi.fn(),
    getHoneypotStats: vi.fn(),
    getHoneypotProbes: vi.fn(),
    getHoneypotTraps: vi.fn(),
    addHoneypotTrap: vi.fn(),
    simulateHoneypotProbe: vi.fn(),
    getGeoIPPolicies: vi.fn(),
    createGeoIPPolicy: vi.fn(),
    deleteGeoIPPolicy: vi.fn(),
    evaluateGeoIP: vi.fn(),
    getMLStatus: vi.fn(),
    classifyTraffic: vi.fn(),
  },
}));

describe('NetworkDefensePage Component (Phase 11)', () => {
  beforeEach(() => {
    vi.clearAllMocks();

    vi.mocked(networkDefenseApi.getFirewallStatus).mockResolvedValue({
      os_type: 'Windows',
      is_elevated: true,
      is_operational: true,
      active_rules_count: 2,
      verified_rules_count: 2,
      failed_rules_count: 0,
      pending_rules_count: 0,
      execution_mode: 'RESTRICTED',
      managed_os_rules: ['PX_TEST_1'],
    });

    vi.mocked(networkDefenseApi.getFirewallRules).mockResolvedValue([
      {
        id: 'rule-1',
        organization_id: 'org-1',
        name: 'PX_BLOCK_1',
        display_name: 'Block Attacker IP',
        remote_ip_or_cidr: '198.51.100.99/32',
        direction: 'in',
        action: 'block',
        protocol: 'TCP',
        is_active: true,
        verified_active: true,
        enforcement_status: 'VERIFIED',
        created_at: new Date().toISOString(),
        updated_at: new Date().toISOString(),
      },
    ]);

    vi.mocked(networkDefenseApi.getDynamicBlocks).mockResolvedValue([
      {
        id: 'block-1',
        organization_id: 'org-1',
        ip_or_cidr: '203.0.113.88/32',
        reason: 'SSH brute force',
        status: 'ACTIVE',
        expires_at: new Date(Date.now() + 3600000).toISOString(),
        created_at: new Date().toISOString(),
        updated_at: new Date().toISOString(),
      },
    ]);

    vi.mocked(networkDefenseApi.getRateLimitPolicies).mockResolvedValue([
      {
        id: 'pol-1',
        organization_id: 'org-1',
        name: 'Auth Rate Limit',
        endpoint_pattern: '/api/v1/auth/.*',
        scope: 'IP',
        algorithm: 'SLIDING_WINDOW',
        max_requests: 10,
        window_seconds: 60,
        burst_capacity: 5,
        refill_rate_per_sec: 1.0,
        is_active: true,
        created_at: new Date().toISOString(),
        updated_at: new Date().toISOString(),
      },
    ]);

    vi.mocked(networkDefenseApi.getReplayReports).mockResolvedValue([]);
    vi.mocked(networkDefenseApi.getHoneypotStats).mockResolvedValue({
      total_probes: 12,
      unique_attacker_ips: 4,
      top_traps: [{ trap_path: '/.env', hits: 7 }],
      active_decoy_count: 19,
    });
    vi.mocked(networkDefenseApi.getHoneypotProbes).mockResolvedValue([]);
    vi.mocked(networkDefenseApi.getHoneypotTraps).mockResolvedValue(['/.env', '/wp-admin/*']);
    vi.mocked(networkDefenseApi.getGeoIPPolicies).mockResolvedValue([
      {
        id: 'geo-1',
        organization_id: 'org-1',
        country_code: 'KP',
        country_name: 'North Korea',
        action: 'DENY',
        risk_score_modifier: 50.0,
        is_active: true,
        created_at: new Date().toISOString(),
        updated_at: new Date().toISOString(),
      },
    ]);
    vi.mocked(networkDefenseApi.getMLStatus).mockResolvedValue({
      model_version: 'v1.0.0-rf-ensemble',
      algorithm: 'Random Forest Ensemble',
      training_sample_count: 34,
      features_count: 16,
      is_ready: true,
      precision: 0.85,
      recall: 0.75,
      f1_score: 0.80,
      advisory_mode: true,
    });
  });

  const renderComponent = () =>
    render(
      <BrowserRouter>
        <NetworkDefensePage />
      </BrowserRouter>
    );

  it('renders page header and core telemetry metrics cards', async () => {
    renderComponent();

    await waitFor(() => {
      expect(screen.getByText('Advanced Network Defense & Detection Layer')).toBeInTheDocument();
    });

    expect(screen.getByText('Elevated Administrator')).toBeInTheDocument();
    expect(screen.getByText('1 Active')).toBeInTheDocument();
    expect(screen.getByText('1 Rules')).toBeInTheDocument();
    expect(screen.getByText('80% F1')).toBeInTheDocument();
  });

  it('renders firewall management tab with rules table', async () => {
    renderComponent();

    await waitFor(() => {
      expect(screen.getByText('Block Attacker IP')).toBeInTheDocument();
      expect(screen.getByText('198.51.100.99/32')).toBeInTheDocument();
      expect(screen.getByText('VERIFIED')).toBeInTheDocument();
    });
  });

  it('navigates to dynamic blocking tab and displays active bans', async () => {
    renderComponent();

    await waitFor(() => {
      expect(screen.getByText('Dynamic IP Blocking')).toBeInTheDocument();
    });

    fireEvent.click(screen.getByText('Dynamic IP Blocking'));

    await waitFor(() => {
      expect(screen.getByText('203.0.113.88/32')).toBeInTheDocument();
      expect(screen.getByText('SSH brute force')).toBeInTheDocument();
      expect(screen.getByText('ACTIVE')).toBeInTheDocument();
    });
  });

  it('navigates to honeypot tab and displays configured traps', async () => {
    renderComponent();

    await waitFor(() => {
      expect(screen.getByText('Honeypot Decoys')).toBeInTheDocument();
    });

    fireEvent.click(screen.getByText('Honeypot Decoys'));

    await waitFor(() => {
      expect(screen.getByText('Captured Reconnaissance Probes')).toBeInTheDocument();
      expect(screen.getByText('Register Custom Decoy Trap')).toBeInTheDocument();
    });
  });

  it('navigates to ML classification tab and displays telemetry', async () => {
    renderComponent();

    await waitFor(() => {
      expect(screen.getByText('ML Classification')).toBeInTheDocument();
    });

    fireEvent.click(screen.getByText('ML Classification'));

    await waitFor(() => {
      expect(screen.getByText('Model Architecture Telemetry')).toBeInTheDocument();
      expect(screen.getAllByText('v1.0.0-rf-ensemble').length).toBeGreaterThanOrEqual(1);
      expect(screen.getByText('Compute Advisory Prediction')).toBeInTheDocument();
    });
  });
});
