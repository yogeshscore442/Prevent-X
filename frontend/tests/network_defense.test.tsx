import { render, screen, fireEvent, waitFor } from '@testing-library/react';
import { describe, it, expect, vi, beforeEach } from 'vitest';
import { BrowserRouter } from 'react-router-dom';
import { NetworkDefensePage } from '@/pages/NetworkDefensePage';
import { networkDefenseApi } from '@/services/networkDefenseApi';

let mockHasPermission = vi.fn().mockReturnValue(true);

vi.mock('@/contexts/AuthContext', () => ({
  useAuth: () => ({
    user: {
      id: 'usr-1',
      email: 'admin@preventx.internal',
      full_name: 'Security Admin',
      is_superuser: true,
      is_active: true,
      current_organization_id: 'org-1',
      memberships: [],
    },
    activeOrgId: 'org-1',
    isAuthenticated: true,
    isLoading: false,
    login: vi.fn(),
    logout: vi.fn(),
    switchOrganization: vi.fn(),
    hasPermission: (perm: string) => mockHasPermission(perm),
    refreshUser: vi.fn(),
  }),
  AuthProvider: ({ children }: { children: React.ReactNode }) => <>{children}</>,
}));

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
    deleteRateLimitPolicy: vi.fn(),
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
    mockHasPermission.mockReturnValue(true);

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
      expect(screen.getByText('Elevated Administrator')).toBeInTheDocument();
      expect(screen.getByText('1 Active')).toBeInTheDocument();
      expect(screen.getByText('1 Rules')).toBeInTheDocument();
      expect(screen.getByText('80% F1')).toBeInTheDocument();
    });
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

  // Fix 1 Regression Test: Rate Limiting evaluate API call
  it('submits rate-limit test probe and displays evaluation result from /evaluate endpoint', async () => {
    vi.mocked(networkDefenseApi.testRateLimit).mockResolvedValueOnce({
      allowed: true,
      remaining: 59,
      retry_after: 0,
      limit: 60,
      scope: 'IP',
      algorithm: 'SLIDING_WINDOW',
    });

    renderComponent();

    await waitFor(() => {
      expect(screen.getByText('Rate Limiting')).toBeInTheDocument();
    });

    fireEvent.click(screen.getByText('Rate Limiting'));

    const probeBtn = screen.getByRole('button', { name: /send rate test probe/i });
    expect(probeBtn).toBeInTheDocument();

    fireEvent.click(probeBtn);

    await waitFor(() => {
      expect(networkDefenseApi.testRateLimit).toHaveBeenCalledWith('192.168.1.100', '/api/v1/auth/login');
      expect(screen.getByText(/Quota Allowed! Remaining: 59 \/ 60/i)).toBeInTheDocument();
    });
  });

  // Fix 3 Test: Rate Limiting policy creation and deletion
  it('creates and deletes rate limit policies via UI', async () => {
    vi.mocked(networkDefenseApi.createRateLimitPolicy).mockResolvedValueOnce({
      id: 'pol-2',
      organization_id: 'org-1',
      name: 'Search Throttling',
      endpoint_pattern: '/api/v1/search.*',
      scope: 'IP',
      algorithm: 'SLIDING_WINDOW',
      max_requests: 30,
      window_seconds: 60,
      burst_capacity: 10,
      refill_rate_per_sec: 1.0,
      is_active: true,
      created_at: new Date().toISOString(),
      updated_at: new Date().toISOString(),
    });
    vi.mocked(networkDefenseApi.deleteRateLimitPolicy).mockResolvedValueOnce();

    renderComponent();

    await waitFor(() => {
      expect(screen.getByText('Rate Limiting')).toBeInTheDocument();
    });

    fireEvent.click(screen.getByText('Rate Limiting'));

    // Check Create Policy form
    expect(screen.getByRole('heading', { name: 'Create Rate Limit Policy' })).toBeInTheDocument();
    const nameInput = screen.getByPlaceholderText('e.g. Auth Login Throttling');
    const patternInput = screen.getByPlaceholderText('e.g. /api/v1/auth/.*');

    fireEvent.change(nameInput, { target: { value: 'Search Throttling' } });
    fireEvent.change(patternInput, { target: { value: '/api/v1/search.*' } });

    const createBtn = screen.getByRole('button', { name: /create policy/i });
    fireEvent.click(createBtn);

    await waitFor(() => {
      expect(networkDefenseApi.createRateLimitPolicy).toHaveBeenCalledWith(
        expect.objectContaining({
          name: 'Search Throttling',
          endpoint_pattern: '/api/v1/search.*',
        })
      );
    });

    // Check Delete Policy button
    const deleteBtn = screen.getByRole('button', { name: /delete/i });
    fireEvent.click(deleteBtn);

    await waitFor(() => {
      expect(networkDefenseApi.deleteRateLimitPolicy).toHaveBeenCalledWith('pol-1');
    });
  });

  // Fix 4 Test: GeoIP policy creation and deletion
  it('creates and deletes GeoIP policies via UI', async () => {
    vi.mocked(networkDefenseApi.createGeoIPPolicy).mockResolvedValueOnce({
      id: 'geo-2',
      organization_id: 'org-1',
      country_code: 'CN',
      country_name: 'China',
      action: 'DENY',
      risk_score_modifier: 40.0,
      is_active: true,
      created_at: new Date().toISOString(),
      updated_at: new Date().toISOString(),
    });
    vi.mocked(networkDefenseApi.deleteGeoIPPolicy).mockResolvedValueOnce({ message: 'Deleted' });

    renderComponent();

    const geoTab = await screen.findByRole('button', { name: /geoip policies/i });
    fireEvent.click(geoTab);

    // Create GeoIP policy
    expect(screen.getByRole('heading', { name: 'Create GeoIP Policy' })).toBeInTheDocument();
    const codeInput = screen.getByPlaceholderText('e.g. KP');
    const nameInput = screen.getByPlaceholderText('e.g. North Korea');

    fireEvent.change(codeInput, { target: { value: 'CN' } });
    fireEvent.change(nameInput, { target: { value: 'China' } });

    const createBtn = screen.getByRole('button', { name: /create geoip policy/i });
    fireEvent.click(createBtn);

    await waitFor(() => {
      expect(networkDefenseApi.createGeoIPPolicy).toHaveBeenCalledWith(
        expect.objectContaining({
          country_code: 'CN',
          country_name: 'China',
          action: 'DENY',
        })
      );
    });

    // Delete GeoIP policy
    const deleteBtn = screen.getByRole('button', { name: /delete/i });
    fireEvent.click(deleteBtn);

    await waitFor(() => {
      expect(networkDefenseApi.deleteGeoIPPolicy).toHaveBeenCalledWith('geo-1');
    });
  });

  // Fix 5 Test: Empty-state rows
  it('renders informative empty state rows when tables contain no data', async () => {
    vi.mocked(networkDefenseApi.getFirewallRules).mockResolvedValue([]);
    vi.mocked(networkDefenseApi.getDynamicBlocks).mockResolvedValue([]);
    vi.mocked(networkDefenseApi.getRateLimitPolicies).mockResolvedValue([]);
    vi.mocked(networkDefenseApi.getReplayReports).mockResolvedValue([]);
    vi.mocked(networkDefenseApi.getHoneypotProbes).mockResolvedValue([]);
    vi.mocked(networkDefenseApi.getGeoIPPolicies).mockResolvedValue([]);

    renderComponent();

    // 1. Firewall empty state
    await waitFor(() => {
      expect(screen.getByText(/no firewall rules created yet/i)).toBeInTheDocument();
    });

    // 2. Dynamic Blocking empty state
    fireEvent.click(screen.getByText('Dynamic IP Blocking'));
    await waitFor(() => {
      expect(screen.getByText(/no dynamic blocks recorded/i)).toBeInTheDocument();
    });

    // 3. Rate Limiting empty state
    fireEvent.click(screen.getByText('Rate Limiting'));
    await waitFor(() => {
      expect(screen.getByText(/no rate limit policies configured/i)).toBeInTheDocument();
    });

    // 4. Traffic Replay empty state
    fireEvent.click(screen.getByText('Traffic Replay'));
    await waitFor(() => {
      expect(screen.getByText(/no traffic replay validation runs executed yet/i)).toBeInTheDocument();
    });

    // 5. Honeypot empty state
    fireEvent.click(screen.getByText('Honeypot Decoys'));
    await waitFor(() => {
      expect(screen.getByText(/no reconnaissance probes captured yet/i)).toBeInTheDocument();
    });

    // 6. GeoIP empty state
    fireEvent.click(screen.getByRole('button', { name: /geoip policies/i }));
    await waitFor(() => {
      expect(screen.getByText(/no geoip access policies defined/i)).toBeInTheDocument();
    });
  });

  // Fix 2 Test: RBAC permission restrictions
  it('enforces RBAC controls by disabling/hiding privileged actions for unprivileged users', async () => {
    // Simulate user lacking all write/execute permissions (e.g. VIEWER)
    mockHasPermission.mockReturnValue(false);

    renderComponent();

    // 1. Firewall: Enforce Rule button should be disabled, Rollback button should be absent
    await waitFor(() => {
      const enforceBtn = screen.getByRole('button', { name: /enforce rule on os/i });
      expect(enforceBtn).toBeDisabled();
      expect(screen.queryByRole('button', { name: /rollback/i })).not.toBeInTheDocument();
      expect(screen.getByText(/requires 'response_action:execute' permission/i)).toBeInTheDocument();
    });

    // 2. Dynamic Blocking: Place Ban should be disabled, Unblock should be absent
    fireEvent.click(screen.getByText('Dynamic IP Blocking'));
    await waitFor(() => {
      const banBtn = screen.getByRole('button', { name: /place dynamic ban/i });
      expect(banBtn).toBeDisabled();
      expect(screen.queryByRole('button', { name: /unblock/i })).not.toBeInTheDocument();
    });

    // 3. Rate Limiting: Create Policy disabled, Delete button absent
    fireEvent.click(screen.getByText('Rate Limiting'));
    await waitFor(() => {
      const createPolBtn = screen.getByRole('button', { name: /create policy/i });
      expect(createPolBtn).toBeDisabled();
      expect(screen.queryByRole('button', { name: /delete/i })).not.toBeInTheDocument();
    });

    // 4. Traffic Replay: Execute Replay button should be disabled
    fireEvent.click(screen.getByText('Traffic Replay'));
    await waitFor(() => {
      const replayBtn = screen.getByRole('button', { name: /execute replay validation run/i });
      expect(replayBtn).toBeDisabled();
    });

    // 5. Honeypot: Register Decoy button should be disabled
    fireEvent.click(screen.getByText('Honeypot Decoys'));
    await waitFor(() => {
      const trapBtn = screen.getByRole('button', { name: /register decoy path/i });
      expect(trapBtn).toBeDisabled();
    });

    // 6. GeoIP: Create GeoIP Policy disabled, Delete button absent
    fireEvent.click(screen.getByRole('button', { name: /geoip policies/i }));
    await waitFor(() => {
      const createGeoBtn = screen.getByRole('button', { name: /create geoip policy/i });
      expect(createGeoBtn).toBeDisabled();
      expect(screen.queryByRole('button', { name: /delete/i })).not.toBeInTheDocument();
    });
  });

  // Test 6: UI Rendering of failed, active, and rolled-back firewall states
  it('renders failed, active, and rolled-back firewall rules with truthful enforcement states', async () => {
    vi.mocked(networkDefenseApi.getFirewallRules).mockResolvedValue([
      {
        id: 'rule-verified-1',
        organization_id: 'org-1',
        name: 'PX_ACTIVE_1',
        display_name: 'Verified Active Block',
        remote_ip_or_cidr: '198.51.100.10/32',
        direction: 'in',
        action: 'block',
        protocol: 'TCP',
        is_active: true,
        verified_active: true,
        is_os_enforced: true,
        enforcement_status: 'VERIFIED',
        created_at: new Date().toISOString(),
        updated_at: new Date().toISOString(),
      },
      {
        id: 'rule-failed-1',
        organization_id: 'org-1',
        name: 'PX_FAILED_1',
        display_name: 'Elevation Failed Block',
        remote_ip_or_cidr: '198.51.100.20/32',
        direction: 'in',
        action: 'block',
        protocol: 'TCP',
        is_active: true,
        verified_active: false,
        is_os_enforced: false,
        enforcement_status: 'FAILED',
        error_message: 'Windows Firewall operation requires administrative elevation.',
        created_at: new Date().toISOString(),
        updated_at: new Date().toISOString(),
      },
      {
        id: 'rule-rolledback-1',
        organization_id: 'org-1',
        name: 'PX_ROLLEDBACK_1',
        display_name: 'Previously Rolled Back Block',
        remote_ip_or_cidr: '198.51.100.30/32',
        direction: 'in',
        action: 'block',
        protocol: 'TCP',
        is_active: false,
        verified_active: false,
        is_os_enforced: false,
        enforcement_status: 'ROLLED_BACK',
        created_at: new Date().toISOString(),
        updated_at: new Date().toISOString(),
      },
    ]);

    renderComponent();

    await waitFor(() => {
      // 1. Check Verified Active Rule
      expect(screen.getByText('Verified Active Block')).toBeInTheDocument();
      expect(screen.getByText('198.51.100.10/32')).toBeInTheDocument();
      expect(screen.getByText('BLOCK (in)')).toBeInTheDocument();
      expect(screen.getByText('VERIFIED')).toBeInTheDocument();
      expect(screen.getByText('(OS Enforced)')).toBeInTheDocument();

      // 2. Check Failed Rule: Must NOT display active block!
      expect(screen.getByText('Elevation Failed Block')).toBeInTheDocument();
      expect(screen.getByText('198.51.100.20/32')).toBeInTheDocument();
      expect(screen.getAllByText('BLOCK (in) - NOT ENFORCED').length).toBe(2);
      expect(screen.getByText('FAILED')).toBeInTheDocument();
      expect(screen.getByText('(Un-enforced)')).toBeInTheDocument();
      expect(screen.getByText(/Windows Firewall operation requires administrative elevation/i)).toBeInTheDocument();
      expect(screen.getByRole('button', { name: /dismiss \/ cleanup/i })).toBeInTheDocument();

      // 3. Check Rolled Back Rule
      expect(screen.getByText('Previously Rolled Back Block')).toBeInTheDocument();
      expect(screen.getByText('198.51.100.30/32')).toBeInTheDocument();
      expect(screen.getByText('ROLLED_BACK')).toBeInTheDocument();
      expect(screen.getByText('Rolled Back')).toBeInTheDocument();
    });
  });
});
