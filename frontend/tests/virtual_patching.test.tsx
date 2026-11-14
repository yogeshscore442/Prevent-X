import { render, screen, fireEvent, waitFor } from '@testing-library/react';
import { describe, it, expect, vi, beforeEach } from 'vitest';
import { BrowserRouter } from 'react-router-dom';
import { VirtualPatchingPage } from '@/pages/VirtualPatchingPage';
import { virtualPatchApi } from '@/services/virtualPatchApi';

vi.mock('@/services/virtualPatchApi', () => ({
  virtualPatchApi: {
    getOverview: vi.fn(),
    listRecommendations: vi.fn(),
    generateRecommendations: vi.fn(),
    acceptRecommendation: vi.fn(),
    rejectRecommendation: vi.fn(),
    listRules: vi.fn(),
    createRule: vi.fn(),
    seedBaselineRules: vi.fn(),
    getRule: vi.fn(),
    updateRule: vi.fn(),
    deleteRule: vi.fn(),
    listRuleVersions: vi.fn(),
    listDeployments: vi.fn(),
    stageDeployment: vi.fn(),
    approveDeployment: vi.fn(),
    deployToProduction: vi.fn(),
    rollbackDeployment: vi.fn(),
    listEnforcementLogs: vi.fn(),
    reportFalsePositive: vi.fn(),
  },
}));

describe('VirtualPatchingPage Component (Phase 6)', () => {
  const mockOverview = {
    total_rules: 5,
    active_rules: 4,
    staging_deployments: 1,
    production_deployments: 1,
    pending_approval_deployments: 1,
    total_blocks_recorded: 42,
    false_positives_reported: 2,
    active_recommendations_count: 3,
    proxy_status: 'ACTIVE' as const,
    proxy_listen_port: 8085,
    upstream_url: 'http://127.0.0.1:8086',
  };

  const mockRecommendations = [
    {
      id: 'rec-1',
      organization_id: 'org-1',
      vulnerability_id: 'vuln-1',
      asset_id: 'asset-1',
      asset_name: 'Core Payment Gateway',
      cve_id: 'CVE-2024-1337',
      cwe_id: 'CWE-89',
      attack_type: 'SQLI' as const,
      suggested_rule_name: 'Virtual Patch: SQL Injection Protection [CVE-2024-1337]',
      suggested_pattern: '(?i)(union\\s+select|select\\s+.*\\s+from)',
      target_uri_pattern: '/.*',
      rationale: 'Compensates for SQL injection flaw in payment query handler.',
      confidence: 95,
      status: 'PROPOSED' as const,
      created_at: new Date().toISOString(),
      updated_at: new Date().toISOString(),
    },
  ];

  const mockRules = [
    {
      id: 'rule-1',
      organization_id: 'org-1',
      rule_name: 'Virtual Patch: SQL Injection Protection [CVE-2024-1337]',
      attack_type: 'SQLI' as const,
      description: 'Compensates for SQL injection in query parameters.',
      severity: 'HIGH',
      priority: 50,
      action: 'BLOCK' as const,
      target_uri_pattern: '/.*',
      http_methods: ['GET', 'POST'],
      match_conditions: [
        {
          target: 'QUERY',
          operator: 'REGEX',
          pattern: 'union\\s+select',
          is_case_sensitive: false,
        },
      ],
      status: 'PRODUCTION' as const,
      is_active: true,
      is_system_rule: false,
      version: 1,
      false_positive_count: 0,
      enforcement_count: 15,
      created_at: new Date().toISOString(),
      updated_at: new Date().toISOString(),
    },
  ];

  const mockDeployments = [
    {
      id: 'dep-1',
      organization_id: 'org-1',
      environment: 'STAGING' as const,
      status: 'PENDING_APPROVAL' as const,
      deployed_rules_count: 4,
      config_hash: 'abcdef1234567890abcdef1234567890abcdef1234567890',
      listen_port: 8085,
      upstream_url: 'http://127.0.0.1:8086',
      created_at: new Date().toISOString(),
      updated_at: new Date().toISOString(),
    },
  ];

  const mockLogs = [
    {
      id: 'log-1',
      organization_id: 'org-1',
      client_ip: '198.51.100.42',
      http_method: 'GET',
      uri: '/products?q=1%20UNION%20SELECT%201,2',
      decision: 'BLOCKED' as const,
      block_reason: 'Matched pattern: union select',
      response_status_code: 403,
      is_false_positive_reported: false,
      created_at: new Date().toISOString(),
    },
  ];

  beforeEach(() => {
    vi.clearAllMocks();
    vi.mocked(virtualPatchApi.getOverview).mockResolvedValue(mockOverview);
    vi.mocked(virtualPatchApi.listRecommendations).mockResolvedValue(mockRecommendations);
    vi.mocked(virtualPatchApi.listRules).mockResolvedValue(mockRules);
    vi.mocked(virtualPatchApi.listDeployments).mockResolvedValue(mockDeployments);
    vi.mocked(virtualPatchApi.listEnforcementLogs).mockResolvedValue(mockLogs);
  });

  it('renders Virtual Patching dashboard overview KPIs correctly', async () => {
    render(
      <BrowserRouter>
        <VirtualPatchingPage />
      </BrowserRouter>
    );

    await waitFor(() => {
      expect(screen.getByText('Intelligent Virtual Patching Engine')).toBeInTheDocument();
      expect(screen.getByText('Port 8085')).toBeInTheDocument();
      expect(screen.getByText('42')).toBeInTheDocument(); // total blocks
    });
  });

  it('renders AI recommendations and allows accepting a proposal', async () => {
    vi.mocked(virtualPatchApi.acceptRecommendation).mockResolvedValue({
      ...mockRules[0],
      id: 'rule-new',
    });

    render(
      <BrowserRouter>
        <VirtualPatchingPage />
      </BrowserRouter>
    );

    await waitFor(() => {
      expect(screen.getByText('Virtual Patch: SQL Injection Protection [CVE-2024-1337]')).toBeInTheDocument();
      expect(screen.getByText(/Accept & Create Draft Rule/i)).toBeInTheDocument();
    });

    fireEvent.click(screen.getByText(/Accept & Create Draft Rule/i));

    await waitFor(() => {
      expect(virtualPatchApi.acceptRecommendation).toHaveBeenCalledWith('rec-1');
    });
  });

  it('switches to Rules catalog and displays registered rules', async () => {
    render(
      <BrowserRouter>
        <VirtualPatchingPage />
      </BrowserRouter>
    );

    await waitFor(() => {
      expect(screen.getByText(/WAF Rules & Versioning/i)).toBeInTheDocument();
    });

    fireEvent.click(screen.getByText(/WAF Rules & Versioning/i));

    await waitFor(() => {
      expect(screen.getByText('#50')).toBeInTheDocument();
      expect(screen.getByText('v1')).toBeInTheDocument();
      expect(screen.getByText('BLOCK')).toBeInTheDocument();
    });
  });

  it('switches to Deployments tab and approves staged configuration', async () => {
    vi.mocked(virtualPatchApi.approveDeployment).mockResolvedValue({
      ...mockDeployments[0],
      status: 'APPROVED' as const,
    });

    render(
      <BrowserRouter>
        <VirtualPatchingPage />
      </BrowserRouter>
    );

    await waitFor(() => {
      expect(screen.getByText(/Deployments & Human Sign-Off/i)).toBeInTheDocument();
    });

    fireEvent.click(screen.getByText(/Deployments & Human Sign-Off/i));

    await waitFor(() => {
      expect(screen.getByText('Approve')).toBeInTheDocument();
    });

    fireEvent.click(screen.getByText('Approve'));

    await waitFor(() => {
      expect(virtualPatchApi.approveDeployment).toHaveBeenCalledWith('dep-1');
    });
  });

  it('switches to Reverse Proxy Logs and opens False Positive dialog', async () => {
    render(
      <BrowserRouter>
        <VirtualPatchingPage />
      </BrowserRouter>
    );

    await waitFor(() => {
      expect(screen.getByText(/Reverse Proxy Audit Logs/i)).toBeInTheDocument();
    });

    fireEvent.click(screen.getByText(/Reverse Proxy Audit Logs/i));

    await waitFor(() => {
      expect(screen.getByText('198.51.100.42')).toBeInTheDocument();
      expect(screen.getByText('Flag False Positive')).toBeInTheDocument();
    });

    fireEvent.click(screen.getByText('Flag False Positive'));

    await waitFor(() => {
      expect(screen.getByText('Report False Positive')).toBeInTheDocument();
      expect(screen.getByText('Submit Feedback')).toBeInTheDocument();
    });
  });
});
