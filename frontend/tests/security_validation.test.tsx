import { render, screen, fireEvent, waitFor } from '@testing-library/react';
import { describe, it, expect, vi, beforeEach } from 'vitest';
import { BrowserRouter } from 'react-router-dom';
import { SecurityValidationPage } from '@/pages/SecurityValidationPage';
import { securityValidationApi } from '@/services/securityValidationApi';

vi.mock('@/services/securityValidationApi', () => ({
  securityValidationApi: {
    getOverview: vi.fn(),
    listJobs: vi.fn(),
    getJob: vi.fn(),
    getJobResults: vi.fn(),
    runValidation: vi.fn(),
    executeRollback: vi.fn(),
    listRollbacks: vi.fn(),
    getCanaryPolicy: vi.fn(),
    updateCanaryPolicy: vi.fn(),
  },
}));

describe('SecurityValidationPage Component (Phase 7)', () => {
  const mockOverview = {
    total_validation_jobs: 12,
    passed_validation_jobs: 11,
    failed_validation_jobs: 1,
    overall_pass_rate_percent: 91.7,
    total_attacks_tested: 48,
    attacks_blocked_percent: 100.0,
    legitimate_traffic_allowed_percent: 100.0,
    active_canary_weight: 10,
    last_rollback_status: 'COMPLETED',
    last_rollback_time: new Date().toISOString(),
    active_proxy_port: 8085,
    active_proxy_healthy: true,
    coverage_by_category: [
      {
        category: 'SQLI',
        total_tests: 12,
        passed_tests: 12,
        failed_tests: 0,
        pass_rate_percentage: 100.0,
      },
    ],
  };

  const mockJobs = [
    {
      id: 'job-11111111-2222-3333-4444-555555555555',
      organization_id: 'org-1',
      deployment_id: 'dep-1',
      environment: 'STAGING',
      target_url: 'http://127.0.0.1:8085',
      status: 'PASSED' as const,
      trigger_type: 'MANUAL' as const,
      canary_percentage: 10,
      total_tests: 8,
      passed_tests: 8,
      failed_tests: 0,
      blocked_attacks: 6,
      allowed_legitimate: 2,
      false_positives_detected: 0,
      bypasses_detected: 0,
      pass_rate_percentage: 100.0,
      active_config_hash: 'a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2',
      created_at: new Date().toISOString(),
      updated_at: new Date().toISOString(),
    },
  ];

  const mockTestResults = [
    {
      id: 'res-1',
      job_id: 'job-11111111-2222-3333-4444-555555555555',
      organization_id: 'org-1',
      test_id: 'TEST-SQLI-01',
      test_category: 'SQLI' as const,
      test_name: 'SQL Injection: Classic Union Select',
      description: 'Tests blocking of raw SQL injection union attack vectors',
      target_endpoint: '/api/v1/search?q=%27%20UNION%20SELECT%201,2,3--',
      http_method: 'GET',
      request_headers_redacted: 'Host: 127.0.0.1:8085',
      request_payload_redacted: '',
      expected_status_code: 403,
      actual_status_code: 403,
      expected_decision: 'BLOCKED' as const,
      actual_decision: 'BLOCKED' as const,
      result: 'PASSED' as const,
      latency_ms: 12.4,
      evidence_snippet: 'HTTP 403 Forbidden with PREVENT-X WAF block page.',
      confidence: 100,
      created_at: new Date().toISOString(),
    },
    {
      id: 'res-2',
      job_id: 'job-11111111-2222-3333-4444-555555555555',
      organization_id: 'org-1',
      test_id: 'TEST-LEGIT-01',
      test_category: 'LEGITIMATE_TRAFFIC' as const,
      test_name: 'Legitimate Request: Product Browsing',
      description: 'Verifies normal traffic with words resembling SQL are allowed',
      target_endpoint: '/api/v1/items?category=selection_products',
      http_method: 'GET',
      request_headers_redacted: 'Host: 127.0.0.1:8085',
      request_payload_redacted: '',
      expected_status_code: 200,
      actual_status_code: 200,
      expected_decision: 'ALLOWED' as const,
      actual_decision: 'ALLOWED' as const,
      result: 'PASSED' as const,
      latency_ms: 8.1,
      evidence_snippet: 'HTTP 200 OK passed through cleanly.',
      confidence: 100,
      created_at: new Date().toISOString(),
    },
  ];

  const mockRollbacks = [
    {
      id: 'rb-1',
      organization_id: 'org-1',
      deployment_id: 'dep-1',
      trigger_source: 'MANUAL',
      rollback_reason: 'Routine rollback validation test',
      previous_config_hash: 'a1b2c3d4e5f6',
      restored_config_hash: 'f6e5d4c3b2a1',
      status: 'COMPLETED' as const,
      is_restoration_verified: true,
      verification_evidence: 'HTTP 200 OK probe verification passed.',
      started_at: new Date().toISOString(),
      created_at: new Date().toISOString(),
    },
  ];

  const mockCanaryPolicy = {
    id: 'canary-1',
    organization_id: 'org-1',
    name: 'Default SMB Canary Safety Policy',
    canary_traffic_weight: 10,
    max_failure_rate_percent: 5.0,
    max_latency_ms: 1000.0,
    max_false_positive_count: 1,
    auto_rollback_enabled: true,
    auto_promotion_enabled: false,
    is_active: true,
    created_at: new Date().toISOString(),
    updated_at: new Date().toISOString(),
  };

  beforeEach(() => {
    vi.clearAllMocks();
    vi.mocked(securityValidationApi.getOverview).mockResolvedValue(mockOverview);
    vi.mocked(securityValidationApi.listJobs).mockResolvedValue(mockJobs);
    vi.mocked(securityValidationApi.getJobResults).mockResolvedValue(mockTestResults);
    vi.mocked(securityValidationApi.listRollbacks).mockResolvedValue(mockRollbacks);
    vi.mocked(securityValidationApi.getCanaryPolicy).mockResolvedValue(mockCanaryPolicy);
  });

  it('renders overview KPI cards and execution header correctly', async () => {
    render(
      <BrowserRouter>
        <SecurityValidationPage />
      </BrowserRouter>
    );

    expect(await screen.findByText('Automated Security Validation & Rollback')).toBeInTheDocument();
    expect(screen.getByText('MOD-10 & MOD-08')).toBeInTheDocument();

    // Verify KPIs
    expect(await screen.findByText('91.7%')).toBeInTheDocument();
    expect(screen.getAllByText('100%').length).toBeGreaterThanOrEqual(1);
    expect(screen.getByText('ACTIVE')).toBeInTheDocument();
  });

  it('navigates between tabs and renders test probe explorer', async () => {
    render(
      <BrowserRouter>
        <SecurityValidationPage />
      </BrowserRouter>
    );

    await waitFor(() => {
      expect(securityValidationApi.getOverview).toHaveBeenCalled();
    });

    // Switch to Evidence & Test Probes Explorer
    const explorerTab = screen.getByRole('button', { name: /Evidence & Test Probes Explorer/i });
    fireEvent.click(explorerTab);

    // Verify test probe results are displayed
    expect(await screen.findByText('SQL Injection: Classic Union Select')).toBeInTheDocument();
    expect(screen.getByText('Legitimate Request: Product Browsing')).toBeInTheDocument();
  });

  it('switches to WAF Regression Matrix tab', async () => {
    render(
      <BrowserRouter>
        <SecurityValidationPage />
      </BrowserRouter>
    );

    await waitFor(() => {
      expect(securityValidationApi.getOverview).toHaveBeenCalled();
    });

    const matrixTab = screen.getByRole('button', { name: /WAF Regression & Bypass Matrix/i });
    fireEvent.click(matrixTab);

    expect(await screen.findByText('URL Percent-Encoding')).toBeInTheDocument();
    expect(screen.getByText('Mixed-Case Permutations')).toBeInTheDocument();
    expect(screen.getByText('ReDoS & Bounded Input Size')).toBeInTheDocument();
  });

  it('switches to Rollback Orchestrator tab and displays restoration history', async () => {
    render(
      <BrowserRouter>
        <SecurityValidationPage />
      </BrowserRouter>
    );

    await waitFor(() => {
      expect(securityValidationApi.getOverview).toHaveBeenCalled();
    });

    const rollbackTab = screen.getByRole('button', { name: /Rollback Orchestrator & Snapshots/i });
    fireEvent.click(rollbackTab);

    expect(await screen.findByText('Routine rollback validation test')).toBeInTheDocument();
    expect(screen.getByText('VERIFIED')).toBeInTheDocument();
  });

  it('opens and submits Run Security Validation modal', async () => {
    const newRun = {
      ...mockJobs[0],
      id: 'job-new-2222-3333-4444-555555555555',
      pass_rate_percentage: 100.0,
    };
    vi.mocked(securityValidationApi.runValidation).mockResolvedValue(newRun);

    render(
      <BrowserRouter>
        <SecurityValidationPage />
      </BrowserRouter>
    );

    await waitFor(() => {
      expect(securityValidationApi.getOverview).toHaveBeenCalled();
    });

    const runBtn = screen.getByRole('button', { name: /Run Security Validation/i });
    fireEvent.click(runBtn);

    expect(await screen.findByText('Execute Security Validation')).toBeInTheDocument();

    const submitBtn = screen.getByRole('button', { name: /Execute Validation Probes/i });
    fireEvent.click(submitBtn);

    await waitFor(() => {
      expect(securityValidationApi.runValidation).toHaveBeenCalled();
    });
  });

  it('switches to Canary Safety tab and updates policy thresholds', async () => {
    vi.mocked(securityValidationApi.updateCanaryPolicy).mockResolvedValue({
      ...mockCanaryPolicy,
      canary_traffic_weight: 20,
    });

    render(
      <BrowserRouter>
        <SecurityValidationPage />
      </BrowserRouter>
    );

    await waitFor(() => {
      expect(securityValidationApi.getOverview).toHaveBeenCalled();
    });

    const canaryTab = screen.getByRole('button', { name: /Canary Safety Policies & Thresholds/i });
    fireEvent.click(canaryTab);

    expect(await screen.findByText('Canary Traffic Allocation Weight (%)')).toBeInTheDocument();

    const saveBtn = screen.getByRole('button', { name: /Save Policy Configuration/i });
    fireEvent.click(saveBtn);

    await waitFor(() => {
      expect(securityValidationApi.updateCanaryPolicy).toHaveBeenCalled();
    });
  });
});
