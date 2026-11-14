import { render, screen, fireEvent } from '@testing-library/react';
import { describe, it, expect, vi, beforeEach } from 'vitest';
import { BrowserRouter } from 'react-router-dom';
import { AttackSurfacePage } from '@/pages/AttackSurfacePage';
import { AuthProvider } from '@/contexts/AuthContext';
import { attackSurfaceApi } from '@/services/attackSurfaceApi';

vi.mock('@/services/api', () => ({
  api: {
    get: vi.fn((url: string) => {
      if (url === '/assets') {
        return Promise.resolve({
          data: {
            items: [
              {
                id: 'asset-1',
                name: 'Main SMB Portal',
                target: 'portal.smbclient.in',
                is_in_scope: true,
              },
            ],
          },
        });
      }
      return Promise.resolve({ data: {} });
    }),
    interceptors: {
      request: { use: vi.fn() },
      response: { use: vi.fn() },
    },
  },
}));

vi.mock('@/services/attackSurfaceApi', () => ({
  attackSurfaceApi: {
    getOverview: vi.fn(),
    listJobs: vi.fn(),
    listDomains: vi.fn(),
    listFindings: vi.fn(),
    getJob: vi.fn(),
    createJob: vi.fn(),
    cancelJob: vi.fn(),
    getDomainDetail: vi.fn(),
    listActiveScans: vi.fn(),
    getActiveScan: vi.fn(),
    createActiveScan: vi.fn(),
    cancelActiveScan: vi.fn(),
    listScanServices: vi.fn(),
    listServices: vi.fn(),
  },
}));

describe('AttackSurfacePage Component (Phase 2 Prompt 1)', () => {
  beforeEach(() => {
    vi.clearAllMocks();

    (attackSurfaceApi.getOverview as any).mockResolvedValue({
      total_discovered_domains: 5,
      total_public_ips: 2,
      average_exposure_score: 35.0,
      active_findings_count: 3,
      findings_by_severity: {
        CRITICAL: 0,
        HIGH: 1,
        MEDIUM: 1,
        LOW: 1,
        INFO: 0,
      },
      findings_by_category: {
        DNS_CONFIGURATION: 1,
        CERTIFICATE_EXPOSURE: 1,
      },
      recent_jobs: [
        {
          id: 'job-101',
          target_domain: 'portal.smbclient.in',
          status: 'COMPLETED',
          progress_percent: 100,
          current_stage: 'COMPLETED',
          authorized_scope: 'portal.smbclient.in',
          authorization_confirmed: true,
          authorized_at: new Date().toISOString(),
          created_at: new Date().toISOString(),
          domains_discovered_count: 5,
          findings_count: 3,
          initial_exposure_score: 35.0,
        },
      ],
    });

    (attackSurfaceApi.listJobs as any).mockResolvedValue([
      {
        id: 'job-101',
        target_domain: 'portal.smbclient.in',
        status: 'COMPLETED',
        progress_percent: 100,
        current_stage: 'COMPLETED',
        authorized_scope: 'portal.smbclient.in',
        authorization_confirmed: true,
        authorized_at: new Date().toISOString(),
        created_at: new Date().toISOString(),
        domains_discovered_count: 5,
        findings_count: 3,
        initial_exposure_score: 35.0,
      },
    ]);

    (attackSurfaceApi.listDomains as any).mockResolvedValue([
      {
        id: 'dom-1',
        domain_name: 'portal.smbclient.in',
        parent_domain: null,
        is_subdomain: false,
        discovery_source: 'PRIMARY_ASSET',
        confidence_score: 1.0,
        first_observed_at: new Date().toISOString(),
        last_observed_at: new Date().toISOString(),
      },
      {
        id: 'dom-2',
        domain_name: 'api.portal.smbclient.in',
        parent_domain: 'portal.smbclient.in',
        is_subdomain: true,
        discovery_source: 'CERTIFICATE_TRANSPARENCY',
        confidence_score: 1.0,
        first_observed_at: new Date().toISOString(),
        last_observed_at: new Date().toISOString(),
      },
    ]);

    (attackSurfaceApi.listFindings as any).mockResolvedValue([
      {
        id: 'find-1',
        target: 'portal.smbclient.in',
        finding_category: 'DNS_CONFIGURATION',
        severity: 'HIGH',
        confidence: 'HIGH',
        title: 'Missing SPF Record (Email Spoofing Risk)',
        description: 'No SPF record found on domain.',
        evidence: JSON.stringify({ domain: 'portal.smbclient.in' }),
        discovery_source: 'DNS_RESOLVER',
        first_observed_at: new Date().toISOString(),
        last_observed_at: new Date().toISOString(),
        current_status: 'ACTIVE',
      },
    ]);

    (attackSurfaceApi.listActiveScans as any).mockResolvedValue([
      {
        id: 'scan-1',
        target: 'portal.smbclient.in',
        target_ip: '203.0.113.15',
        scan_profile: 'BASIC',
        selected_ports: '[80, 443]',
        status: 'COMPLETED',
        progress_percent: 100,
        current_stage: 'COMPLETED',
        ports_scanned_count: 2,
        services_discovered_count: 2,
        started_at: new Date().toISOString(),
        completed_at: new Date().toISOString(),
      },
    ]);

    (attackSurfaceApi.listServices as any).mockResolvedValue([
      {
        id: 'svc-1',
        port: 443,
        protocol: 'tcp',
        service_name: 'https',
        state: 'OPEN',
        confidence: 'CONFIRMED_OBSERVATION',
        target: 'portal.smbclient.in',
        target_ip: '203.0.113.15',
        tls_metadata: JSON.stringify({
          subject_cn: 'portal.smbclient.in',
          issuer: 'Let\'s Encrypt',
          days_remaining: 85,
        }),
        http_metadata: JSON.stringify({
          status_code: 200,
          server_header: 'nginx',
          title: 'SMB Portal Login',
        }),
        discovered_at: new Date().toISOString(),
      },
    ]);
  });

  it('renders page header and navigation tabs', async () => {
    render(
      <BrowserRouter>
        <AuthProvider>
          <AttackSurfacePage />
        </AuthProvider>
      </BrowserRouter>
    );

    expect(await screen.findByText('Attack Surface Intelligence')).toBeInTheDocument();
    expect(screen.getByText('MOD-01 (Phase 2)')).toBeInTheDocument();
    expect(screen.getByRole('button', { name: /overview/i })).toBeInTheDocument();
    expect(screen.getByRole('button', { name: /discovery center/i })).toBeInTheDocument();
    expect(screen.getByRole('button', { name: /active service discovery/i })).toBeInTheDocument();
    expect(screen.getByRole('button', { name: /discovered assets/i })).toBeInTheDocument();
    expect(screen.getByRole('button', { name: /findings/i })).toBeInTheDocument();
  });

  it('renders overview telemetry cards and deterministic scoring breakdown', async () => {
    render(
      <BrowserRouter>
        <AuthProvider>
          <AttackSurfacePage />
        </AuthProvider>
      </BrowserRouter>
    );

    expect(await screen.findByText('Discovered Domains')).toBeInTheDocument();
    expect(screen.getByText('Public IP Footprint')).toBeInTheDocument();
    expect(screen.getByText('Active Exposure Findings')).toBeInTheDocument();
    expect(screen.getByText('Exposure Risk Score')).toBeInTheDocument();
    expect(screen.getByText('Deterministic Risk Scoring Model (0–100 Scale)')).toBeInTheDocument();
    expect(screen.getByText('1. Perimeter Breadth & Sprawl')).toBeInTheDocument();
    expect(screen.getByText('4. Email Spoofing Defense')).toBeInTheDocument();
    expect(screen.getByText('5. Resource Takeover Indicators')).toBeInTheDocument();
  });

  it('switches to Discovery Center tab and displays form with mandatory authorization checkbox and policy selector', async () => {
    render(
      <BrowserRouter>
        <AuthProvider>
          <AttackSurfacePage />
        </AuthProvider>
      </BrowserRouter>
    );

    const discoveryTabBtn = await screen.findByRole('button', { name: /discovery center/i });
    fireEvent.click(discoveryTabBtn);

    expect(await screen.findByText('Initiate Authorized Passive Discovery')).toBeInTheDocument();
    expect(screen.getByText(/Discovery Policy/i)).toBeInTheDocument();
    expect(screen.getByText(/Mandatory Scope Confirmation:/i)).toBeInTheDocument();

    const submitBtn = screen.getByRole('button', { name: /launch passive discovery/i });
    // Initially disabled until checkbox confirmed
    expect(submitBtn).toBeDisabled();

    // Check confirmation checkbox
    const checkbox = screen.getByRole('checkbox', { name: /Mandatory Scope Confirmation/i });
    fireEvent.click(checkbox);
    expect(submitBtn).toBeEnabled();
  });

  it('switches to Discovered Assets and Findings tabs', async () => {
    render(
      <BrowserRouter>
        <AuthProvider>
          <AttackSurfacePage />
        </AuthProvider>
      </BrowserRouter>
    );

    // Discovered Assets tab
    const assetsTabBtn = await screen.findByRole('button', { name: /discovered assets/i });
    fireEvent.click(assetsTabBtn);
    expect(await screen.findByText('api.portal.smbclient.in')).toBeInTheDocument();
    expect(screen.getAllByText('portal.smbclient.in').length).toBeGreaterThan(0);

    // Findings tab
    const findingsTabBtn = screen.getByRole('button', { name: /findings/i });
    fireEvent.click(findingsTabBtn);
    expect(await screen.findByText('Missing SPF Record (Email Spoofing Risk)')).toBeInTheDocument();
    expect(screen.getByRole('button', { name: /view evidence/i })).toBeInTheDocument();
  });

  it('switches to Active Service Discovery tab, validates authorization checkbox, profiles, and services table', async () => {
    render(
      <BrowserRouter>
        <AuthProvider>
          <AttackSurfacePage />
        </AuthProvider>
      </BrowserRouter>
    );

    const activeTabBtn = await screen.findByRole('button', { name: /active service discovery/i });
    fireEvent.click(activeTabBtn);

    expect(await screen.findByText('Controlled Active Service Discovery Engine')).toBeInTheDocument();
    expect(screen.getByText('Mandatory Security Testing Authorization')).toBeInTheDocument();
    expect(screen.getByRole('button', { name: /BASIC/i })).toBeInTheDocument();
    expect(screen.getByRole('button', { name: /STANDARD/i })).toBeInTheDocument();
    expect(screen.getByRole('button', { name: /CUSTOM/i })).toBeInTheDocument();

    const submitBtn = screen.getByRole('button', { name: /launch active scan/i });
    expect(submitBtn).toBeDisabled();

    // Check authorization checkbox
    const checkbox = screen.getByRole('checkbox');
    fireEvent.click(checkbox);
    expect(submitBtn).toBeEnabled();

    // Verify discovered services table shows mocked service
    expect(screen.getByText('443 / tcp')).toBeInTheDocument();
    expect(screen.getByText('https')).toBeInTheDocument();
    expect(screen.getByText('Confirmed')).toBeInTheDocument();

    // Inspect service modal
    const inspectBtn = screen.getByRole('button', { name: /inspect/i });
    fireEvent.click(inspectBtn);
    expect(screen.getAllByText(/TLS Certificate Metadata/i).length).toBeGreaterThan(0);
    expect(screen.getAllByText(/HTTP Endpoint Telemetry/i).length).toBeGreaterThan(0);
  });
});
