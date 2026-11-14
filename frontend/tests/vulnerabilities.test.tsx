import { render, screen, fireEvent, waitFor } from '@testing-library/react';
import { describe, it, expect, vi, beforeEach } from 'vitest';
import { BrowserRouter } from 'react-router-dom';
import { VulnerabilitiesPage } from '@/pages/VulnerabilitiesPage';
import { AuthProvider } from '@/contexts/AuthContext';
import { vulnerabilityApi } from '@/services/vulnerabilityApi';

vi.mock('@/services/api', () => ({
  api: {
    get: vi.fn((url: string) => {
      if (url === '/assets') {
        return Promise.resolve({
          data: {
            items: [
              {
                id: 'asset-1',
                name: 'Web Server Alpha',
                target: 'web.alphacorp.in',
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

vi.mock('@/services/vulnerabilityApi', () => ({
  vulnerabilityApi: {
    getOverview: vi.fn(),
    listRecords: vi.fn(),
    getRecord: vi.fn(),
    updateStatus: vi.fn(),
    triggerScan: vi.fn(),
    listScanJobs: vi.fn(),
    getScanJob: vi.fn(),
    triggerFeedSync: vi.fn(),
    searchCveCatalog: vi.fn(),
    getCveDetail: vi.fn(),
  },
}));

describe('VulnerabilitiesPage Component (Phase 3)', () => {
  const mockOverview = {
    total_vulnerabilities: 4,
    critical_count: 2,
    high_count: 1,
    medium_count: 1,
    low_count: 0,
    info_count: 0,
    known_exploited_count: 2,
    average_risk_score: 88.5,
    unmitigated_count: 3,
    affected_assets_count: 2,
    last_scan_at: '2026-11-14T19:30:00Z',
    feed_last_updated_at: '2026-11-14T19:00:00Z',
  };

  const mockRecords = [
    {
      id: 'vuln-1',
      organization_id: 'org-1',
      asset_id: 'asset-1',
      asset_name: 'Web Server Alpha',
      asset_target: 'web.alphacorp.in',
      service_id: 'srv-1',
      service_port: 80,
      service_name: 'http',
      cve_id: 'CVE-2021-41773',
      title: 'Path Traversal in Apache HTTP Server 2.4.49',
      description: 'A flaw in path normalization in Apache 2.4.49 allows file mapping outside DocumentRoot.',
      severity: 'CRITICAL',
      confidence: 'CONFIRMED_MATCH',
      matched_cpe: 'cpe:2.3:a:apache:http_server:2.4.49',
      matched_service_name: 'http_server',
      matched_version: '2.4.49',
      risk_score: 90.6,
      prioritization_explanation: 'Actively exploited in wild (CISA KEV catalog). High EPSS exploit probability.',
      remediation_guidance: 'Upgrade Apache HTTP Server to version 2.4.51 or apply virtual patch.',
      status: 'DETECTED',
      is_known_exploited: true,
      epss_score: 0.9723,
      cvss_score: 7.5,
      created_at: '2026-11-14T19:25:00Z',
      updated_at: '2026-11-14T19:25:00Z',
    },
    {
      id: 'vuln-2',
      organization_id: 'org-1',
      asset_id: 'asset-1',
      asset_name: 'Web Server Alpha',
      service_port: 22,
      service_name: 'ssh',
      cve_id: 'CVE-2024-6387',
      title: 'regreSSHion in OpenSSH',
      description: 'Signal race condition RCE.',
      severity: 'HIGH',
      confidence: 'POTENTIAL_MATCH',
      matched_version: null,
      risk_score: 45.0,
      prioritization_explanation: 'Version unconfirmed from banner, 50% confidence discount.',
      remediation_guidance: 'Upgrade OpenSSH.',
      status: 'IN_TRIAGE',
      is_known_exploited: true,
      epss_score: 0.6841,
      cvss_score: 8.1,
      created_at: '2026-11-14T19:20:00Z',
      updated_at: '2026-11-14T19:20:00Z',
    },
  ];

  beforeEach(() => {
    vi.clearAllMocks();
    (vulnerabilityApi.getOverview as any).mockResolvedValue(mockOverview);
    (vulnerabilityApi.listRecords as any).mockResolvedValue({
      items: mockRecords,
      total: 2,
      skip: 0,
      limit: 100,
    });
    (vulnerabilityApi.searchCveCatalog as any).mockResolvedValue({
      items: [
        {
          id: 'cve-1',
          cve_id: 'CVE-2021-44228',
          description: 'Apache Log4j RCE',
          cvss_score: 10.0,
          severity: 'CRITICAL',
          is_known_exploited: true,
          epss_score: 0.9754,
          source: 'NVD+CISA_KEV+FIRST_EPSS',
        },
      ],
      total: 1,
      skip: 0,
      limit: 50,
    });
    (vulnerabilityApi.listScanJobs as any).mockResolvedValue([
      {
        id: 'job-1',
        organization_id: 'org-1',
        asset_id: null,
        status: 'COMPLETED',
        services_scanned_count: 5,
        vulnerabilities_found_count: 2,
        created_at: '2026-11-14T19:20:00Z',
      },
    ]);
  });

  const renderComponent = () =>
    render(
      <BrowserRouter>
        <AuthProvider>
          <VulnerabilitiesPage />
        </AuthProvider>
      </BrowserRouter>
    );

  it('renders page header and KPI overview summary cards', async () => {
    renderComponent();

    expect(screen.getByText(/Vulnerability Management & Mapping/i)).toBeInTheDocument();

    await waitFor(() => {
      expect(screen.getByText('88.5')).toBeInTheDocument();
      expect(screen.getByText('Total Findings')).toBeInTheDocument();
      expect(screen.getByText('Critical & High')).toBeInTheDocument();
      expect(screen.getByText('Known Exploited (KEV)')).toBeInTheDocument();
    });
  });

  it('renders vulnerability findings inventory table with badges and threat indicators', async () => {
    renderComponent();

    await waitFor(() => {
      expect(screen.getByText('CVE-2021-41773')).toBeInTheDocument();
      expect(screen.getByText('CVE-2024-6387')).toBeInTheDocument();
      expect(screen.getByText('CONFIRMED MATCH')).toBeInTheDocument();
      expect(screen.getByText('POTENTIAL MATCH')).toBeInTheDocument();
      expect(screen.getAllByText(/CISA KEV/i).length).toBeGreaterThan(0);
      expect(screen.getByText(/EPSS 97.2%/i)).toBeInTheDocument();
    });
  });

  it('opens slide-over drawer when Inspect button is clicked and displays evidence', async () => {
    renderComponent();

    await waitFor(() => {
      expect(screen.getAllByText('Inspect').length).toBeGreaterThan(0);
    });

    const inspectButtons = screen.getAllByText('Inspect');
    fireEvent.click(inspectButtons[0]);

    await waitFor(() => {
      expect(screen.getByText(/Contextual Risk Score/i)).toBeInTheDocument();
      expect(screen.getByText(/Observed Evidence & Match/i)).toBeInTheDocument();
      expect(screen.getByText(/cpe:2.3:a:apache:http_server:2.4.49/i)).toBeInTheDocument();
      expect(screen.getByText(/Remediation Guidance/i)).toBeInTheDocument();
      expect(screen.getByText(/Save Status & Log Audit Event/i)).toBeInTheDocument();
    });
  });

  it('updates triage status and calls API', async () => {
    (vulnerabilityApi.updateStatus as any).mockResolvedValue({
      ...mockRecords[0],
      status: 'IN_TRIAGE',
    });

    renderComponent();

    await waitFor(() => {
      expect(screen.getAllByText('Inspect').length).toBeGreaterThan(0);
    });

    fireEvent.click(screen.getAllByText('Inspect')[0]);

    await waitFor(() => {
      expect(screen.getByText(/Save Status & Log Audit Event/i)).toBeInTheDocument();
    });

    const saveButton = screen.getByText(/Save Status & Log Audit Event/i);
    fireEvent.click(saveButton);

    await waitFor(() => {
      expect(vulnerabilityApi.updateStatus).toHaveBeenCalledWith('vuln-1', 'DETECTED', '');
    });
  });

  it('switches to CVE Threat Catalog tab and displays catalog items', async () => {
    renderComponent();

    const catalogTab = screen.getByRole('button', { name: /CVE Threat Catalog/i });
    fireEvent.click(catalogTab);

    await waitFor(() => {
      expect(vulnerabilityApi.searchCveCatalog).toHaveBeenCalled();
      expect(screen.getByText('CVE-2021-44228')).toBeInTheDocument();
      expect(screen.getByText('Apache Log4j RCE')).toBeInTheDocument();
    });
  });

  it('opens scan launch modal and triggers scan', async () => {
    (vulnerabilityApi.triggerScan as any).mockResolvedValue({
      id: 'job-new',
      status: 'PENDING',
      services_scanned_count: 0,
      vulnerabilities_found_count: 0,
      created_at: new Date().toISOString(),
    });

    renderComponent();

    const runScanButton = screen.getByRole('button', { name: /Run Vulnerability Scan/i });
    fireEvent.click(runScanButton);

    await waitFor(() => {
      expect(screen.getByText(/Execute Vulnerability Mapping/i)).toBeInTheDocument();
      expect(screen.getByRole('button', { name: /Initiate Mapping Scan/i })).toBeInTheDocument();
    });

    const initiateButton = screen.getByRole('button', { name: /Initiate Mapping Scan/i });
    fireEvent.click(initiateButton);

    await waitFor(() => {
      expect(vulnerabilityApi.triggerScan).toHaveBeenCalled();
    });
  });
});
