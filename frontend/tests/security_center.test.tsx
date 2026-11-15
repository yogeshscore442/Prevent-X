import { render, screen, fireEvent, waitFor } from '@testing-library/react';
import { describe, it, expect, vi, beforeEach } from 'vitest';
import { BrowserRouter } from 'react-router-dom';
import { SecurityCenterPage } from '@/pages/SecurityCenterPage';
import { monitoringApi } from '@/services/monitoringApi';

// Mock EventSource
class MockEventSource {
  url: string;
  onopen: (() => void) | null = null;
  onerror: (() => void) | null = null;
  listeners: Record<string, ((e: any) => void)[]> = {};

  constructor(url: string) {
    this.url = url;
    setTimeout(() => {
      if (this.onopen) this.onopen();
    }, 10);
  }

  addEventListener(event: string, cb: (e: any) => void) {
    if (!this.listeners[event]) this.listeners[event] = [];
    this.listeners[event].push(cb);
  }

  removeEventListener(event: string, cb: (e: any) => void) {
    if (this.listeners[event]) {
      this.listeners[event] = this.listeners[event].filter((c) => c !== cb);
    }
  }

  close() {
    this.listeners = {};
  }
}

(global as any).EventSource = MockEventSource;

vi.mock('@/services/monitoringApi', () => ({
  monitoringApi: {
    getOverview: vi.fn(),
    getEvents: vi.fn(),
    getIncidents: vi.fn(),
    getIncidentDetail: vi.fn(),
    createIncident: vi.fn(),
    updateIncident: vi.fn(),
    addIncidentNote: vi.fn(),
    executeContainment: vi.fn(),
    getAlerts: vi.fn(),
    acknowledgeAlert: vi.fn(),
    getRetentionPolicy: vi.fn(),
    updateRetentionPolicy: vi.fn(),
    pruneEventsNow: vi.fn(),
    getSSEUrl: vi.fn().mockReturnValue('/api/v1/monitoring/events/stream'),
  },
}));

describe('SecurityCenterPage Component (Phase 8)', () => {
  const mockOverview = {
    security_score: 88,
    security_grade: 'A',
    open_incidents_total: 2,
    critical_incidents_count: 1,
    high_incidents_count: 1,
    medium_incidents_count: 0,
    events_24h_count: 1420,
    waf_blocked_24h: 312,
    waf_allowed_24h: 1108,
    exposed_assets_count: 5,
    active_virtual_patches_count: 8,
    trust_distribution: {
      TRUSTED: 3,
      RESTRICTED: 1,
      UNTRUSTED: 1,
    },
    recent_rollbacks_count: 0,
    validation_failures_24h: 0,
    unacknowledged_alerts_count: 1,
  };

  const mockIncidents = [
    {
      id: 'inc-11111111-2222-3333-4444-555555555555',
      incident_number: 'INC-202611-0001',
      organization_id: 'org-1',
      title: 'Repeated SQL Injection Probing against Payment Service',
      description: 'Hostile actor attempting sql injection queries from 198.51.100.22',
      severity: 'CRITICAL',
      status: 'OPEN',
      source: 'CORRELATION_ENGINE',
      primary_asset_id: 'asset-1',
      mitre_attack_id: 'T1190',
      mitre_technique: 'Exploit Public-Facing Application',
      recommended_action: 'Block source IP at WAF and deploy virtual patch.',
      containment_action_taken: undefined,
      containment_requires_approval: true,
      containment_approved_by: undefined,
      containment_executed_at: undefined,
      assigned_user_id: undefined,
      iocs: { source_ip: '198.51.100.22' },
      first_seen_at: new Date().toISOString(),
      last_seen_at: new Date().toISOString(),
      created_at: new Date().toISOString(),
      updated_at: new Date().toISOString(),
    },
  ];

  const mockEvents = [
    {
      id: 'ev-11111111-2222-3333-4444-555555555555',
      organization_id: 'org-1',
      source: 'WAF_ENFORCEMENT',
      category: 'SECURITY',
      severity: 'CRITICAL',
      confidence: 1.0,
      title: 'Virtual Patch Blocked SQL Injection Pattern',
      description: 'Blocked hostile query parameter union select',
      source_ip: '198.51.100.22',
      target_uri: '/api/v1/checkout',
      http_method: 'GET',
      status_code: 403,
      fingerprint: 'abcd1234efgh5678',
      raw_payload: 'q=UNION+SELECT+1,2,3',
      is_correlated: true,
      timestamp: new Date().toISOString(),
      created_at: new Date().toISOString(),
    },
  ];

  const mockAlerts = [
    {
      id: 'al-11111111-2222-3333-4444-555555555555',
      organization_id: 'org-1',
      title: 'WAF Block Rate Spike Detected',
      message: 'Sudden spike of 50+ WAF blocks in 5 minutes.',
      category: 'WAF_BLOCK_SPIKE',
      severity: 'HIGH',
      is_acknowledged: false,
      created_at: new Date().toISOString(),
    },
  ];

  const mockRetention = {
    id: 'ret-1',
    organization_id: 'org-1',
    retention_days: 30,
    max_stored_events: 50000,
    auto_prune_enabled: true,
    last_pruned_at: new Date().toISOString(),
    created_at: new Date().toISOString(),
    updated_at: new Date().toISOString(),
  };

  beforeEach(() => {
    vi.clearAllMocks();
    vi.mocked(monitoringApi.getOverview).mockResolvedValue(mockOverview);
    vi.mocked(monitoringApi.getIncidents).mockResolvedValue({
      items: mockIncidents,
      total: 1,
      page: 1,
      size: 50,
    });
    vi.mocked(monitoringApi.getEvents).mockResolvedValue({
      items: mockEvents,
      total: 1,
      page: 1,
      size: 100,
    });
    vi.mocked(monitoringApi.getAlerts).mockResolvedValue(mockAlerts);
    vi.mocked(monitoringApi.getRetentionPolicy).mockResolvedValue(mockRetention);
  });

  it('renders executive posture score and core KPI cards correctly', async () => {
    render(
      <BrowserRouter>
        <SecurityCenterPage />
      </BrowserRouter>
    );

    await waitFor(() => {
      expect(screen.getByText('Centralized Security Center')).toBeInTheDocument();
    });

    // Verify Posture Score and Grade
    expect(screen.getByText('88')).toBeInTheDocument();
    expect(screen.getByText(/Grade A/i)).toBeInTheDocument();

    // Verify KPI counters
    expect(screen.getByText('1,420')).toBeInTheDocument();
    expect(screen.getByText('312')).toBeInTheDocument();
    expect(screen.getByText('1 Critical')).toBeInTheDocument();
  });

  it('navigates to Live Security Events tab and shows event table', async () => {
    render(
      <BrowserRouter>
        <SecurityCenterPage />
      </BrowserRouter>
    );

    await waitFor(() => {
      expect(screen.getByText('Live Security Events')).toBeInTheDocument();
    });

    fireEvent.click(screen.getByText('Live Security Events'));

    await waitFor(() => {
      expect(screen.getByText('Virtual Patch Blocked SQL Injection Pattern')).toBeInTheDocument();
      expect(screen.getByText('198.51.100.22')).toBeInTheDocument();
      expect(screen.getByText('/api/v1/checkout')).toBeInTheDocument();
    });
  });

  it('navigates to Correlated Incidents tab and handles selection', async () => {
    vi.mocked(monitoringApi.getIncidentDetail).mockResolvedValue({
      ...mockIncidents[0],
      timeline_entries: [
        {
          id: 'tl-1',
          incident_id: mockIncidents[0].id,
          organization_id: 'org-1',
          entry_type: 'SYSTEM_EVENT',
          message: 'Automated correlation matched 3 attacks in 10 minutes',
          created_at: new Date().toISOString(),
        },
      ],
      events: mockEvents,
    });

    render(
      <BrowserRouter>
        <SecurityCenterPage />
      </BrowserRouter>
    );

    await waitFor(() => {
      expect(screen.getByText('Correlated Incidents')).toBeInTheDocument();
    });

    fireEvent.click(screen.getByText('Correlated Incidents'));

    await waitFor(() => {
      expect(screen.getByText('INC-202611-0001')).toBeInTheDocument();
      expect(screen.getByText('T1190')).toBeInTheDocument();
    });

    // Click on incident row
    fireEvent.click(screen.getByText('INC-202611-0001'));

    await waitFor(() => {
      expect(monitoringApi.getIncidentDetail).toHaveBeenCalledWith(mockIncidents[0].id);
      expect(screen.getByText(/Automated correlation matched 3 attacks/i)).toBeInTheDocument();
      expect(screen.getByText('Containment Workflow')).toBeInTheDocument();
    });
  });

  it('navigates to Alerts & Retention tab and acknowledges alert', async () => {
    vi.mocked(monitoringApi.acknowledgeAlert).mockResolvedValue({
      ...mockAlerts[0],
      is_acknowledged: true,
      acknowledged_at: new Date().toISOString(),
    });

    render(
      <BrowserRouter>
        <SecurityCenterPage />
      </BrowserRouter>
    );

    await waitFor(() => {
      expect(screen.getByText('In-App Alerts & Retention')).toBeInTheDocument();
    });

    fireEvent.click(screen.getByText('In-App Alerts & Retention'));

    await waitFor(() => {
      expect(screen.getByText('WAF Block Rate Spike Detected')).toBeInTheDocument();
      expect(screen.getByText('Acknowledge')).toBeInTheDocument();
    });

    fireEvent.click(screen.getByText('Acknowledge'));

    await waitFor(() => {
      expect(monitoringApi.acknowledgeAlert).toHaveBeenCalledWith(mockAlerts[0].id);
      expect(screen.getByText(/Alert acknowledged/i)).toBeInTheDocument();
    });
  });
});
