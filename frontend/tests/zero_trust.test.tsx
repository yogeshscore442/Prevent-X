import { render, screen, fireEvent, waitFor } from '@testing-library/react';
import { describe, it, expect, vi, beforeEach } from 'vitest';
import { BrowserRouter } from 'react-router-dom';
import { ZeroTrustPage } from '@/pages/ZeroTrustPage';
import { zeroTrustApi } from '@/services/zeroTrustApi';

vi.mock('@/services/zeroTrustApi', () => ({
  zeroTrustApi: {
    getOverview: vi.fn(),
    listAssessments: vi.fn(),
    evaluatePosture: vi.fn(),
    listThreatIndicators: vi.fn(),
    syncThreatFeed: vi.fn(),
    correlateThreats: vi.fn(),
    listThreatCorrelations: vi.fn(),
    listAnomalies: vi.fn(),
    detectAnomalies: vi.fn(),
    updateAnomalyStatus: vi.fn(),
    listResponseActions: vi.fn(),
    approveResponseAction: vi.fn(),
    rejectResponseAction: vi.fn(),
    executeResponseAction: vi.fn(),
    rollbackResponseAction: vi.fn(),
  },
}));

describe('ZeroTrustPage Component (Phase 5)', () => {
  const mockOverview = {
    total_assets: 4,
    trusted_count: 1,
    restricted_count: 1,
    untrusted_count: 1,
    insufficient_evidence_count: 1,
    average_trust_score: 56.5,
    active_threat_indicators: 5,
    correlated_threats_count: 1,
    active_anomalies_count: 2,
    zero_day_indicators_count: 1,
    pending_approval_actions: 1,
    executed_actions: 1,
  };

  const mockAssessments = [
    {
      id: 'ass-1',
      organization_id: 'org-1',
      asset_id: 'asset-1',
      asset_name: 'Secure Web Gateway',
      asset_target: 'gateway.smb.in',
      asset_type: 'WEB_APPLICATION',
      asset_criticality: 'HIGH',
      trust_decision: 'TRUSTED',
      trust_score: 85.0,
      positive_factors: [
        {
          category: 'TRANSPORT_SECURITY',
          factor: 'Valid TLS 1.3 certificate',
          impact: 'POSITIVE',
          score_delta: 15.0,
          description: 'Transport is strongly encrypted.',
        },
      ],
      risk_factors: [],
      least_privilege_recommendations: ['Enforce micro-segmentation'],
      decision_reason: 'Asset is positively verified and classified TRUSTED.',
      last_evaluated_at: new Date().toISOString(),
      is_stale: false,
      created_at: new Date().toISOString(),
      updated_at: new Date().toISOString(),
    },
    {
      id: 'ass-2',
      organization_id: 'org-1',
      asset_id: 'asset-2',
      asset_name: 'Compromised Host',
      asset_target: 'c2.internal.lan',
      asset_type: 'INTERNAL_SERVER',
      asset_criticality: 'CRITICAL',
      trust_decision: 'UNTRUSTED',
      trust_score: 15.0,
      positive_factors: [],
      risk_factors: [
        {
          category: 'THREAT_INTELLIGENCE',
          factor: 'Active C2 correlation',
          impact: 'NEGATIVE',
          score_delta: -50.0,
          description: 'Matched known APT indicator.',
        },
      ],
      least_privilege_recommendations: ['Isolate immediately'],
      decision_reason: 'Asset is classified UNTRUSTED due to C2 IOC match.',
      last_evaluated_at: new Date().toISOString(),
      is_stale: false,
      created_at: new Date().toISOString(),
      updated_at: new Date().toISOString(),
    },
  ];

  const mockThreatIndicators = [
    {
      id: 'threat-1',
      indicator_type: 'IP',
      indicator_value: '198.51.100.24',
      confidence: 90,
      source: 'CERT-In Threat Feed',
      threat_actor: 'APT-PhishStorm',
      description: 'Known C2 beacon listener',
      severity: 'CRITICAL',
      tlp: 'WHITE',
      is_active: true,
      expires_at: new Date(Date.now() + 86400000).toISOString(),
      mitre_tactics: ['Command and Control'],
      mitre_techniques: ['T1071'],
      tags: ['c2', 'cert-in'],
      is_expired: false,
      created_at: new Date().toISOString(),
      updated_at: new Date().toISOString(),
    },
  ];

  const mockCorrelations = [
    {
      id: 'corr-1',
      organization_id: 'org-1',
      threat_intel_id: 'threat-1',
      asset_id: 'asset-2',
      asset_name: 'Compromised Host',
      asset_target: 'c2.internal.lan',
      threat_indicator: '198.51.100.24',
      threat_type: 'IP',
      correlation_type: 'SERVICE_IP_MATCH',
      matched_value: '198.51.100.24:8080',
      severity: 'CRITICAL',
      confidence: 95,
      details: 'Matches active APT-PhishStorm C2 infrastructure.',
      status: 'ACTIVE',
      created_at: new Date().toISOString(),
      updated_at: new Date().toISOString(),
    },
  ];

  const mockAnomalies = [
    {
      id: 'anom-1',
      organization_id: 'org-1',
      asset_id: 'asset-2',
      asset_name: 'Compromised Host',
      asset_target: 'c2.internal.lan',
      anomaly_type: 'UNKNOWN_PROTOCOL_PAYLOAD',
      severity: 'CRITICAL',
      confidence: 'CONFIRMED',
      anomaly_score: 92.0,
      description: 'Unmapped binary exploit payload detected on port 8080.',
      evidence_data: { service_port: 8080, payload: 'NOP_SLED_BINARY' },
      status: 'OPEN',
      is_zero_day_indicator: true,
      created_at: new Date().toISOString(),
      updated_at: new Date().toISOString(),
    },
  ];

  const mockResponseActions = [
    {
      id: 'act-1',
      organization_id: 'org-1',
      asset_id: 'asset-2',
      asset_name: 'Compromised Host',
      action_type: 'NETWORK_ISOLATION',
      title: 'Quarantine Asset from Subnet',
      description: 'Isolate compromised host to contain lateral movement.',
      target_entity: 'c2.internal.lan',
      execution_payload: { rule: 'DROP ALL' },
      rollback_payload: { rule: 'RESTORE ALL' },
      status: 'PENDING_APPROVAL' as const,
      is_disruptive: true,
      created_at: new Date().toISOString(),
      updated_at: new Date().toISOString(),
    },
    {
      id: 'act-2',
      organization_id: 'org-1',
      asset_id: 'asset-1',
      asset_name: 'Secure Web Gateway',
      action_type: 'INCREASE_TELEMETRY_LOGGING',
      title: 'Elevate Logging Verbosity',
      description: 'Set logging level to DEBUG.',
      target_entity: 'TELEMETRY_SUBSYSTEM',
      execution_payload: { log_level: 'DEBUG' },
      status: 'EXECUTED' as const,
      is_disruptive: false,
      executed_at: new Date().toISOString(),
      created_at: new Date().toISOString(),
      updated_at: new Date().toISOString(),
    },
  ];

  beforeEach(() => {
    vi.clearAllMocks();
    vi.mocked(zeroTrustApi.getOverview).mockResolvedValue(mockOverview);
    vi.mocked(zeroTrustApi.listAssessments).mockResolvedValue(mockAssessments);
    vi.mocked(zeroTrustApi.listThreatIndicators).mockResolvedValue(mockThreatIndicators);
    vi.mocked(zeroTrustApi.listThreatCorrelations).mockResolvedValue(mockCorrelations);
    vi.mocked(zeroTrustApi.listAnomalies).mockResolvedValue(mockAnomalies);
    vi.mocked(zeroTrustApi.listResponseActions).mockResolvedValue(mockResponseActions);
  });

  it('renders Zero Trust dashboard overview KPIs correctly', async () => {
    render(
      <BrowserRouter>
        <ZeroTrustPage />
      </BrowserRouter>
    );

    await waitFor(() => {
      expect(screen.getByText('Zero Trust & Zero-Day Resilience Engine')).toBeInTheDocument();
      expect(screen.getByText('56.5')).toBeInTheDocument(); // Avg trust score
      expect(screen.getByText('Trusted Assets')).toBeInTheDocument();
      expect(screen.getByText('Zero-Day Signals')).toBeInTheDocument();
      expect(screen.getByText('Pending Approval')).toBeInTheDocument();
    });
  });

  it('displays asset trust evaluations with score and status badges', async () => {
    render(
      <BrowserRouter>
        <ZeroTrustPage />
      </BrowserRouter>
    );

    await waitFor(() => {
      expect(screen.getByText('Secure Web Gateway')).toBeInTheDocument();
      expect(screen.getByText('Compromised Host')).toBeInTheDocument();
      expect(screen.getAllByText('TRUSTED').length).toBeGreaterThan(0);
      expect(screen.getAllByText('UNTRUSTED').length).toBeGreaterThan(0);
    });
  });

  it('inspects asset posture modal with positive/risk factors and recommendations', async () => {
    render(
      <BrowserRouter>
        <ZeroTrustPage />
      </BrowserRouter>
    );

    await waitFor(() => {
      expect(screen.getAllByText('Inspect Posture').length).toBeGreaterThan(0);
    });

    fireEvent.click(screen.getAllByText('Inspect Posture')[0]);

    await waitFor(() => {
      expect(screen.getByText(/Trust Assessment: Secure Web Gateway/)).toBeInTheDocument();
      expect(screen.getByText(/Valid TLS 1.3 certificate/)).toBeInTheDocument();
      expect(screen.getByText(/Enforce micro-segmentation/)).toBeInTheDocument();
    });
  });

  it('navigates to Threat Intelligence tab and renders correlations and indicators', async () => {
    render(
      <BrowserRouter>
        <ZeroTrustPage />
      </BrowserRouter>
    );

    await waitFor(() => {
      expect(screen.getByText(/Threat Intelligence & Correlations/)).toBeInTheDocument();
    });

    fireEvent.click(screen.getByText(/Threat Intelligence & Correlations/));

    await waitFor(() => {
      expect(screen.getAllByText('198.51.100.24').length).toBeGreaterThan(0);
      expect(screen.getAllByText(/APT-PhishStorm/).length).toBeGreaterThan(0);
      expect(screen.getByText('SERVICE_IP_MATCH')).toBeInTheDocument();
    });
  });

  it('navigates to Behavioral & Zero-Day Alerts tab and displays zero-day indicator badge', async () => {
    render(
      <BrowserRouter>
        <ZeroTrustPage />
      </BrowserRouter>
    );

    await waitFor(() => {
      expect(screen.getByText(/Behavioral & Zero-Day Alerts/)).toBeInTheDocument();
    });

    fireEvent.click(screen.getByText(/Behavioral & Zero-Day Alerts/));

    await waitFor(() => {
      expect(screen.getByText('ZERO-DAY RESILIENCE')).toBeInTheDocument();
      expect(screen.getByText('UNKNOWN_PROTOCOL_PAYLOAD')).toBeInTheDocument();
      expect(screen.getByText(/Unmapped binary exploit payload detected/)).toBeInTheDocument();
    });
  });

  it('navigates to Automated Response Actions tab and verifies approval gate workflow', async () => {
    vi.mocked(zeroTrustApi.approveResponseAction).mockResolvedValue({ status: 'APPROVED' });

    render(
      <BrowserRouter>
        <ZeroTrustPage />
      </BrowserRouter>
    );

    await waitFor(() => {
      expect(screen.getByText(/Automated Response Actions/)).toBeInTheDocument();
    });

    fireEvent.click(screen.getByText(/Automated Response Actions/));

    await waitFor(() => {
      expect(screen.getByText(/Strict Human Authorization Gate Active/)).toBeInTheDocument();
      expect(screen.getByText('Quarantine Asset from Subnet')).toBeInTheDocument();
      expect(screen.getByText('DISRUPTIVE')).toBeInTheDocument();
      expect(screen.getAllByText('PENDING_APPROVAL').length).toBeGreaterThan(0);
      expect(screen.getByText('Approve')).toBeInTheDocument();
    });

    // Test clicking Approve
    fireEvent.click(screen.getByText('Approve'));

    await waitFor(() => {
      expect(zeroTrustApi.approveResponseAction).toHaveBeenCalledWith('act-1');
    });
  });
});
