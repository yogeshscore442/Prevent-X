import { render, screen, fireEvent, waitFor } from '@testing-library/react';
import { describe, it, expect, vi, beforeEach } from 'vitest';
import { BrowserRouter } from 'react-router-dom';
import { AttackPathsPage } from '@/pages/AttackPathsPage';
import { attackPathApi } from '@/services/attackPathApi';

vi.mock('@/services/api', () => ({
  api: {
    get: vi.fn((url: string) => {
      if (url === '/assets') {
        return Promise.resolve({
          data: [
            {
              id: 'asset-1',
              name: 'Public Portal',
              target: 'portal.smbclient.in',
              criticality: 'MEDIUM',
              asset_type: 'WEB_APPLICATION',
              is_in_scope: true,
            },
            {
              id: 'asset-2',
              name: 'Core Database',
              target: '192.168.1.10',
              criticality: 'CRITICAL',
              asset_type: 'INTERNAL_SERVER',
              is_in_scope: true,
            },
          ],
        });
      }
      return Promise.resolve({ data: {} });
    }),
    post: vi.fn(),
    patch: vi.fn(),
    delete: vi.fn(),
    interceptors: {
      request: { use: vi.fn() },
      response: { use: vi.fn() },
    },
  },
}));

vi.mock('@/services/attackPathApi', () => ({
  attackPathApi: {
    getOverview: vi.fn(),
    listPaths: vi.fn(),
    getPath: vi.fn(),
    updatePathStatus: vi.fn(),
    triggerAnalysis: vi.fn(),
    listRecommendations: vi.fn(),
    updateRecommendationStatus: vi.fn(),
    listTrustRelationships: vi.fn(),
    createTrustRelationship: vi.fn(),
    deleteTrustRelationship: vi.fn(),
  },
}));

describe('AttackPathsPage Component (Phase 4)', () => {
  const mockOverview = {
    total_paths: 3,
    critical_paths: 1,
    high_paths: 1,
    medium_paths: 1,
    low_paths: 0,
    entry_points_count: 2,
    crown_jewels_at_risk_count: 1,
    average_risk_score: 74.5,
    total_recommendations: 5,
    implemented_recommendations: 2,
    top_mitre_tactics: [
      { tactic: 'Initial Access', count: 3 },
      { tactic: 'Lateral Movement', count: 2 },
      { tactic: 'Impact', count: 3 },
    ],
  };

  const mockPaths = [
    {
      id: 'path-uuid-1',
      organization_id: 'org-uuid',
      name: 'PATH-Public_Portal-TO-Core_Database',
      title: 'Lateral Pivoting: Public Portal \u2192 Core Database',
      description: 'Attack chain originating at Public Portal reaching critical Core Database',
      severity: 'CRITICAL' as const,
      confidence: 'CONFIRMED' as const,
      step_count: 2,
      risk_score: 87.5,
      status: 'IDENTIFIED' as const,
      entry_point_asset_id: 'asset-1',
      target_asset_id: 'asset-2',
      entry_point_asset_name: 'Public Portal',
      target_asset_name: 'Core Database',
      target_asset_criticality: 'CRITICAL',
      path_narrative: '1. Adversary exploits T1190 on Public Portal.\n2. Lateral pivot via DATABASE_LINK to Core Database.',
      graph_data: {
        nodes: [
          {
            id: 'asset-1',
            name: 'Public Portal',
            asset_type: 'WEB_APPLICATION',
            criticality: 'MEDIUM',
            is_entry_point: true,
            is_crown_jewel: false,
            technologies: ['Apache', 'PHP'],
            vulnerabilities_count: 1,
          },
          {
            id: 'asset-2',
            name: 'Core Database',
            asset_type: 'INTERNAL_SERVER',
            criticality: 'CRITICAL',
            is_entry_point: false,
            is_crown_jewel: true,
            technologies: ['PostgreSQL'],
            vulnerabilities_count: 0,
          },
        ],
        edges: [
          {
            source: 'asset-1',
            target: 'asset-2',
            hop_type: 'DATABASE_LINK',
            port: 5432,
            mitre_technique: 'Exploitation of Remote Services',
            mitre_technique_id: 'T1210',
            evidence_source: 'EXPLICIT_TRUST_RELATIONSHIP',
            justification: 'Application holds direct connection credentials to database.',
          },
        ],
      },
      mitre_tactics: ['Initial Access', 'Lateral Movement', 'Impact'],
      mitre_techniques: [
        {
          id: 'T1190',
          name: 'Exploit Public-Facing Application',
          tactic_id: 'TA0001',
          tactic: 'Initial Access',
          description: 'Adversary exploits Internet-facing web application.',
        },
        {
          id: 'T1210',
          name: 'Exploitation of Remote Services',
          tactic_id: 'TA0008',
          tactic: 'Lateral Movement',
          description: 'Adversary leverages remote database services.',
        },
      ],
      prerequisites: ['Internet-routable IP address', 'Database route on port 5432'],
      evidence_references: ['SERVICE:443/apache', 'TRUST:DATABASE_LINK'],
      recommendations_count: 2,
      created_at: new Date().toISOString(),
      updated_at: new Date().toISOString(),
    },
  ];

  const mockRecommendations = [
    {
      id: 'rec-1',
      organization_id: 'org-uuid',
      attack_path_id: 'path-uuid-1',
      attack_path_title: 'Lateral Pivoting: Public Portal \u2192 Core Database',
      target_asset_id: 'asset-1',
      target_asset_name: 'Public Portal',
      title: 'Deploy Virtual Patch Rule for CVE-2023-38606',
      category: 'VIRTUAL_PATCH' as const,
      description: 'Deploy WAF inspection rule to block exploit attempts targeting Public Portal.',
      risk_reduction: 'HIGH' as const,
      implementation_complexity: 'LOW' as const,
      smb_operational_impact: 'MINIMAL' as const,
      priority_rank: 1,
      mitre_technique_id: 'T1190',
      status: 'PROPOSED' as const,
      created_at: new Date().toISOString(),
      updated_at: new Date().toISOString(),
    },
  ];

  const mockTrustLinks = [
    {
      id: 'trust-1',
      organization_id: 'org-uuid',
      source_asset_id: 'asset-1',
      target_asset_id: 'asset-2',
      source_asset_name: 'Public Portal',
      target_asset_name: 'Core Database',
      relationship_type: 'DATABASE_LINK',
      port: 5432,
      evidence_source: 'MANUAL_VERIFIED',
      is_verified: true,
      created_at: new Date().toISOString(),
      updated_at: new Date().toISOString(),
    },
  ];

  beforeEach(() => {
    vi.clearAllMocks();
    (attackPathApi.getOverview as any).mockResolvedValue(mockOverview);
    (attackPathApi.listPaths as any).mockResolvedValue({ total: 1, items: mockPaths });
    (attackPathApi.listRecommendations as any).mockResolvedValue({
      total: 1,
      items: mockRecommendations,
    });
    (attackPathApi.listTrustRelationships as any).mockResolvedValue(mockTrustLinks);
  });

  it('renders overview KPI cards correctly', async () => {
    render(
      <BrowserRouter>
        <AttackPathsPage />
      </BrowserRouter>
    );

    await waitFor(() => {
      expect(screen.getByText('AI Attack Path & Prevention Engine')).toBeInTheDocument();
      expect(screen.getByText('MOD-03')).toBeInTheDocument();
    });

    expect(screen.getByText('Total Attack Paths')).toBeInTheDocument();
    expect(screen.getByText('Critical Paths')).toBeInTheDocument();
    expect(screen.getByText('Crown Jewels at Risk')).toBeInTheDocument();
    expect(screen.getByText('Compensating Controls')).toBeInTheDocument();
  });

  it('displays attack paths and inspects details', async () => {
    render(
      <BrowserRouter>
        <AttackPathsPage />
      </BrowserRouter>
    );

    await waitFor(() => {
      expect(
        screen.getAllByText('Lateral Pivoting: Public Portal → Core Database').length
      ).toBeGreaterThan(0);
    });

    // Verify badges
    expect(screen.getAllByText('CRITICAL').length).toBeGreaterThan(0);
    expect(screen.getAllByText('CONFIRMED').length).toBeGreaterThan(0);

    // Verify visual graph components
    expect(screen.getByText('Evidence-Backed Attack Graph Visualizer')).toBeInTheDocument();
    expect(screen.getByText('Step-by-Step Kill-Chain Narrative')).toBeInTheDocument();
    expect(screen.getByText('T1190')).toBeInTheDocument();
    expect(screen.getByText('Exploit Public-Facing Application')).toBeInTheDocument();
  });

  it('switches to Prevention Recommendations tab', async () => {
    render(
      <BrowserRouter>
        <AttackPathsPage />
      </BrowserRouter>
    );

    await waitFor(() => {
      expect(screen.getByText(/Prevention Recommendations/i)).toBeInTheDocument();
    });

    const recsTab = screen.getByText(/Prevention Recommendations/i);
    fireEvent.click(recsTab);

    await waitFor(() => {
      expect(screen.getByText('Deploy Virtual Patch Rule for CVE-2023-38606')).toBeInTheDocument();
      expect(screen.getByText('VIRTUAL PATCH')).toBeInTheDocument();
      expect(screen.getByText('#1')).toBeInTheDocument();
    });
  });

  it('switches to Trust Relationships tab', async () => {
    render(
      <BrowserRouter>
        <AttackPathsPage />
      </BrowserRouter>
    );

    await waitFor(() => {
      expect(screen.getByText(/Asset Trust Relationships/i)).toBeInTheDocument();
    });

    const trustTab = screen.getByText(/Asset Trust Relationships/i);
    fireEvent.click(trustTab);

    await waitFor(() => {
      expect(screen.getByText('DATABASE_LINK')).toBeInTheDocument();
      expect(screen.getByText('5432')).toBeInTheDocument();
    });
  });
});
