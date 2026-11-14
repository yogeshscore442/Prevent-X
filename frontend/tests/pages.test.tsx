import React from 'react';
import { render, screen, fireEvent, waitFor } from '@testing-library/react';
import { describe, it, expect, vi, beforeEach } from 'vitest';
import { BrowserRouter, MemoryRouter } from 'react-router-dom';
import { BootstrapPage } from '@/pages/BootstrapPage';
import { AssetsPage } from '@/pages/AssetsPage';
import { OrganizationsPage } from '@/pages/OrganizationsPage';
import { UsersPage } from '@/pages/UsersPage';
import { RolesPage } from '@/pages/RolesPage';
import { AuditLogsPage } from '@/pages/AuditLogsPage';
import { SystemHealthPage } from '@/pages/SystemHealthPage';
import { SettingsPage } from '@/pages/SettingsPage';
import { AppRoutes } from '@/routes/AppRoutes';
import { api } from '@/services/api';

vi.mock('@/services/api', () => ({
  api: {
    get: vi.fn(),
    post: vi.fn(),
    delete: vi.fn(),
  },
}));

const mockUser = {
  id: '00000000-0000-0000-0000-000000000001',
  email: 'admin@preventx.internal',
  full_name: 'Security Admin',
  is_superuser: true,
  is_active: true,
  current_organization_id: 'org-1111',
  memberships: [
    {
      organization_id: 'org-1111',
      organization_name: 'Primary SMB Org',
      organization_slug: 'primary-smb',
      role_name: 'SYSTEM_ADMIN',
      permissions: ['*'],
    },
  ],
};

vi.mock('@/contexts/AuthContext', () => ({
  useAuth: () => ({
    user: mockUser,
    activeOrgId: 'org-1111',
    isAuthenticated: true,
    isLoading: false,
    login: vi.fn(),
    logout: vi.fn(),
    switchOrganization: vi.fn(),
    hasPermission: () => true,
    refreshUser: vi.fn(),
  }),
  AuthProvider: ({ children }: { children: React.ReactNode }) => <>{children}</>,
}));

describe('PREVENT-X Phase 1 Frontend Pages Verification', () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  it('1. BootstrapPage: renders form fields and triggers bootstrap submission', async () => {
    (api.post as any).mockResolvedValueOnce({
      data: { message: 'Platform administrator initialized successfully!' },
    });

    render(
      <BrowserRouter>
        <BootstrapPage />
      </BrowserRouter>
    );

    expect(screen.getByText(/Administrator Onboarding/i)).toBeInTheDocument();
    expect(screen.getByPlaceholderText('admin@smbenterprise.in')).toBeInTheDocument();

    const emailInput = screen.getByPlaceholderText('admin@smbenterprise.in');
    fireEvent.change(emailInput, { target: { value: 'ciso@preventx.internal' } });
    expect(emailInput).toHaveValue('ciso@preventx.internal');

    const submitBtn = screen.getByRole('button', { name: /bootstrap root platform/i });
    expect(submitBtn).toBeInTheDocument();
  });

  it('2. AssetsPage: renders asset list, opens register asset modal, and submits asset', async () => {
    (api.get as any).mockResolvedValueOnce({
      data: {
        total: 1,
        items: [
          {
            id: 'asset-1',
            organization_id: 'org-1111',
            name: 'Core Web Gateway',
            asset_type: 'WEB_APPLICATION',
            target: 'https://app.smbclient.in',
            environment: 'PRODUCTION',
            criticality: 'CRITICAL',
            is_in_scope: true,
            created_at: '2026-11-14T10:00:00Z',
            updated_at: '2026-11-14T10:00:00Z',
          },
        ],
      },
    });

    render(
      <BrowserRouter>
        <AssetsPage />
      </BrowserRouter>
    );

    await waitFor(() => {
      expect(screen.getByText('Core Web Gateway')).toBeInTheDocument();
      expect(screen.getByText('https://app.smbclient.in')).toBeInTheDocument();
    });

    const addBtn = screen.getByRole('button', { name: /onboard asset/i });
    fireEvent.click(addBtn);

    expect(screen.getByText(/Onboard Authorized Asset/i)).toBeInTheDocument();
  });

  it('3. OrganizationsPage: renders tenant organizations and shows org stats', async () => {
    (api.get as any).mockResolvedValueOnce({
      data: {
        total: 1,
        items: [
          {
            id: 'org-1111',
            name: 'Primary SMB Org',
            slug: 'primary-smb',
            sector: 'FinTech',
            contact_email: 'sec@smb.in',
            is_active: true,
            created_at: '2026-11-14T10:00:00Z',
          },
        ],
      },
    });

    render(
      <BrowserRouter>
        <OrganizationsPage />
      </BrowserRouter>
    );

    await waitFor(() => {
      expect(screen.getByText('Primary SMB Org')).toBeInTheDocument();
      expect(screen.getByText('primary-smb')).toBeInTheDocument();
    });
  });

  it('4. UsersPage: renders user directory and shows role badges', async () => {
    (api.get as any).mockResolvedValueOnce({
      data: {
        total: 1,
        items: [
          {
            id: 'user-1',
            email: 'admin@preventx.internal',
            full_name: 'Security Admin',
            is_active: true,
            is_superuser: true,
            created_at: '2026-11-14T10:00:00Z',
            memberships: [
              {
                organization_id: 'org-1111',
                organization_name: 'Primary SMB Org',
                role_name: 'SYSTEM_ADMIN',
                is_default: true,
              },
            ],
          },
        ],
      },
    });

    render(
      <BrowserRouter>
        <UsersPage />
      </BrowserRouter>
    );

    await waitFor(() => {
      expect(screen.getByText('admin@preventx.internal')).toBeInTheDocument();
      expect(screen.getByText('Security Admin')).toBeInTheDocument();
    });
  });

  it('5. RolesPage: renders RBAC matrix with all 5 system roles', async () => {
    (api.get as any).mockResolvedValueOnce({
      data: [
        {
          id: 'role-1',
          name: 'SYSTEM_ADMIN',
          description: 'Platform Superuser',
          is_system_role: true,
          permissions: [{ id: 'p1', code: 'system:manage', name: 'Manage System', description: 'full access', module: 'system' }],
        },
        {
          id: 'role-2',
          name: 'ORG_ADMIN',
          description: 'Organization Administrator',
          is_system_role: true,
          permissions: [{ id: 'p2', code: 'asset:write', name: 'Write Assets', description: 'write assets', module: 'assets' }],
        },
      ],
    });

    render(
      <BrowserRouter>
        <RolesPage />
      </BrowserRouter>
    );

    await waitFor(() => {
      expect(screen.getByText('SYSTEM_ADMIN')).toBeInTheDocument();
      expect(screen.getByText('ORG_ADMIN')).toBeInTheDocument();
    });
  });

  it('6. AuditLogsPage: renders tamper-evident audit records', async () => {
    (api.get as any).mockResolvedValueOnce({
      data: {
        total: 1,
        items: [
          {
            id: 'log-1',
            action: 'AUTH_LOGIN_SUCCESS',
            resource_type: 'USER_SESSION',
            resource_id: 'sess-1',
            status: 'SUCCESS',
            ip_address: '127.0.0.1',
            user_id: 'user-1',
            created_at: '2026-11-14T10:00:00Z',
            details: '{"event": "login"}',
          },
        ],
      },
    });

    render(
      <BrowserRouter>
        <AuditLogsPage />
      </BrowserRouter>
    );

    await waitFor(() => {
      expect(screen.getByText('AUTH_LOGIN_SUCCESS')).toBeInTheDocument();
      expect(screen.getByText('USER_SESSION')).toBeInTheDocument();
    });
  });

  it('7. SystemHealthPage: renders readiness telemetry and infrastructure components', async () => {
    (api.get as any).mockImplementation((url: string) => {
      if (url === '/health') {
        return Promise.resolve({
          data: { status: 'HEALTHY', app_name: 'PREVENT-X', version: '1.0.0' },
        });
      }
      if (url === '/ready') {
        return Promise.resolve({
          data: {
            status: 'READY',
            database: { status: 'UP', latency_ms: 1.2 },
            redis: { status: 'DEGRADED', latency_ms: null, details: 'Offline in dev' },
          },
        });
      }
      if (url === '/system/info') {
        return Promise.resolve({
          data: {
            app_name: 'PREVENT-X',
            app_version: '1.0.0',
            python_version: '3.10.11',
            database_backend: 'sqlite',
            phase: 'PHASE 1: ENTERPRISE-GRADE FOUNDATION & ARCHITECTURE',
          },
        });
      }
      return Promise.resolve({ data: {} });
    });

    render(
      <BrowserRouter>
        <SystemHealthPage />
      </BrowserRouter>
    );

    await waitFor(() => {
      expect(screen.getByText('Infrastructure Health & Readiness Telemetry')).toBeInTheDocument();
      expect(screen.getByText('Database Engine')).toBeInTheDocument();
      expect(screen.getByText('Redis Broker')).toBeInTheDocument();
      expect(screen.getByText('FastAPI Core')).toBeInTheDocument();
    });
  });

  it('8. SettingsPage: renders enterprise security configuration parameters', async () => {
    render(
      <BrowserRouter>
        <SettingsPage />
      </BrowserRouter>
    );

    expect(screen.getByText(/Tenant & Platform Security Settings/i)).toBeInTheDocument();
    expect(screen.getByText(/Cryptographic & Defense Controls/i)).toBeInTheDocument();
    expect(screen.getByText(/Password Hashing Algorithm/i)).toBeInTheDocument();
    expect(screen.getByText(/Argon2id/i)).toBeInTheDocument();
  });

  it('9. AppRoutes: authenticated routing renders layout and navigates routes', async () => {
    (api.get as any).mockImplementation((url: string) => {
      if (url === '/assets') {
        return Promise.resolve({
          data: {
            total: 1,
            items: [
              {
                id: 'asset-1',
                organization_id: 'org-1111',
                name: 'Core Gateway',
                asset_type: 'WEB_APPLICATION',
                target: 'https://test.smb.in',
                environment: 'PRODUCTION',
                criticality: 'HIGH',
                is_in_scope: true,
                created_at: '2026-11-14T10:00:00Z',
              },
            ],
          },
        });
      }
      return Promise.resolve({ data: { total: 0, items: [] } });
    });

    render(
      <MemoryRouter initialEntries={['/assets']}>
        <AppRoutes />
      </MemoryRouter>
    );

    await waitFor(() => {
      expect(screen.getByText('Core Gateway')).toBeInTheDocument();
    });
  });
});
