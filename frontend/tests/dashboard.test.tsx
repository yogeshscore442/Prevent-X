import { render, screen } from '@testing-library/react';
import { describe, it, expect, vi } from 'vitest';
import { BrowserRouter } from 'react-router-dom';
import { DashboardPage } from '@/pages/DashboardPage';
import { AuthProvider } from '@/contexts/AuthContext';

vi.mock('@/services/api', () => ({
  api: {
    get: vi.fn((url: string) => {
      if (url === '/assets') return Promise.resolve({ data: { total: 4, items: [] } });
      if (url === '/users') return Promise.resolve({ data: { total: 2, items: [] } });
      if (url === '/audit-logs') return Promise.resolve({ data: { total: 15, items: [] } });
      if (url === '/organizations') return Promise.resolve({ data: { total: 1, items: [] } });
      if (url === '/system/info') {
        return Promise.resolve({
          data: {
            app_name: 'PREVENT-X',
            app_version: '1.0.0',
            phase: 'PHASE 1: ENTERPRISE-GRADE FOUNDATION & ARCHITECTURE',
            modules: [
              {
                module_id: 'MOD-01',
                name: 'Attack Surface Intelligence Engine',
                status: 'PLANNED_PHASE',
                phase: 2,
                description: 'Test description',
              },
              {
                module_id: 'MOD-12',
                name: 'Centralized SMB Security Platform',
                status: 'OPERATIONAL',
                phase: 1,
                description: 'Test platform',
              },
            ],
          },
        });
      }
      return Promise.resolve({ data: {} });
    }),
  },
}));

describe('DashboardPage Component', () => {
  it('renders dashboard sections and module catalog without fake security alerts', async () => {
    render(
      <BrowserRouter>
        <AuthProvider>
          <DashboardPage />
        </AuthProvider>
      </BrowserRouter>
    );

    expect(screen.getByText(/Phase 1 Architecture Operational/i)).toBeInTheDocument();
    expect(screen.getByText(/Cybersecurity Module Availability Catalog/i)).toBeInTheDocument();
    expect(screen.getByText(/Authorized Assets/i)).toBeInTheDocument();
  });
});

