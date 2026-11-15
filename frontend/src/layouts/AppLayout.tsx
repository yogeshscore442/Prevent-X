import React, { useState } from 'react';
import { Outlet, NavLink } from 'react-router-dom';
import {
  ShieldAlert,
  ShieldCheck,
  Server,
  Globe,
  Bug,
  Building2,
  Users,
  KeyRound,
  FileText,
  Activity,
  Settings,
  LogOut,
  ChevronDown,
  LayoutDashboard,
  Layers,
  Workflow,
  CheckCheck,
  Radio,
  Menu,
  X,
} from 'lucide-react';
import { useAuth } from '@/contexts/AuthContext';
import { ErrorBoundary } from '@/components/common/ErrorBoundary';

export const AppLayout: React.FC = () => {
  const { user, activeOrgId, switchOrganization, logout } = useAuth();
  const [mobileMenuOpen, setMobileMenuOpen] = useState(false);
  const [orgDropdownOpen, setOrgDropdownOpen] = useState(false);

  const memberships = user?.memberships || [];
  const activeMembership = memberships.find(
    (m) => m.organization_id === activeOrgId
  ) || memberships[0];

  const navItems = [
    { name: 'Dashboard', path: '/', icon: LayoutDashboard },
    { name: 'Security Center', path: '/security-center', icon: Radio },
    { name: 'Managed Assets', path: '/assets', icon: Server },
    { name: 'Attack Surface', path: '/attack-surface', icon: Globe },
    { name: 'Vulnerabilities', path: '/vulnerabilities', icon: Bug },
    { name: 'Attack Paths', path: '/attack-paths', icon: Workflow },
    { name: 'Zero Trust & Resilience', path: '/zero-trust', icon: ShieldCheck },
    { name: 'Virtual Patching', path: '/virtual-patching', icon: ShieldAlert },
    { name: 'Security Validation', path: '/security-validation', icon: CheckCheck },
    { name: 'Organizations', path: '/organizations', icon: Building2 },
    { name: 'Users & Access', path: '/users', icon: Users },
    { name: 'Roles & Permissions', path: '/roles', icon: KeyRound },
    { name: 'Audit Logs', path: '/audit-logs', icon: FileText },
    { name: 'System Health', path: '/system-health', icon: Activity },
    { name: 'Settings', path: '/settings', icon: Settings },
  ];

  return (
    <div className="flex h-screen bg-navy-950 text-slate-100 overflow-hidden font-sans">
      {/* Sidebar Desktop */}
      <aside className="hidden md:flex flex-col w-64 bg-navy-900 border-r border-navy-800 flex-shrink-0">
        {/* Brand Header */}
        <div className="h-16 flex items-center px-6 border-b border-navy-800 gap-3">
          <div className="w-9 h-9 rounded-lg bg-gradient-to-br from-cyan-500 to-blue-600 flex items-center justify-center shadow-lg shadow-cyan-500/20">
            <ShieldAlert className="w-5 h-5 text-white" />
          </div>
          <div>
            <span className="font-bold tracking-wider text-white text-base">PREVENT-X</span>
            <div className="text-[10px] text-cyan-400 font-mono tracking-widest uppercase">
              Virtual Patching
            </div>
          </div>
        </div>

        {/* Tenant Organization Switcher */}
        <div className="p-4 border-b border-navy-800">
          <div className="text-[11px] font-semibold text-slate-400 uppercase tracking-wider mb-2">
            Active Tenant
          </div>
          <div className="relative">
            <button
              onClick={() => setOrgDropdownOpen(!orgDropdownOpen)}
              className="w-full flex items-center justify-between p-2.5 rounded-lg bg-navy-850 hover:bg-navy-800 border border-navy-700 text-left transition-colors"
            >
              <div className="truncate">
                <div className="text-sm font-medium text-slate-200 truncate">
                  {activeMembership?.organization_name || 'Select Organization'}
                </div>
                <div className="text-[11px] text-slate-400 font-mono truncate">
                  Role: {activeMembership?.role_name || (user?.is_superuser ? 'SUPER_ADMIN' : 'MEMBER')}
                </div>
              </div>
              <ChevronDown className="w-4 h-4 text-slate-400 ml-2 flex-shrink-0" />
            </button>

            {orgDropdownOpen && user && memberships.length > 0 && (
              <div className="absolute left-0 right-0 mt-1.5 bg-navy-850 border border-navy-700 rounded-lg shadow-xl z-50 py-1 max-h-48 overflow-y-auto">
                {memberships.map((m) => (
                  <button
                    key={m.organization_id}
                    onClick={() => {
                      switchOrganization(m.organization_id);
                      setOrgDropdownOpen(false);
                    }}
                    className={`w-full text-left px-3 py-2 text-xs flex flex-col hover:bg-navy-750 transition-colors ${m.organization_id === activeOrgId ? 'bg-cyan-950/40 text-cyan-300 font-medium' : 'text-slate-300'
                      }`}
                  >
                    <span>{m.organization_name}</span>
                    <span className="text-[10px] text-slate-400 font-mono">{m.role_name}</span>
                  </button>
                ))}
              </div>
            )}
          </div>
        </div>

        {/* Navigation Links */}
        <nav className="flex-1 px-3 py-4 space-y-1 overflow-y-auto">
          <div className="text-[11px] font-semibold text-slate-400 uppercase tracking-wider px-3 mb-2">
            Core Foundation (Phase 1)
          </div>
          {navItems.map((item) => {
            const Icon = item.icon;
            return (
              <NavLink
                key={item.path}
                to={item.path}
                end={item.path === '/'}
                className={({ isActive }) =>
                  `flex items-center gap-3 px-3 py-2 rounded-lg text-sm font-medium transition-all ${isActive
                    ? 'bg-cyan-500/10 text-cyan-400 border border-cyan-500/30'
                    : 'text-slate-400 hover:text-slate-200 hover:bg-navy-800/60'
                  }`
                }
              >
                <Icon className="w-4 h-4" />
                <span>{item.name}</span>
              </NavLink>
            );
          })}

          {/* Architectural Extension Modules Roadmap */}
          <div className="pt-6">
            <div className="text-[11px] font-semibold text-slate-500 uppercase tracking-wider px-3 mb-2 flex items-center gap-1.5">
              <Layers className="w-3 h-3 text-slate-500" />
              <span>Engines Roadmap</span>
            </div>
            <div className="space-y-1 px-3 text-[11px] text-slate-500 font-mono">
              <div className="flex items-center justify-between py-1 border-b border-navy-850">
                <span>MOD-01 Attack Surface</span>
                <span className="text-[9px] bg-navy-800 px-1.5 py-0.5 rounded text-amber-400/80">Phase 2</span>
              </div>
              <div className="flex items-center justify-between py-1 border-b border-navy-850">
                <span>MOD-02 Vuln Mapping</span>
                <span className="text-[9px] bg-navy-800 px-1.5 py-0.5 rounded text-amber-400/80">Phase 3</span>
              </div>
              <div className="flex items-center justify-between py-1 border-b border-navy-850">
                <span>MOD-04 Zero Trust</span>
                <span className="text-[9px] bg-navy-800 px-1.5 py-0.5 rounded text-amber-400/80">Phase 4</span>
              </div>
              <div className="flex items-center justify-between py-1 border-b border-navy-850">
                <span>MOD-08 Virtual Patching</span>
                <span className="text-[9px] bg-navy-800 px-1.5 py-0.5 rounded text-cyan-400/80">Phase 6</span>
              </div>
            </div>
          </div>
        </nav>

        {/* User Footer */}
        <div className="p-4 border-t border-navy-800 flex items-center justify-between bg-navy-950/60">
          <div className="truncate mr-2">
            <div className="text-xs font-semibold text-slate-200 truncate">{user?.full_name}</div>
            <div className="text-[10px] text-slate-400 truncate font-mono">{user?.email}</div>
          </div>
          <button
            onClick={logout}
            title="Sign Out"
            className="p-1.5 rounded-md hover:bg-navy-800 text-slate-400 hover:text-rose-400 transition-colors"
          >
            <LogOut className="w-4 h-4" />
          </button>
        </div>
      </aside>

      {/* Main Content Area */}
      <div className="flex-1 flex flex-col min-w-0 overflow-hidden">
        {/* Top Navbar */}
        <header className="h-16 bg-navy-900 border-b border-navy-800 flex items-center justify-between px-6 flex-shrink-0">
          <div className="flex items-center gap-4">
            <button
              onClick={() => setMobileMenuOpen(!mobileMenuOpen)}
              className="md:hidden p-2 rounded-lg bg-navy-800 text-slate-300"
            >
              {mobileMenuOpen ? <X className="w-5 h-5" /> : <Menu className="w-5 h-5" />}
            </button>
            <div className="flex items-center gap-2">
              <span className="text-xs font-mono text-cyan-400 px-2 py-0.5 rounded bg-cyan-950/60 border border-cyan-800/40">
                NASSCOM ARB 2.0 PS-05
              </span>
              <span className="hidden sm:inline-block text-xs text-slate-400">
                Indian SMB Defense Foundation
              </span>
            </div>
          </div>

          <div className="flex items-center gap-4">
            {/* Live Health Pulse Indicator */}
            <div className="flex items-center gap-2 px-3 py-1.5 rounded-full bg-emerald-950/50 border border-emerald-800/50 text-emerald-300 text-xs font-mono">
              <span className="w-2 h-2 rounded-full bg-emerald-400 animate-pulse"></span>
              <span>API: LIVE</span>
            </div>

            <div className="hidden sm:flex text-xs text-slate-400 font-mono">
              v1.0.0 (Phase 1)
            </div>
          </div>
        </header>

        {/* Scrollable Page Body */}
        <main className="flex-1 overflow-y-auto p-6 bg-navy-950">
          <ErrorBoundary fallbackTitle="Module View Render Error">
            <Outlet />
          </ErrorBoundary>
        </main>
      </div>
    </div>
  );
};
