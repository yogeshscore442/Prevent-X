import React, { useState, useEffect } from 'react';
import { Link } from 'react-router-dom';
import {
  Server,
  Building2,
  Users,
  FileText,
  Layers,
  ArrowRight,
  Shield,
  Plus,
} from 'lucide-react';
import { api } from '@/services/api';
import { useAuth } from '@/contexts/AuthContext';
import { SystemInfo } from '@/types/system';

export const DashboardPage: React.FC = () => {
  const { user, activeOrgId } = useAuth();
  const [stats, setStats] = useState({
    assetCount: 0,
    userCount: 0,
    auditCount: 0,
    orgCount: 0,
  });
  const [systemInfo, setSystemInfo] = useState<SystemInfo | null>(null);
  const [loading, setLoading] = useState(true);

  const memberships = user?.memberships || [];
  const activeMembership = memberships.find(
    (m) => m.organization_id === activeOrgId
  ) || memberships[0];

  useEffect(() => {
    const fetchDashboardData = async () => {
      try {
        const [assetRes, userRes, auditRes, orgRes, sysRes] = await Promise.all([
          api.get('/assets').catch(() => ({ data: { total: 0 } })),
          api.get('/users').catch(() => ({ data: { total: 0 } })),
          api.get('/audit-logs').catch(() => ({ data: { total: 0 } })),
          api.get('/organizations').catch(() => ({ data: { total: 0 } })),
          api.get('/system/info').catch(() => ({ data: null })),
        ]);

        setStats({
          assetCount: assetRes.data.total || 0,
          userCount: userRes.data.total || 0,
          auditCount: auditRes.data.total || 0,
          orgCount: orgRes.data.total || 0,
        });
        setSystemInfo(sysRes.data);
      } finally {
        setLoading(false);
      }
    };

    fetchDashboardData();
  }, [activeOrgId]);

  return (
    <div className="space-y-6 max-w-7xl mx-auto">
      {/* Welcome Banner */}
      <div className="bg-gradient-to-r from-navy-900 to-navy-850 border border-navy-800 rounded-2xl p-6 shadow-xl relative overflow-hidden">
        <div className="relative z-10 flex flex-col md:flex-row md:items-center justify-between gap-4">
          <div>
            <div className="inline-flex items-center gap-2 px-2.5 py-0.5 rounded-full bg-cyan-950 border border-cyan-800/60 text-cyan-400 text-xs font-mono mb-2">
              <Shield className="w-3.5 h-3.5" />
              <span>Phase 1 Architecture Operational</span>
            </div>
            <h1 className="text-2xl font-bold text-white tracking-tight">
              Tenant Security Hub: {activeMembership?.organization_name || 'PREVENT-X Platform'}
            </h1>
            <p className="text-sm text-slate-400 mt-1 max-w-2xl">
              NASSCOM Problem Statement 5 compliant virtual patching foundation. Real-time multi-tenant asset scope and cryptographic audit log enforcement.
            </p>
          </div>

          <div className="flex items-center gap-3">
            <Link
              to="/assets"
              className="inline-flex items-center gap-2 px-4 py-2 bg-cyan-600 hover:bg-cyan-500 text-white rounded-lg text-xs font-semibold shadow-lg shadow-cyan-600/20 transition-all"
            >
              <Plus className="w-4 h-4" />
              <span>Add Managed Asset</span>
            </Link>
          </div>
        </div>
      </div>

      {/* Verified Real Database Metrics */}
      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
        {/* Managed Assets */}
        <div className="bg-navy-900 border border-navy-800 rounded-xl p-5 shadow-lg">
          <div className="flex items-center justify-between text-slate-400 mb-3">
            <span className="text-xs font-semibold uppercase tracking-wider">Authorized Assets</span>
            <Server className="w-4 h-4 text-cyan-400" />
          </div>
          <div className="text-2xl font-bold text-white font-mono">{loading ? '...' : stats.assetCount}</div>
          <div className="text-xs text-slate-400 mt-2 flex items-center justify-between">
            <span>In Protection Scope</span>
            <Link to="/assets" className="text-cyan-400 hover:underline inline-flex items-center gap-1">
              <span>View</span>
              <ArrowRight className="w-3 h-3" />
            </Link>
          </div>
        </div>

        {/* Tenant Users */}
        <div className="bg-navy-900 border border-navy-800 rounded-xl p-5 shadow-lg">
          <div className="flex items-center justify-between text-slate-400 mb-3">
            <span className="text-xs font-semibold uppercase tracking-wider">Tenant Users</span>
            <Users className="w-4 h-4 text-blue-400" />
          </div>
          <div className="text-2xl font-bold text-white font-mono">{loading ? '...' : stats.userCount}</div>
          <div className="text-xs text-slate-400 mt-2 flex items-center justify-between">
            <span>Scoped Identities</span>
            <Link to="/users" className="text-cyan-400 hover:underline inline-flex items-center gap-1">
              <span>Manage</span>
              <ArrowRight className="w-3 h-3" />
            </Link>
          </div>
        </div>

        {/* Audit Events */}
        <div className="bg-navy-900 border border-navy-800 rounded-xl p-5 shadow-lg">
          <div className="flex items-center justify-between text-slate-400 mb-3">
            <span className="text-xs font-semibold uppercase tracking-wider">Audit Trail Records</span>
            <FileText className="w-4 h-4 text-emerald-400" />
          </div>
          <div className="text-2xl font-bold text-white font-mono">{loading ? '...' : stats.auditCount}</div>
          <div className="text-xs text-slate-400 mt-2 flex items-center justify-between">
            <span>Immutable Events</span>
            <Link to="/audit-logs" className="text-cyan-400 hover:underline inline-flex items-center gap-1">
              <span>Browse</span>
              <ArrowRight className="w-3 h-3" />
            </Link>
          </div>
        </div>

        {/* Active Organizations */}
        <div className="bg-navy-900 border border-navy-800 rounded-xl p-5 shadow-lg">
          <div className="flex items-center justify-between text-slate-400 mb-3">
            <span className="text-xs font-semibold uppercase tracking-wider">Accessible SMBs</span>
            <Building2 className="w-4 h-4 text-amber-400" />
          </div>
          <div className="text-2xl font-bold text-white font-mono">{loading ? '...' : stats.orgCount}</div>
          <div className="text-xs text-slate-400 mt-2 flex items-center justify-between">
            <span>Multi-Tenant Scope</span>
            <Link to="/organizations" className="text-cyan-400 hover:underline inline-flex items-center gap-1">
              <span>View</span>
              <ArrowRight className="w-3 h-3" />
            </Link>
          </div>
        </div>
      </div>

      {/* Honest Module Availability Catalog */}
      <div className="bg-navy-900 border border-navy-800 rounded-2xl p-6 shadow-xl">
        <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2 pb-4 border-b border-navy-800 mb-6">
          <div>
            <h2 className="text-lg font-bold text-white flex items-center gap-2">
              <Layers className="w-5 h-5 text-cyan-400" />
              <span>Cybersecurity Module Availability Catalog</span>
            </h2>
            <p className="text-xs text-slate-400 mt-0.5">
              Strict distinction between Phase 1 operational foundation and planned future modules.
            </p>
          </div>
          <div className="flex items-center gap-3 text-xs font-mono">
            <span className="flex items-center gap-1 text-emerald-400">
              <span className="w-2 h-2 rounded-full bg-emerald-400"></span>
              Operational (Phase 1)
            </span>
            <span className="flex items-center gap-1 text-amber-400">
              <span className="w-2 h-2 rounded-full bg-amber-400"></span>
              Planned (Phase 2-8)
            </span>
          </div>
        </div>

        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
          {(systemInfo?.modules || []).map((mod) => {
            const isOp = mod.status === 'OPERATIONAL';
            return (
              <div
                key={mod.module_id}
                className={`p-4 rounded-xl border transition-all ${isOp
                    ? 'bg-navy-850/80 border-cyan-500/30 hover:border-cyan-500/60'
                    : 'bg-navy-950/60 border-navy-800'
                  }`}
              >
                <div className="flex items-start justify-between gap-2 mb-2">
                  <span className="text-xs font-mono font-bold text-cyan-300 bg-navy-800 px-2 py-0.5 rounded">
                    {mod.module_id}
                  </span>
                  <span
                    className={`text-[10px] font-mono px-2 py-0.5 rounded uppercase font-semibold ${isOp
                        ? 'bg-emerald-950 text-emerald-300 border border-emerald-800/50'
                        : 'bg-amber-950/60 text-amber-300 border border-amber-800/50'
                      }`}
                  >
                    {isOp ? 'OPERATIONAL' : `Phase ${mod.phase} Planned`}
                  </span>
                </div>
                <h3 className="text-sm font-semibold text-slate-100 mb-1">{mod.name}</h3>
                <p className="text-xs text-slate-400 leading-relaxed mb-3">{mod.description}</p>
                <div className="text-[11px] font-mono text-slate-500 pt-2 border-t border-navy-800/80 flex items-center justify-between">
                  <span>Architecture: Defined</span>
                  <span>{isOp ? 'Execution: Ready' : 'Execution: Future Phase'}</span>
                </div>
              </div>
            );
          })}
        </div>
      </div>
    </div>
  );
};
