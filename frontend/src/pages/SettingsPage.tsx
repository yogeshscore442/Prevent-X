import React from 'react';
import { Settings, Shield, User, Building } from 'lucide-react';
import { useAuth } from '@/contexts/AuthContext';

export const SettingsPage: React.FC = () => {
  const { user, activeOrgId } = useAuth();

  const memberships = user?.memberships || [];
  const activeMembership = memberships.find(
    (m) => m.organization_id === activeOrgId
  ) || memberships[0];

  return (
    <div className="space-y-6 max-w-4xl mx-auto">
      {/* Header */}
      <div className="pb-4 border-b border-navy-800">
        <h1 className="text-xl font-bold text-white flex items-center gap-2">
          <Settings className="w-5 h-5 text-cyan-400" />
          <span>Tenant & Platform Security Settings</span>
        </h1>
        <p className="text-xs text-slate-400 mt-1">
          Cryptographic enforcement parameters, session security thresholds, and tenant profiles.
        </p>
      </div>

      {/* Tenant Context */}
      <div className="bg-navy-900 border border-navy-800 rounded-xl p-6 shadow-xl space-y-4">
        <h2 className="text-sm font-bold text-white flex items-center gap-2">
          <Building className="w-4 h-4 text-cyan-400" />
          <span>Active Tenant Configuration</span>
        </h2>
        <div className="grid grid-cols-1 sm:grid-cols-2 gap-4 text-xs font-mono">
          <div>
            <label className="text-slate-400 block mb-1">Organization Name</label>
            <input
              type="text"
              readOnly
              value={activeMembership?.organization_name || 'PREVENT-X Platform'}
              className="w-full px-3 py-2 bg-navy-850 border border-navy-750 rounded-lg text-slate-200 cursor-not-allowed"
            />
          </div>
          <div>
            <label className="text-slate-400 block mb-1">Tenant Organization Slug</label>
            <input
              type="text"
              readOnly
              value={activeMembership?.organization_slug || 'platform'}
              className="w-full px-3 py-2 bg-navy-850 border border-navy-750 rounded-lg text-slate-200 cursor-not-allowed"
            />
          </div>
        </div>
      </div>

      {/* Security Policies */}
      <div className="bg-navy-900 border border-navy-800 rounded-xl p-6 shadow-xl space-y-4">
        <h2 className="text-sm font-bold text-white flex items-center gap-2">
          <Shield className="w-4 h-4 text-emerald-400" />
          <span>Cryptographic & Defense Controls</span>
        </h2>

        <div className="space-y-3 text-xs">
          <div className="flex items-center justify-between p-3 rounded-lg bg-navy-850 border border-navy-750">
            <div>
              <div className="font-semibold text-slate-200 font-sans">Password Hashing Algorithm</div>
              <div className="text-slate-400 font-mono text-[11px]">Argon2id (time_cost: 3, memory: 64MB, parallelism: 4)</div>
            </div>
            <span className="text-[10px] font-mono px-2 py-0.5 rounded bg-emerald-950 text-emerald-400 font-semibold">
              ACTIVE
            </span>
          </div>

          <div className="flex items-center justify-between p-3 rounded-lg bg-navy-850 border border-navy-750">
            <div>
              <div className="font-semibold text-slate-200 font-sans">Cross-Site Request Forgery (CSRF)</div>
              <div className="text-slate-400 font-mono text-[11px]">Double-submit cookie & X-CSRF-Token validation</div>
            </div>
            <span className="text-[10px] font-mono px-2 py-0.5 rounded bg-emerald-950 text-emerald-400 font-semibold">
              ENFORCED
            </span>
          </div>

          <div className="flex items-center justify-between p-3 rounded-lg bg-navy-850 border border-navy-750">
            <div>
              <div className="font-semibold text-slate-200 font-sans">Session Expiration & Revocation</div>
              <div className="text-slate-400 font-mono text-[11px]">24-hour absolute lifespan with server-side database revocation</div>
            </div>
            <span className="text-[10px] font-mono px-2 py-0.5 rounded bg-cyan-950 text-cyan-300 font-semibold">
              24 HOURS
            </span>
          </div>

          <div className="flex items-center justify-between p-3 rounded-lg bg-navy-850 border border-navy-750">
            <div>
              <div className="font-semibold text-slate-200 font-sans">Sliding Window Rate Limiting</div>
              <div className="text-slate-400 font-mono text-[11px]">Auth: 10 req/min | API: 60 req/min</div>
            </div>
            <span className="text-[10px] font-mono px-2 py-0.5 rounded bg-emerald-950 text-emerald-400 font-semibold">
              ACTIVE
            </span>
          </div>
        </div>
      </div>

      {/* User Session Info */}
      <div className="bg-navy-900 border border-navy-800 rounded-xl p-6 shadow-xl space-y-3">
        <h2 className="text-sm font-bold text-white flex items-center gap-2">
          <User className="w-4 h-4 text-blue-400" />
          <span>Active Authenticated Session</span>
        </h2>
        <div className="grid grid-cols-1 sm:grid-cols-3 gap-3 font-mono text-xs">
          <div className="p-3 bg-navy-850 rounded border border-navy-750">
            <div className="text-slate-500 text-[10px]">OPERATOR EMAIL</div>
            <div className="text-slate-200 mt-1 truncate">{user?.email}</div>
          </div>
          <div className="p-3 bg-navy-850 rounded border border-navy-750">
            <div className="text-slate-500 text-[10px]">TENANT ROLE</div>
            <div className="text-cyan-300 mt-1">{activeMembership?.role_name || (user?.is_superuser ? 'SUPER_ADMIN' : 'MEMBER')}</div>
          </div>
          <div className="p-3 bg-navy-850 rounded border border-navy-750">
            <div className="text-slate-500 text-[10px]">SUPERUSER STATUS</div>
            <div className="text-slate-200 mt-1">{user?.is_superuser ? 'TRUE' : 'FALSE'}</div>
          </div>
        </div>
      </div>
    </div>
  );
};
