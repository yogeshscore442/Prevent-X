import React, { useState, useEffect } from 'react';
import { KeyRound, Check, Loader2, AlertCircle } from 'lucide-react';
import { api } from '@/services/api';
import { Role } from '@/types/role';

export const RolesPage: React.FC = () => {
  const [roles, setRoles] = useState<Role[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    const fetchRBAC = async () => {
      setLoading(true);
      try {
        const rolesRes = await api.get('/roles');
        setRoles(rolesRes.data || []);
      } catch (err: any) {
        setError(err.response?.data?.detail?.message || 'Failed to load RBAC metadata');
      } finally {
        setLoading(false);
      }
    };

    fetchRBAC();
  }, []);

  return (
    <div className="space-y-6 max-w-7xl mx-auto">
      {/* Header */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 pb-4 border-b border-navy-800">
        <div>
          <h1 className="text-xl font-bold text-white flex items-center gap-2">
            <KeyRound className="w-5 h-5 text-cyan-400" />
            <span>Role-Based Access Control (RBAC) Matrix</span>
          </h1>
          <p className="text-xs text-slate-400 mt-1">
            System security roles and their granular operational permission definitions.
          </p>
        </div>
      </div>

      {error && (
        <div className="p-3 rounded-lg bg-rose-950/60 border border-rose-800 text-rose-300 text-xs flex items-center gap-2">
          <AlertCircle className="w-4 h-4 flex-shrink-0" />
          <span>{error}</span>
        </div>
      )}

      {loading ? (
        <div className="py-16 text-center text-slate-400 text-xs flex flex-col items-center gap-2">
          <Loader2 className="w-6 h-6 animate-spin text-cyan-500" />
          <span>Loading RBAC rules...</span>
        </div>
      ) : (
        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-5">
          {roles.map((role) => (
            <div key={role.id} className="p-5 bg-navy-900 border border-navy-800 rounded-xl shadow-lg flex flex-col justify-between">
              <div>
                <div className="flex items-center justify-between mb-2">
                  <span className="text-xs font-mono font-bold text-cyan-300 px-2 py-0.5 rounded bg-navy-800">
                    {role.name}
                  </span>
                  <span className="text-[10px] font-mono text-slate-400 bg-navy-850 px-2 py-0.5 rounded">
                    SYSTEM ROLE
                  </span>
                </div>
                <p className="text-xs text-slate-300 mb-4">{role.description}</p>

                <div className="text-[11px] font-semibold text-slate-400 uppercase tracking-wider mb-2">
                  Granted Permissions ({role.permissions.length})
                </div>
                <div className="space-y-1.5 max-h-48 overflow-y-auto font-mono text-[11px]">
                  {role.permissions.map((p) => (
                    <div key={p.id} className="flex items-center gap-2 text-slate-300 bg-navy-850/60 p-1.5 rounded">
                      <Check className="w-3.5 h-3.5 text-cyan-400 flex-shrink-0" />
                      <span className="font-semibold text-cyan-200">{p.code}</span>
                    </div>
                  ))}
                </div>
              </div>
            </div>
          ))}
        </div>
      )}
    </div>
  );
};
