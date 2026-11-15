import React, { useState, useEffect } from 'react';
import { Building2, Plus, AlertCircle, Loader2, Globe, Mail } from 'lucide-react';
import { api } from '@/services/api';
import { useAuth } from '@/contexts/AuthContext';
import { Organization, OrganizationCreatePayload } from '@/types/organization';

export const OrganizationsPage: React.FC = () => {
  const { user, switchOrganization, activeOrgId } = useAuth();
  const isSuperUser = !!user?.is_superuser;

  const [orgs, setOrgs] = useState<Organization[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  const [showAddModal, setShowAddModal] = useState(false);
  const [name, setName] = useState('');
  const [slug, setSlug] = useState('');
  const [sector, setSector] = useState('Fintech & Payments');
  const [contactEmail, setContactEmail] = useState('');
  const [creating, setCreating] = useState(false);

  const fetchOrganizations = async () => {
    setLoading(true);
    try {
      const resp = await api.get('/organizations');
      const items = Array.isArray(resp.data) ? resp.data : (resp.data?.items || []);
      setOrgs(items);
    } catch (err: any) {
      setError(err.response?.data?.detail?.message || 'Failed to load organizations');
      setOrgs([]);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchOrganizations();
  }, []);

  const handleCreateOrg = async (e: React.FormEvent) => {
    e.preventDefault();
    setCreating(true);
    setError(null);
    try {
      const payload: OrganizationCreatePayload = {
        name,
        slug: slug.toLowerCase(),
        sector,
        contact_email: contactEmail,
      };
      await api.post('/organizations', payload);
      setShowAddModal(false);
      setName('');
      setSlug('');
      setContactEmail('');
      fetchOrganizations();
    } catch (err: any) {
      setError(err.response?.data?.detail?.message || 'Failed to create organization');
    } finally {
      setCreating(false);
    }
  };

  return (
    <div className="space-y-6 max-w-7xl mx-auto">
      {/* Header */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 pb-4 border-b border-navy-800">
        <div>
          <h1 className="text-xl font-bold text-white flex items-center gap-2">
            <Building2 className="w-5 h-5 text-amber-400" />
            <span>SMB Tenant Organizations</span>
          </h1>
          <p className="text-xs text-slate-400 mt-1">
            Isolated tenant domains ensuring multi-tenant SMB data segregation and organization-scoped virtual patching.
          </p>
        </div>

        {isSuperUser && (
          <button
            onClick={() => setShowAddModal(true)}
            className="inline-flex items-center gap-2 px-3.5 py-2 bg-amber-600 hover:bg-amber-500 text-white rounded-lg text-xs font-semibold shadow-lg shadow-amber-600/20 transition-all cursor-pointer"
          >
            <Plus className="w-4 h-4" />
            <span>Provision Tenant</span>
          </button>
        )}
      </div>

      {error && (
        <div className="p-3 rounded-lg bg-rose-950/60 border border-rose-800 text-rose-300 text-xs flex items-center justify-between">
          <div className="flex items-center gap-2">
            <AlertCircle className="w-4 h-4 flex-shrink-0" />
            <span>{error}</span>
          </div>
          <button onClick={() => setError(null)} className="text-xs text-rose-400 hover:underline">
            Dismiss
          </button>
        </div>
      )}

      {/* Grid of Organizations */}
      {loading ? (
        <div className="py-16 text-center text-slate-400 text-xs flex flex-col items-center gap-2">
          <Loader2 className="w-6 h-6 animate-spin text-amber-500" />
          <span>Loading tenant organizations...</span>
        </div>
      ) : (
        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
          {(orgs || []).map((org) => {
            const isCurrent = org.id === activeOrgId;
            return (
              <div
                key={org.id}
                className={`p-5 rounded-xl border bg-navy-900 flex flex-col justify-between transition-all ${isCurrent ? 'border-cyan-500/50 shadow-lg shadow-cyan-500/10' : 'border-navy-800'
                  }`}
              >
                <div>
                  <div className="flex items-start justify-between gap-2 mb-2">
                    <span className="text-xs font-mono text-slate-400 bg-navy-850 px-2 py-0.5 rounded border border-navy-750">
                      {org.slug}
                    </span>
                    {isCurrent ? (
                      <span className="text-[10px] font-mono px-2 py-0.5 rounded bg-cyan-950 text-cyan-300 border border-cyan-800/60 font-semibold">
                        ACTIVE CONTEXT
                      </span>
                    ) : (
                      <span className="text-[10px] font-mono px-2 py-0.5 rounded bg-emerald-950 text-emerald-400">
                        HEALTHY
                      </span>
                    )}
                  </div>
                  <h3 className="text-base font-bold text-white mb-1">{org.name}</h3>
                  <div className="space-y-1.5 text-xs text-slate-400 my-3">
                    <div className="flex items-center gap-2">
                      <Globe className="w-3.5 h-3.5 text-slate-500" />
                      <span>Sector: {org.sector || 'Unassigned'}</span>
                    </div>
                    <div className="flex items-center gap-2">
                      <Mail className="w-3.5 h-3.5 text-slate-500" />
                      <span className="truncate">{org.contact_email}</span>
                    </div>
                  </div>
                </div>

                <div className="pt-4 border-t border-navy-800 flex items-center justify-between">
                  <span className="text-[10px] text-slate-500 font-mono">
                    ID: {org.id.slice(0, 8)}...
                  </span>
                  {!isCurrent && (
                    <button
                      onClick={() => switchOrganization(org.id)}
                      className="px-2.5 py-1 rounded bg-navy-800 hover:bg-navy-750 text-xs font-medium text-cyan-300 transition-colors"
                    >
                      Switch To
                    </button>
                  )}
                </div>
              </div>
            );
          })}
        </div>
      )}

      {/* Provision Modal */}
      {showAddModal && (
        <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-navy-950/80 backdrop-blur-sm">
          <div className="bg-navy-900 border border-navy-800 rounded-2xl w-full max-w-lg p-6 shadow-2xl space-y-4">
            <div className="flex items-center justify-between pb-3 border-b border-navy-800">
              <h2 className="text-base font-bold text-white flex items-center gap-2">
                <Building2 className="w-4 h-4 text-amber-400" />
                <span>Provision New SMB Tenant</span>
              </h2>
              <button
                onClick={() => setShowAddModal(false)}
                className="text-slate-400 hover:text-slate-200 text-sm font-mono"
              >
                ✕
              </button>
            </div>

            <form onSubmit={handleCreateOrg} className="space-y-4">
              <div>
                <label className="block text-xs font-medium text-slate-300 uppercase tracking-wider mb-1">
                  Organization Name
                </label>
                <input
                  type="text"
                  required
                  placeholder="e.g. Bharat Healthcare Digital"
                  value={name}
                  onChange={(e) => {
                    setName(e.target.value);
                    if (!slug) {
                      setSlug(e.target.value.toLowerCase().replace(/[^a-z0-9]/g, '-'));
                    }
                  }}
                  className="w-full px-3 py-2 bg-navy-850 border border-navy-700 rounded-lg text-sm text-slate-100 focus:outline-none focus:ring-1 focus:ring-amber-500"
                />
              </div>

              <div>
                <label className="block text-xs font-medium text-slate-300 uppercase tracking-wider mb-1">
                  Tenant Slug (Alphanumeric and dashes)
                </label>
                <input
                  type="text"
                  required
                  placeholder="bharat-healthcare"
                  value={slug}
                  onChange={(e) => setSlug(e.target.value.toLowerCase())}
                  className="w-full px-3 py-2 bg-navy-850 border border-navy-700 rounded-lg text-sm text-slate-100 font-mono focus:outline-none focus:ring-1 focus:ring-amber-500"
                />
              </div>

              <div>
                <label className="block text-xs font-medium text-slate-300 uppercase tracking-wider mb-1">
                  Industry / Sector
                </label>
                <input
                  type="text"
                  placeholder="e.g. Healthcare, Retail, Financial Services"
                  value={sector}
                  onChange={(e) => setSector(e.target.value)}
                  className="w-full px-3 py-2 bg-navy-850 border border-navy-700 rounded-lg text-sm text-slate-100 focus:outline-none focus:ring-1 focus:ring-amber-500"
                />
              </div>

              <div>
                <label className="block text-xs font-medium text-slate-300 uppercase tracking-wider mb-1">
                  Security Contact Email
                </label>
                <input
                  type="email"
                  required
                  placeholder="security@tenant.in"
                  value={contactEmail}
                  onChange={(e) => setContactEmail(e.target.value)}
                  className="w-full px-3 py-2 bg-navy-850 border border-navy-700 rounded-lg text-sm text-slate-100 focus:outline-none focus:ring-1 focus:ring-amber-500"
                />
              </div>

              <div className="pt-3 flex items-center justify-end gap-3">
                <button
                  type="button"
                  onClick={() => setShowAddModal(false)}
                  className="px-4 py-2 rounded-lg bg-navy-800 hover:bg-navy-750 text-slate-300 text-xs font-medium"
                >
                  Cancel
                </button>
                <button
                  type="submit"
                  disabled={creating}
                  className="px-4 py-2 rounded-lg bg-amber-600 hover:bg-amber-500 text-white text-xs font-semibold shadow-lg shadow-amber-600/20 disabled:opacity-50 cursor-pointer"
                >
                  {creating ? 'Provisioning...' : 'Provision Tenant'}
                </button>
              </div>
            </form>
          </div>
        </div>
      )}
    </div>
  );
};
