import React, { useState, useEffect } from 'react';
import {
  Server,
  Plus,
  Trash2,
  AlertCircle,
  Loader2,
  CheckCircle2,
} from 'lucide-react';
import { api } from '@/services/api';
import { useAuth } from '@/contexts/AuthContext';
import { ManagedAsset, AssetCreatePayload, AssetType, EnvironmentType, CriticalityType } from '@/types/asset';

export const AssetsPage: React.FC = () => {
  const { hasPermission } = useAuth();
  const canWrite = hasPermission('asset:write');
  const canDelete = hasPermission('asset:delete');

  const [assets, setAssets] = useState<ManagedAsset[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  // Modal / Form state
  const [showAddModal, setShowAddModal] = useState(false);
  const [name, setName] = useState('');
  const [assetType, setAssetType] = useState<AssetType>('WEB_APPLICATION');
  const [target, setTarget] = useState('');
  const [environment, setEnvironment] = useState<EnvironmentType>('PRODUCTION');
  const [criticality, setCriticality] = useState<CriticalityType>('HIGH');
  const [creating, setCreating] = useState(false);

  const fetchAssets = async () => {
    setLoading(true);
    try {
      const resp = await api.get('/assets');
      setAssets(resp.data.items || []);
    } catch (err: any) {
      setError(err.response?.data?.detail?.message || 'Failed to load assets');
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchAssets();
  }, []);

  const handleCreateAsset = async (e: React.FormEvent) => {
    e.preventDefault();
    setCreating(true);
    setError(null);
    try {
      const payload: AssetCreatePayload = {
        name,
        asset_type: assetType,
        target,
        environment,
        criticality,
        is_in_scope: true,
      };
      await api.post('/assets', payload);
      setShowAddModal(false);
      setName('');
      setTarget('');
      fetchAssets();
    } catch (err: any) {
      setError(err.response?.data?.detail?.message || 'Failed to register asset');
    } finally {
      setCreating(false);
    }
  };

  const handleDeleteAsset = async (id: string, assetName: string) => {
    if (!window.confirm(`Are you sure you want to remove "${assetName}" from protection scope?`)) {
      return;
    }
    try {
      await api.delete(`/assets/${id}`);
      setAssets(assets.filter((a) => a.id !== id));
    } catch (err: any) {
      setError(err.response?.data?.detail?.message || 'Failed to delete asset');
    }
  };

  return (
    <div className="space-y-6 max-w-7xl mx-auto">
      {/* Header */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 pb-4 border-b border-navy-800">
        <div>
          <h1 className="text-xl font-bold text-white flex items-center gap-2">
            <Server className="w-5 h-5 text-cyan-400" />
            <span>Authorized SMB Asset Inventory</span>
          </h1>
          <p className="text-xs text-slate-400 mt-1">
            Registered digital exposure points explicitly authorized for virtual patching and defensive inspection.
          </p>
        </div>

        {canWrite && (
          <button
            onClick={() => setShowAddModal(true)}
            className="inline-flex items-center gap-2 px-3.5 py-2 bg-cyan-600 hover:bg-cyan-500 text-white rounded-lg text-xs font-semibold shadow-lg shadow-cyan-600/20 transition-all cursor-pointer"
          >
            <Plus className="w-4 h-4" />
            <span>Onboard Asset</span>
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

      {/* Assets Table */}
      <div className="bg-navy-900 border border-navy-800 rounded-xl overflow-hidden shadow-xl">
        {loading ? (
          <div className="py-16 text-center text-slate-400 text-xs flex flex-col items-center gap-2">
            <Loader2 className="w-6 h-6 animate-spin text-cyan-500" />
            <span>Loading tenant assets...</span>
          </div>
        ) : assets.length === 0 ? (
          <div className="py-16 text-center text-slate-400 text-xs flex flex-col items-center gap-3">
            <div className="w-12 h-12 rounded-full bg-navy-850 flex items-center justify-center text-slate-500">
              <Server className="w-6 h-6" />
            </div>
            <div className="font-medium text-slate-300 text-sm">No Authorized Assets Registered</div>
            <p className="text-slate-500 max-w-sm">
              Add your SMB web applications, APIs, public IPs, or host servers to establish your authorized attack surface inventory.
            </p>
            {canWrite && (
              <button
                onClick={() => setShowAddModal(true)}
                className="mt-2 px-3 py-1.5 rounded-lg bg-cyan-600 hover:bg-cyan-500 text-white text-xs font-medium"
              >
                Register First Asset
              </button>
            )}
          </div>
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full text-left text-xs">
              <thead className="bg-navy-850 text-slate-400 uppercase font-mono tracking-wider border-b border-navy-800">
                <tr>
                  <th className="py-3 px-4">Asset Name</th>
                  <th className="py-3 px-4">Type</th>
                  <th className="py-3 px-4">Target / Endpoint</th>
                  <th className="py-3 px-4">Environment</th>
                  <th className="py-3 px-4">Criticality</th>
                  <th className="py-3 px-4">Scope</th>
                  <th className="py-3 px-4 text-right">Actions</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-navy-800 font-mono">
                {assets.map((asset) => (
                  <tr key={asset.id} className="hover:bg-navy-850/50 transition-colors">
                    <td className="py-3 px-4 font-sans font-semibold text-slate-200">
                      {asset.name}
                    </td>
                    <td className="py-3 px-4">
                      <span className="px-2 py-0.5 rounded text-[10px] bg-navy-800 text-cyan-300 border border-navy-700">
                        {asset.asset_type}
                      </span>
                    </td>
                    <td className="py-3 px-4 text-slate-300">{asset.target}</td>
                    <td className="py-3 px-4">
                      <span className="text-slate-400">{asset.environment}</span>
                    </td>
                    <td className="py-3 px-4">
                      <span
                        className={`px-2 py-0.5 rounded text-[10px] font-semibold ${
                          asset.criticality === 'CRITICAL'
                            ? 'bg-rose-950 text-rose-300 border border-rose-800/60'
                            : asset.criticality === 'HIGH'
                            ? 'bg-amber-950 text-amber-300 border border-amber-800/60'
                            : 'bg-slate-800 text-slate-300'
                        }`}
                      >
                        {asset.criticality}
                      </span>
                    </td>
                    <td className="py-3 px-4">
                      <span className="inline-flex items-center gap-1 text-emerald-400 text-[11px]">
                        <CheckCircle2 className="w-3.5 h-3.5" />
                        <span>AUTHORIZED</span>
                      </span>
                    </td>
                    <td className="py-3 px-4 text-right font-sans">
                      {canDelete && (
                        <button
                          onClick={() => handleDeleteAsset(asset.id, asset.name)}
                          title="Remove asset"
                          className="p-1 rounded text-slate-500 hover:text-rose-400 transition-colors cursor-pointer"
                        >
                          <Trash2 className="w-4 h-4" />
                        </button>
                      )}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </div>

      {/* Add Modal */}
      {showAddModal && (
        <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-navy-950/80 backdrop-blur-sm">
          <div className="bg-navy-900 border border-navy-800 rounded-2xl w-full max-w-lg p-6 shadow-2xl space-y-4">
            <div className="flex items-center justify-between pb-3 border-b border-navy-800">
              <h2 className="text-base font-bold text-white flex items-center gap-2">
                <Server className="w-4 h-4 text-cyan-400" />
                <span>Onboard Authorized Asset</span>
              </h2>
              <button
                onClick={() => setShowAddModal(false)}
                className="text-slate-400 hover:text-slate-200 text-sm font-mono"
              >
                ✕
              </button>
            </div>

            <form onSubmit={handleCreateAsset} className="space-y-4">
              <div>
                <label className="block text-xs font-medium text-slate-300 uppercase tracking-wider mb-1">
                  Asset Title
                </label>
                <input
                  type="text"
                  required
                  placeholder="e.g. Core Banking API Gateway"
                  value={name}
                  onChange={(e) => setName(e.target.value)}
                  className="w-full px-3 py-2 bg-navy-850 border border-navy-700 rounded-lg text-sm text-slate-100 focus:outline-none focus:ring-1 focus:ring-cyan-500"
                />
              </div>

              <div className="grid grid-cols-2 gap-3">
                <div>
                  <label className="block text-xs font-medium text-slate-300 uppercase tracking-wider mb-1">
                    Asset Type
                  </label>
                  <select
                    value={assetType}
                    onChange={(e) => setAssetType(e.target.value as AssetType)}
                    className="w-full px-3 py-2 bg-navy-850 border border-navy-700 rounded-lg text-sm text-slate-100 focus:outline-none focus:ring-1 focus:ring-cyan-500"
                  >
                    <option value="WEB_APPLICATION">Web Application</option>
                    <option value="API_GATEWAY">API Gateway</option>
                    <option value="PUBLIC_IP">Public IP Address</option>
                    <option value="INTERNAL_SERVER">Internal Server</option>
                    <option value="DOMAIN">Domain Name (FQDN)</option>
                  </select>
                </div>

                <div>
                  <label className="block text-xs font-medium text-slate-300 uppercase tracking-wider mb-1">
                    Criticality
                  </label>
                  <select
                    value={criticality}
                    onChange={(e) => setCriticality(e.target.value as CriticalityType)}
                    className="w-full px-3 py-2 bg-navy-850 border border-navy-700 rounded-lg text-sm text-slate-100 focus:outline-none focus:ring-1 focus:ring-cyan-500"
                  >
                    <option value="CRITICAL">Critical</option>
                    <option value="HIGH">High</option>
                    <option value="MEDIUM">Medium</option>
                    <option value="LOW">Low</option>
                  </select>
                </div>
              </div>

              <div>
                <label className="block text-xs font-medium text-slate-300 uppercase tracking-wider mb-1">
                  Target Endpoint / IP / URL
                </label>
                <input
                  type="text"
                  required
                  placeholder="https://api.smbclient.in or 203.0.113.10"
                  value={target}
                  onChange={(e) => setTarget(e.target.value)}
                  className="w-full px-3 py-2 bg-navy-850 border border-navy-700 rounded-lg text-sm text-slate-100 font-mono focus:outline-none focus:ring-1 focus:ring-cyan-500"
                />
              </div>

              <div>
                <label className="block text-xs font-medium text-slate-300 uppercase tracking-wider mb-1">
                  Environment
                </label>
                <select
                  value={environment}
                  onChange={(e) => setEnvironment(e.target.value as EnvironmentType)}
                  className="w-full px-3 py-2 bg-navy-850 border border-navy-700 rounded-lg text-sm text-slate-100 focus:outline-none focus:ring-1 focus:ring-cyan-500"
                >
                  <option value="PRODUCTION">Production</option>
                  <option value="STAGING">Staging</option>
                  <option value="DEVELOPMENT">Development</option>
                </select>
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
                  className="px-4 py-2 rounded-lg bg-cyan-600 hover:bg-cyan-500 text-white text-xs font-semibold shadow-lg shadow-cyan-600/20 disabled:opacity-50 cursor-pointer"
                >
                  {creating ? 'Registering...' : 'Confirm Authorization & Save'}
                </button>
              </div>
            </form>
          </div>
        </div>
      )}
    </div>
  );
};
