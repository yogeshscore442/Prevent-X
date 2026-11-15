import React, { useState, useEffect } from 'react';
import { FileText, AlertCircle, CheckCircle, XCircle, Loader2, RefreshCw } from 'lucide-react';
import { api } from '@/services/api';
import { AuditEvent } from '@/types/audit';
import { formatErrorMessage } from '@/utils/formatError';

export const AuditLogsPage: React.FC = () => {
  const [logs, setLogs] = useState<AuditEvent[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  const fetchLogs = async () => {
    setLoading(true);
    try {
      const resp = await api.get('/audit-logs?limit=100');
      const items = Array.isArray(resp.data) ? resp.data : (resp.data?.items || []);
      setLogs(items);
    } catch (err: any) {
      setError(err.response?.data?.detail?.message || 'Failed to retrieve audit trail');
      setLogs([]);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchLogs();
  }, []);

  return (
    <div className="space-y-6 max-w-7xl mx-auto">
      {/* Header */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 pb-4 border-b border-navy-800">
        <div>
          <h1 className="text-xl font-bold text-white flex items-center gap-2">
            <FileText className="w-5 h-5 text-emerald-400" />
            <span>Cryptographic Audit Trail</span>
          </h1>
          <p className="text-xs text-slate-400 mt-1">
            Immutable, structured security audit events verifying tenant integrity, administrative changes, and auth operations.
          </p>
        </div>

        <button
          onClick={fetchLogs}
          className="inline-flex items-center gap-2 px-3 py-1.5 rounded-lg bg-navy-850 hover:bg-navy-800 border border-navy-700 text-slate-300 text-xs font-mono transition-colors cursor-pointer"
        >
          <RefreshCw className={`w-3.5 h-3.5 ${loading ? 'animate-spin' : ''}`} />
          <span>Refresh Trail</span>
        </button>
      </div>

      {error && (
        <div className="p-3 rounded-lg bg-rose-950/60 border border-rose-800 text-rose-300 text-xs flex items-center gap-2">
          <AlertCircle className="w-4 h-4 flex-shrink-0" />
          <span>{typeof error === 'string' ? error : formatErrorMessage(error)}</span>
        </div>
      )}

      {/* Logs Table */}
      <div className="bg-navy-900 border border-navy-800 rounded-xl overflow-hidden shadow-xl">
        {loading ? (
          <div className="py-16 text-center text-slate-400 text-xs flex flex-col items-center gap-2">
            <Loader2 className="w-6 h-6 animate-spin text-emerald-500" />
            <span>Streaming audit records...</span>
          </div>
        ) : (logs || []).length === 0 ? (
          <div className="py-16 text-center text-slate-400 text-xs">
            No audit records found in current organization scope.
          </div>
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full text-left text-xs font-mono">
              <thead className="bg-navy-850 text-slate-400 uppercase tracking-wider border-b border-navy-800">
                <tr>
                  <th className="py-3 px-4">Timestamp (UTC)</th>
                  <th className="py-3 px-4">Action</th>
                  <th className="py-3 px-4">Resource</th>
                  <th className="py-3 px-4">Status</th>
                  <th className="py-3 px-4">Client IP</th>
                  <th className="py-3 px-4">Details</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-navy-800 text-[11px]">
                {(logs || []).map((log) => (
                  <tr key={log.id} className="hover:bg-navy-850/50 transition-colors">
                    <td className="py-3 px-4 text-slate-400 whitespace-nowrap">
                      {new Date(log.created_at).toISOString().replace('T', ' ').slice(0, 19)}
                    </td>
                    <td className="py-3 px-4">
                      <span className="text-cyan-300 font-semibold">{log.action}</span>
                    </td>
                    <td className="py-3 px-4">
                      <span className="text-slate-300">{log.resource_type}</span>
                    </td>
                    <td className="py-3 px-4">
                      {log.status === 'SUCCESS' ? (
                        <span className="inline-flex items-center gap-1 text-emerald-400">
                          <CheckCircle className="w-3 h-3" />
                          <span>SUCCESS</span>
                        </span>
                      ) : (
                        <span className="inline-flex items-center gap-1 text-rose-400">
                          <XCircle className="w-3 h-3" />
                          <span>{log.status}</span>
                        </span>
                      )}
                    </td>
                    <td className="py-3 px-4 text-slate-400">{log.ip_address || 'internal'}</td>
                    <td className="py-3 px-4 text-slate-300 max-w-xs truncate" title={log.details || ''}>
                      {log.details || '-'}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </div>
    </div>
  );
};
