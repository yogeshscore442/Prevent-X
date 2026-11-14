import React, { useState, useEffect } from 'react';
import { Activity, Database, Server, Cpu, RefreshCw, CheckCircle2, AlertTriangle, XCircle, Loader2 } from 'lucide-react';
import { api } from '@/services/api';
import { HealthInfo, ReadinessInfo, SystemInfo } from '@/types/system';

export const SystemHealthPage: React.FC = () => {
  const [health, setHealth] = useState<HealthInfo | null>(null);
  const [readiness, setReadiness] = useState<ReadinessInfo | null>(null);
  const [systemInfo, setSystemInfo] = useState<SystemInfo | null>(null);
  const [loading, setLoading] = useState(true);

  const fetchTelemetry = async () => {
    setLoading(true);
    try {
      const [hRes, rRes, sRes] = await Promise.all([
        api.get('/health'),
        api.get('/ready'),
        api.get('/system/info'),
      ]);
      setHealth(hRes.data);
      setReadiness(rRes.data);
      setSystemInfo(sRes.data);
    } catch (e) {
      console.error('Failed to fetch system telemetry', e);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchTelemetry();
  }, []);

  return (
    <div className="space-y-6 max-w-7xl mx-auto">
      {/* Header */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 pb-4 border-b border-navy-800">
        <div>
          <h1 className="text-xl font-bold text-white flex items-center gap-2">
            <Activity className="w-5 h-5 text-emerald-400" />
            <span>Infrastructure Health & Readiness Telemetry</span>
          </h1>
          <p className="text-xs text-slate-400 mt-1">
            Real-time verification of backend API, database connection pool latency, and background worker queues.
          </p>
        </div>

        <button
          onClick={fetchTelemetry}
          className="inline-flex items-center gap-2 px-3 py-1.5 rounded-lg bg-navy-850 hover:bg-navy-800 border border-navy-700 text-slate-300 text-xs font-mono transition-colors cursor-pointer"
        >
          <RefreshCw className={`w-3.5 h-3.5 ${loading ? 'animate-spin' : ''}`} />
          <span>Probe Health</span>
        </button>
      </div>

      {loading ? (
        <div className="py-16 text-center text-slate-400 text-xs flex flex-col items-center gap-2">
          <Loader2 className="w-6 h-6 animate-spin text-emerald-500" />
          <span>Probing system endpoints...</span>
        </div>
      ) : (
        <div className="space-y-6">
          {/* Readiness Indicators */}
          <div className="grid grid-cols-1 md:grid-cols-3 gap-5">
            {/* Core API */}
            <div className="p-5 bg-navy-900 border border-navy-800 rounded-xl shadow-lg">
              <div className="flex items-center justify-between mb-3">
                <span className="text-xs font-semibold text-slate-400 uppercase tracking-wider">FastAPI Core</span>
                <Server className="w-4 h-4 text-cyan-400" />
              </div>
              <div className="flex items-center gap-2">
                <CheckCircle2 className="w-5 h-5 text-emerald-400" />
                <span className="text-lg font-bold text-white font-mono">{health?.status || 'UNKNOWN'}</span>
              </div>
              <div className="text-xs text-slate-400 mt-3 font-mono">
                Environment: {health?.environment}
              </div>
            </div>

            {/* Database Engine */}
            <div className="p-5 bg-navy-900 border border-navy-800 rounded-xl shadow-lg">
              <div className="flex items-center justify-between mb-3">
                <span className="text-xs font-semibold text-slate-400 uppercase tracking-wider">Database Engine</span>
                <Database className="w-4 h-4 text-emerald-400" />
              </div>
              <div className="flex items-center gap-2">
                {readiness?.database?.status === 'UP' ? (
                  <CheckCircle2 className="w-5 h-5 text-emerald-400" />
                ) : (
                  <XCircle className="w-5 h-5 text-rose-400" />
                )}
                <span className="text-lg font-bold text-white font-mono">
                  {readiness?.database?.status || 'DOWN'}
                </span>
              </div>
              <div className="text-xs text-slate-400 mt-3 font-mono flex items-center justify-between">
                <span>Latency: {readiness?.database?.latency_ms ?? '--'} ms</span>
                <span className="text-slate-500 uppercase">{systemInfo?.database_backend}</span>
              </div>
            </div>

            {/* Redis Cache / Queue */}
            <div className="p-5 bg-navy-900 border border-navy-800 rounded-xl shadow-lg">
              <div className="flex items-center justify-between mb-3">
                <span className="text-xs font-semibold text-slate-400 uppercase tracking-wider">Redis Broker</span>
                <Cpu className="w-4 h-4 text-amber-400" />
              </div>
              <div className="flex items-center gap-2">
                {readiness?.redis?.status === 'UP' ? (
                  <CheckCircle2 className="w-5 h-5 text-emerald-400" />
                ) : (
                  <AlertTriangle className="w-5 h-5 text-amber-400" />
                )}
                <span className="text-lg font-bold text-white font-mono">
                  {readiness?.redis?.status || 'DOWN'}
                </span>
              </div>
              <div className="text-xs text-slate-400 mt-3 font-mono truncate" title={readiness?.redis?.details}>
                {readiness?.redis?.details}
              </div>
            </div>
          </div>

          {/* System Environment Specification */}
          <div className="bg-navy-900 border border-navy-800 rounded-xl p-6 shadow-xl">
            <h2 className="text-base font-bold text-white mb-4">Runtime Platform Specifications</h2>
            <div className="grid grid-cols-1 sm:grid-cols-2 md:grid-cols-4 gap-4 font-mono text-xs">
              <div className="p-3 bg-navy-850 rounded-lg border border-navy-800">
                <div className="text-slate-500 uppercase text-[10px]">App Name</div>
                <div className="text-slate-200 font-bold mt-1">{systemInfo?.app_name}</div>
              </div>

              <div className="p-3 bg-navy-850 rounded-lg border border-navy-800">
                <div className="text-slate-500 uppercase text-[10px]">Version</div>
                <div className="text-cyan-400 font-bold mt-1">v{systemInfo?.app_version}</div>
              </div>

              <div className="p-3 bg-navy-850 rounded-lg border border-navy-800">
                <div className="text-slate-500 uppercase text-[10px]">Python Runtime</div>
                <div className="text-slate-200 font-bold mt-1">{systemInfo?.python_version}</div>
              </div>

              <div className="p-3 bg-navy-850 rounded-lg border border-navy-800">
                <div className="text-slate-500 uppercase text-[10px]">ORM Dialect</div>
                <div className="text-slate-200 font-bold mt-1 uppercase">{systemInfo?.database_backend}</div>
              </div>
            </div>
          </div>
        </div>
      )}
    </div>
  );
};

