import React, { useState, useEffect, useCallback } from 'react';
import {
  Globe,
  Search,
  ShieldAlert,
  Eye,
  RefreshCw,
  Server,
  Play,
  X,
  Layers,
  Activity,
  FileText,
  AlertCircle,
} from 'lucide-react';
import { attackSurfaceApi } from '@/services/attackSurfaceApi';
import { api } from '@/services/api';
import {
  AttackSurfaceOverview,
  DiscoveryJob,
  DiscoveredDomain,
  ExposureFinding,
} from '@/types/attackSurface';

interface AssetOption {
  id: string;
  name: string;
  target: string;
  is_in_scope: boolean;
}

export const AttackSurfacePage: React.FC = () => {
  const [activeTab, setActiveTab] = useState<'overview' | 'discovery' | 'domains' | 'findings'>('overview');
  const [overview, setOverview] = useState<AttackSurfaceOverview | null>(null);
  const [jobs, setJobs] = useState<DiscoveryJob[]>([]);
  const [activeJob, setActiveJob] = useState<DiscoveryJob | null>(null);
  const [domains, setDomains] = useState<DiscoveredDomain[]>([]);
  const [findings, setFindings] = useState<ExposureFinding[]>([]);
  const [assets, setAssets] = useState<AssetOption[]>([]);
  const [isLoading, setIsLoading] = useState<boolean>(true);
  const [error, setError] = useState<string | null>(null);

  // Discovery Form State
  const [selectedAssetId, setSelectedAssetId] = useState<string>('');
  const [discoveryPolicy, setDiscoveryPolicy] = useState<'PUBLIC_PASSIVE' | 'AUTHORIZED_INTERNAL'>('PUBLIC_PASSIVE');
  const [customSubdomain, setCustomSubdomain] = useState<string>('');
  const [authConfirmed, setAuthConfirmed] = useState<boolean>(false);
  const [isSubmittingJob, setIsSubmittingJob] = useState<boolean>(false);

  // Inspection Drawer State
  const [inspectDomain, setInspectDomain] = useState<DiscoveredDomain | null>(null);
  const [inspectFinding, setInspectFinding] = useState<ExposureFinding | null>(null);
  const [domainSearch, setDomainSearch] = useState<string>('');
  const [findingSeverityFilter, setFindingSeverityFilter] = useState<string>('ALL');
  const [findingCategoryFilter, setFindingCategoryFilter] = useState<string>('ALL');
  const [findingNatureFilter, setFindingNatureFilter] = useState<string>('ALL');

  // Load Initial Data
  const loadInitialData = useCallback(async () => {
    try {
      setIsLoading(true);
      setError(null);
      const [ovData, jobsData, domainsData, findingsData, assetsRes] = await Promise.all([
        attackSurfaceApi.getOverview(),
        attackSurfaceApi.listJobs(),
        attackSurfaceApi.listDomains(),
        attackSurfaceApi.listFindings(),
        api.get('/assets'),
      ]);

      setOverview(ovData);
      setJobs(jobsData);
      setDomains(domainsData);
      setFindings(findingsData);

      const assetList = (assetsRes.data?.items || assetsRes.data || []) as AssetOption[];
      setAssets(assetList.filter((a) => a.is_in_scope));
      if (assetList.length > 0 && !selectedAssetId) {
        setSelectedAssetId(assetList[0].id);
      }

      // Check if any job is currently in progress
      const running = jobsData.find((j) => j.status === 'RUNNING' || j.status === 'QUEUED');
      if (running) {
        setActiveJob(running);
      }
    } catch (err: any) {
      setError(err?.response?.data?.detail || 'Failed to initialize attack surface engine.');
    } finally {
      setIsLoading(false);
    }
  }, [selectedAssetId]);

  useEffect(() => {
    loadInitialData();
  }, [loadInitialData]);

  // Polling for active running discovery job
  useEffect(() => {
    let interval: NodeJS.Timeout;
    if (activeJob && (activeJob.status === 'RUNNING' || activeJob.status === 'QUEUED')) {
      interval = setInterval(async () => {
        try {
          const updated = await attackSurfaceApi.getJob(activeJob.id);
          setActiveJob(updated);
          if (updated.status !== 'RUNNING' && updated.status !== 'QUEUED') {
            // Job concluded, reload all telemetry
            loadInitialData();
          }
        } catch {
          // ignore transient poll error
        }
      }, 3000);
    }
    return () => {
      if (interval) clearInterval(interval);
    };
  }, [activeJob, loadInitialData]);

  const handleLaunchDiscovery = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!selectedAssetId || !authConfirmed) return;

    try {
      setIsSubmittingJob(true);
      setError(null);
      const created = await attackSurfaceApi.createJob({
        asset_id: selectedAssetId,
        target_domain: customSubdomain.trim() || undefined,
        authorization_confirmed: authConfirmed,
        discovery_policy: discoveryPolicy,
      });

      setActiveJob(created);
      setJobs((prev) => [created, ...prev]);
      setActiveTab('discovery');
    } catch (err: any) {
      setError(err?.response?.data?.detail || 'Failed to trigger discovery job.');
    } finally {
      setIsSubmittingJob(false);
    }
  };

  const handleCancelJob = async (jobId: string) => {
    try {
      const cancelled = await attackSurfaceApi.cancelJob(jobId, 'Cancelled by user from Discovery Center');
      setActiveJob(cancelled);
      setJobs((prev) => prev.map((j) => (j.id === jobId ? cancelled : j)));
    } catch (err: any) {
      setError(err?.response?.data?.detail || 'Failed to cancel discovery job.');
    }
  };

  const handleInspectDomain = async (domainId: string) => {
    try {
      const detail = await attackSurfaceApi.getDomainDetail(domainId);
      setInspectDomain(detail);
    } catch (err: any) {
      setError(err?.response?.data?.detail || 'Failed to load domain inspection details.');
    }
  };

  const filteredDomains = domains.filter((d) =>
    domainSearch ? d.domain_name.toLowerCase().includes(domainSearch.toLowerCase()) : true
  );

  const filteredFindings = findings.filter((f) => {
    const matchSev = findingSeverityFilter === 'ALL' || f.severity === findingSeverityFilter;
    const matchCat = findingCategoryFilter === 'ALL' || f.finding_category === findingCategoryFilter;
    const matchNature = findingNatureFilter === 'ALL' || f.evidence_nature === findingNatureFilter;
    return matchSev && matchCat && matchNature;
  });

  const getSeverityBadgeClass = (severity: string) => {
    switch (severity.toUpperCase()) {
      case 'CRITICAL':
        return 'bg-rose-950/60 border-rose-500/50 text-rose-300';
      case 'HIGH':
        return 'bg-amber-950/60 border-amber-500/50 text-amber-300';
      case 'MEDIUM':
        return 'bg-yellow-950/60 border-yellow-500/50 text-yellow-300';
      case 'LOW':
        return 'bg-blue-950/60 border-blue-500/50 text-blue-300';
      default:
        return 'bg-slate-800 border-slate-700 text-slate-300';
    }
  };

  const getRiskScoreColor = (score: number) => {
    if (score >= 75) return 'text-rose-400 border-rose-500 bg-rose-950/30';
    if (score >= 50) return 'text-amber-400 border-amber-500 bg-amber-950/30';
    if (score >= 20) return 'text-yellow-400 border-yellow-500 bg-yellow-950/30';
    return 'text-emerald-400 border-emerald-500 bg-emerald-950/30';
  };

  return (
    <div className="flex-1 overflow-y-auto p-6 space-y-6">
      {/* Header */}
      <div className="flex flex-col md:flex-row md:items-center md:justify-between gap-4 border-b border-navy-800 pb-5">
        <div>
          <div className="flex items-center gap-3">
            <div className="w-10 h-10 rounded-lg bg-cyan-950/80 border border-cyan-500/30 flex items-center justify-center">
              <Globe className="w-6 h-6 text-cyan-400" />
            </div>
            <div>
              <h1 className="text-xl font-bold tracking-tight text-white flex items-center gap-2">
                Attack Surface Intelligence
                <span className="text-[10px] font-mono px-2 py-0.5 rounded bg-cyan-950 text-cyan-400 border border-cyan-800">
                  MOD-01 (Phase 2)
                </span>
              </h1>
              <p className="text-xs text-slate-400">
                Continuous passive external intelligence, Certificate Transparency logs, DNS posture, and exposure telemetry.
              </p>
            </div>
          </div>
        </div>

        {/* Global Tab Navigation */}
        <div className="flex items-center gap-1.5 bg-navy-900 border border-navy-800 p-1 rounded-lg">
          <button
            onClick={() => setActiveTab('overview')}
            className={`px-3 py-1.5 rounded-md text-xs font-medium transition-colors flex items-center gap-1.5 ${
              activeTab === 'overview' ? 'bg-cyan-600 text-white shadow' : 'text-slate-400 hover:text-white'
            }`}
          >
            <Activity className="w-3.5 h-3.5" />
            Overview
          </button>
          <button
            onClick={() => setActiveTab('discovery')}
            className={`px-3 py-1.5 rounded-md text-xs font-medium transition-colors flex items-center gap-1.5 ${
              activeTab === 'discovery' ? 'bg-cyan-600 text-white shadow' : 'text-slate-400 hover:text-white'
            }`}
          >
            <Play className="w-3.5 h-3.5" />
            Discovery Center
            {activeJob && (activeJob.status === 'RUNNING' || activeJob.status === 'QUEUED') && (
              <span className="w-2 h-2 rounded-full bg-cyan-400 animate-pulse ml-1" />
            )}
          </button>
          <button
            onClick={() => setActiveTab('domains')}
            className={`px-3 py-1.5 rounded-md text-xs font-medium transition-colors flex items-center gap-1.5 ${
              activeTab === 'domains' ? 'bg-cyan-600 text-white shadow' : 'text-slate-400 hover:text-white'
            }`}
          >
            <Layers className="w-3.5 h-3.5" />
            Discovered Assets ({domains.length})
          </button>
          <button
            onClick={() => setActiveTab('findings')}
            className={`px-3 py-1.5 rounded-md text-xs font-medium transition-colors flex items-center gap-1.5 ${
              activeTab === 'findings' ? 'bg-cyan-600 text-white shadow' : 'text-slate-400 hover:text-white'
            }`}
          >
            <ShieldAlert className="w-3.5 h-3.5" />
            Findings ({findings.length})
          </button>
          <button
            onClick={loadInitialData}
            title="Refresh Telemetry"
            className="p-1.5 text-slate-400 hover:text-cyan-400 transition-colors ml-1"
          >
            <RefreshCw className={`w-3.5 h-3.5 ${isLoading ? 'animate-spin' : ''}`} />
          </button>
        </div>
      </div>

      {error && (
        <div className="p-3.5 bg-rose-950/60 border border-rose-500/40 rounded-lg flex items-center justify-between text-xs text-rose-300">
          <div className="flex items-center gap-2">
            <AlertCircle className="w-4 h-4 flex-shrink-0" />
            <span>{error}</span>
          </div>
          <button onClick={() => setError(null)} className="text-slate-400 hover:text-white">
            <X className="w-4 h-4" />
          </button>
        </div>
      )}

      {/* =========================================================================
          SECTION 1: OVERVIEW & RISK METRICS
      ========================================================================= */}
      {activeTab === 'overview' && (
        <div className="space-y-6">
          {/* Top Metrics Cards */}
          <div className="grid grid-cols-1 md:grid-cols-4 gap-4">
            <div className="bg-navy-900 border border-navy-800 rounded-xl p-5 shadow-sm">
              <div className="flex items-center justify-between">
                <span className="text-xs font-medium text-slate-400">Discovered Domains</span>
                <Globe className="w-4 h-4 text-cyan-400" />
              </div>
              <div className="mt-2 text-2xl font-bold font-mono text-white">
                {overview?.total_discovered_domains ?? 0}
              </div>
              <p className="mt-1 text-[11px] text-slate-400">External FQDNs observed via CT logs</p>
            </div>

            <div className="bg-navy-900 border border-navy-800 rounded-xl p-5 shadow-sm">
              <div className="flex items-center justify-between">
                <span className="text-xs font-medium text-slate-400">Public IP Footprint</span>
                <Server className="w-4 h-4 text-blue-400" />
              </div>
              <div className="mt-2 text-2xl font-bold font-mono text-white">
                {overview?.total_public_ips ?? 0}
              </div>
              <p className="mt-1 text-[11px] text-slate-400">Routable IPv4/IPv6 endpoints</p>
            </div>

            <div className="bg-navy-900 border border-navy-800 rounded-xl p-5 shadow-sm">
              <div className="flex items-center justify-between">
                <span className="text-xs font-medium text-slate-400">Active Exposure Findings</span>
                <ShieldAlert className="w-4 h-4 text-amber-400" />
              </div>
              <div className="mt-2 text-2xl font-bold font-mono text-white">
                {overview?.active_findings_count ?? 0}
              </div>
              <p className="mt-1 text-[11px] text-slate-400">Identified misconfigurations & exposures</p>
            </div>

            <div
              className={`bg-navy-900 border rounded-xl p-5 shadow-sm ${getRiskScoreColor(
                overview?.average_exposure_score ?? 0
              )}`}
            >
              <div className="flex items-center justify-between">
                <span className="text-xs font-medium">Exposure Risk Score</span>
                <span className="text-[10px] font-mono px-2 py-0.5 rounded border uppercase">
                  {overview?.average_exposure_score && overview.average_exposure_score >= 75
                    ? 'CRITICAL'
                    : overview?.average_exposure_score && overview.average_exposure_score >= 50
                    ? 'HIGH'
                    : overview?.average_exposure_score && overview.average_exposure_score >= 20
                    ? 'MEDIUM'
                    : 'LOW'}
                </span>
              </div>
              <div className="mt-2 text-2xl font-bold font-mono">
                {overview?.average_exposure_score?.toFixed(1) ?? '0.0'} / 100
              </div>
              {/* Progress bar */}
              <div className="mt-2 w-full bg-navy-950 rounded-full h-1.5 overflow-hidden">
                <div
                  className="bg-current h-full transition-all duration-500"
                  style={{ width: `${Math.min(overview?.average_exposure_score ?? 0, 100)}%` }}
                />
              </div>
            </div>
          </div>

          {/* Explainable Risk Scoring Engine Breakdown */}
          <div className="bg-navy-900 border border-navy-800 rounded-xl p-6 space-y-4">
            <div className="flex items-center justify-between">
              <div>
                <h2 className="text-base font-semibold text-white flex items-center gap-2">
                  <ShieldAlert className="w-4 h-4 text-cyan-400" />
                  Deterministic Risk Scoring Model (0–100 Scale)
                </h2>
                <p className="text-xs text-slate-400">
                  Fully explainable mathematical evaluation with transparent factor weights. No black-box machine learning.
                </p>
              </div>
              <span className="text-[11px] font-mono text-cyan-400 bg-navy-850 px-2.5 py-1 rounded border border-navy-700">
                NASSCOM PS-05 Exposure Model
              </span>
            </div>

            <div className="grid grid-cols-1 md:grid-cols-3 gap-4 pt-2">
              <div className="p-4 rounded-lg bg-navy-950/60 border border-navy-800">
                <div className="flex items-center justify-between text-xs font-semibold text-slate-200">
                  <span>1. Perimeter Breadth & Sprawl</span>
                  <span className="font-mono text-cyan-400">Max 20 pts</span>
                </div>
                <p className="text-[11px] text-slate-400 mt-1">
                  Exposure indicator measuring external perimeter. &gt;5 subdomains adds 12 pts; &gt;20 subdomains adds 20 pts. Not proof of compromise.
                </p>
              </div>

              <div className="p-4 rounded-lg bg-navy-950/60 border border-navy-800">
                <div className="flex items-center justify-between text-xs font-semibold text-slate-200">
                  <span>2. Certificate Scope Posture</span>
                  <span className="font-mono text-cyan-400">Max 15 pts</span>
                </div>
                <p className="text-[11px] text-slate-400 mt-1">
                  Architecture indicator. Wildcard TLS certificates (+10 pts) expand compromise blast radius across all hostnames.
                </p>
              </div>

              <div className="p-4 rounded-lg bg-navy-950/60 border border-navy-800">
                <div className="flex items-center justify-between text-xs font-semibold text-slate-200">
                  <span>3. Service Availability (TLS)</span>
                  <span className="font-mono text-cyan-400">Max 20 pts</span>
                </div>
                <p className="text-[11px] text-slate-400 mt-1">
                  Evaluates service availability and trust breakdown. Expired certificate (+20 pts) breaks visitor access. Not code exploitability.
                </p>
              </div>

              <div className="p-4 rounded-lg bg-navy-950/60 border border-navy-800">
                <div className="flex items-center justify-between text-xs font-semibold text-slate-200">
                  <span>4. Email Spoofing Defense</span>
                  <span className="font-mono text-cyan-400">Max 20 pts</span>
                </div>
                <p className="text-[11px] text-slate-400 mt-1">
                  Evaluates domain spoofing hygiene. Missing SPF and DMARC (+20 pts) allows email impersonation. Distinct from app exposure.
                </p>
              </div>

              <div className="p-4 rounded-lg bg-navy-950/60 border border-navy-800">
                <div className="flex items-center justify-between text-xs font-semibold text-slate-200">
                  <span>5. Resource Takeover Indicators</span>
                  <span className="font-mono text-cyan-400">Max 15 pts</span>
                </div>
                <p className="text-[11px] text-slate-400 mt-1">
                  Distinguishes verified unclaimed resources via NXDOMAIN (+15 pts) from unverified third-party cloud CNAME pointers (+7.5 pts).
                </p>
              </div>

              <div className="p-4 rounded-lg bg-navy-950/60 border border-navy-800">
                <div className="flex items-center justify-between text-xs font-semibold text-slate-200">
                  <span>6. Network Topology Exposure</span>
                  <span className="font-mono text-cyan-400">Max 10 pts</span>
                </div>
                <p className="text-[11px] text-slate-400 mt-1">
                  Private RFC 1918 addresses (+10 pts) leaked in public DNS reveal internal network numbering.
                </p>
              </div>
            </div>
          </div>

          {/* Severity & Category Distributions */}
          <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
            <div className="bg-navy-900 border border-navy-800 rounded-xl p-5 space-y-3">
              <h3 className="text-sm font-semibold text-white">Findings by Severity</h3>
              <div className="space-y-2">
                {['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO'].map((sev) => {
                  const count = overview?.findings_by_severity?.[sev] || 0;
                  return (
                    <div key={sev} className="flex items-center justify-between text-xs">
                      <span className={`px-2 py-0.5 rounded border text-[11px] font-mono ${getSeverityBadgeClass(sev)}`}>
                        {sev}
                      </span>
                      <span className="font-mono text-slate-300 font-medium">{count}</span>
                    </div>
                  );
                })}
              </div>
            </div>

            <div className="bg-navy-900 border border-navy-800 rounded-xl p-5 space-y-3">
              <h3 className="text-sm font-semibold text-white">Recent Discovery Jobs</h3>
              {overview?.recent_jobs && overview.recent_jobs.length > 0 ? (
                <div className="space-y-2">
                  {overview.recent_jobs.map((j) => (
                    <div
                      key={j.id}
                      className="p-2.5 rounded-lg bg-navy-950/60 border border-navy-800 flex items-center justify-between text-xs"
                    >
                      <div>
                        <div className="font-mono font-medium text-slate-200">{j.target_domain}</div>
                        <div className="text-[10px] text-slate-400">
                          {new Date(j.created_at).toLocaleString()} • {j.domains_discovered_count} domains
                        </div>
                      </div>
                      <span
                        className={`px-2 py-0.5 rounded text-[10px] font-mono border ${
                          j.status === 'COMPLETED'
                            ? 'bg-emerald-950/60 border-emerald-500/50 text-emerald-300'
                            : j.status === 'RUNNING'
                            ? 'bg-cyan-950/60 border-cyan-500/50 text-cyan-300 animate-pulse'
                            : j.status === 'FAILED'
                            ? 'bg-rose-950/60 border-rose-500/50 text-rose-300'
                            : 'bg-slate-800 border-slate-700 text-slate-300'
                        }`}
                      >
                        {j.status}
                      </span>
                    </div>
                  ))}
                </div>
              ) : (
                <p className="text-xs text-slate-400 italic">No discovery runs logged yet.</p>
              )}
            </div>
          </div>
        </div>
      )}

      {/* =========================================================================
          SECTION 2: DISCOVERY CENTER
      ========================================================================= */}
      {activeTab === 'discovery' && (
        <div className="space-y-6">
          {/* Active Job Real-Time Card */}
          {activeJob && (activeJob.status === 'RUNNING' || activeJob.status === 'QUEUED') && (
            <div className="bg-cyan-950/40 border border-cyan-500/40 rounded-xl p-5 space-y-3">
              <div className="flex items-center justify-between">
                <div className="flex items-center gap-2.5">
                  <RefreshCw className="w-4 h-4 text-cyan-400 animate-spin" />
                  <span className="text-sm font-semibold text-cyan-200">
                    Active Discovery In Progress: {activeJob.target_domain}
                  </span>
                </div>
                <button
                  onClick={() => handleCancelJob(activeJob.id)}
                  className="px-2.5 py-1 text-xs font-medium text-rose-300 hover:text-white bg-rose-950/80 hover:bg-rose-900 border border-rose-600/50 rounded-md transition-colors"
                >
                  Cancel Job
                </button>
              </div>

              {/* Progress Bar */}
              <div className="space-y-1">
                <div className="flex justify-between text-xs font-mono text-cyan-300">
                  <span>Stage: {activeJob.current_stage}</span>
                  <span>{activeJob.progress_percent}%</span>
                </div>
                <div className="w-full bg-navy-950 rounded-full h-2 overflow-hidden border border-cyan-800">
                  <div
                    className="bg-cyan-500 h-full transition-all duration-500"
                    style={{ width: `${activeJob.progress_percent}%` }}
                  />
                </div>
              </div>

              <div className="text-[11px] text-slate-400 flex items-center gap-4">
                <span>Job ID: {activeJob.id}</span>
                <span>Scope: {activeJob.authorized_scope}</span>
                <span>Discovered: {activeJob.domains_discovered_count} domains</span>
              </div>
            </div>
          )}

          {/* Launch Form */}
          <div className="bg-navy-900 border border-navy-800 rounded-xl p-6 space-y-5">
            <div>
              <h2 className="text-base font-semibold text-white flex items-center gap-2">
                <Play className="w-4 h-4 text-cyan-400" />
                Initiate Authorized Passive Discovery
              </h2>
              <p className="text-xs text-slate-400">
                Executes non-intrusive reconnaissance via public Certificate Transparency logs, DNS enumeration, and RDAP.
              </p>
            </div>

            <form onSubmit={handleLaunchDiscovery} className="space-y-4">
              <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
                {/* Discovery Policy Selection */}
                <div className="space-y-1.5">
                  <label className="text-xs font-medium text-slate-300 flex items-center gap-1.5">
                    <ShieldAlert className="w-3.5 h-3.5 text-cyan-400" />
                    Discovery Policy <span className="text-rose-400">*</span>
                  </label>
                  <select
                    value={discoveryPolicy}
                    onChange={(e) => setDiscoveryPolicy(e.target.value as any)}
                    className="w-full bg-navy-950 border border-navy-700 rounded-lg px-3 py-2 text-xs text-slate-100 focus:outline-none focus:border-cyan-500 font-mono"
                  >
                    <option value="PUBLIC_PASSIVE">PUBLIC_PASSIVE (External Passive Recon)</option>
                    <option value="AUTHORIZED_INTERNAL">AUTHORIZED_INTERNAL (Internal Scoped Recon)</option>
                  </select>
                </div>

                {/* Managed Asset Selection */}
                <div className="space-y-1.5">
                  <label className="text-xs font-medium text-slate-300 flex items-center gap-1.5">
                    <Server className="w-3.5 h-3.5 text-slate-400" />
                    Authorized Managed Asset <span className="text-rose-400">*</span>
                  </label>
                  <select
                    value={selectedAssetId}
                    onChange={(e) => setSelectedAssetId(e.target.value)}
                    required
                    className="w-full bg-navy-950 border border-navy-700 rounded-lg px-3 py-2 text-xs text-slate-100 focus:outline-none focus:border-cyan-500"
                  >
                    <option value="" disabled>Select an in-scope asset</option>
                    {assets.map((a) => (
                      <option key={a.id} value={a.id}>
                        {a.name} ({a.target})
                      </option>
                    ))}
                  </select>
                </div>

                {/* Subdomain Target Override */}
                <div className="space-y-1.5">
                  <label className="text-xs font-medium text-slate-300 flex items-center gap-1.5">
                    <Globe className="w-3.5 h-3.5 text-slate-400" />
                    Target Domain / IP (Optional)
                  </label>
                  <input
                    type="text"
                    value={customSubdomain}
                    onChange={(e) => setCustomSubdomain(e.target.value)}
                    placeholder="e.g. portal.smbclient.in (defaults to asset target)"
                    className="w-full bg-navy-950 border border-navy-700 rounded-lg px-3 py-2 text-xs text-slate-100 placeholder-slate-600 focus:outline-none focus:border-cyan-500"
                  />
                </div>
              </div>

              {/* Mandatory Authorization Checkbox */}
              <div className="p-3.5 bg-navy-950 border border-navy-800 rounded-lg flex items-start gap-3">
                <input
                  type="checkbox"
                  id="auth-confirm"
                  checked={authConfirmed}
                  onChange={(e) => setAuthConfirmed(e.target.checked)}
                  className="mt-0.5 rounded border-navy-700 text-cyan-600 focus:ring-cyan-500 bg-navy-900"
                />
                <label htmlFor="auth-confirm" className="text-xs text-slate-300 leading-relaxed cursor-pointer">
                  <span className="font-semibold text-white">Mandatory Scope Confirmation:</span> I confirm that our organization owns or holds explicit authorization to scan and catalog the digital attack surface for this target. All SSRF restrictions, private IP exclusions, and tenant boundaries apply.
                </label>
              </div>

              <button
                type="submit"
                disabled={!authConfirmed || !selectedAssetId || isSubmittingJob || (activeJob?.status === 'RUNNING')}
                className="px-4 py-2 bg-gradient-to-r from-cyan-600 to-blue-600 hover:from-cyan-500 hover:to-blue-500 disabled:opacity-50 disabled:cursor-not-allowed text-white text-xs font-semibold rounded-lg shadow transition-all flex items-center gap-2"
              >
                {isSubmittingJob ? (
                  <>
                    <RefreshCw className="w-3.5 h-3.5 animate-spin" />
                    Queuing Job...
                  </>
                ) : (
                  <>
                    <Play className="w-3.5 h-3.5" />
                    Launch Passive Discovery
                  </>
                )}
              </button>
            </form>
          </div>

          {/* Job History Table */}
          <div className="bg-navy-900 border border-navy-800 rounded-xl overflow-hidden">
            <div className="px-5 py-4 border-b border-navy-800 flex items-center justify-between">
              <h3 className="text-sm font-semibold text-white">Discovery Execution History</h3>
              <span className="text-xs text-slate-400 font-mono">{jobs.length} total runs</span>
            </div>
            <div className="overflow-x-auto">
              <table className="w-full text-left text-xs">
                <thead className="bg-navy-950 text-slate-400 uppercase font-mono text-[10px]">
                  <tr>
                    <th className="px-4 py-3">Target Domain</th>
                    <th className="px-4 py-3">Status</th>
                    <th className="px-4 py-3">Stage</th>
                    <th className="px-4 py-3">Domains</th>
                    <th className="px-4 py-3">Findings</th>
                    <th className="px-4 py-3">Risk Score</th>
                    <th className="px-4 py-3">Completed At</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-navy-800">
                  {jobs.map((j) => (
                    <tr key={j.id} className="hover:bg-navy-850/50 transition-colors">
                      <td className="px-4 py-3 font-mono font-medium text-slate-200">
                        {j.target_domain}
                      </td>
                      <td className="px-4 py-3">
                        <span
                          className={`px-2 py-0.5 rounded text-[10px] font-mono border ${
                            j.status === 'COMPLETED'
                              ? 'bg-emerald-950/60 border-emerald-500/50 text-emerald-300'
                              : j.status === 'PARTIALLY_COMPLETED'
                              ? 'bg-yellow-950/60 border-yellow-500/50 text-yellow-300'
                              : j.status === 'RUNNING'
                              ? 'bg-cyan-950/60 border-cyan-500/50 text-cyan-300 animate-pulse'
                              : j.status === 'FAILED'
                              ? 'bg-rose-950/60 border-rose-500/50 text-rose-300'
                              : 'bg-slate-800 border-slate-700 text-slate-300'
                          }`}
                        >
                          {j.status}
                        </span>
                      </td>
                      <td className="px-4 py-3 font-mono text-[11px] text-slate-300">{j.current_stage}</td>
                      <td className="px-4 py-3 font-mono text-slate-300">{j.domains_discovered_count}</td>
                      <td className="px-4 py-3 font-mono text-slate-300">{j.findings_count}</td>
                      <td className="px-4 py-3 font-mono">
                        {j.initial_exposure_score !== null && j.initial_exposure_score !== undefined ? (
                          <span className={getRiskScoreColor(j.initial_exposure_score)}>
                            {j.initial_exposure_score.toFixed(1)}
                          </span>
                        ) : (
                          '—'
                        )}
                      </td>
                      <td className="px-4 py-3 text-slate-400">
                        {j.completed_at ? new Date(j.completed_at).toLocaleString() : '—'}
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </div>
        </div>
      )}

      {/* =========================================================================
          SECTION 3: DISCOVERED ASSETS & SUBDOMAINS
      ========================================================================= */}
      {activeTab === 'domains' && (
        <div className="space-y-4">
          <div className="flex flex-col md:flex-row md:items-center justify-between gap-3">
            <div className="relative flex-1 max-w-md">
              <Search className="w-4 h-4 text-slate-400 absolute left-3 top-2.5" />
              <input
                type="text"
                value={domainSearch}
                onChange={(e) => setDomainSearch(e.target.value)}
                placeholder="Search discovered hostnames and subdomains..."
                className="w-full bg-navy-900 border border-navy-800 rounded-lg pl-9 pr-3 py-2 text-xs text-slate-100 placeholder-slate-500 focus:outline-none focus:border-cyan-500"
              />
            </div>
            <div className="text-xs text-slate-400 font-mono">
              Showing {filteredDomains.length} of {domains.length} domains
            </div>
          </div>

          <div className="bg-navy-900 border border-navy-800 rounded-xl overflow-hidden">
            <div className="overflow-x-auto">
              <table className="w-full text-left text-xs">
                <thead className="bg-navy-950 text-slate-400 uppercase font-mono text-[10px]">
                  <tr>
                    <th className="px-4 py-3">Hostname</th>
                    <th className="px-4 py-3">Type</th>
                    <th className="px-4 py-3">Parent Domain</th>
                    <th className="px-4 py-3">Discovery Source</th>
                    <th className="px-4 py-3">First Observed</th>
                    <th className="px-4 py-3">Last Observed</th>
                    <th className="px-4 py-3 text-right">Actions</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-navy-800">
                  {filteredDomains.map((d) => (
                    <tr key={d.id} className="hover:bg-navy-850/50 transition-colors">
                      <td className="px-4 py-3 font-mono font-medium text-cyan-300">
                        {d.domain_name}
                      </td>
                      <td className="px-4 py-3">
                        <span
                          className={`px-2 py-0.5 rounded text-[10px] font-mono border ${
                            d.is_subdomain
                              ? 'bg-blue-950/60 border-blue-500/40 text-blue-300'
                              : 'bg-purple-950/60 border-purple-500/40 text-purple-300'
                          }`}
                        >
                          {d.is_subdomain ? 'SUBDOMAIN' : 'APEX'}
                        </span>
                      </td>
                      <td className="px-4 py-3 font-mono text-slate-400">{d.parent_domain || '—'}</td>
                      <td className="px-4 py-3 font-mono text-[11px] text-slate-300">{d.discovery_source}</td>
                      <td className="px-4 py-3 text-slate-400">{new Date(d.first_observed_at).toLocaleDateString()}</td>
                      <td className="px-4 py-3 text-slate-400">{new Date(d.last_observed_at).toLocaleDateString()}</td>
                      <td className="px-4 py-3 text-right">
                        <button
                          onClick={() => handleInspectDomain(d.id)}
                          className="px-2.5 py-1 text-[11px] font-medium text-cyan-300 hover:text-white bg-cyan-950/60 hover:bg-cyan-900 border border-cyan-800 rounded transition-colors inline-flex items-center gap-1"
                        >
                          <Eye className="w-3 h-3" />
                          Inspect
                        </button>
                      </td>
                    </tr>
                  ))}
                  {filteredDomains.length === 0 && (
                    <tr>
                      <td colSpan={7} className="px-4 py-8 text-center text-slate-500 italic">
                        No domains discovered matching your filter.
                      </td>
                    </tr>
                  )}
                </tbody>
              </table>
            </div>
          </div>
        </div>
      )}

      {/* =========================================================================
          SECTION 4: EXPOSURE FINDINGS
      ========================================================================= */}
      {activeTab === 'findings' && (
        <div className="space-y-4">
          {/* Filter Bar */}
          <div className="flex flex-wrap items-center gap-3">
            <div className="flex items-center gap-2">
              <span className="text-xs text-slate-400">Severity:</span>
              <select
                value={findingSeverityFilter}
                onChange={(e) => setFindingSeverityFilter(e.target.value)}
                className="bg-navy-900 border border-navy-800 rounded-lg px-2.5 py-1.5 text-xs text-slate-200 focus:outline-none focus:border-cyan-500"
              >
                <option value="ALL">All Severities</option>
                <option value="CRITICAL">Critical</option>
                <option value="HIGH">High</option>
                <option value="MEDIUM">Medium</option>
                <option value="LOW">Low</option>
                <option value="INFO">Info</option>
              </select>
            </div>

            {/* Finding Nature Filter */}
            <div className="flex items-center gap-2">
              <span className="text-xs text-slate-400">Nature:</span>
              <select
                value={findingNatureFilter}
                onChange={(e) => setFindingNatureFilter(e.target.value)}
                className="bg-navy-900 border border-navy-800 rounded-lg px-2.5 py-1.5 text-xs text-slate-200 focus:outline-none focus:border-cyan-500"
              >
                <option value="ALL">All Natures</option>
                <option value="OBSERVED_FACT">Observed Fact</option>
                <option value="POTENTIAL_WEAKNESS">Potential Weakness</option>
                <option value="VERIFIED_ISSUE">Verified Issue</option>
                <option value="UNVERIFIED_FINDING">Unverified Finding</option>
              </select>
            </div>

            <div className="flex items-center gap-2">
              <span className="text-xs text-slate-400">Category:</span>
              <select
                value={findingCategoryFilter}
                onChange={(e) => setFindingCategoryFilter(e.target.value)}
                className="bg-navy-900 border border-navy-800 rounded-lg px-2.5 py-1.5 text-xs text-slate-200 focus:outline-none focus:border-cyan-500"
              >
                <option value="ALL">All Categories</option>
                <option value="ATTACK_SURFACE_EXPOSURE">Attack Surface Exposure</option>
                <option value="EMAIL_SECURITY_POSTURE">Email Security Posture</option>
                <option value="CERTIFICATE_TLS_POSTURE">Certificate & TLS Posture</option>
                <option value="DNS_CONFIGURATION_WEAKNESS">DNS Configuration Weakness</option>
                <option value="RESOURCE_TAKEOVER_INDICATOR">Resource Takeover Indicator</option>
              </select>
            </div>

            <div className="ml-auto text-xs text-slate-400 font-mono">
              Showing {filteredFindings.length} of {findings.length} findings
            </div>
          </div>

          <div className="bg-navy-900 border border-navy-800 rounded-xl overflow-hidden">
            <div className="overflow-x-auto">
              <table className="w-full text-left text-xs">
                <thead className="bg-navy-950 text-slate-400 uppercase font-mono text-[10px]">
                  <tr>
                    <th className="px-4 py-3">Severity</th>
                    <th className="px-4 py-3">Nature</th>
                    <th className="px-4 py-3">Title</th>
                    <th className="px-4 py-3">Target</th>
                    <th className="px-4 py-3">Category</th>
                    <th className="px-4 py-3">Verification</th>
                    <th className="px-4 py-3 text-right">Evidence</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-navy-800">
                  {filteredFindings.map((f) => (
                    <tr key={f.id} className="hover:bg-navy-850/50 transition-colors">
                      <td className="px-4 py-3">
                        <span className={`px-2 py-0.5 rounded text-[10px] font-mono border ${getSeverityBadgeClass(f.severity)}`}>
                          {f.severity}
                        </span>
                      </td>
                      <td className="px-4 py-3">
                        <span className={`px-2 py-0.5 rounded text-[10px] font-mono border ${
                          f.evidence_nature === 'VERIFIED_ISSUE'
                            ? 'bg-rose-950/60 border-rose-600/50 text-rose-300'
                            : f.evidence_nature === 'POTENTIAL_WEAKNESS'
                            ? 'bg-amber-950/60 border-amber-600/50 text-amber-300'
                            : f.evidence_nature === 'OBSERVED_FACT'
                            ? 'bg-blue-950/60 border-blue-600/50 text-blue-300'
                            : 'bg-slate-800 border-slate-700 text-slate-300'
                        }`}>
                          {f.evidence_nature || 'FACT'}
                        </span>
                      </td>
                      <td className="px-4 py-3 font-medium text-slate-200 max-w-xs truncate">
                        {f.title}
                      </td>
                      <td className="px-4 py-3 font-mono text-cyan-300">{f.target}</td>
                      <td className="px-4 py-3 font-mono text-[11px] text-slate-400">{f.finding_category}</td>
                      <td className="px-4 py-3 font-mono text-[11px] text-slate-300">
                        {f.verification_status ? (
                          <span className={`px-1.5 py-0.5 rounded text-[9px] border ${
                            f.verification_status === 'VERIFIED_UNCLAIMED_RESOURCE'
                              ? 'bg-rose-950/80 border-rose-500 text-rose-300 font-bold'
                              : 'bg-navy-950 border-navy-700 text-slate-400'
                          }`}>
                            {f.verification_status}
                          </span>
                        ) : '—'}
                      </td>
                      <td className="px-4 py-3 text-right">
                        <button
                          onClick={() => setInspectFinding(f)}
                          className="px-2.5 py-1 text-[11px] font-medium text-cyan-300 hover:text-white bg-cyan-950/60 hover:bg-cyan-900 border border-cyan-800 rounded transition-colors inline-flex items-center gap-1"
                        >
                          <FileText className="w-3 h-3" />
                          View Evidence
                        </button>
                      </td>
                    </tr>
                  ))}
                  {filteredFindings.length === 0 && (
                    <tr>
                      <td colSpan={7} className="px-4 py-8 text-center text-slate-500 italic">
                        No exposure findings matched the selected criteria.
                      </td>
                    </tr>
                  )}
                </tbody>
              </table>
            </div>
          </div>
        </div>
      )}

      {/* =========================================================================
          DRAWER: DOMAIN DETAIL INSPECTION
      ========================================================================= */}
      {inspectDomain && (
        <div className="fixed inset-0 bg-black/60 backdrop-blur-sm z-50 flex justify-end animate-fadeIn">
          <div className="w-full max-w-2xl bg-navy-900 border-l border-navy-800 h-full overflow-y-auto p-6 space-y-6">
            <div className="flex items-center justify-between border-b border-navy-800 pb-4">
              <div>
                <h3 className="text-base font-bold text-white font-mono flex items-center gap-2">
                  <Globe className="w-4 h-4 text-cyan-400" />
                  {inspectDomain.domain_name}
                </h3>
                <p className="text-xs text-slate-400">
                  Detailed DNS, Certificate Transparency, and RDAP registration metadata.
                </p>
              </div>
              <button
                onClick={() => setInspectDomain(null)}
                className="text-slate-400 hover:text-white p-1 rounded-lg hover:bg-navy-800"
              >
                <X className="w-5 h-5" />
              </button>
            </div>

            {/* DNS Records Section */}
            <div className="space-y-3">
              <h4 className="text-xs font-semibold text-cyan-300 uppercase tracking-wider">
                DNS Records ({inspectDomain.dns_records?.length ?? 0})
              </h4>
              {inspectDomain.dns_records && inspectDomain.dns_records.length > 0 ? (
                <div className="bg-navy-950 border border-navy-800 rounded-lg overflow-hidden">
                  <table className="w-full text-left text-xs font-mono">
                    <thead className="bg-navy-900 text-slate-400 text-[10px]">
                      <tr>
                        <th className="px-3 py-2">Type</th>
                        <th className="px-3 py-2">Value</th>
                        <th className="px-3 py-2">TTL</th>
                      </tr>
                    </thead>
                    <tbody className="divide-y divide-navy-800">
                      {inspectDomain.dns_records.map((r) => (
                        <tr key={r.id}>
                          <td className="px-3 py-2 text-cyan-400 font-bold">{r.record_type}</td>
                          <td className="px-3 py-2 text-slate-200 break-all">{r.record_value}</td>
                          <td className="px-3 py-2 text-slate-400">{r.ttl ?? '—'}</td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              ) : (
                <p className="text-xs text-slate-500 italic">No DNS records captured for this hostname.</p>
              )}
            </div>

            {/* Certificate Evidence Section */}
            <div className="space-y-3">
              <h4 className="text-xs font-semibold text-cyan-300 uppercase tracking-wider">
                Certificate Evidence ({inspectDomain.certificates?.length ?? 0})
              </h4>
              {inspectDomain.certificates && inspectDomain.certificates.length > 0 ? (
                <div className="space-y-3">
                  {inspectDomain.certificates.map((c) => (
                    <div key={c.id} className="p-3.5 bg-navy-950 border border-navy-800 rounded-lg space-y-2 text-xs">
                      <div className="flex items-center justify-between">
                        <span className="font-mono font-bold text-slate-200">{c.common_name}</span>
                        <div className="flex items-center gap-2">
                          {c.is_wildcard && (
                            <span className="px-1.5 py-0.5 rounded text-[10px] font-mono bg-blue-950 text-blue-300 border border-blue-800">
                              WILDCARD
                            </span>
                          )}
                          {c.is_expired ? (
                            <span className="px-1.5 py-0.5 rounded text-[10px] font-mono bg-rose-950 text-rose-300 border border-rose-800">
                              EXPIRED
                            </span>
                          ) : (
                            <span className="px-1.5 py-0.5 rounded text-[10px] font-mono bg-emerald-950 text-emerald-300 border border-emerald-800">
                              VALID
                            </span>
                          )}
                        </div>
                      </div>
                      <div className="text-[11px] text-slate-400">Issuer: {c.issuer_name || 'Unknown'}</div>
                      <div className="text-[11px] text-slate-400 font-mono">
                        Valid: {c.not_before ? new Date(c.not_before).toLocaleDateString() : '—'} to{' '}
                        {c.not_after ? new Date(c.not_after).toLocaleDateString() : '—'}
                      </div>
                    </div>
                  ))}
                </div>
              ) : (
                <p className="text-xs text-slate-500 italic">No certificate evidence found.</p>
              )}
            </div>

            {/* RDAP Profile Section */}
            <div className="space-y-3">
              <h4 className="text-xs font-semibold text-cyan-300 uppercase tracking-wider">
                RDAP Registration Metadata (Privacy-Preserved)
              </h4>
              {inspectDomain.rdap ? (
                <div className="p-4 bg-navy-950 border border-navy-800 rounded-lg space-y-2 text-xs">
                  <div className="flex justify-between">
                    <span className="text-slate-400">Registrar:</span>
                    <span className="font-medium text-slate-200">{inspectDomain.rdap.registrar_name || 'N/A'}</span>
                  </div>
                  <div className="flex justify-between">
                    <span className="text-slate-400">Registration Date:</span>
                    <span className="font-mono text-slate-200">
                      {inspectDomain.rdap.registration_date ? new Date(inspectDomain.rdap.registration_date).toLocaleDateString() : '—'}
                    </span>
                  </div>
                  <div className="flex justify-between">
                    <span className="text-slate-400">Expiration Date:</span>
                    <span className="font-mono text-slate-200">
                      {inspectDomain.rdap.expiration_date ? new Date(inspectDomain.rdap.expiration_date).toLocaleDateString() : '—'}
                    </span>
                  </div>
                  <div className="flex justify-between">
                    <span className="text-slate-400">Nameservers:</span>
                    <span className="font-mono text-slate-200">{inspectDomain.rdap.nameservers || '—'}</span>
                  </div>
                </div>
              ) : (
                <p className="text-xs text-slate-500 italic">No RDAP profile recorded.</p>
              )}
            </div>
          </div>
        </div>
      )}

      {/* =========================================================================
          DRAWER: EXPOSURE FINDING EVIDENCE
      ========================================================================= */}
      {inspectFinding && (
        <div className="fixed inset-0 bg-black/60 backdrop-blur-sm z-50 flex justify-end animate-fadeIn">
          <div className="w-full max-w-xl bg-navy-900 border-l border-navy-800 h-full overflow-y-auto p-6 space-y-5">
            <div className="flex items-center justify-between border-b border-navy-800 pb-4">
              <div>
                <span className={`px-2 py-0.5 rounded text-[10px] font-mono border ${getSeverityBadgeClass(inspectFinding.severity)}`}>
                  {inspectFinding.severity}
                </span>
                <h3 className="text-base font-bold text-white mt-2">{inspectFinding.title}</h3>
                <p className="text-xs text-cyan-300 font-mono mt-0.5">Target: {inspectFinding.target}</p>
              </div>
              <button
                onClick={() => setInspectFinding(null)}
                className="text-slate-400 hover:text-white p-1 rounded-lg hover:bg-navy-800"
              >
                <X className="w-5 h-5" />
              </button>
            </div>

            <div className="space-y-2">
              <h4 className="text-xs font-semibold text-slate-300 uppercase tracking-wider">Description</h4>
              <p className="text-xs text-slate-300 leading-relaxed bg-navy-950 p-3.5 rounded-lg border border-navy-800">
                {inspectFinding.description}
              </p>
            </div>

            <div className="space-y-2">
              <h4 className="text-xs font-semibold text-slate-300 uppercase tracking-wider">Raw Evidence Payload</h4>
              <pre className="bg-navy-950 border border-navy-800 rounded-lg p-3.5 text-[11px] font-mono text-cyan-300 overflow-x-auto whitespace-pre-wrap">
                {(() => {
                  try {
                    return JSON.stringify(JSON.parse(inspectFinding.evidence), null, 2);
                  } catch {
                    return inspectFinding.evidence;
                  }
                })()}
              </pre>
            </div>

            <div className="p-3.5 bg-navy-950/60 border border-navy-800 rounded-lg space-y-1 text-xs">
              <div className="flex justify-between">
                <span className="text-slate-400">Category:</span>
                <span className="font-mono text-slate-200">{inspectFinding.finding_category}</span>
              </div>
              <div className="flex justify-between">
                <span className="text-slate-400">Discovery Source:</span>
                <span className="font-mono text-slate-200">{inspectFinding.discovery_source}</span>
              </div>
              <div className="flex justify-between">
                <span className="text-slate-400">Confidence:</span>
                <span className="font-mono text-slate-200">{inspectFinding.confidence}</span>
              </div>
            </div>
          </div>
        </div>
      )}
    </div>
  );
};
