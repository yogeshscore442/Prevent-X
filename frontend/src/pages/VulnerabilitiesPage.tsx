import React, { useEffect, useState } from 'react';
import {
  Bug,
  CheckCircle2,
  Clock,
  Database,
  Flame,
  Info,
  Loader2,
  RefreshCw,
  Search,
  ShieldAlert,
  ShieldCheck,
  X,
  Zap,
} from 'lucide-react';
import {
  CveRecord,
  VulnerabilityOverview,
  VulnerabilityRecord,
  VulnerabilityScanJob,
} from '@/types/vulnerability';
import { vulnerabilityApi } from '@/services/vulnerabilityApi';
import { api } from '@/services/api';
import { ManagedAsset } from '@/types/asset';

export const VulnerabilitiesPage: React.FC = () => {
  const [activeTab, setActiveTab] = useState<'inventory' | 'catalog' | 'history'>('inventory');

  // State
  const [overview, setOverview] = useState<VulnerabilityOverview | null>(null);
  const [records, setRecords] = useState<VulnerabilityRecord[]>([]);
  const [totalRecords, setTotalRecords] = useState(0);
  const [isLoading, setIsLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  // Filters
  const [search, setSearch] = useState('');
  const [severityFilter, setSeverityFilter] = useState<string>('ALL');
  const [confidenceFilter, setConfidenceFilter] = useState<string>('ALL');
  const [statusFilter, setStatusFilter] = useState<string>('ALL');
  const [kevOnly, setKevOnly] = useState(false);

  // Inspection Drawer
  const [selectedRecord, setSelectedRecord] = useState<VulnerabilityRecord | null>(null);
  const [triageStatus, setTriageStatus] = useState<string>('DETECTED');
  const [triageNotes, setTriageNotes] = useState('');
  const [isUpdatingStatus, setIsUpdatingStatus] = useState(false);

  // Scan Launch Modal
  const [isScanModalOpen, setIsScanModalOpen] = useState(false);
  const [assets, setAssets] = useState<ManagedAsset[]>([]);
  const [selectedAssetId, setSelectedAssetId] = useState<string>('ALL');
  const [isStartingScan, setIsStartingScan] = useState(false);

  // Feed Sync State
  const [isSyncingFeeds, setIsSyncingFeeds] = useState(false);
  const [syncFeedback, setSyncFeedback] = useState<string | null>(null);

  // CVE Catalog Tab State
  const [cveList, setCveList] = useState<CveRecord[]>([]);
  const [cveTotal, setCveTotal] = useState(0);
  const [cveSearch, setCveSearch] = useState('');
  const [isLoadingCves, setIsLoadingCves] = useState(false);

  // Scan Jobs History
  const [scanJobs, setScanJobs] = useState<VulnerabilityScanJob[]>([]);
  const [isLoadingJobs, setIsLoadingJobs] = useState(false);

  const fetchOverview = async () => {
    try {
      const data = await vulnerabilityApi.getOverview();
      setOverview(data);
    } catch (err: any) {
      console.error('Failed to load vulnerability overview', err);
    }
  };

  const fetchRecords = async () => {
    setIsLoading(true);
    setError(null);
    try {
      const params: any = {
        skip: 0,
        limit: 100,
      };
      if (search) params.search = search;
      if (severityFilter !== 'ALL') params.severity = severityFilter;
      if (confidenceFilter !== 'ALL') params.confidence = confidenceFilter;
      if (statusFilter !== 'ALL') params.status = statusFilter;
      if (kevOnly) params.is_kev = true;

      const data = await vulnerabilityApi.listRecords(params);
      setRecords(data?.items || []);
      setTotalRecords(data?.total || 0);
    } catch (err: any) {
      setError(err?.response?.data?.detail?.message || 'Failed to load vulnerability records.');
      setRecords([]);
    } finally {
      setIsLoading(false);
    }
  };

  const fetchCatalog = async () => {
    setIsLoadingCves(true);
    try {
      const data = await vulnerabilityApi.searchCveCatalog({
        query: cveSearch || undefined,
        limit: 50,
      });
      setCveList(data?.items || []);
      setCveTotal(data?.total || 0);
    } catch (err) {
      console.error('Failed to search CVE catalog', err);
      setCveList([]);
    } finally {
      setIsLoadingCves(false);
    }
  };

  const fetchJobs = async () => {
    setIsLoadingJobs(true);
    try {
      const data = await vulnerabilityApi.listScanJobs(20);
      setScanJobs(Array.isArray(data) ? data : ((data as any)?.items || []));
    } catch (err) {
      console.error('Failed to load scan jobs', err);
      setScanJobs([]);
    } finally {
      setIsLoadingJobs(false);
    }
  };

  useEffect(() => {
    fetchOverview();
    fetchRecords();
    api
      .get<{ items: ManagedAsset[] }>('/assets')
      .then((res) => {
        const items = Array.isArray(res.data) ? res.data : (res.data?.items || []);
        setAssets(items);
      })
      .catch(() => setAssets([]));
  }, []);

  useEffect(() => {
    if (activeTab === 'inventory') {
      fetchRecords();
    } else if (activeTab === 'catalog') {
      fetchCatalog();
    } else if (activeTab === 'history') {
      fetchJobs();
    }
  }, [activeTab, severityFilter, confidenceFilter, statusFilter, kevOnly]);

  const handleSearchSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    if (activeTab === 'inventory') {
      fetchRecords();
    } else if (activeTab === 'catalog') {
      fetchCatalog();
    }
  };

  const handleStartScan = async () => {
    setIsStartingScan(true);
    try {
      const targetId = selectedAssetId === 'ALL' ? undefined : selectedAssetId;
      await vulnerabilityApi.triggerScan(targetId);
      setIsScanModalOpen(false);
      fetchOverview();
      fetchRecords();
      fetchJobs();
    } catch (err: any) {
      alert(err?.response?.data?.detail?.message || 'Failed to start vulnerability mapping scan.');
    } finally {
      setIsStartingScan(false);
    }
  };

  const handleFeedSync = async () => {
    setIsSyncingFeeds(true);
    setSyncFeedback(null);
    try {
      const res = await vulnerabilityApi.triggerFeedSync(false);
      setSyncFeedback(`Successfully synchronized feeds. ${res.cve_total} total CVEs cataloged.`);
      fetchOverview();
      if (activeTab === 'catalog') fetchCatalog();
    } catch (err: any) {
      setSyncFeedback('Feed synchronization failed or rate-limited.');
    } finally {
      setIsSyncingFeeds(false);
    }
  };

  const handleStatusUpdate = async () => {
    if (!selectedRecord) return;
    setIsUpdatingStatus(true);
    try {
      const updated = await vulnerabilityApi.updateStatus(selectedRecord.id, triageStatus, triageNotes);
      setSelectedRecord(updated);
      setRecords((prev) => prev.map((r) => (r.id === updated.id ? updated : r)));
      fetchOverview();
      setTriageNotes('');
    } catch (err: any) {
      alert('Failed to update vulnerability status.');
    } finally {
      setIsUpdatingStatus(false);
    }
  };

  const openInspection = (record: VulnerabilityRecord) => {
    setSelectedRecord(record);
    setTriageStatus(record.status);
    setTriageNotes('');
  };

  // Badges
  const getSeverityBadge = (severity: string) => {
    switch (severity.toUpperCase()) {
      case 'CRITICAL':
        return <span className="px-2 py-0.5 rounded text-[11px] font-bold bg-rose-950 text-rose-400 border border-rose-800">CRITICAL</span>;
      case 'HIGH':
        return <span className="px-2 py-0.5 rounded text-[11px] font-bold bg-amber-950 text-amber-400 border border-amber-800">HIGH</span>;
      case 'MEDIUM':
        return <span className="px-2 py-0.5 rounded text-[11px] font-bold bg-yellow-950 text-yellow-400 border border-yellow-800">MEDIUM</span>;
      case 'LOW':
        return <span className="px-2 py-0.5 rounded text-[11px] font-bold bg-blue-950 text-blue-400 border border-blue-800">LOW</span>;
      default:
        return <span className="px-2 py-0.5 rounded text-[11px] font-bold bg-slate-800 text-slate-400 border border-slate-700">INFO</span>;
    }
  };

  const getConfidenceBadge = (confidence: string) => {
    switch (confidence) {
      case 'CONFIRMED_MATCH':
        return <span className="px-2 py-0.5 rounded text-[10px] font-mono font-semibold bg-emerald-950 text-emerald-400 border border-emerald-800">CONFIRMED MATCH</span>;
      case 'LIKELY_MATCH':
        return <span className="px-2 py-0.5 rounded text-[10px] font-mono font-semibold bg-cyan-950 text-cyan-400 border border-cyan-800">LIKELY MATCH</span>;
      case 'POTENTIAL_MATCH':
        return <span className="px-2 py-0.5 rounded text-[10px] font-mono font-semibold bg-amber-950 text-amber-400 border border-amber-800">POTENTIAL MATCH</span>;
      default:
        return <span className="px-2 py-0.5 rounded text-[10px] font-mono font-semibold bg-slate-800 text-slate-400 border border-slate-700">{confidence}</span>;
    }
  };

  const getStatusBadge = (status: string) => {
    switch (status) {
      case 'DETECTED':
        return <span className="px-2 py-0.5 rounded text-[10px] font-semibold bg-rose-900/40 text-rose-300 border border-rose-800/60">DETECTED</span>;
      case 'IN_TRIAGE':
        return <span className="px-2 py-0.5 rounded text-[10px] font-semibold bg-amber-900/40 text-amber-300 border border-amber-800/60">IN TRIAGE</span>;
      case 'MITIGATED':
      case 'PATCHED':
        return <span className="px-2 py-0.5 rounded text-[10px] font-semibold bg-emerald-900/40 text-emerald-300 border border-emerald-800/60">{status}</span>;
      case 'FALSE_POSITIVE':
        return <span className="px-2 py-0.5 rounded text-[10px] font-semibold bg-slate-800 text-slate-400 border border-slate-700">FALSE POSITIVE</span>;
      default:
        return <span className="px-2 py-0.5 rounded text-[10px] font-semibold bg-navy-800 text-slate-300 border border-navy-700">{status}</span>;
    }
  };

  return (
    <div className="p-6 max-w-7xl mx-auto space-y-6">
      {/* Page Header */}
      <div className="flex flex-col md:flex-row md:items-center justify-between gap-4 border-b border-navy-800 pb-5">
        <div>
          <div className="flex items-center gap-2">
            <ShieldAlert className="w-7 h-7 text-rose-500" />
            <h1 className="text-2xl font-bold tracking-tight text-white">Vulnerability Management & Mapping</h1>
          </div>
          <p className="text-sm text-slate-400 mt-1">
            Phase 3 Engine: Automated NVD/CISA KEV ingestion, intelligent CPE/version comparison, and contextual risk scoring.
          </p>
        </div>

        <div className="flex items-center gap-3">
          <button
            onClick={handleFeedSync}
            disabled={isSyncingFeeds}
            className="flex items-center gap-2 px-3 py-2 bg-navy-800 hover:bg-navy-750 text-slate-200 border border-navy-700 rounded-lg text-xs font-medium transition-colors"
          >
            <RefreshCw className={`w-3.5 h-3.5 ${isSyncingFeeds ? 'animate-spin text-cyan-400' : ''}`} />
            <span>{isSyncingFeeds ? 'Syncing Feeds...' : 'Sync Threat Feeds'}</span>
          </button>

          <button
            onClick={() => setIsScanModalOpen(true)}
            className="flex items-center gap-2 px-4 py-2 bg-gradient-to-r from-rose-600 to-red-700 hover:from-rose-500 hover:to-red-600 text-white rounded-lg text-xs font-semibold shadow-lg shadow-rose-900/30 transition-all"
          >
            <Zap className="w-4 h-4" />
            <span>Run Vulnerability Scan</span>
          </button>
        </div>
      </div>

      {syncFeedback && (
        <div className="p-3 bg-cyan-950/40 border border-cyan-800/80 rounded-lg text-xs text-cyan-300 flex items-center justify-between">
          <div className="flex items-center gap-2">
            <Info className="w-4 h-4 text-cyan-400" />
            <span>{syncFeedback}</span>
          </div>
          <button onClick={() => setSyncFeedback(null)} className="text-cyan-400 hover:text-white">
            <X className="w-4 h-4" />
          </button>
        </div>
      )}

      {error && (
        <div className="p-3 bg-rose-950/40 border border-rose-800 rounded-lg text-xs text-rose-300 flex items-center justify-between">
          <div className="flex items-center gap-2">
            <ShieldAlert className="w-4 h-4 text-rose-400" />
            <span>{error}</span>
          </div>
          <button onClick={() => setError(null)} className="text-rose-400 hover:text-white">
            <X className="w-4 h-4" />
          </button>
        </div>
      )}

      {/* KPI Overview Cards */}
      {overview && (
        <div className="grid grid-cols-2 md:grid-cols-5 gap-4">
          <div className="bg-navy-900 border border-navy-800 rounded-xl p-4">
            <div className="text-[11px] font-semibold text-slate-400 uppercase tracking-wider">Total Findings</div>
            <div className="text-2xl font-bold text-white mt-1">{overview.total_vulnerabilities}</div>
            <div className="text-xs text-slate-400 mt-1">{overview.affected_assets_count} affected asset(s)</div>
          </div>

          <div className="bg-navy-900 border border-navy-800 rounded-xl p-4">
            <div className="text-[11px] font-semibold text-rose-400 uppercase tracking-wider flex items-center gap-1.5">
              <ShieldAlert className="w-3.5 h-3.5" />
              Critical & High
            </div>
            <div className="text-2xl font-bold text-rose-400 mt-1">
              {overview.critical_count + overview.high_count}
            </div>
            <div className="text-xs text-slate-400 mt-1">
              {overview.critical_count} critical, {overview.high_count} high
            </div>
          </div>

          <div className="bg-navy-900 border border-navy-800 rounded-xl p-4">
            <div className="text-[11px] font-semibold text-amber-400 uppercase tracking-wider flex items-center gap-1.5">
              <Flame className="w-3.5 h-3.5" />
              Known Exploited (KEV)
            </div>
            <div className="text-2xl font-bold text-amber-400 mt-1">{overview.known_exploited_count}</div>
            <div className="text-xs text-slate-400 mt-1">In CISA Catalog</div>
          </div>

          <div className="bg-navy-900 border border-navy-800 rounded-xl p-4">
            <div className="text-[11px] font-semibold text-cyan-400 uppercase tracking-wider">Avg Contextual Risk</div>
            <div className="text-2xl font-bold text-cyan-400 mt-1">{(overview?.average_risk_score ?? 0).toFixed(1)}</div>
            <div className="text-xs text-slate-400 mt-1">Scale 0 - 100</div>
          </div>

          <div className="bg-navy-900 border border-navy-800 rounded-xl p-4">
            <div className="text-[11px] font-semibold text-slate-400 uppercase tracking-wider">Unmitigated Queue</div>
            <div className="text-2xl font-bold text-slate-200 mt-1">{overview.unmitigated_count}</div>
            <div className="text-xs text-slate-400 mt-1">Detected / In Triage</div>
          </div>
        </div>
      )}

      {/* Navigation Tabs */}
      <div className="flex border-b border-navy-800 gap-6 text-sm font-medium">
        <button
          onClick={() => setActiveTab('inventory')}
          className={`pb-3 transition-colors flex items-center gap-2 border-b-2 ${activeTab === 'inventory'
            ? 'border-rose-500 text-rose-400 font-semibold'
            : 'border-transparent text-slate-400 hover:text-slate-200'
            }`}
        >
          <Bug className="w-4 h-4" />
          <span>Vulnerability Inventory ({totalRecords})</span>
        </button>

        <button
          onClick={() => setActiveTab('catalog')}
          className={`pb-3 transition-colors flex items-center gap-2 border-b-2 ${activeTab === 'catalog'
            ? 'border-rose-500 text-rose-400 font-semibold'
            : 'border-transparent text-slate-400 hover:text-slate-200'
            }`}
        >
          <Database className="w-4 h-4" />
          <span>CVE Threat Catalog {cveTotal > 0 && `(${cveTotal})`}</span>
        </button>

        <button
          onClick={() => setActiveTab('history')}
          className={`pb-3 transition-colors flex items-center gap-2 border-b-2 ${activeTab === 'history'
            ? 'border-rose-500 text-rose-400 font-semibold'
            : 'border-transparent text-slate-400 hover:text-slate-200'
            }`}
        >
          <Clock className="w-4 h-4" />
          <span>Scan Execution History</span>
        </button>
      </div>

      {/* TAB 1: INVENTORY VIEW */}
      {activeTab === 'inventory' && (
        <div className="space-y-4">
          {/* Filter Bar */}
          <div className="bg-navy-900 border border-navy-800 rounded-xl p-4 flex flex-wrap gap-3 items-center justify-between">
            <form onSubmit={handleSearchSubmit} className="flex-1 min-w-[240px] relative">
              <Search className="w-4 h-4 text-slate-400 absolute left-3 top-2.5" />
              <input
                type="text"
                placeholder="Search by CVE ID, title, software, or asset name..."
                value={search}
                onChange={(e) => setSearch(e.target.value)}
                className="w-full pl-9 pr-3 py-1.5 bg-navy-950 border border-navy-700 rounded-lg text-xs text-slate-200 placeholder-slate-500 focus:outline-none focus:border-rose-500"
              />
            </form>

            <div className="flex flex-wrap items-center gap-2">
              <select
                value={severityFilter}
                onChange={(e) => setSeverityFilter(e.target.value)}
                className="bg-navy-950 border border-navy-700 rounded-lg px-2.5 py-1.5 text-xs text-slate-300 focus:outline-none"
              >
                <option value="ALL">All Severities</option>
                <option value="CRITICAL">Critical</option>
                <option value="HIGH">High</option>
                <option value="MEDIUM">Medium</option>
                <option value="LOW">Low</option>
              </select>

              <select
                value={confidenceFilter}
                onChange={(e) => setConfidenceFilter(e.target.value)}
                className="bg-navy-950 border border-navy-700 rounded-lg px-2.5 py-1.5 text-xs text-slate-300 focus:outline-none"
              >
                <option value="ALL">All Confidences</option>
                <option value="CONFIRMED_MATCH">Confirmed Match</option>
                <option value="LIKELY_MATCH">Likely Match</option>
                <option value="POTENTIAL_MATCH">Potential Match</option>
              </select>

              <select
                value={statusFilter}
                onChange={(e) => setStatusFilter(e.target.value)}
                className="bg-navy-950 border border-navy-700 rounded-lg px-2.5 py-1.5 text-xs text-slate-300 focus:outline-none"
              >
                <option value="ALL">All Statuses</option>
                <option value="DETECTED">Detected</option>
                <option value="IN_TRIAGE">In Triage</option>
                <option value="MITIGATED">Mitigated</option>
                <option value="PATCHED">Patched</option>
                <option value="FALSE_POSITIVE">False Positive</option>
              </select>

              <button
                type="button"
                onClick={() => setKevOnly(!kevOnly)}
                className={`px-3 py-1.5 rounded-lg text-xs font-semibold flex items-center gap-1.5 transition-colors border ${kevOnly
                  ? 'bg-rose-950 text-rose-300 border-rose-700'
                  : 'bg-navy-950 text-slate-400 border-navy-700 hover:text-slate-200'
                  }`}
              >
                <Flame className="w-3.5 h-3.5" />
                <span>KEV Exploited</span>
              </button>
            </div>
          </div>

          {/* Records Table */}
          <div className="bg-navy-900 border border-navy-800 rounded-xl overflow-hidden shadow-xl">
            {isLoading ? (
              <div className="p-12 text-center text-slate-400 flex flex-col items-center gap-3">
                <Loader2 className="w-8 h-8 animate-spin text-rose-500" />
                <span className="text-xs font-mono">Loading Vulnerability Findings...</span>
              </div>
            ) : records.length === 0 ? (
              <div className="p-12 text-center text-slate-400 space-y-2">
                <ShieldCheck className="w-10 h-10 text-emerald-500 mx-auto" />
                <div className="text-sm font-medium text-slate-200">No Vulnerabilities Detected</div>
                <div className="text-xs text-slate-500">
                  No active vulnerabilities matching current filters were found in your asset scope.
                </div>
              </div>
            ) : (
              <div className="overflow-x-auto">
                <table className="w-full text-left text-xs border-collapse">
                  <thead>
                    <tr className="bg-navy-950/80 border-b border-navy-800 text-slate-400 font-semibold uppercase tracking-wider">
                      <th className="py-3 px-4">Risk Score</th>
                      <th className="py-3 px-4">Vulnerability / CVE</th>
                      <th className="py-3 px-4">Target Asset & Service</th>
                      <th className="py-3 px-4">Confidence</th>
                      <th className="py-3 px-4">Threat Signals</th>
                      <th className="py-3 px-4">Status</th>
                      <th className="py-3 px-4 text-right">Action</th>
                    </tr>
                  </thead>
                  <tbody className="divide-y divide-navy-800/60">
                    {records.map((r) => (
                      <tr key={r.id} className="hover:bg-navy-850/50 transition-colors">
                        <td className="py-3 px-4">
                          <div className="flex items-center gap-2">
                            <span className="font-mono font-bold text-sm text-slate-100">{(r.risk_score ?? 0).toFixed(1)}</span>
                            {getSeverityBadge(r.severity)}
                          </div>
                        </td>

                        <td className="py-3 px-4 max-w-xs">
                          <div className="font-mono font-semibold text-rose-400">{r.cve_id}</div>
                          <div className="text-slate-200 font-medium truncate mt-0.5" title={r.title}>
                            {r.title}
                          </div>
                          {r.cvss_score != null && (
                            <div className="text-[10px] text-slate-500 font-mono mt-0.5">
                              CVSS {Number(r.cvss_score).toFixed(1)}
                            </div>
                          )}
                        </td>

                        <td className="py-3 px-4">
                          <div className="font-medium text-slate-200">{r.asset_name || r.asset_target}</div>
                          <div className="text-[11px] text-slate-400 font-mono flex items-center gap-1 mt-0.5">
                            <span>Port {r.service_port}</span>
                            <span>•</span>
                            <span>{r.matched_service_name || r.service_name}</span>
                            {r.matched_version && <span className="text-cyan-400">({r.matched_version})</span>}
                          </div>
                        </td>

                        <td className="py-3 px-4">{getConfidenceBadge(r.confidence)}</td>

                        <td className="py-3 px-4">
                          <div className="flex flex-col gap-1 items-start">
                            {r.is_known_exploited && (
                              <span className="px-1.5 py-0.5 rounded text-[10px] font-semibold bg-rose-950 text-rose-300 border border-rose-800 flex items-center gap-1">
                                <Flame className="w-3 h-3 text-rose-400" />
                                CISA KEV
                              </span>
                            )}
                            {r.epss_score !== null && r.epss_score !== undefined && (
                              <span className="px-1.5 py-0.5 rounded text-[10px] font-mono text-cyan-300 bg-cyan-950/60 border border-cyan-800">
                                EPSS {(Number(r.epss_score) * 100).toFixed(1)}%
                              </span>
                            )}
                          </div>
                        </td>

                        <td className="py-3 px-4">{getStatusBadge(r.status)}</td>

                        <td className="py-3 px-4 text-right">
                          <button
                            onClick={() => openInspection(r)}
                            className="px-2.5 py-1 bg-navy-800 hover:bg-navy-750 text-slate-200 border border-navy-700 rounded text-xs transition-colors"
                          >
                            Inspect
                          </button>
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            )}
          </div>
        </div>
      )}

      {/* TAB 2: CVE THREAT CATALOG */}
      {activeTab === 'catalog' && (
        <div className="space-y-4">
          <div className="bg-navy-900 border border-navy-800 rounded-xl p-4 flex gap-3 items-center">
            <form onSubmit={handleSearchSubmit} className="flex-1 relative">
              <Search className="w-4 h-4 text-slate-400 absolute left-3 top-2.5" />
              <input
                type="text"
                placeholder="Search global CVE threat catalog (e.g. CVE-2024-6387, log4j, openssh, apache)..."
                value={cveSearch}
                onChange={(e) => setCveSearch(e.target.value)}
                className="w-full pl-9 pr-3 py-1.5 bg-navy-950 border border-navy-700 rounded-lg text-xs text-slate-200 placeholder-slate-500 focus:outline-none focus:border-rose-500"
              />
            </form>
            <button
              onClick={fetchCatalog}
              className="px-3 py-1.5 bg-navy-800 hover:bg-navy-750 text-slate-200 border border-navy-700 rounded-lg text-xs font-medium"
            >
              Search
            </button>
          </div>

          <div className="bg-navy-900 border border-navy-800 rounded-xl overflow-hidden">
            {isLoadingCves ? (
              <div className="p-12 text-center text-slate-400">Loading catalog...</div>
            ) : (
              <table className="w-full text-left text-xs border-collapse">
                <thead>
                  <tr className="bg-navy-950/80 border-b border-navy-800 text-slate-400 font-semibold uppercase">
                    <th className="py-3 px-4">CVE Identifier</th>
                    <th className="py-3 px-4">Severity & CVSS</th>
                    <th className="py-3 px-4">Exploit Indicators</th>
                    <th className="py-3 px-4">Description</th>
                    <th className="py-3 px-4">Source</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-navy-800/60">
                  {cveList.map((cve) => (
                    <tr key={cve.id} className="hover:bg-navy-850/40">
                      <td className="py-3 px-4 font-mono font-bold text-rose-400">{cve.cve_id}</td>
                      <td className="py-3 px-4">
                        <div className="flex items-center gap-1.5">
                          {getSeverityBadge(cve.severity)}
                          {cve.cvss_score != null && <span className="font-mono text-slate-300">{Number(cve.cvss_score).toFixed(1)}</span>}
                        </div>
                      </td>
                      <td className="py-3 px-4">
                        <div className="flex flex-col gap-1 items-start">
                          {cve.is_known_exploited && (
                            <span className="px-1.5 py-0.5 rounded text-[10px] font-semibold bg-rose-950 text-rose-300 border border-rose-800">
                              CISA KEV
                            </span>
                          )}
                          {cve.epss_score !== null && cve.epss_score !== undefined && (
                            <span className="px-1.5 py-0.5 rounded text-[10px] font-mono text-cyan-300 bg-cyan-950/60 border border-cyan-800">
                              EPSS {(Number(cve.epss_score) * 100).toFixed(1)}%
                            </span>
                          )}
                        </div>
                      </td>
                      <td className="py-3 px-4 max-w-md text-slate-300">{cve.description}</td>
                      <td className="py-3 px-4 font-mono text-slate-400">{cve.source}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            )}
          </div>
        </div>
      )}

      {/* TAB 3: SCAN HISTORY */}
      {activeTab === 'history' && (
        <div className="bg-navy-900 border border-navy-800 rounded-xl overflow-hidden">
          {isLoadingJobs ? (
            <div className="p-12 text-center text-slate-400">Loading scan jobs...</div>
          ) : scanJobs.length === 0 ? (
            <div className="p-12 text-center text-slate-400">No previous vulnerability scan jobs recorded.</div>
          ) : (
            <table className="w-full text-left text-xs border-collapse">
              <thead>
                <tr className="bg-navy-950/80 border-b border-navy-800 text-slate-400 font-semibold uppercase">
                  <th className="py-3 px-4">Job ID</th>
                  <th className="py-3 px-4">Scope</th>
                  <th className="py-3 px-4">Status</th>
                  <th className="py-3 px-4">Services Analyzed</th>
                  <th className="py-3 px-4">Findings Generated</th>
                  <th className="py-3 px-4">Timestamp</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-navy-800/60">
                {scanJobs.map((j) => (
                  <tr key={j.id} className="hover:bg-navy-850/40">
                    <td className="py-3 px-4 font-mono text-slate-400">{j.id.slice(0, 8)}...</td>
                    <td className="py-3 px-4 text-slate-200">{j.asset_id ? 'Single Asset' : 'All Tenant Assets'}</td>
                    <td className="py-3 px-4">
                      <span className="px-2 py-0.5 rounded text-[10px] font-semibold bg-emerald-950 text-emerald-400 border border-emerald-800">
                        {j.status}
                      </span>
                    </td>
                    <td className="py-3 px-4 font-mono text-slate-300">{j.services_scanned_count}</td>
                    <td className="py-3 px-4 font-mono font-bold text-rose-400">{j.vulnerabilities_found_count}</td>
                    <td className="py-3 px-4 text-slate-400 font-mono">{new Date(j.created_at).toLocaleString()}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          )}
        </div>
      )}

      {/* SLIDE-OVER INSPECTION DRAWER */}
      {selectedRecord && (
        <div className="fixed inset-0 z-50 overflow-hidden bg-black/60 backdrop-blur-sm flex justify-end">
          <div className="w-full max-w-2xl bg-navy-900 border-l border-navy-800 h-full overflow-y-auto p-6 space-y-6 shadow-2xl">
            {/* Drawer Header */}
            <div className="flex items-start justify-between border-b border-navy-800 pb-4">
              <div>
                <div className="flex items-center gap-2">
                  <span className="font-mono text-xl font-bold text-rose-400">{selectedRecord.cve_id}</span>
                  {getSeverityBadge(selectedRecord.severity)}
                  {getStatusBadge(selectedRecord.status)}
                </div>
                <h2 className="text-sm font-semibold text-white mt-1">{selectedRecord.title}</h2>
              </div>
              <button
                onClick={() => setSelectedRecord(null)}
                className="p-1 rounded-lg hover:bg-navy-800 text-slate-400 hover:text-white"
              >
                <X className="w-5 h-5" />
              </button>
            </div>

            {/* Contextual Risk & Prioritization Rationale */}
            <div className="p-4 bg-navy-950 border border-navy-800 rounded-xl space-y-2">
              <div className="flex items-center justify-between">
                <span className="text-xs font-semibold text-slate-300 uppercase tracking-wider">Contextual Risk Score</span>
                <span className="text-xl font-mono font-bold text-cyan-400">{(selectedRecord.risk_score ?? 0).toFixed(1)} / 100</span>
              </div>
              <div className="w-full bg-navy-800 rounded-full h-2">
                <div
                  className="bg-gradient-to-r from-yellow-500 via-rose-500 to-red-600 h-2 rounded-full"
                  style={{ width: `${Math.min(100, selectedRecord.risk_score ?? 0)}%` }}
                />
              </div>
              <p className="text-xs text-slate-400 mt-2 leading-relaxed">
                {selectedRecord.prioritization_explanation}
              </p>
              <div className="text-[10px] text-slate-500 italic mt-1">
                Notice: Risk scores indicate contextual urgency for mitigation, not an absolute certainty of exploit breach.
              </div>
            </div>

            {/* Threat Intelligence Evidence */}
            <div className="space-y-3">
              <h3 className="text-xs font-semibold text-slate-400 uppercase tracking-wider">Observed Evidence & Match</h3>
              <div className="p-3 bg-navy-950/80 border border-navy-800 rounded-lg text-xs space-y-2">
                <div className="grid grid-cols-2 gap-2">
                  <div>
                    <span className="text-slate-500 block">Matched Software:</span>
                    <span className="font-mono text-slate-200">{selectedRecord.matched_service_name || 'Generic'}</span>
                  </div>
                  <div>
                    <span className="text-slate-500 block">Identified Version:</span>
                    <span className="font-mono text-cyan-300">{selectedRecord.matched_version || 'Ambiguous / Unconfirmed'}</span>
                  </div>
                  <div>
                    <span className="text-slate-500 block">Match Confidence:</span>
                    <div>{getConfidenceBadge(selectedRecord.confidence)}</div>
                  </div>
                  <div>
                    <span className="text-slate-500 block">Port & Target:</span>
                    <span className="font-mono text-slate-200">Port {selectedRecord.service_port} ({selectedRecord.asset_target})</span>
                  </div>
                </div>

                {selectedRecord.matched_cpe && (
                  <div className="pt-2 border-t border-navy-800">
                    <span className="text-slate-500 block">Matched CPE:</span>
                    <span className="font-mono text-[11px] text-amber-300/90">{selectedRecord.matched_cpe}</span>
                  </div>
                )}
              </div>
            </div>

            {/* Threat Signals (KEV / EPSS / CVSS) */}
            <div className="space-y-3">
              <h3 className="text-xs font-semibold text-slate-400 uppercase tracking-wider">Threat Telemetry</h3>
              <div className="grid grid-cols-2 gap-3 text-xs">
                <div className="p-3 bg-navy-950/60 border border-navy-800 rounded-lg">
                  <span className="text-slate-500 block">CISA KEV Status:</span>
                  {selectedRecord.is_known_exploited ? (
                    <span className="text-rose-400 font-bold flex items-center gap-1 mt-1">
                      <Flame className="w-3.5 h-3.5" /> Actively Exploited
                    </span>
                  ) : (
                    <span className="text-slate-400 mt-1 block">Not Listed in KEV</span>
                  )}
                </div>

                <div className="p-3 bg-navy-950/60 border border-navy-800 rounded-lg">
                  <span className="text-slate-500 block">FIRST EPSS Score:</span>
                  <span className="font-mono font-bold text-cyan-400 mt-1 block">
                    {selectedRecord.epss_score !== null && selectedRecord.epss_score !== undefined
                      ? `${(Number(selectedRecord.epss_score) * 100).toFixed(2)}% Exploit Likelihood`
                      : 'N/A'}
                  </span>
                </div>
              </div>
            </div>

            {/* Description & Remediation */}
            <div className="space-y-3 text-xs">
              <h3 className="text-xs font-semibold text-slate-400 uppercase tracking-wider">Vulnerability Overview</h3>
              <p className="text-slate-300 leading-relaxed bg-navy-950/40 p-3 rounded-lg border border-navy-800/60">
                {selectedRecord.description}
              </p>

              <h3 className="text-xs font-semibold text-slate-400 uppercase tracking-wider mt-4">Remediation Guidance</h3>
              <div className="p-3 bg-emerald-950/20 border border-emerald-900/60 rounded-lg text-emerald-300 flex items-start gap-2">
                <CheckCircle2 className="w-4 h-4 text-emerald-400 flex-shrink-0 mt-0.5" />
                <span>{selectedRecord.remediation_guidance}</span>
              </div>
            </div>

            {/* Triage / Remediation Status Updater */}
            <div className="pt-4 border-t border-navy-800 space-y-3">
              <h3 className="text-xs font-semibold text-slate-300 uppercase tracking-wider">Update Triage Status</h3>
              <div className="grid grid-cols-2 gap-3">
                <div>
                  <label className="text-[11px] text-slate-400 block mb-1">Status</label>
                  <select
                    value={triageStatus}
                    onChange={(e) => setTriageStatus(e.target.value)}
                    className="w-full bg-navy-950 border border-navy-700 rounded-lg px-2.5 py-1.5 text-xs text-slate-200 focus:outline-none"
                  >
                    <option value="DETECTED">DETECTED</option>
                    <option value="IN_TRIAGE">IN_TRIAGE</option>
                    <option value="MITIGATED">MITIGATED</option>
                    <option value="PATCHED">PATCHED</option>
                    <option value="ACCEPTED">ACCEPTED (Risk Accepted)</option>
                    <option value="FALSE_POSITIVE">FALSE_POSITIVE</option>
                  </select>
                </div>
                <div>
                  <label className="text-[11px] text-slate-400 block mb-1">Notes / Rationale</label>
                  <input
                    type="text"
                    placeholder="e.g. Patch scheduled for maintenance window..."
                    value={triageNotes}
                    onChange={(e) => setTriageNotes(e.target.value)}
                    className="w-full bg-navy-950 border border-navy-700 rounded-lg px-2.5 py-1.5 text-xs text-slate-200 focus:outline-none"
                  />
                </div>
              </div>
              <button
                onClick={handleStatusUpdate}
                disabled={isUpdatingStatus}
                className="w-full py-2 bg-navy-800 hover:bg-navy-750 text-slate-200 border border-navy-700 rounded-lg text-xs font-semibold transition-colors flex items-center justify-center gap-2"
              >
                {isUpdatingStatus ? <Loader2 className="w-3.5 h-3.5 animate-spin" /> : <CheckCircle2 className="w-3.5 h-3.5 text-emerald-400" />}
                <span>Save Status & Log Audit Event</span>
              </button>
            </div>
          </div>
        </div>
      )}

      {/* MODAL: RUN VULNERABILITY SCAN */}
      {isScanModalOpen && (
        <div className="fixed inset-0 z-50 bg-black/60 backdrop-blur-sm flex items-center justify-center p-4">
          <div className="bg-navy-900 border border-navy-800 rounded-2xl max-w-md w-full p-6 space-y-4 shadow-2xl">
            <div className="flex items-center justify-between border-b border-navy-800 pb-3">
              <div className="flex items-center gap-2">
                <Zap className="w-5 h-5 text-rose-500" />
                <h3 className="text-base font-bold text-white">Execute Vulnerability Mapping</h3>
              </div>
              <button onClick={() => setIsScanModalOpen(false)} className="text-slate-400 hover:text-white">
                <X className="w-4 h-4" />
              </button>
            </div>

            <p className="text-xs text-slate-400 leading-relaxed">
              Maps discovered TCP/HTTP services against the latest CVE intelligence, evaluating version bounds and calculating contextual risk scores.
            </p>

            <div>
              <label className="text-xs font-semibold text-slate-300 block mb-1.5">Scan Scope</label>
              <select
                value={selectedAssetId}
                onChange={(e) => setSelectedAssetId(e.target.value)}
                className="w-full bg-navy-950 border border-navy-700 rounded-lg p-2 text-xs text-slate-200 focus:outline-none focus:border-rose-500"
              >
                <option value="ALL">All Organization Assets (Full Fleet Scan)</option>
                {assets.map((a) => (
                  <option key={a.id} value={a.id}>
                    {a.name} ({a.target})
                  </option>
                ))}
              </select>
            </div>

            <div className="p-3 bg-navy-950 border border-navy-800 rounded-lg text-[11px] text-slate-400 space-y-1">
              <div className="font-semibold text-slate-300">Phase 3 Guardrails:</div>
              <div>• Non-destructive mapping using discovered service banners.</div>
              <div>• Bounded 0–100 risk score factoring KEV and EPSS signals.</div>
              <div>• Missing or ambiguous version banners will reduce confidence.</div>
            </div>

            <div className="flex items-center justify-end gap-3 pt-3 border-t border-navy-800">
              <button
                type="button"
                onClick={() => setIsScanModalOpen(false)}
                className="px-4 py-2 bg-navy-800 hover:bg-navy-750 text-slate-300 rounded-lg text-xs"
              >
                Cancel
              </button>
              <button
                type="button"
                onClick={handleStartScan}
                disabled={isStartingScan}
                className="px-4 py-2 bg-rose-600 hover:bg-rose-500 text-white rounded-lg text-xs font-semibold flex items-center gap-2 shadow-lg shadow-rose-900/40"
              >
                {isStartingScan ? <Loader2 className="w-3.5 h-3.5 animate-spin" /> : <Zap className="w-3.5 h-3.5" />}
                <span>Initiate Mapping Scan</span>
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
};
