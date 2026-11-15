import React, { useEffect, useState } from 'react';
import {
  AlertTriangle,
  ArrowRight,
  CheckCircle2,
  Flame,
  Globe,
  Info,
  Layers,
  Link as LinkIcon,
  Loader2,
  Network,
  Play,
  RefreshCw,
  Server,
  Shield,
  ShieldAlert,
  ShieldCheck,
  Trash2,
  Workflow,
  X,
  Zap,
} from 'lucide-react';
import {
  AssetTrustRelationship,
  AttackPath,
  AttackPathOverviewStats,
  GraphNode,
  MitreTechnique,
  PreventionRecommendation,
} from '@/types/attackPath';
import { attackPathApi } from '@/services/attackPathApi';
import { api } from '@/services/api';
import { ManagedAsset } from '@/types/asset';

export const AttackPathsPage: React.FC = () => {
  const [activeTab, setActiveTab] = useState<'paths' | 'recommendations' | 'trust'>('paths');

  // State
  const [overview, setOverview] = useState<AttackPathOverviewStats | null>(null);
  const [paths, setPaths] = useState<AttackPath[]>([]);
  const [totalPaths, setTotalPaths] = useState(0);
  const [recommendations, setRecommendations] = useState<PreventionRecommendation[]>([]);
  const [totalRecs, setTotalRecs] = useState(0);
  const [trustLinks, setTrustLinks] = useState<AssetTrustRelationship[]>([]);
  const [assets, setAssets] = useState<ManagedAsset[]>([]);
  const [isLoading, setIsLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  // Filters
  const [severityFilter, setSeverityFilter] = useState<string>('ALL');
  const [confidenceFilter, setConfidenceFilter] = useState<string>('ALL');
  const [statusFilter, setStatusFilter] = useState<string>('ALL');
  const [recCategoryFilter, setRecCategoryFilter] = useState<string>('ALL');

  // Selected Path for Inspection
  const [selectedPath, setSelectedPath] = useState<AttackPath | null>(null);
  const [isUpdatingStatus, setIsUpdatingStatus] = useState(false);

  // Analysis Trigger Modal
  const [isAnalysisModalOpen, setIsAnalysisModalOpen] = useState(false);
  const [isAnalyzing, setIsAnalyzing] = useState(false);
  const [analysisResult, setAnalysisResult] = useState<string | null>(null);

  // New Trust Link Modal
  const [isTrustModalOpen, setIsTrustModalOpen] = useState(false);
  const [newTrustSource, setNewTrustSource] = useState('');
  const [newTrustTarget, setNewTrustTarget] = useState('');
  const [newTrustType, setNewTrustType] = useState('SAME_SUBNET');
  const [newTrustPort, setNewTrustPort] = useState<number | undefined>(undefined);
  const [isCreatingTrust, setIsCreatingTrust] = useState(false);

  // Initial Load
  useEffect(() => {
    fetchInitialData();
  }, []);

  const fetchInitialData = async () => {
    setIsLoading(true);
    setError(null);
    try {
      const [overviewData, pathsData, recsData, trustData, assetsRes] = await Promise.all([
        attackPathApi.getOverview().catch(() => null),
        attackPathApi.listPaths({ limit: 50 }).catch(() => ({ total: 0, items: [], limit: 50, offset: 0 })),
        attackPathApi.listRecommendations({ limit: 50 }).catch(() => ({ total: 0, items: [], limit: 50, offset: 0 })),
        attackPathApi.listTrustRelationships().catch(() => []),
        api.get('/assets').catch(() => ({ data: { items: [], total: 0 } })),
      ]);

      setOverview(overviewData);
      const fetchedPaths = Array.isArray(pathsData?.items) ? pathsData.items : [];
      setPaths(fetchedPaths);
      setTotalPaths(pathsData?.total ?? 0);
      if (fetchedPaths.length > 0 && !selectedPath) {
        setSelectedPath(fetchedPaths[0]);
      }
      setRecommendations(Array.isArray(recsData?.items) ? recsData.items : []);
      setTotalRecs(recsData?.total ?? 0);
      setTrustLinks(Array.isArray(trustData) ? trustData : []);
      const assetList = Array.isArray(assetsRes?.data?.items)
        ? assetsRes.data.items
        : Array.isArray(assetsRes?.data)
          ? assetsRes.data
          : [];
      setAssets(assetList);
    } catch (err: any) {
      setError(err?.response?.data?.detail || 'Failed to load attack path intelligence data.');
    } finally {
      setIsLoading(false);
    }
  };

  const reloadPaths = async () => {
    try {
      const params: any = { limit: 50 };
      if (severityFilter !== 'ALL') params.severity = severityFilter;
      if (confidenceFilter !== 'ALL') params.confidence = confidenceFilter;
      if (statusFilter !== 'ALL') params.status = statusFilter;
      const res = await attackPathApi.listPaths(params).catch(() => ({ total: 0, items: [], limit: 50, offset: 0 }));
      const items = Array.isArray(res?.items) ? res.items : [];
      setPaths(items);
      setTotalPaths(res?.total ?? 0);
      if (items.length > 0 && (!selectedPath || !items.some(p => p.id === selectedPath.id))) {
        setSelectedPath(items[0]);
      }
    } catch (err: any) {
      console.error('Failed to reload paths', err);
    }
  };

  const reloadRecommendations = async () => {
    try {
      const params: any = { limit: 50 };
      if (recCategoryFilter !== 'ALL') params.category = recCategoryFilter;
      const res = await attackPathApi.listRecommendations(params).catch(() => ({ total: 0, items: [], limit: 50, offset: 0 }));
      setRecommendations(Array.isArray(res?.items) ? res.items : []);
      setTotalRecs(res?.total ?? 0);
    } catch (err: any) {
      console.error('Failed to reload recommendations', err);
    }
  };

  useEffect(() => {
    reloadPaths();
  }, [severityFilter, confidenceFilter, statusFilter]);

  useEffect(() => {
    reloadRecommendations();
  }, [recCategoryFilter]);

  const handleUpdatePathStatus = async (newStatus: string) => {
    if (!selectedPath) return;
    setIsUpdatingStatus(true);
    try {
      const updated = await attackPathApi.updatePathStatus(selectedPath.id, newStatus);
      setSelectedPath(updated);
      setPaths(prev => prev.map(p => (p.id === updated.id ? updated : p)));
      const newOverview = await attackPathApi.getOverview();
      setOverview(newOverview);
    } catch (err: any) {
      alert(err?.response?.data?.detail || 'Failed to update path status.');
    } finally {
      setIsUpdatingStatus(false);
    }
  };

  const handleUpdateRecStatus = async (recId: string, newStatus: string) => {
    try {
      const updated = await attackPathApi.updateRecommendationStatus(recId, newStatus);
      setRecommendations(prev => prev.map(r => (r.id === updated.id ? updated : r)));
      const newOverview = await attackPathApi.getOverview();
      setOverview(newOverview);
    } catch (err: any) {
      alert(err?.response?.data?.detail || 'Failed to update recommendation status.');
    }
  };

  const handleTriggerAnalysis = async (sync = true) => {
    setIsAnalyzing(true);
    setAnalysisResult(null);
    try {
      const res = await attackPathApi.triggerAnalysis({ sync });
      setAnalysisResult(`Analysis completed: ${res.paths_discovered || 0} paths discovered, ${res.recommendations_count || 0} prevention controls synthesized.`);
      await fetchInitialData();
    } catch (err: any) {
      setAnalysisResult(`Analysis failed: ${err?.response?.data?.detail || err.message}`);
    } finally {
      setIsAnalyzing(false);
    }
  };

  const handleCreateTrustLink = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!newTrustSource || !newTrustTarget) {
      alert('Please select both source and target assets.');
      return;
    }
    setIsCreatingTrust(true);
    try {
      const newRel = await attackPathApi.createTrustRelationship({
        source_asset_id: newTrustSource,
        target_asset_id: newTrustTarget,
        relationship_type: newTrustType,
        port: newTrustPort || undefined,
        evidence_source: 'MANUAL_VERIFIED',
        is_verified: true,
      });
      setTrustLinks(prev => [newRel, ...prev]);
      setIsTrustModalOpen(false);
      setNewTrustSource('');
      setNewTrustTarget('');
      setNewTrustPort(undefined);
    } catch (err: any) {
      alert(err?.response?.data?.detail || 'Failed to create trust relationship.');
    } finally {
      setIsCreatingTrust(false);
    }
  };

  const handleDeleteTrustLink = async (id: string) => {
    if (!confirm('Are you sure you want to delete this trust relationship?')) return;
    try {
      await attackPathApi.deleteTrustRelationship(id);
      setTrustLinks(prev => prev.filter(r => r.id !== id));
    } catch (err: any) {
      alert(err?.response?.data?.detail || 'Failed to delete trust link.');
    }
  };

  // Severity Helper
  const getSeverityBadge = (severity: string) => {
    switch (severity) {
      case 'CRITICAL':
        return 'bg-red-500/20 text-red-400 border-red-500/30';
      case 'HIGH':
        return 'bg-orange-500/20 text-orange-400 border-orange-500/30';
      case 'MEDIUM':
        return 'bg-amber-500/20 text-amber-400 border-amber-500/30';
      default:
        return 'bg-blue-500/20 text-blue-400 border-blue-500/30';
    }
  };

  const getConfidenceBadge = (confidence: string) => {
    switch (confidence) {
      case 'CONFIRMED':
        return 'bg-emerald-500/20 text-emerald-400 border-emerald-500/30';
      case 'LIKELY':
        return 'bg-cyan-500/20 text-cyan-400 border-cyan-500/30';
      default:
        return 'bg-purple-500/20 text-purple-400 border-purple-500/30';
    }
  };

  return (
    <div className="min-h-screen bg-gray-950 text-gray-100 p-6 space-y-6">
      {/* Top Header */}
      <div className="flex flex-col md:flex-row md:items-center md:justify-between gap-4 border-b border-gray-800 pb-5">
        <div>
          <div className="flex items-center gap-3">
            <div className="p-2 bg-rose-600/20 border border-rose-500/30 rounded-lg text-rose-400">
              <Workflow className="w-6 h-6" />
            </div>
            <div>
              <h1 className="text-2xl font-bold tracking-tight text-white flex items-center gap-2">
                AI Attack Path & Prevention Engine
                <span className="text-xs px-2 py-0.5 rounded-full bg-rose-500/20 text-rose-300 border border-rose-500/40">
                  MOD-03
                </span>
              </h1>
              <p className="text-sm text-gray-400">
                Evidence-backed kill-chain modeling and prioritized compensating controls for SMB infrastructure.
              </p>
            </div>
          </div>
        </div>

        <div className="flex items-center gap-3">
          <button
            onClick={() => fetchInitialData()}
            disabled={isLoading}
            className="flex items-center gap-2 px-3 py-2 text-sm bg-gray-900 hover:bg-gray-800 border border-gray-700 rounded-lg transition-colors"
          >
            <RefreshCw className={`w-4 h-4 ${isLoading ? 'animate-spin' : ''}`} />
            Refresh
          </button>
          <button
            onClick={() => setIsAnalysisModalOpen(true)}
            className="flex items-center gap-2 px-4 py-2 text-sm font-medium bg-rose-600 hover:bg-rose-500 text-white rounded-lg shadow-lg shadow-rose-900/30 transition-all"
          >
            <Play className="w-4 h-4 fill-white" />
            Run Attack Path Analysis
          </button>
        </div>
      </div>

      {error && (
        <div className="p-4 bg-red-900/20 border border-red-700/50 rounded-lg flex items-center gap-3 text-red-300">
          <AlertTriangle className="w-5 h-5 flex-shrink-0" />
          <p className="text-sm">{error}</p>
        </div>
      )}

      {/* KPI Overview Cards */}
      {overview && (
        <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-5 gap-4">
          <div className="bg-gray-900/80 border border-gray-800 rounded-xl p-4 flex flex-col justify-between">
            <div className="flex items-center justify-between text-gray-400 mb-2">
              <span className="text-xs font-semibold uppercase tracking-wider">Total Attack Paths</span>
              <Workflow className="w-4 h-4 text-rose-400" />
            </div>
            <div className="text-2xl font-bold text-white">{overview.total_paths}</div>
            <div className="text-xs text-gray-500 mt-1">Multi-hop kill chains</div>
          </div>

          <div className="bg-gray-900/80 border border-red-900/30 rounded-xl p-4 flex flex-col justify-between">
            <div className="flex items-center justify-between text-red-400 mb-2">
              <span className="text-xs font-semibold uppercase tracking-wider">Critical Paths</span>
              <Flame className="w-4 h-4 text-red-400" />
            </div>
            <div className="text-2xl font-bold text-red-400">{overview.critical_paths}</div>
            <div className="text-xs text-red-400/80 mt-1">High exploitability + Crown Jewel</div>
          </div>

          <div className="bg-gray-900/80 border border-gray-800 rounded-xl p-4 flex flex-col justify-between">
            <div className="flex items-center justify-between text-gray-400 mb-2">
              <span className="text-xs font-semibold uppercase tracking-wider">Crown Jewels at Risk</span>
              <ShieldAlert className="w-4 h-4 text-amber-400" />
            </div>
            <div className="text-2xl font-bold text-amber-300">{overview.crown_jewels_at_risk_count}</div>
            <div className="text-xs text-gray-500 mt-1">Reachable critical targets</div>
          </div>

          <div className="bg-gray-900/80 border border-gray-800 rounded-xl p-4 flex flex-col justify-between">
            <div className="flex items-center justify-between text-gray-400 mb-2">
              <span className="text-xs font-semibold uppercase tracking-wider">Compensating Controls</span>
              <ShieldCheck className="w-4 h-4 text-emerald-400" />
            </div>
            <div className="text-2xl font-bold text-emerald-400">
              {overview.implemented_recommendations}
              <span className="text-sm font-normal text-gray-400"> / {overview.total_recommendations}</span>
            </div>
            <div className="text-xs text-emerald-400/80 mt-1">Implemented / Synthesized</div>
          </div>

          <div className="bg-gray-900/80 border border-gray-800 rounded-xl p-4 flex flex-col justify-between">
            <div className="flex items-center justify-between text-gray-400 mb-2">
              <span className="text-xs font-semibold uppercase tracking-wider">Average Path Risk</span>
              <Zap className="w-4 h-4 text-purple-400" />
            </div>
            <div className="text-2xl font-bold text-purple-300">{overview.average_risk_score} / 100</div>
            <div className="w-full bg-gray-800 h-1.5 rounded-full mt-2 overflow-hidden">
              <div
                className="bg-purple-500 h-full rounded-full"
                style={{ width: `${Math.min(100, overview.average_risk_score)}%` }}
              />
            </div>
          </div>
        </div>
      )}

      {/* Tabs */}
      <div className="border-b border-gray-800 flex gap-4">
        <button
          onClick={() => setActiveTab('paths')}
          className={`pb-3 text-sm font-medium border-b-2 flex items-center gap-2 transition-colors ${activeTab === 'paths'
              ? 'border-rose-500 text-rose-400'
              : 'border-transparent text-gray-400 hover:text-gray-200'
            }`}
        >
          <Workflow className="w-4 h-4" />
          Attack Paths & Visual Graph ({totalPaths})
        </button>

        <button
          onClick={() => setActiveTab('recommendations')}
          className={`pb-3 text-sm font-medium border-b-2 flex items-center gap-2 transition-colors ${activeTab === 'recommendations'
              ? 'border-rose-500 text-rose-400'
              : 'border-transparent text-gray-400 hover:text-gray-200'
            }`}
        >
          <ShieldCheck className="w-4 h-4" />
          Prevention Recommendations ({totalRecs})
        </button>

        <button
          onClick={() => setActiveTab('trust')}
          className={`pb-3 text-sm font-medium border-b-2 flex items-center gap-2 transition-colors ${activeTab === 'trust'
              ? 'border-rose-500 text-rose-400'
              : 'border-transparent text-gray-400 hover:text-gray-200'
            }`}
        >
          <LinkIcon className="w-4 h-4" />
          Asset Trust Relationships ({trustLinks.length})
        </button>
      </div>

      {/* TAB 1: ATTACK PATHS & GRAPH */}
      {activeTab === 'paths' && (
        <div className="grid grid-cols-1 lg:grid-cols-12 gap-6">
          {/* Left Column: Path Inventory List (5 Cols) */}
          <div className="lg:col-span-5 space-y-4">
            {/* Filter Bar */}
            <div className="bg-gray-900 border border-gray-800 p-3 rounded-xl flex flex-wrap gap-2 items-center justify-between text-xs">
              <div className="flex items-center gap-2">
                <span className="text-gray-400">Severity:</span>
                <select
                  value={severityFilter}
                  onChange={e => setSeverityFilter(e.target.value)}
                  className="bg-gray-800 border border-gray-700 text-gray-200 rounded px-2 py-1"
                >
                  <option value="ALL">All</option>
                  <option value="CRITICAL">Critical</option>
                  <option value="HIGH">High</option>
                  <option value="MEDIUM">Medium</option>
                  <option value="LOW">Low</option>
                </select>
              </div>

              <div className="flex items-center gap-2">
                <span className="text-gray-400">Confidence:</span>
                <select
                  value={confidenceFilter}
                  onChange={e => setConfidenceFilter(e.target.value)}
                  className="bg-gray-800 border border-gray-700 text-gray-200 rounded px-2 py-1"
                >
                  <option value="ALL">All</option>
                  <option value="CONFIRMED">Confirmed</option>
                  <option value="LIKELY">Likely</option>
                  <option value="POTENTIAL">Potential</option>
                </select>
              </div>

              <div className="flex items-center gap-2">
                <span className="text-gray-400">Status:</span>
                <select
                  value={statusFilter}
                  onChange={e => setStatusFilter(e.target.value)}
                  className="bg-gray-800 border border-gray-700 text-gray-200 rounded px-2 py-1"
                >
                  <option value="ALL">All</option>
                  <option value="IDENTIFIED">Identified</option>
                  <option value="UNDER_REVIEW">Under Review</option>
                  <option value="MITIGATED">Mitigated</option>
                  <option value="ACCEPTED">Accepted</option>
                </select>
              </div>
            </div>

            {/* List */}
            <div className="space-y-3 max-h-[750px] overflow-y-auto pr-1">
              {paths.length === 0 ? (
                <div className="text-center py-12 bg-gray-900 border border-gray-800 rounded-xl text-gray-400">
                  <Workflow className="w-10 h-10 mx-auto text-gray-600 mb-3" />
                  <p className="font-medium text-gray-300">No attack paths found matching filters.</p>
                  <p className="text-xs text-gray-500 mt-1">
                    Click "Run Attack Path Analysis" to scan assets and compute kill chains.
                  </p>
                </div>
              ) : (
                paths.map(path => {
                  const isSelected = selectedPath?.id === path.id;
                  return (
                    <div
                      key={path.id}
                      onClick={() => setSelectedPath(path)}
                      className={`p-4 rounded-xl border transition-all cursor-pointer ${isSelected
                          ? 'bg-rose-950/20 border-rose-500/60 shadow-lg shadow-rose-950/30'
                          : 'bg-gray-900 border-gray-800 hover:border-gray-700'
                        }`}
                    >
                      <div className="flex items-start justify-between gap-2">
                        <div>
                          <div className="flex items-center gap-2">
                            <span
                              className={`text-[10px] font-bold px-2 py-0.5 rounded border uppercase ${getSeverityBadge(
                                path.severity
                              )}`}
                            >
                              {path.severity}
                            </span>
                            <span
                              className={`text-[10px] font-semibold px-2 py-0.5 rounded border ${getConfidenceBadge(
                                path.confidence
                              )}`}
                            >
                              {path.confidence}
                            </span>
                            <span className="text-[10px] text-gray-400 bg-gray-800 px-2 py-0.5 rounded">
                              {path.step_count} {path.step_count === 1 ? 'hop' : 'hops'}
                            </span>
                          </div>
                          <h3 className="font-semibold text-sm text-gray-100 mt-2 line-clamp-1">
                            {path.title || path.name}
                          </h3>
                        </div>

                        <div className="text-right">
                          <div className="text-base font-bold text-white">{path.risk_score}</div>
                          <div className="text-[10px] text-gray-400 uppercase">Risk Score</div>
                        </div>
                      </div>

                      {/* Entry -> Target flow */}
                      <div className="mt-3 text-xs flex items-center gap-2 text-gray-300 bg-gray-950/60 p-2 rounded-lg border border-gray-800/80">
                        <span className="font-mono text-amber-400 truncate max-w-[120px]">
                          {path.entry_point_asset_name || 'Entry'}
                        </span>
                        <ArrowRight className="w-3.5 h-3.5 text-gray-500 flex-shrink-0" />
                        <span className="font-mono text-rose-400 truncate max-w-[140px]">
                          {path.target_asset_name || 'Target'}
                        </span>
                      </div>

                      {/* Footer tags */}
                      <div className="mt-3 flex items-center justify-between text-xs text-gray-400">
                        <span className="text-[11px] text-gray-500">
                          {path.mitre_tactics.slice(0, 2).join(' \u2192 ')}
                        </span>
                        <span className="text-[10px] px-2 py-0.5 bg-gray-800 rounded font-mono text-gray-300">
                          {path.status}
                        </span>
                      </div>
                    </div>
                  );
                })
              )}
            </div>
          </div>

          {/* Right Column: Visual Graph & Path Deep Dive (7 Cols) */}
          <div className="lg:col-span-7 space-y-4">
            {selectedPath ? (
              <div className="bg-gray-900 border border-gray-800 rounded-xl p-5 space-y-6">
                {/* Header of selected path */}
                <div className="flex flex-col sm:flex-row sm:items-start justify-between gap-4 pb-4 border-b border-gray-800">
                  <div>
                    <div className="flex items-center gap-2">
                      <span
                        className={`text-xs font-bold px-2 py-0.5 rounded border ${getSeverityBadge(
                          selectedPath.severity
                        )}`}
                      >
                        {selectedPath.severity}
                      </span>
                      <span
                        className={`text-xs font-semibold px-2 py-0.5 rounded border ${getConfidenceBadge(
                          selectedPath.confidence
                        )}`}
                      >
                        {selectedPath.confidence}
                      </span>
                      <span className="text-xs text-gray-400">
                        ID: <span className="font-mono">{selectedPath.id.slice(0, 8)}</span>
                      </span>
                    </div>
                    <h2 className="text-lg font-bold text-white mt-1.5">
                      {selectedPath.title || selectedPath.name}
                    </h2>
                    <p className="text-xs text-gray-400 mt-0.5">{selectedPath.description}</p>
                  </div>

                  {/* Status Dropdown */}
                  <div className="flex items-center gap-2">
                    <span className="text-xs text-gray-400">Status:</span>
                    <select
                      value={selectedPath.status}
                      disabled={isUpdatingStatus}
                      onChange={e => handleUpdatePathStatus(e.target.value)}
                      className="bg-gray-800 border border-gray-700 text-xs rounded-lg px-2.5 py-1.5 text-gray-200 focus:outline-none focus:border-rose-500 font-medium"
                    >
                      <option value="IDENTIFIED">IDENTIFIED</option>
                      <option value="UNDER_REVIEW">UNDER REVIEW</option>
                      <option value="MITIGATED">MITIGATED</option>
                      <option value="ACCEPTED">ACCEPTED</option>
                    </select>
                  </div>
                </div>

                {/* VISUAL GRAPH RENDERING */}
                <div className="space-y-2">
                  <div className="flex items-center justify-between text-xs text-gray-400">
                    <span className="font-semibold uppercase tracking-wider flex items-center gap-1.5">
                      <Network className="w-4 h-4 text-rose-400" />
                      Evidence-Backed Attack Graph Visualizer
                    </span>
                    <span className="text-gray-500">
                      {(selectedPath.graph_data?.nodes || []).length || 2} Nodes | {(selectedPath.graph_data?.edges || []).length || 1} Hops
                    </span>
                  </div>

                  <div className="bg-gray-950 border border-gray-800 rounded-xl p-4 overflow-x-auto min-h-[160px] flex items-center justify-center">
                    {/* Visual Node Flow */}
                    <div className="flex items-center gap-3 py-2">
                      {/* Adversary node */}
                      <div className="flex flex-col items-center">
                        <div className="w-12 h-12 rounded-full bg-red-950/40 border border-red-500/50 flex items-center justify-center text-red-400 shadow-md shadow-red-950/40">
                          <Globe className="w-5 h-5" />
                        </div>
                        <span className="text-[10px] font-semibold text-gray-400 mt-1.5">Internet</span>
                        <span className="text-[9px] text-gray-500">Adversary</span>
                      </div>

                      {/* Render Nodes from graph_data */}
                      {(selectedPath.graph_data?.nodes || []).map((node: GraphNode, idx: number) => {
                        const edge = (selectedPath.graph_data?.edges || [])[idx];
                        return (
                          <React.Fragment key={node.id}>
                            {/* Connecting Arrow with Edge label */}
                            <div className="flex flex-col items-center px-2">
                              <span className="text-[9px] font-mono text-rose-400/90 max-w-[100px] truncate text-center">
                                {edge?.mitre_technique_id || 'EXPLOIT'}
                              </span>
                              <div className="flex items-center my-1 text-gray-600">
                                <div className="h-0.5 w-8 bg-gray-700" />
                                <ArrowRight className="w-4 h-4 text-rose-400 -ml-1 flex-shrink-0" />
                              </div>
                              <span className="text-[9px] text-gray-500">
                                {edge?.port ? `Port ${edge.port}` : 'Trust Hop'}
                              </span>
                            </div>

                            {/* Target Node */}
                            <div className="flex flex-col items-center">
                              <div
                                className={`w-14 h-14 rounded-xl border flex flex-col items-center justify-center shadow-lg transition-transform hover:scale-105 ${node.is_crown_jewel
                                    ? 'bg-rose-950/40 border-rose-500 text-rose-300 shadow-rose-950/50'
                                    : node.is_entry_point
                                      ? 'bg-amber-950/40 border-amber-500 text-amber-300 shadow-amber-950/50'
                                      : 'bg-blue-950/40 border-blue-500 text-blue-300 shadow-blue-950/50'
                                  }`}
                              >
                                {node.is_crown_jewel ? (
                                  <ShieldAlert className="w-6 h-6" />
                                ) : node.is_entry_point ? (
                                  <Globe className="w-6 h-6" />
                                ) : (
                                  <Server className="w-6 h-6" />
                                )}
                              </div>
                              <span className="text-[11px] font-semibold text-gray-200 mt-1 max-w-[100px] truncate text-center">
                                {node.name}
                              </span>
                              <span
                                className={`text-[9px] px-1.5 py-0.2 rounded font-mono ${node.is_crown_jewel
                                    ? 'text-rose-400 bg-rose-950/80'
                                    : node.is_entry_point
                                      ? 'text-amber-400 bg-amber-950/80'
                                      : 'text-blue-400 bg-blue-950/80'
                                  }`}
                              >
                                {node.is_crown_jewel ? 'Crown Jewel' : node.is_entry_point ? 'Entry Point' : 'Pivot'}
                              </span>
                            </div>
                          </React.Fragment>
                        );
                      })}
                    </div>
                  </div>
                </div>

                {/* Kill Chain Step-by-Step Narrative */}
                <div className="space-y-2">
                  <h4 className="text-xs font-semibold text-gray-300 uppercase tracking-wider flex items-center gap-1.5">
                    <Info className="w-4 h-4 text-blue-400" />
                    Step-by-Step Kill-Chain Narrative
                  </h4>
                  <div className="bg-gray-950 border border-gray-800 rounded-xl p-3.5 text-xs text-gray-300 font-mono whitespace-pre-line leading-relaxed">
                    {selectedPath.path_narrative || 'No narrative generated for this path.'}
                  </div>
                </div>

                {/* MITRE ATT&CK Matrix Mapping */}
                <div className="space-y-3">
                  <h4 className="text-xs font-semibold text-gray-300 uppercase tracking-wider flex items-center gap-1.5">
                    <Layers className="w-4 h-4 text-purple-400" />
                    MITRE ATT&CK Alignment
                  </h4>

                  <div className="grid grid-cols-1 sm:grid-cols-2 gap-3">
                    {(selectedPath.mitre_techniques || []).map((tech: MitreTechnique, idx: number) => (
                      <div
                        key={idx}
                        className="bg-gray-950 border border-gray-800 p-3 rounded-lg text-xs space-y-1.5"
                      >
                        <div className="flex items-center justify-between">
                          <span className="font-mono font-bold text-rose-400 bg-rose-950/50 px-1.5 py-0.5 rounded border border-rose-800/40">
                            {tech.id}
                          </span>
                          <span className="text-[10px] text-gray-400 uppercase tracking-wider">
                            {tech.tactic}
                          </span>
                        </div>
                        <div className="font-medium text-gray-200">{tech.name}</div>
                        <p className="text-[11px] text-gray-400 line-clamp-2">{tech.description}</p>
                      </div>
                    ))}
                  </div>
                </div>

                {/* Exploit Prerequisites */}
                {(selectedPath.prerequisites || []).length > 0 && (
                  <div className="space-y-2">
                    <h4 className="text-xs font-semibold text-gray-300 uppercase tracking-wider flex items-center gap-1.5">
                      <Shield className="w-4 h-4 text-amber-400" />
                      Required Exploit Prerequisites
                    </h4>
                    <ul className="grid grid-cols-1 sm:grid-cols-2 gap-2 text-xs">
                      {(selectedPath.prerequisites || []).map((prereq: string, idx: number) => (
                        <li
                          key={idx}
                          className="bg-gray-950 border border-gray-800/80 p-2 rounded text-gray-300 flex items-start gap-2"
                        >
                          <span className="w-1.5 h-1.5 rounded-full bg-amber-400 mt-1.5 flex-shrink-0" />
                          <span>{prereq}</span>
                        </li>
                      ))}
                    </ul>
                  </div>
                )}

                {/* Evidence References */}
                {(selectedPath.evidence_references || []).length > 0 && (
                  <div className="space-y-2">
                    <h4 className="text-xs font-semibold text-gray-400 uppercase tracking-wider">
                      Empirical Evidence Citations
                    </h4>
                    <div className="flex flex-wrap gap-1.5">
                      {(selectedPath.evidence_references || []).map((ref: string, idx: number) => (
                        <span
                          key={idx}
                          className="text-[10px] font-mono bg-gray-950 border border-gray-800 text-gray-300 px-2 py-1 rounded"
                        >
                          {ref}
                        </span>
                      ))}
                    </div>
                  </div>
                )}
              </div>
            ) : (
              <div className="bg-gray-900 border border-gray-800 rounded-xl p-12 text-center text-gray-400">
                <Workflow className="w-12 h-12 mx-auto text-gray-600 mb-3" />
                <p className="font-semibold text-gray-300">Select an attack path from the list</p>
                <p className="text-xs text-gray-500 mt-1">
                  Inspect the multi-hop kill chain, MITRE mapping, and evidence breakdown.
                </p>
              </div>
            )}
          </div>
        </div>
      )}

      {/* TAB 2: PREVENTION RECOMMENDATIONS */}
      {activeTab === 'recommendations' && (
        <div className="space-y-4">
          {/* Controls Bar */}
          <div className="bg-gray-900 border border-gray-800 p-3 rounded-xl flex flex-wrap items-center justify-between gap-4 text-xs">
            <div className="flex items-center gap-2">
              <span className="text-gray-400">Category Filter:</span>
              <select
                value={recCategoryFilter}
                onChange={e => setRecCategoryFilter(e.target.value)}
                className="bg-gray-800 border border-gray-700 text-gray-200 rounded px-2.5 py-1.5"
              >
                <option value="ALL">All Categories</option>
                <option value="VIRTUAL_PATCH">Virtual Patching</option>
                <option value="NETWORK_SEGMENTATION">Network Segmentation</option>
                <option value="MFA_ACCESS_CONTROL">MFA & Access Control</option>
                <option value="SERVICE_HARDENING">Service Hardening</option>
                <option value="LOGGING_MONITORING">Logging & Telemetry</option>
              </select>
            </div>

            <div className="text-gray-400 text-xs">
              Showing <span className="text-white font-semibold">{recommendations.length}</span> prioritized compensating controls
            </div>
          </div>

          {/* Recommendations Table */}
          <div className="bg-gray-900 border border-gray-800 rounded-xl overflow-hidden">
            <div className="overflow-x-auto">
              <table className="w-full text-left text-xs">
                <thead className="bg-gray-950/80 text-gray-400 border-b border-gray-800 uppercase tracking-wider font-semibold">
                  <tr>
                    <th className="py-3 px-4 w-12 text-center">Rank</th>
                    <th className="py-3 px-4">Compensating Control</th>
                    <th className="py-3 px-4">Category</th>
                    <th className="py-3 px-4">Risk Reduction</th>
                    <th className="py-3 px-4">Complexity</th>
                    <th className="py-3 px-4">SMB Impact</th>
                    <th className="py-3 px-4">Status</th>
                    <th className="py-3 px-4 text-right">Action</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-gray-800/80">
                  {recommendations.length === 0 ? (
                    <tr>
                      <td colSpan={8} className="text-center py-12 text-gray-500">
                        No prevention recommendations generated. Run analysis to synthesize compensating controls.
                      </td>
                    </tr>
                  ) : (
                    recommendations.map(rec => (
                      <tr key={rec.id} className="hover:bg-gray-800/40 transition-colors">
                        <td className="py-3.5 px-4 text-center font-bold font-mono text-rose-400">
                          #{rec.priority_rank}
                        </td>
                        <td className="py-3.5 px-4 max-w-sm">
                          <div className="font-semibold text-gray-100 text-sm">{rec.title}</div>
                          <p className="text-gray-400 text-xs mt-1 line-clamp-2">{rec.description}</p>
                          {rec.attack_path_title && (
                            <div className="text-[10px] text-gray-500 mt-1 flex items-center gap-1">
                              <span>Path:</span>
                              <span className="font-mono text-gray-400">{rec.attack_path_title}</span>
                            </div>
                          )}
                        </td>
                        <td className="py-3.5 px-4">
                          <span className="text-[10px] font-semibold px-2 py-0.5 rounded bg-gray-800 border border-gray-700 text-gray-300">
                            {rec.category.replace('_', ' ')}
                          </span>
                        </td>
                        <td className="py-3.5 px-4">
                          <span
                            className={`text-[10px] font-bold px-2 py-0.5 rounded ${rec.risk_reduction === 'HIGH'
                                ? 'bg-emerald-500/20 text-emerald-400 border border-emerald-500/30'
                                : 'bg-blue-500/20 text-blue-400 border border-blue-500/30'
                              }`}
                          >
                            {rec.risk_reduction}
                          </span>
                        </td>
                        <td className="py-3.5 px-4">
                          <span
                            className={`text-[10px] font-semibold px-2 py-0.5 rounded ${rec.implementation_complexity === 'LOW'
                                ? 'text-emerald-400 bg-emerald-950/40'
                                : 'text-amber-400 bg-amber-950/40'
                              }`}
                          >
                            {rec.implementation_complexity}
                          </span>
                        </td>
                        <td className="py-3.5 px-4">
                          <span
                            className={`text-[10px] font-semibold px-2 py-0.5 rounded ${rec.smb_operational_impact === 'MINIMAL'
                                ? 'text-emerald-400 bg-emerald-950/40'
                                : 'text-amber-400 bg-amber-950/40'
                              }`}
                          >
                            {rec.smb_operational_impact}
                          </span>
                        </td>
                        <td className="py-3.5 px-4">
                          <span
                            className={`text-[10px] font-mono px-2 py-0.5 rounded ${rec.status === 'IMPLEMENTED'
                                ? 'bg-emerald-500/20 text-emerald-400 border border-emerald-500/30'
                                : rec.status === 'ACCEPTED'
                                  ? 'bg-blue-500/20 text-blue-400 border border-blue-500/30'
                                  : 'bg-gray-800 text-gray-300 border border-gray-700'
                              }`}
                          >
                            {rec.status}
                          </span>
                        </td>
                        <td className="py-3.5 px-4 text-right">
                          <select
                            value={rec.status}
                            onChange={e => handleUpdateRecStatus(rec.id, e.target.value)}
                            className="bg-gray-800 border border-gray-700 text-gray-200 text-xs rounded px-2 py-1"
                          >
                            <option value="PROPOSED">PROPOSED</option>
                            <option value="ACCEPTED">ACCEPTED</option>
                            <option value="IMPLEMENTED">IMPLEMENTED</option>
                            <option value="DISMISSED">DISMISSED</option>
                          </select>
                        </td>
                      </tr>
                    ))
                  )}
                </tbody>
              </table>
            </div>
          </div>
        </div>
      )}

      {/* TAB 3: TRUST RELATIONSHIPS */}
      {activeTab === 'trust' && (
        <div className="space-y-4">
          <div className="flex items-center justify-between">
            <p className="text-xs text-gray-400">
              Verified communication links, database connections, and subnet boundaries used to model empirical lateral movement paths.
            </p>
            <button
              onClick={() => setIsTrustModalOpen(true)}
              className="flex items-center gap-1.5 px-3 py-1.5 text-xs bg-rose-600 hover:bg-rose-500 text-white rounded-lg transition-colors font-medium"
            >
              <LinkIcon className="w-3.5 h-3.5" />
              Add Verified Trust Link
            </button>
          </div>

          <div className="bg-gray-900 border border-gray-800 rounded-xl overflow-hidden">
            <table className="w-full text-left text-xs">
              <thead className="bg-gray-950/80 text-gray-400 border-b border-gray-800 uppercase tracking-wider font-semibold">
                <tr>
                  <th className="py-3 px-4">Source Asset</th>
                  <th className="py-3 px-4">Relationship</th>
                  <th className="py-3 px-4">Target Asset</th>
                  <th className="py-3 px-4">Port</th>
                  <th className="py-3 px-4">Evidence Source</th>
                  <th className="py-3 px-4">Verified</th>
                  <th className="py-3 px-4 text-right">Actions</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-gray-800/80">
                {trustLinks.length === 0 ? (
                  <tr>
                    <td colSpan={7} className="text-center py-10 text-gray-500">
                      No explicit trust relationships defined. Subnet-based adjacency is automatically computed.
                    </td>
                  </tr>
                ) : (
                  trustLinks.map(rel => (
                    <tr key={rel.id} className="hover:bg-gray-800/40">
                      <td className="py-3 px-4 font-medium text-gray-200">
                        {rel.source_asset_name || rel.source_asset_id.slice(0, 8)}
                      </td>
                      <td className="py-3 px-4">
                        <span className="font-mono text-[11px] text-rose-400 bg-rose-950/50 px-2 py-0.5 rounded border border-rose-800/40">
                          {rel.relationship_type}
                        </span>
                      </td>
                      <td className="py-3 px-4 font-medium text-gray-200">
                        {rel.target_asset_name || rel.target_asset_id.slice(0, 8)}
                      </td>
                      <td className="py-3 px-4 font-mono text-gray-300">{rel.port || 'Any'}</td>
                      <td className="py-3 px-4 text-gray-400">{rel.evidence_source}</td>
                      <td className="py-3 px-4">
                        <CheckCircle2 className="w-4 h-4 text-emerald-400" />
                      </td>
                      <td className="py-3 px-4 text-right">
                        <button
                          onClick={() => handleDeleteTrustLink(rel.id)}
                          className="p-1 hover:text-red-400 transition-colors"
                          title="Delete Relationship"
                        >
                          <Trash2 className="w-4 h-4" />
                        </button>
                      </td>
                    </tr>
                  ))
                )}
              </tbody>
            </table>
          </div>
        </div>
      )}

      {/* MODAL: Run Attack Path Analysis */}
      {isAnalysisModalOpen && (
        <div className="fixed inset-0 z-50 bg-black/70 backdrop-blur-sm flex items-center justify-center p-4">
          <div className="bg-gray-900 border border-gray-800 rounded-2xl max-w-md w-full p-6 space-y-4 shadow-2xl">
            <div className="flex items-center justify-between border-b border-gray-800 pb-3">
              <h3 className="text-lg font-bold text-white flex items-center gap-2">
                <Workflow className="w-5 h-5 text-rose-400" />
                Execute Attack Path Analysis
              </h3>
              <button
                onClick={() => setIsAnalysisModalOpen(false)}
                className="text-gray-400 hover:text-gray-200"
              >
                <X className="w-5 h-5" />
              </button>
            </div>

            <p className="text-xs text-gray-400 leading-relaxed">
              Analyzes discovered services, vulnerability records, and verified network boundaries across all tenant assets to construct evidence-backed kill-chain paths and ranked compensating controls.
            </p>

            {analysisResult && (
              <div className="p-3 bg-gray-950 border border-gray-800 rounded-lg text-xs font-mono text-rose-300">
                {analysisResult}
              </div>
            )}

            <div className="flex justify-end gap-3 pt-2">
              <button
                type="button"
                onClick={() => setIsAnalysisModalOpen(false)}
                className="px-4 py-2 text-xs bg-gray-800 hover:bg-gray-700 text-gray-300 rounded-lg"
              >
                Close
              </button>
              <button
                type="button"
                disabled={isAnalyzing}
                onClick={() => handleTriggerAnalysis(true)}
                className="flex items-center gap-2 px-4 py-2 text-xs font-semibold bg-rose-600 hover:bg-rose-500 text-white rounded-lg disabled:opacity-50"
              >
                {isAnalyzing ? (
                  <>
                    <Loader2 className="w-4 h-4 animate-spin" />
                    Analyzing Kill Chains...
                  </>
                ) : (
                  <>
                    <Play className="w-4 h-4 fill-white" />
                    Start Analysis
                  </>
                )}
              </button>
            </div>
          </div>
        </div>
      )}

      {/* MODAL: Add Trust Link */}
      {isTrustModalOpen && (
        <div className="fixed inset-0 z-50 bg-black/70 backdrop-blur-sm flex items-center justify-center p-4">
          <form
            onSubmit={handleCreateTrustLink}
            className="bg-gray-900 border border-gray-800 rounded-2xl max-w-md w-full p-6 space-y-4 shadow-2xl"
          >
            <div className="flex items-center justify-between border-b border-gray-800 pb-3">
              <h3 className="text-lg font-bold text-white flex items-center gap-2">
                <LinkIcon className="w-5 h-5 text-rose-400" />
                New Verified Trust Relationship
              </h3>
              <button
                type="button"
                onClick={() => setIsTrustModalOpen(false)}
                className="text-gray-400 hover:text-gray-200"
              >
                <X className="w-5 h-5" />
              </button>
            </div>

            <div className="space-y-3 text-xs">
              <div>
                <label className="block text-gray-300 mb-1 font-medium">Source Asset (Origin)</label>
                <select
                  value={newTrustSource}
                  onChange={e => setNewTrustSource(e.target.value)}
                  required
                  className="w-full bg-gray-800 border border-gray-700 rounded-lg p-2 text-gray-200"
                >
                  <option value="">Select source asset...</option>
                  {(assets || []).map(a => (
                    <option key={a.id} value={a.id}>
                      {a.name} ({a.target})
                    </option>
                  ))}
                </select>
              </div>

              <div>
                <label className="block text-gray-300 mb-1 font-medium">Target Asset (Destination)</label>
                <select
                  value={newTrustTarget}
                  onChange={e => setNewTrustTarget(e.target.value)}
                  required
                  className="w-full bg-gray-800 border border-gray-700 rounded-lg p-2 text-gray-200"
                >
                  <option value="">Select target asset...</option>
                  {(assets || [])
                    .filter(a => a.id !== newTrustSource)
                    .map(a => (
                      <option key={a.id} value={a.id}>
                        {a.name} ({a.target})
                      </option>
                    ))}
                </select>
              </div>

              <div>
                <label className="block text-gray-300 mb-1 font-medium">Relationship Type</label>
                <select
                  value={newTrustType}
                  onChange={e => setNewTrustType(e.target.value)}
                  className="w-full bg-gray-800 border border-gray-700 rounded-lg p-2 text-gray-200"
                >
                  <option value="DATABASE_LINK">DATABASE_LINK (e.g. App to PostgreSQL/MySQL)</option>
                  <option value="SSH_ADMIN_ACCESS">SSH_ADMIN_ACCESS (e.g. Bastion to Host)</option>
                  <option value="ACTIVE_DIRECTORY_TRUST">ACTIVE_DIRECTORY_TRUST</option>
                  <option value="API_DEPENDENCY">API_DEPENDENCY (Internal Microservice)</option>
                  <option value="SAME_SUBNET">SAME_SUBNET (Direct L2/L3 Reachability)</option>
                </select>
              </div>

              <div>
                <label className="block text-gray-300 mb-1 font-medium">Destination Port (Optional)</label>
                <input
                  type="number"
                  placeholder="e.g. 5432, 22, 3306"
                  value={newTrustPort || ''}
                  onChange={e => setNewTrustPort(e.target.value ? parseInt(e.target.value, 10) : undefined)}
                  className="w-full bg-gray-800 border border-gray-700 rounded-lg p-2 text-gray-200"
                />
              </div>
            </div>

            <div className="flex justify-end gap-3 pt-3 border-t border-gray-800">
              <button
                type="button"
                onClick={() => setIsTrustModalOpen(false)}
                className="px-4 py-2 text-xs bg-gray-800 hover:bg-gray-700 text-gray-300 rounded-lg"
              >
                Cancel
              </button>
              <button
                type="submit"
                disabled={isCreatingTrust}
                className="px-4 py-2 text-xs font-semibold bg-rose-600 hover:bg-rose-500 text-white rounded-lg disabled:opacity-50"
              >
                {isCreatingTrust ? 'Creating...' : 'Create Trust Link'}
              </button>
            </div>
          </form>
        </div>
      )}
    </div>
  );
};
