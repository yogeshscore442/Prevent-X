import React, { useEffect, useState } from 'react';
import {
  AlertCircle,
  AlertOctagon,
  AlertTriangle,
  CheckCircle2,
  Clock,
  Eye,
  Filter,
  Flame,
  Globe,
  Loader2,
  Lock,
  Play,
  RefreshCw,
  RotateCcw,
  Shield,
  ShieldCheck,
  UserCheck,
  X,
  Zap,
} from 'lucide-react';
import {
  AssetTrustAssessment,
  BehavioralAnomaly,
  ResponseAction,
  ThreatAssetCorrelation,
  ThreatIntelRecord,
  TrustDecision,
  ZeroTrustOverviewStats,
} from '@/types/zeroTrust';
import { zeroTrustApi } from '@/services/zeroTrustApi';

export const ZeroTrustPage: React.FC = () => {
  const [activeTab, setActiveTab] = useState<'posture' | 'threat_intel' | 'anomalies' | 'responses'>('posture');

  // State
  const [overview, setOverview] = useState<ZeroTrustOverviewStats | null>(null);
  const [assessments, setAssessments] = useState<AssetTrustAssessment[]>([]);
  const [threatIndicators, setThreatIndicators] = useState<ThreatIntelRecord[]>([]);
  const [correlations, setCorrelations] = useState<ThreatAssetCorrelation[]>([]);
  const [anomalies, setAnomalies] = useState<BehavioralAnomaly[]>([]);
  const [responseActions, setResponseActions] = useState<ResponseAction[]>([]);
  const [isLoading, setIsLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [actionMessage, setActionMessage] = useState<string | null>(null);

  // Filters
  const [decisionFilter, setDecisionFilter] = useState<string>('ALL');
  const [threatTypeFilter, setThreatTypeFilter] = useState<string>('ALL');
  const [anomalyFilter, setAnomalyFilter] = useState<string>('ALL');
  const [responseStatusFilter, setResponseStatusFilter] = useState<string>('ALL');

  // Modals & Selection
  const [selectedAssessment, setSelectedAssessment] = useState<AssetTrustAssessment | null>(null);
  const [selectedAction, setSelectedAction] = useState<ResponseAction | null>(null);
  const [isProcessingAction, setIsProcessingAction] = useState(false);

  // Initial Data Load
  useEffect(() => {
    loadAllData();
  }, []);

  const loadAllData = async () => {
    setIsLoading(true);
    setError(null);
    try {
      const [ovData, assData, indData, corrData, anomData, actData] = await Promise.all([
        zeroTrustApi.getOverview(),
        zeroTrustApi.listAssessments(),
        zeroTrustApi.listThreatIndicators(),
        zeroTrustApi.listThreatCorrelations(),
        zeroTrustApi.listAnomalies(),
        zeroTrustApi.listResponseActions(),
      ]);
      setOverview(ovData);
      setAssessments(assData);
      setThreatIndicators(indData);
      setCorrelations(corrData);
      setAnomalies(anomData);
      setResponseActions(actData);
    } catch (err: any) {
      setError(err?.response?.data?.detail || err?.message || 'Failed to load Zero Trust telemetry.');
    } finally {
      setIsLoading(false);
    }
  };

  const handleEvaluatePosture = async () => {
    setIsProcessingAction(true);
    try {
      await zeroTrustApi.evaluatePosture({ force_refresh: true });
      setActionMessage('Zero Trust posture evaluation initiated.');
      await loadAllData();
    } catch (err: any) {
      setError(err?.response?.data?.detail || err?.message || 'Evaluation failed.');
    } finally {
      setIsProcessingAction(false);
    }
  };

  const handleSyncThreatFeeds = async () => {
    setIsProcessingAction(true);
    try {
      const res = await zeroTrustApi.syncThreatFeed();
      setActionMessage(res.message || 'Threat feeds synchronized.');
      await loadAllData();
    } catch (err: any) {
      setError(err?.response?.data?.detail || err?.message || 'Threat sync failed.');
    } finally {
      setIsProcessingAction(false);
    }
  };

  const handleCorrelateThreats = async () => {
    setIsProcessingAction(true);
    try {
      await zeroTrustApi.correlateThreats();
      setActionMessage('Threat-to-asset correlation analysis completed.');
      await loadAllData();
    } catch (err: any) {
      setError(err?.response?.data?.detail || err?.message || 'Correlation failed.');
    } finally {
      setIsProcessingAction(false);
    }
  };

  const handleDetectAnomalies = async () => {
    setIsProcessingAction(true);
    try {
      await zeroTrustApi.detectAnomalies();
      setActionMessage('Behavioral anomaly detection scan completed.');
      await loadAllData();
    } catch (err: any) {
      setError(err?.response?.data?.detail || err?.message || 'Anomaly detection failed.');
    } finally {
      setIsProcessingAction(false);
    }
  };

  const handleApproveAction = async (actionId: string) => {
    setIsProcessingAction(true);
    try {
      await zeroTrustApi.approveResponseAction(actionId);
      setActionMessage('Response action approved by administrator.');
      await loadAllData();
    } catch (err: any) {
      setError(err?.response?.data?.detail || err?.message || 'Approval failed.');
    } finally {
      setIsProcessingAction(false);
    }
  };

  const handleRejectAction = async (actionId: string) => {
    setIsProcessingAction(true);
    try {
      await zeroTrustApi.rejectResponseAction(actionId, 'Rejected from dashboard.');
      setActionMessage('Response action rejected.');
      await loadAllData();
    } catch (err: any) {
      setError(err?.response?.data?.detail || err?.message || 'Rejection failed.');
    } finally {
      setIsProcessingAction(false);
    }
  };

  const handleExecuteAction = async (actionId: string) => {
    setIsProcessingAction(true);
    try {
      await zeroTrustApi.executeResponseAction(actionId);
      setActionMessage('Mitigation policy enforced successfully.');
      await loadAllData();
    } catch (err: any) {
      setError(err?.response?.data?.detail || err?.message || 'Execution failed.');
    } finally {
      setIsProcessingAction(false);
    }
  };

  const handleRollbackAction = async (actionId: string) => {
    setIsProcessingAction(true);
    try {
      await zeroTrustApi.rollbackResponseAction(actionId);
      setActionMessage('Response action rolled back to baseline.');
      await loadAllData();
    } catch (err: any) {
      setError(err?.response?.data?.detail || err?.message || 'Rollback failed.');
    } finally {
      setIsProcessingAction(false);
    }
  };

  const handleUpdateAnomalyStatus = async (anomalyId: string, status: string) => {
    try {
      await zeroTrustApi.updateAnomalyStatus(anomalyId, status);
      await loadAllData();
    } catch (err: any) {
      setError(err?.response?.data?.detail || err?.message || 'Status update failed.');
    }
  };

  // Decision badge styling
  const getDecisionBadge = (decision: TrustDecision | string) => {
    switch (decision) {
      case 'TRUSTED':
        return (
          <span className="inline-flex items-center gap-1.5 px-2.5 py-1 rounded-full text-xs font-semibold bg-emerald-500/10 text-emerald-400 border border-emerald-500/30">
            <ShieldCheck className="w-3.5 h-3.5" />
            TRUSTED
          </span>
        );
      case 'RESTRICTED':
        return (
          <span className="inline-flex items-center gap-1.5 px-2.5 py-1 rounded-full text-xs font-semibold bg-amber-500/10 text-amber-400 border border-amber-500/30">
            <AlertTriangle className="w-3.5 h-3.5" />
            RESTRICTED
          </span>
        );
      case 'UNTRUSTED':
        return (
          <span className="inline-flex items-center gap-1.5 px-2.5 py-1 rounded-full text-xs font-semibold bg-rose-500/10 text-rose-400 border border-rose-500/30">
            <AlertOctagon className="w-3.5 h-3.5" />
            UNTRUSTED
          </span>
        );
      case 'INSUFFICIENT_EVIDENCE':
      default:
        return (
          <span className="inline-flex items-center gap-1.5 px-2.5 py-1 rounded-full text-xs font-semibold bg-purple-500/10 text-purple-400 border border-purple-500/30">
            <Clock className="w-3.5 h-3.5" />
            INSUFFICIENT EVIDENCE
          </span>
        );
    }
  };

  // Severity styling
  const getSeverityBadge = (severity: string) => {
    switch (severity?.toUpperCase()) {
      case 'CRITICAL':
        return <span className="px-2 py-0.5 rounded text-xs font-bold bg-rose-950 text-rose-300 border border-rose-700">CRITICAL</span>;
      case 'HIGH':
        return <span className="px-2 py-0.5 rounded text-xs font-bold bg-orange-950 text-orange-300 border border-orange-700">HIGH</span>;
      case 'MEDIUM':
        return <span className="px-2 py-0.5 rounded text-xs font-bold bg-amber-950 text-amber-300 border border-amber-700">MEDIUM</span>;
      case 'LOW':
      default:
        return <span className="px-2 py-0.5 rounded text-xs font-bold bg-blue-950 text-blue-300 border border-blue-700">LOW</span>;
    }
  };

  const filteredAssessments = assessments.filter((a) => {
    if (decisionFilter === 'ALL') return true;
    return a.trust_decision === decisionFilter;
  });

  const filteredThreats = threatIndicators.filter((t) => {
    if (threatTypeFilter === 'ALL') return true;
    return t.indicator_type === threatTypeFilter;
  });

  const filteredAnomalies = anomalies.filter((an) => {
    if (anomalyFilter === 'ALL') return true;
    if (anomalyFilter === 'ZERO_DAY') return an.is_zero_day_indicator;
    return an.status === anomalyFilter;
  });

  const filteredActions = responseActions.filter((ac) => {
    if (responseStatusFilter === 'ALL') return true;
    return ac.status === responseStatusFilter;
  });

  return (
    <div className="min-h-screen bg-slate-950 text-slate-100 p-6">
      {/* Header */}
      <div className="flex flex-col md:flex-row md:items-center justify-between gap-4 pb-6 border-b border-slate-800">
        <div>
          <div className="flex items-center gap-3">
            <div className="p-2.5 rounded-lg bg-indigo-600/20 border border-indigo-500/40 text-indigo-400">
              <Shield className="w-6 h-6" />
            </div>
            <div>
              <h1 className="text-2xl font-bold tracking-tight text-white flex items-center gap-2">
                Zero Trust & Zero-Day Resilience Engine
              </h1>
              <p className="text-sm text-slate-400">
                MOD-04 / MOD-05 • Continuous Trust Posture, Threat Correlation & Automated Containment
              </p>
            </div>
          </div>
        </div>

        {/* Global Actions */}
        <div className="flex items-center flex-wrap gap-2.5">
          <button
            onClick={handleEvaluatePosture}
            disabled={isProcessingAction}
            className="flex items-center gap-2 px-3.5 py-2 rounded-lg bg-indigo-600 hover:bg-indigo-500 text-white text-sm font-medium transition disabled:opacity-50"
          >
            {isProcessingAction ? <Loader2 className="w-4 h-4 animate-spin" /> : <Play className="w-4 h-4" />}
            Evaluate Posture
          </button>
          <button
            onClick={handleSyncThreatFeeds}
            disabled={isProcessingAction}
            className="flex items-center gap-2 px-3.5 py-2 rounded-lg bg-slate-800 hover:bg-slate-700 text-slate-200 text-sm font-medium border border-slate-700 transition disabled:opacity-50"
          >
            <RefreshCw className="w-4 h-4" />
            Sync Feeds
          </button>
          <button
            onClick={handleCorrelateThreats}
            disabled={isProcessingAction}
            className="flex items-center gap-2 px-3.5 py-2 rounded-lg bg-slate-800 hover:bg-slate-700 text-slate-200 text-sm font-medium border border-slate-700 transition disabled:opacity-50"
          >
            <Zap className="w-4 h-4 text-amber-400" />
            Correlate Threats
          </button>
          <button
            onClick={handleDetectAnomalies}
            disabled={isProcessingAction}
            className="flex items-center gap-2 px-3.5 py-2 rounded-lg bg-slate-800 hover:bg-slate-700 text-slate-200 text-sm font-medium border border-slate-700 transition disabled:opacity-50"
          >
            <AlertTriangle className="w-4 h-4 text-rose-400" />
            Detect Anomalies
          </button>
          <button
            onClick={loadAllData}
            disabled={isLoading}
            className="p-2 rounded-lg bg-slate-800 hover:bg-slate-700 text-slate-300 border border-slate-700 transition"
            title="Refresh All Data"
          >
            <RefreshCw className={`w-4 h-4 ${isLoading ? 'animate-spin' : ''}`} />
          </button>
        </div>
      </div>

      {/* Notifications */}
      {actionMessage && (
        <div className="mt-4 p-3.5 rounded-lg bg-indigo-950/80 border border-indigo-700/60 text-indigo-200 text-sm flex items-center justify-between">
          <div className="flex items-center gap-2">
            <CheckCircle2 className="w-4 h-4 text-indigo-400 shrink-0" />
            <span>{actionMessage}</span>
          </div>
          <button onClick={() => setActionMessage(null)} className="text-slate-400 hover:text-white">
            <X className="w-4 h-4" />
          </button>
        </div>
      )}

      {error && (
        <div className="mt-4 p-3.5 rounded-lg bg-rose-950/80 border border-rose-700/60 text-rose-200 text-sm flex items-center justify-between">
          <div className="flex items-center gap-2">
            <AlertCircle className="w-4 h-4 text-rose-400 shrink-0" />
            <span>{error}</span>
          </div>
          <button onClick={() => setError(null)} className="text-slate-400 hover:text-white">
            <X className="w-4 h-4" />
          </button>
        </div>
      )}

      {/* KPI Overview Cards */}
      <div className="grid grid-cols-2 sm:grid-cols-3 lg:grid-cols-6 gap-3.5 mt-6">
        <div className="p-4 rounded-xl bg-slate-900/90 border border-slate-800">
          <div className="flex items-center justify-between text-slate-400 text-xs font-medium">
            <span>Avg Trust Score</span>
            <Shield className="w-4 h-4 text-indigo-400" />
          </div>
          <div className="mt-2 text-2xl font-bold text-white">
            {overview?.average_trust_score ?? '0.0'}
            <span className="text-xs font-normal text-slate-400 ml-1">/ 100</span>
          </div>
          <div className="mt-1 text-xs text-slate-400">{overview?.total_assets ?? 0} Total Assets</div>
        </div>

        <div className="p-4 rounded-xl bg-slate-900/90 border border-slate-800">
          <div className="flex items-center justify-between text-emerald-400 text-xs font-medium">
            <span>Trusted Assets</span>
            <ShieldCheck className="w-4 h-4" />
          </div>
          <div className="mt-2 text-2xl font-bold text-emerald-400">{overview?.trusted_count ?? 0}</div>
          <div className="mt-1 text-xs text-slate-400">Positively Verified</div>
        </div>

        <div className="p-4 rounded-xl bg-slate-900/90 border border-slate-800">
          <div className="flex items-center justify-between text-amber-400 text-xs font-medium">
            <span>Restricted</span>
            <AlertTriangle className="w-4 h-4" />
          </div>
          <div className="mt-2 text-2xl font-bold text-amber-400">{overview?.restricted_count ?? 0}</div>
          <div className="mt-1 text-xs text-slate-400">Constrained Privilege</div>
        </div>

        <div className="p-4 rounded-xl bg-slate-900/90 border border-slate-800">
          <div className="flex items-center justify-between text-rose-400 text-xs font-medium">
            <span>Untrusted / Threat</span>
            <AlertOctagon className="w-4 h-4" />
          </div>
          <div className="mt-2 text-2xl font-bold text-rose-400">{overview?.untrusted_count ?? 0}</div>
          <div className="mt-1 text-xs text-slate-400">Immediate Risk / C2 Match</div>
        </div>

        <div className="p-4 rounded-xl bg-slate-900/90 border border-slate-800">
          <div className="flex items-center justify-between text-purple-400 text-xs font-medium">
            <span>Zero-Day Signals</span>
            <Flame className="w-4 h-4" />
          </div>
          <div className="mt-2 text-2xl font-bold text-purple-400">{overview?.zero_day_indicators_count ?? 0}</div>
          <div className="mt-1 text-xs text-slate-400">Unmapped Payload Flaws</div>
        </div>

        <div className="p-4 rounded-xl bg-slate-900/90 border border-slate-800">
          <div className="flex items-center justify-between text-cyan-400 text-xs font-medium">
            <span>Pending Approval</span>
            <UserCheck className="w-4 h-4" />
          </div>
          <div className="mt-2 text-2xl font-bold text-cyan-400">{overview?.pending_approval_actions ?? 0}</div>
          <div className="mt-1 text-xs text-slate-400">Disruptive Gate Actions</div>
        </div>
      </div>

      {/* Navigation Tabs */}
      <div className="flex items-center gap-2 mt-6 border-b border-slate-800 pb-2">
        <button
          onClick={() => setActiveTab('posture')}
          className={`flex items-center gap-2 px-4 py-2 rounded-lg text-sm font-medium transition ${
            activeTab === 'posture'
              ? 'bg-indigo-600 text-white shadow-lg shadow-indigo-600/30'
              : 'text-slate-400 hover:text-white hover:bg-slate-900'
          }`}
        >
          <Shield className="w-4 h-4" />
          Asset Trust Posture ({assessments.length})
        </button>

        <button
          onClick={() => setActiveTab('threat_intel')}
          className={`flex items-center gap-2 px-4 py-2 rounded-lg text-sm font-medium transition ${
            activeTab === 'threat_intel'
              ? 'bg-indigo-600 text-white shadow-lg shadow-indigo-600/30'
              : 'text-slate-400 hover:text-white hover:bg-slate-900'
          }`}
        >
          <Globe className="w-4 h-4" />
          Threat Intelligence & Correlations ({threatIndicators.length} IOCs / {correlations.length} Matched)
        </button>

        <button
          onClick={() => setActiveTab('anomalies')}
          className={`flex items-center gap-2 px-4 py-2 rounded-lg text-sm font-medium transition ${
            activeTab === 'anomalies'
              ? 'bg-indigo-600 text-white shadow-lg shadow-indigo-600/30'
              : 'text-slate-400 hover:text-white hover:bg-slate-900'
          }`}
        >
          <AlertTriangle className="w-4 h-4" />
          Behavioral & Zero-Day Alerts ({anomalies.length})
        </button>

        <button
          onClick={() => setActiveTab('responses')}
          className={`flex items-center gap-2 px-4 py-2 rounded-lg text-sm font-medium transition ${
            activeTab === 'responses'
              ? 'bg-indigo-600 text-white shadow-lg shadow-indigo-600/30'
              : 'text-slate-400 hover:text-white hover:bg-slate-900'
          }`}
        >
          <Lock className="w-4 h-4" />
          Automated Response Actions ({responseActions.length})
        </button>
      </div>

      {/* Tab 1: Asset Trust Posture */}
      {activeTab === 'posture' && (
        <div className="mt-6 space-y-4">
          <div className="flex items-center justify-between">
            <div className="flex items-center gap-2 text-sm text-slate-400">
              <Filter className="w-4 h-4" />
              <span>Filter Decision:</span>
              {['ALL', 'TRUSTED', 'RESTRICTED', 'UNTRUSTED', 'INSUFFICIENT_EVIDENCE'].map((d) => (
                <button
                  key={d}
                  onClick={() => setDecisionFilter(d)}
                  className={`px-2.5 py-1 rounded text-xs font-medium transition ${
                    decisionFilter === d ? 'bg-indigo-600 text-white' : 'bg-slate-900 text-slate-400 hover:text-white'
                  }`}
                >
                  {d}
                </button>
              ))}
            </div>
            <div className="text-xs text-slate-400">
              Showing {filteredAssessments.length} of {assessments.length} evaluations
            </div>
          </div>

          <div className="overflow-x-auto rounded-xl border border-slate-800 bg-slate-900/50">
            <table className="w-full text-left text-sm text-slate-300">
              <thead className="bg-slate-900 text-xs uppercase font-semibold text-slate-400 border-b border-slate-800">
                <tr>
                  <th className="px-4 py-3">Asset Target / Name</th>
                  <th className="px-4 py-3">Trust Decision</th>
                  <th className="px-4 py-3">Trust Score</th>
                  <th className="px-4 py-3">Positive Factors</th>
                  <th className="px-4 py-3">Risk Factors</th>
                  <th className="px-4 py-3">Last Evaluated</th>
                  <th className="px-4 py-3 text-right">Actions</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-800/60 font-medium">
                {filteredAssessments.length === 0 ? (
                  <tr>
                    <td colSpan={7} className="px-4 py-8 text-center text-slate-500">
                      No asset trust evaluations found matching the filter.
                    </td>
                  </tr>
                ) : (
                  filteredAssessments.map((a) => (
                    <tr key={a.id} className="hover:bg-slate-800/40 transition">
                      <td className="px-4 py-3.5">
                        <div className="font-semibold text-white">{a.asset_name || 'Unnamed Asset'}</div>
                        <div className="text-xs font-mono text-slate-400">{a.asset_target || 'N/A'}</div>
                      </td>
                      <td className="px-4 py-3.5">{getDecisionBadge(a.trust_decision)}</td>
                      <td className="px-4 py-3.5">
                        <div className="flex items-center gap-2.5">
                          <div className="w-24 bg-slate-800 rounded-full h-2 overflow-hidden">
                            <div
                              className={`h-2 rounded-full ${
                                a.trust_score >= 70
                                  ? 'bg-emerald-500'
                                  : a.trust_score >= 30
                                  ? 'bg-amber-500'
                                  : 'bg-rose-500'
                              }`}
                              style={{ width: `${Math.min(100, Math.max(5, a.trust_score))}%` }}
                            />
                          </div>
                          <span className="font-mono text-xs font-bold text-white">{a.trust_score}</span>
                        </div>
                      </td>
                      <td className="px-4 py-3.5 text-xs text-emerald-400">
                        {a.positive_factors?.length || 0} factors (+{a.positive_factors?.reduce((acc, f) => acc + (f.score_delta || 0), 0) || 0})
                      </td>
                      <td className="px-4 py-3.5 text-xs text-rose-400">
                        {a.risk_factors?.length || 0} factors ({a.risk_factors?.reduce((acc, f) => acc + (f.score_delta || 0), 0) || 0})
                      </td>
                      <td className="px-4 py-3.5 text-xs text-slate-400">
                        {new Date(a.last_evaluated_at).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' })}
                      </td>
                      <td className="px-4 py-3.5 text-right">
                        <button
                          onClick={() => setSelectedAssessment(a)}
                          className="px-2.5 py-1 text-xs rounded bg-slate-800 hover:bg-slate-700 text-indigo-300 border border-slate-700 transition"
                        >
                          Inspect Posture
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

      {/* Tab 2: Threat Intelligence & Correlations */}
      {activeTab === 'threat_intel' && (
        <div className="mt-6 space-y-6">
          {/* Section: Threat-to-Asset Correlations */}
          <div className="space-y-3">
            <div className="flex items-center justify-between">
              <h3 className="text-base font-semibold text-white flex items-center gap-2">
                <Zap className="w-4 h-4 text-amber-400" />
                Active Local Asset Correlations ({correlations.length})
              </h3>
              <span className="text-xs text-slate-400">Cross-referenced against verified threat feeds</span>
            </div>

            <div className="overflow-x-auto rounded-xl border border-slate-800 bg-slate-900/50">
              <table className="w-full text-left text-sm text-slate-300">
                <thead className="bg-slate-900 text-xs uppercase font-semibold text-slate-400 border-b border-slate-800">
                  <tr>
                    <th className="px-4 py-3">Asset</th>
                    <th className="px-4 py-3">Threat Indicator</th>
                    <th className="px-4 py-3">Correlation Type</th>
                    <th className="px-4 py-3">Matched Value</th>
                    <th className="px-4 py-3">Severity</th>
                    <th className="px-4 py-3">Confidence</th>
                    <th className="px-4 py-3">Details</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-slate-800/60 font-medium">
                  {correlations.length === 0 ? (
                    <tr>
                      <td colSpan={7} className="px-4 py-8 text-center text-slate-500">
                        No active threat IOCs correlate with current tenant assets or services.
                      </td>
                    </tr>
                  ) : (
                    correlations.map((c) => (
                      <tr key={c.id} className="hover:bg-slate-800/40 transition">
                        <td className="px-4 py-3">
                          <div className="font-semibold text-white">{c.asset_name || 'Asset'}</div>
                          <div className="text-xs text-slate-400">{c.asset_target}</div>
                        </td>
                        <td className="px-4 py-3 font-mono text-xs text-amber-300">{c.threat_indicator}</td>
                        <td className="px-4 py-3 text-xs">{c.correlation_type}</td>
                        <td className="px-4 py-3 font-mono text-xs text-rose-300">{c.matched_value}</td>
                        <td className="px-4 py-3">{getSeverityBadge(c.severity)}</td>
                        <td className="px-4 py-3 text-xs font-bold text-white">{c.confidence}%</td>
                        <td className="px-4 py-3 text-xs text-slate-400 max-w-xs truncate" title={c.details}>
                          {c.details}
                        </td>
                      </tr>
                    ))
                  )}
                </tbody>
              </table>
            </div>
          </div>

          {/* Section: Threat Intelligence Catalog */}
          <div className="space-y-3 pt-4 border-t border-slate-800">
            <div className="flex items-center justify-between">
              <h3 className="text-base font-semibold text-white flex items-center gap-2">
                <Globe className="w-4 h-4 text-indigo-400" />
                Verified Threat Indicators Catalog ({threatIndicators.length})
              </h3>
              <div className="flex items-center gap-2 text-xs">
                {['ALL', 'IP', 'DOMAIN', 'HASH', 'URL'].map((t) => (
                  <button
                    key={t}
                    onClick={() => setThreatTypeFilter(t)}
                    className={`px-2 py-1 rounded text-xs transition ${
                      threatTypeFilter === t ? 'bg-indigo-600 text-white' : 'bg-slate-900 text-slate-400'
                    }`}
                  >
                    {t}
                  </button>
                ))}
              </div>
            </div>

            <div className="overflow-x-auto rounded-xl border border-slate-800 bg-slate-900/50">
              <table className="w-full text-left text-sm text-slate-300">
                <thead className="bg-slate-900 text-xs uppercase font-semibold text-slate-400 border-b border-slate-800">
                  <tr>
                    <th className="px-4 py-3">Type</th>
                    <th className="px-4 py-3">Indicator Value</th>
                    <th className="px-4 py-3">Severity</th>
                    <th className="px-4 py-3">Confidence</th>
                    <th className="px-4 py-3">Source & Actor</th>
                    <th className="px-4 py-3">MITRE Tactics</th>
                    <th className="px-4 py-3">Freshness / Expiration</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-slate-800/60 font-medium">
                  {filteredThreats.map((t) => (
                    <tr key={t.id} className="hover:bg-slate-800/40 transition">
                      <td className="px-4 py-3 font-semibold text-xs text-indigo-300">{t.indicator_type}</td>
                      <td className="px-4 py-3 font-mono text-xs text-white max-w-xs truncate" title={t.indicator_value}>
                        {t.indicator_value}
                      </td>
                      <td className="px-4 py-3">{getSeverityBadge(t.severity)}</td>
                      <td className="px-4 py-3 text-xs">{t.confidence}%</td>
                      <td className="px-4 py-3 text-xs">
                        <div className="text-white font-medium">{t.source}</div>
                        {t.threat_actor && <div className="text-slate-400">Actor: {t.threat_actor}</div>}
                      </td>
                      <td className="px-4 py-3 text-xs">
                        <div className="flex flex-wrap gap-1">
                          {t.mitre_tactics?.slice(0, 2).map((tac) => (
                            <span key={tac} className="px-1.5 py-0.5 rounded bg-slate-800 text-slate-300 text-[10px]">
                              {tac}
                            </span>
                          ))}
                        </div>
                      </td>
                      <td className="px-4 py-3 text-xs text-slate-400">
                        {t.expires_at ? new Date(t.expires_at).toLocaleDateString() : 'Persistent'}
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </div>
        </div>
      )}

      {/* Tab 3: Behavioral Anomalies & Zero-Day Resilience */}
      {activeTab === 'anomalies' && (
        <div className="mt-6 space-y-4">
          <div className="flex items-center justify-between">
            <div className="flex items-center gap-2 text-sm text-slate-400">
              <Filter className="w-4 h-4" />
              <span>Filter:</span>
              {['ALL', 'ZERO_DAY', 'OPEN', 'INVESTIGATING', 'RESOLVED'].map((f) => (
                <button
                  key={f}
                  onClick={() => setAnomalyFilter(f)}
                  className={`px-2.5 py-1 rounded text-xs font-medium transition ${
                    anomalyFilter === f ? 'bg-indigo-600 text-white' : 'bg-slate-900 text-slate-400 hover:text-white'
                  }`}
                >
                  {f}
                </button>
              ))}
            </div>
            <div className="text-xs text-slate-400">Showing {filteredAnomalies.length} anomaly detections</div>
          </div>

          <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
            {filteredAnomalies.length === 0 ? (
              <div className="col-span-2 p-8 text-center text-slate-500 rounded-xl border border-slate-800 bg-slate-900/50">
                No behavioral deviations or zero-day anomaly indicators detected.
              </div>
            ) : (
              filteredAnomalies.map((an) => (
                <div
                  key={an.id}
                  className={`p-4 rounded-xl border transition ${
                    an.is_zero_day_indicator
                      ? 'border-purple-600/50 bg-purple-950/20'
                      : 'border-slate-800 bg-slate-900/60'
                  }`}
                >
                  <div className="flex items-start justify-between gap-3">
                    <div>
                      <div className="flex items-center gap-2">
                        {an.is_zero_day_indicator && (
                          <span className="px-2 py-0.5 rounded text-[11px] font-bold bg-purple-600 text-white flex items-center gap-1">
                            <Flame className="w-3 h-3" />
                            ZERO-DAY RESILIENCE
                          </span>
                        )}
                        <span className="font-semibold text-white text-sm">{an.anomaly_type}</span>
                        {getSeverityBadge(an.severity)}
                      </div>
                      <div className="text-xs text-slate-400 mt-1 font-mono">
                        Target Asset: {an.asset_name || an.asset_target}
                      </div>
                    </div>
                    <div className="text-right">
                      <div className="text-xs font-mono font-bold text-amber-400">Score: {an.anomaly_score}/100</div>
                      <span className="px-2 py-0.5 rounded text-[10px] uppercase font-bold bg-slate-800 text-slate-300">
                        {an.confidence}
                      </span>
                    </div>
                  </div>

                  <p className="text-xs text-slate-300 mt-3 leading-relaxed">{an.description}</p>

                  {an.evidence_data && (
                    <div className="mt-3 p-2.5 rounded bg-slate-950/80 border border-slate-800/80 text-[11px] font-mono text-slate-400">
                      <pre className="whitespace-pre-wrap">{JSON.stringify(an.evidence_data, null, 2)}</pre>
                    </div>
                  )}

                  <div className="mt-4 pt-3 border-t border-slate-800/80 flex items-center justify-between text-xs">
                    <span className="text-slate-400">
                      Status: <strong className="text-white">{an.status}</strong>
                    </span>
                    <div className="flex items-center gap-2">
                      {an.status === 'OPEN' && (
                        <button
                          onClick={() => handleUpdateAnomalyStatus(an.id, 'INVESTIGATING')}
                          className="px-2.5 py-1 rounded bg-slate-800 hover:bg-slate-700 text-slate-200 transition"
                        >
                          Investigate
                        </button>
                      )}
                      {an.status !== 'RESOLVED' && (
                        <button
                          onClick={() => handleUpdateAnomalyStatus(an.id, 'RESOLVED')}
                          className="px-2.5 py-1 rounded bg-emerald-600/20 text-emerald-400 border border-emerald-600/30 hover:bg-emerald-600/30 transition"
                        >
                          Resolve
                        </button>
                      )}
                    </div>
                  </div>
                </div>
              ))
            )}
          </div>
        </div>
      )}

      {/* Tab 4: Automated Response Actions & Approval Gate */}
      {activeTab === 'responses' && (
        <div className="mt-6 space-y-4">
          {/* Human-in-the-Loop Gate Notice */}
          <div className="p-4 rounded-xl bg-amber-950/30 border border-amber-600/40 text-amber-200 text-xs flex items-center gap-3">
            <Lock className="w-5 h-5 text-amber-400 shrink-0" />
            <div>
              <strong className="text-amber-300 font-semibold">Strict Human Authorization Gate Active:</strong> Disruptive
              containment policies (e.g. Network Boundary Isolation, Service Port Drop, Virtual WAF Patching) require
              explicit human OrgAdmin approval before execution. Reversible rollback payloads are recorded for all actions.
            </div>
          </div>

          <div className="flex items-center justify-between">
            <div className="flex items-center gap-2 text-sm text-slate-400">
              <Filter className="w-4 h-4" />
              <span>Filter Status:</span>
              {['ALL', 'PENDING_APPROVAL', 'APPROVED', 'EXECUTED', 'ROLLED_BACK', 'REJECTED'].map((st) => (
                <button
                  key={st}
                  onClick={() => setResponseStatusFilter(st)}
                  className={`px-2.5 py-1 rounded text-xs font-medium transition ${
                    responseStatusFilter === st
                      ? 'bg-indigo-600 text-white'
                      : 'bg-slate-900 text-slate-400 hover:text-white'
                  }`}
                >
                  {st}
                </button>
              ))}
            </div>
            <div className="text-xs text-slate-400">Showing {filteredActions.length} response mitigation actions</div>
          </div>

          <div className="overflow-x-auto rounded-xl border border-slate-800 bg-slate-900/50">
            <table className="w-full text-left text-sm text-slate-300">
              <thead className="bg-slate-900 text-xs uppercase font-semibold text-slate-400 border-b border-slate-800">
                <tr>
                  <th className="px-4 py-3">Action Title / Target</th>
                  <th className="px-4 py-3">Type</th>
                  <th className="px-4 py-3">Disruptive</th>
                  <th className="px-4 py-3">Status</th>
                  <th className="px-4 py-3">Approved By</th>
                  <th className="px-4 py-3">Executed At</th>
                  <th className="px-4 py-3 text-right">Gate Workflow</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-800/60 font-medium">
                {filteredActions.length === 0 ? (
                  <tr>
                    <td colSpan={7} className="px-4 py-8 text-center text-slate-500">
                      No response mitigation actions found.
                    </td>
                  </tr>
                ) : (
                  filteredActions.map((ac) => (
                    <tr key={ac.id} className="hover:bg-slate-800/40 transition">
                      <td className="px-4 py-3.5">
                        <div className="font-semibold text-white">{ac.title}</div>
                        <div className="text-xs text-slate-400 font-mono">Target: {ac.target_entity}</div>
                      </td>
                      <td className="px-4 py-3.5 text-xs text-indigo-300 font-mono">{ac.action_type}</td>
                      <td className="px-4 py-3.5">
                        {ac.is_disruptive ? (
                          <span className="px-2 py-0.5 rounded text-[10px] font-bold bg-rose-950 text-rose-300 border border-rose-800">
                            DISRUPTIVE
                          </span>
                        ) : (
                          <span className="px-2 py-0.5 rounded text-[10px] font-bold bg-slate-800 text-slate-400">
                            TRANSPARENT
                          </span>
                        )}
                      </td>
                      <td className="px-4 py-3.5">
                        <span
                          className={`px-2 py-0.5 rounded text-xs font-semibold ${
                            ac.status === 'EXECUTED'
                              ? 'bg-emerald-500/20 text-emerald-400 border border-emerald-500/30'
                              : ac.status === 'APPROVED'
                              ? 'bg-cyan-500/20 text-cyan-400 border border-cyan-500/30'
                              : ac.status === 'PENDING_APPROVAL'
                              ? 'bg-amber-500/20 text-amber-400 border border-amber-500/30'
                              : ac.status === 'ROLLED_BACK'
                              ? 'bg-purple-500/20 text-purple-400 border border-purple-500/30'
                              : 'bg-rose-500/20 text-rose-400'
                          }`}
                        >
                          {ac.status}
                        </span>
                      </td>
                      <td className="px-4 py-3.5 text-xs text-slate-400">{ac.approved_by_user_name || '—'}</td>
                      <td className="px-4 py-3.5 text-xs text-slate-400">
                        {ac.executed_at ? new Date(ac.executed_at).toLocaleTimeString() : '—'}
                      </td>
                      <td className="px-4 py-3.5 text-right">
                        <div className="flex items-center justify-end gap-2">
                          {ac.status === 'PENDING_APPROVAL' && (
                            <>
                              <button
                                onClick={() => handleApproveAction(ac.id)}
                                disabled={isProcessingAction}
                                className="px-2.5 py-1 text-xs rounded bg-emerald-600 hover:bg-emerald-500 text-white font-medium transition"
                              >
                                Approve
                              </button>
                              <button
                                onClick={() => handleRejectAction(ac.id)}
                                disabled={isProcessingAction}
                                className="px-2.5 py-1 text-xs rounded bg-rose-950 hover:bg-rose-900 text-rose-300 border border-rose-800 transition"
                              >
                                Reject
                              </button>
                            </>
                          )}

                          {ac.status === 'APPROVED' && (
                            <button
                              onClick={() => handleExecuteAction(ac.id)}
                              disabled={isProcessingAction}
                              className="px-2.5 py-1 text-xs rounded bg-indigo-600 hover:bg-indigo-500 text-white font-medium transition flex items-center gap-1"
                            >
                              <Play className="w-3 h-3" />
                              Execute
                            </button>
                          )}

                          {ac.status === 'EXECUTED' && (
                            <button
                              onClick={() => handleRollbackAction(ac.id)}
                              disabled={isProcessingAction}
                              className="px-2.5 py-1 text-xs rounded bg-slate-800 hover:bg-slate-700 text-amber-300 border border-slate-700 transition flex items-center gap-1"
                            >
                              <RotateCcw className="w-3 h-3" />
                              Rollback
                            </button>
                          )}

                          <button
                            onClick={() => setSelectedAction(ac)}
                            className="p-1 rounded text-slate-400 hover:text-white hover:bg-slate-800 transition"
                            title="Inspect Details"
                          >
                            <Eye className="w-3.5 h-3.5" />
                          </button>
                        </div>
                      </td>
                    </tr>
                  ))
                )}
              </tbody>
            </table>
          </div>
        </div>
      )}

      {/* Posture Inspection Modal */}
      {selectedAssessment && (
        <div className="fixed inset-0 z-50 bg-black/80 flex items-center justify-center p-4">
          <div className="bg-slate-900 border border-slate-800 rounded-2xl max-w-2xl w-full max-h-[90vh] overflow-y-auto p-6 space-y-5">
            <div className="flex items-center justify-between pb-4 border-b border-slate-800">
              <div className="flex items-center gap-3">
                <div className="p-2 rounded bg-indigo-600/20 text-indigo-400">
                  <Shield className="w-5 h-5" />
                </div>
                <div>
                  <h3 className="text-lg font-bold text-white">Trust Assessment: {selectedAssessment.asset_name}</h3>
                  <p className="text-xs text-slate-400 font-mono">{selectedAssessment.asset_target}</p>
                </div>
              </div>
              <button onClick={() => setSelectedAssessment(null)} className="text-slate-400 hover:text-white">
                <X className="w-5 h-5" />
              </button>
            </div>

            <div className="grid grid-cols-2 gap-4">
              <div className="p-3.5 rounded-xl bg-slate-950 border border-slate-800">
                <div className="text-xs text-slate-400">Trust Decision</div>
                <div className="mt-1">{getDecisionBadge(selectedAssessment.trust_decision)}</div>
              </div>
              <div className="p-3.5 rounded-xl bg-slate-950 border border-slate-800">
                <div className="text-xs text-slate-400">Trust Score</div>
                <div className="mt-1 text-xl font-bold text-white">{selectedAssessment.trust_score} / 100</div>
              </div>
            </div>

            <div>
              <h4 className="text-xs font-semibold uppercase text-slate-400">Decision Rationale</h4>
              <p className="mt-1 text-sm text-slate-300 leading-relaxed bg-slate-950 p-3 rounded-lg border border-slate-800">
                {selectedAssessment.decision_reason}
              </p>
            </div>

            {/* Positive Factors */}
            <div>
              <h4 className="text-xs font-semibold uppercase text-emerald-400 flex items-center gap-1.5">
                <CheckCircle2 className="w-3.5 h-3.5" />
                Positive Security Posture Factors ({selectedAssessment.positive_factors?.length || 0})
              </h4>
              <div className="mt-2 space-y-2">
                {selectedAssessment.positive_factors?.length === 0 ? (
                  <div className="text-xs text-slate-500 italic">No positive factors verified yet.</div>
                ) : (
                  selectedAssessment.positive_factors?.map((f, idx) => (
                    <div key={idx} className="p-2.5 rounded bg-emerald-950/20 border border-emerald-800/30 text-xs">
                      <div className="flex items-center justify-between text-emerald-300 font-semibold">
                        <span>{f.factor}</span>
                        <span className="font-mono">+{f.score_delta}</span>
                      </div>
                      <p className="text-slate-400 mt-0.5">{f.description}</p>
                    </div>
                  ))
                )}
              </div>
            </div>

            {/* Risk Factors */}
            <div>
              <h4 className="text-xs font-semibold uppercase text-rose-400 flex items-center gap-1.5">
                <AlertTriangle className="w-3.5 h-3.5" />
                Risk Penalties & Exposures ({selectedAssessment.risk_factors?.length || 0})
              </h4>
              <div className="mt-2 space-y-2">
                {selectedAssessment.risk_factors?.length === 0 ? (
                  <div className="text-xs text-slate-500 italic">Zero negative risk factors detected.</div>
                ) : (
                  selectedAssessment.risk_factors?.map((f, idx) => (
                    <div key={idx} className="p-2.5 rounded bg-rose-950/20 border border-rose-800/30 text-xs">
                      <div className="flex items-center justify-between text-rose-300 font-semibold">
                        <span>{f.factor}</span>
                        <span className="font-mono">{f.score_delta}</span>
                      </div>
                      <p className="text-slate-400 mt-0.5">{f.description}</p>
                    </div>
                  ))
                )}
              </div>
            </div>

            {/* Least Privilege Recommendations */}
            <div>
              <h4 className="text-xs font-semibold uppercase text-indigo-400 flex items-center gap-1.5">
                <Lock className="w-3.5 h-3.5" />
                Least-Privilege & Hardening Recommendations
              </h4>
              <ul className="mt-2 space-y-1.5 text-xs text-slate-300">
                {selectedAssessment.least_privilege_recommendations?.map((r, idx) => (
                  <li key={idx} className="flex items-start gap-2 p-2 rounded bg-slate-950 border border-slate-800">
                    <span className="text-indigo-400 font-bold shrink-0">•</span>
                    <span>{r}</span>
                  </li>
                ))}
              </ul>
            </div>
          </div>
        </div>
      )}

      {/* Response Action Inspection Modal */}
      {selectedAction && (
        <div className="fixed inset-0 z-50 bg-black/80 flex items-center justify-center p-4">
          <div className="bg-slate-900 border border-slate-800 rounded-2xl max-w-xl w-full p-6 space-y-4">
            <div className="flex items-center justify-between pb-3 border-b border-slate-800">
              <h3 className="text-base font-bold text-white">Action: {selectedAction.title}</h3>
              <button onClick={() => setSelectedAction(null)} className="text-slate-400 hover:text-white">
                <X className="w-4 h-4" />
              </button>
            </div>

            <div className="text-xs text-slate-300 leading-relaxed">{selectedAction.description}</div>

            {selectedAction.execution_payload && (
              <div>
                <h5 className="text-xs font-semibold text-slate-400">Execution Configuration</h5>
                <pre className="mt-1 p-3 rounded bg-slate-950 border border-slate-800 text-[11px] font-mono text-slate-300 overflow-x-auto">
                  {JSON.stringify(selectedAction.execution_payload, null, 2)}
                </pre>
              </div>
            )}

            {selectedAction.rollback_payload && (
              <div>
                <h5 className="text-xs font-semibold text-slate-400">Reversible Rollback Configuration</h5>
                <pre className="mt-1 p-3 rounded bg-slate-950 border border-slate-800 text-[11px] font-mono text-slate-300 overflow-x-auto">
                  {JSON.stringify(selectedAction.rollback_payload, null, 2)}
                </pre>
              </div>
            )}

            {selectedAction.execution_log && (
              <div>
                <h5 className="text-xs font-semibold text-slate-400">Execution Log</h5>
                <pre className="mt-1 p-3 rounded bg-slate-950 border border-slate-800 text-[11px] font-mono text-emerald-400 whitespace-pre-wrap">
                  {selectedAction.execution_log}
                </pre>
              </div>
            )}
          </div>
        </div>
      )}
    </div>
  );
};
