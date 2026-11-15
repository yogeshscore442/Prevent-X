import React, { useEffect, useState } from 'react';
import {
  AlertCircle,
  AlertTriangle,
  CheckCircle2,
  Clock,
  Code2,
  History,
  Layers,
  Loader2,
  Lock,
  Plus,
  RefreshCw,
  RotateCcw,
  Server,
  Shield,
  ShieldAlert,
  ShieldCheck,
  Trash2,
  UserCheck,
  X,
  Zap,
} from 'lucide-react';
import {
  VirtualPatchDeployment,
  VirtualPatchOverviewStats,
  VirtualPatchRecommendation,
  VirtualPatchRule,
  VirtualPatchRuleCreatePayload,
  VirtualPatchVersion,
  WafEnforcementLog,
} from '@/types/virtualPatch';
import { virtualPatchApi } from '@/services/virtualPatchApi';
import { formatErrorMessage } from '@/utils/formatError';

export const VirtualPatchingPage: React.FC = () => {
  const [activeTab, setActiveTab] = useState<'recommendations' | 'rules' | 'deployments' | 'logs'>('recommendations');

  // Core Telemetry State
  const [overview, setOverview] = useState<VirtualPatchOverviewStats | null>(null);
  const [recommendations, setRecommendations] = useState<VirtualPatchRecommendation[]>([]);
  const [rules, setRules] = useState<VirtualPatchRule[]>([]);
  const [deployments, setDeployments] = useState<VirtualPatchDeployment[]>([]);
  const [logs, setLogs] = useState<WafEnforcementLog[]>([]);
  const [isLoading, setIsLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [actionMessage, setActionMessage] = useState<string | null>(null);

  // Filters
  const [attackTypeFilter, setAttackTypeFilter] = useState<string>('ALL');
  const [logDecisionFilter, setLogDecisionFilter] = useState<string>('ALL');

  // Modals & Active Selections
  const [selectedRuleForVersions, setSelectedRuleForVersions] = useState<VirtualPatchRule | null>(null);
  const [ruleVersions, setRuleVersions] = useState<VirtualPatchVersion[]>([]);
  const [isVersionsLoading, setIsVersionsLoading] = useState(false);

  const [isCreateModalOpen, setIsCreateModalOpen] = useState(false);
  const [isStageModalOpen, setIsStageModalOpen] = useState(false);
  const [isFalsePositiveModalOpen, setIsFalsePositiveModalOpen] = useState(false);
  const [selectedLogForFP, setSelectedLogForFP] = useState<WafEnforcementLog | null>(null);
  const [fpNotes, setFpNotes] = useState('');

  // Processing indicator
  const [isProcessing, setIsProcessing] = useState(false);

  // Form states for Create Rule
  const [newRule, setNewRule] = useState<VirtualPatchRuleCreatePayload>({
    rule_name: '',
    attack_type: 'SQLI',
    description: '',
    severity: 'HIGH',
    priority: 100,
    action: 'BLOCK',
    target_uri_pattern: '/.*',
    http_methods: ['GET', 'POST', 'PUT', 'DELETE'],
    match_conditions: [
      {
        target: 'QUERY',
        operator: 'REGEX',
        pattern: "(?i)(union\\s+select|select\\s+.*\\s+from|'\\s*or\\s*'1'='1')",
        is_case_sensitive: false,
      },
    ],
  });

  // Form states for Stage Deployment
  const [stagePort, setStagePort] = useState(8085);
  const [stageUpstream, setStageUpstream] = useState('http://127.0.0.1:8086');

  useEffect(() => {
    loadAllData();
  }, []);

  const loadAllData = async () => {
    setIsLoading(true);
    setError(null);
    try {
      const [ovData, recData, ruleData, depData, logData] = await Promise.all([
        virtualPatchApi.getOverview(),
        virtualPatchApi.listRecommendations(),
        virtualPatchApi.listRules(),
        virtualPatchApi.listDeployments(),
        virtualPatchApi.listEnforcementLogs({ limit: 100 }),
      ]);
      setOverview(ovData);
      setRecommendations(Array.isArray(recData) ? recData : []);
      setRules(Array.isArray(ruleData) ? ruleData : []);
      setDeployments(Array.isArray(depData) ? depData : []);
      setLogs(Array.isArray(logData) ? logData : []);
    } catch (err: any) {
      setError(formatErrorMessage(err, 'Failed to load Virtual Patching telemetry.'));
      setRecommendations([]);
      setRules([]);
      setDeployments([]);
      setLogs([]);
    } finally {
      setIsLoading(false);
    }
  };

  // ---------------------------------------------------------------------------
  // RECOMMENDATIONS ACTIONS
  // ---------------------------------------------------------------------------
  const handleGenerateRecommendations = async () => {
    setIsProcessing(true);
    try {
      const res = await virtualPatchApi.generateRecommendations();
      setActionMessage(`Synthesized ${res.length} explainable virtual patch recommendations.`);
      await loadAllData();
    } catch (err: any) {
      setError(err?.response?.data?.detail || err?.message || 'Synthesis failed.');
    } finally {
      setIsProcessing(false);
    }
  };

  const handleAcceptRecommendation = async (id: string) => {
    setIsProcessing(true);
    try {
      await virtualPatchApi.acceptRecommendation(id);
      setActionMessage('Recommendation accepted and instantiated as draft WAF rule.');
      await loadAllData();
    } catch (err: any) {
      setError(err?.response?.data?.detail || err?.message || 'Acceptance failed.');
    } finally {
      setIsProcessing(false);
    }
  };

  const handleRejectRecommendation = async (id: string) => {
    setIsProcessing(true);
    try {
      await virtualPatchApi.rejectRecommendation(id);
      setActionMessage('Recommendation marked rejected.');
      await loadAllData();
    } catch (err: any) {
      setError(err?.response?.data?.detail || err?.message || 'Rejection failed.');
    } finally {
      setIsProcessing(false);
    }
  };

  // ---------------------------------------------------------------------------
  // RULES ACTIONS
  // ---------------------------------------------------------------------------
  const handleSeedBaselineRules = async () => {
    setIsProcessing(true);
    try {
      const res = await virtualPatchApi.seedBaselineRules();
      setActionMessage(`Installed ${res.length} SMB baseline virtual patch rules.`);
      await loadAllData();
    } catch (err: any) {
      setError(err?.response?.data?.detail || err?.message || 'Baseline seeding failed.');
    } finally {
      setIsProcessing(false);
    }
  };

  const handleToggleRule = async (rule: VirtualPatchRule) => {
    setIsProcessing(true);
    try {
      await virtualPatchApi.updateRule(rule.id, {
        is_active: !rule.is_active,
        change_summary: `Rule toggled to ${!rule.is_active ? 'ACTIVE' : 'DISABLED'}`,
      });
      await loadAllData();
    } catch (err: any) {
      setError(err?.response?.data?.detail || err?.message || 'Update failed.');
    } finally {
      setIsProcessing(false);
    }
  };

  const handleDeleteRule = async (id: string) => {
    if (!window.confirm('Delete this virtual patch rule and its version history?')) return;
    setIsProcessing(true);
    try {
      await virtualPatchApi.deleteRule(id);
      setActionMessage('Rule deleted.');
      await loadAllData();
    } catch (err: any) {
      setError(err?.response?.data?.detail || err?.message || 'Deletion failed.');
    } finally {
      setIsProcessing(false);
    }
  };

  const handleViewVersions = async (rule: VirtualPatchRule) => {
    setSelectedRuleForVersions(rule);
    setIsVersionsLoading(true);
    try {
      const vers = await virtualPatchApi.listRuleVersions(rule.id);
      setRuleVersions(Array.isArray(vers) ? vers : []);
    } catch (err: any) {
      setError(err?.response?.data?.detail || err?.message || 'Failed to load versions.');
      setRuleVersions([]);
    } finally {
      setIsVersionsLoading(false);
    }
  };

  const handleCreateRuleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setIsProcessing(true);
    try {
      await virtualPatchApi.createRule(newRule);
      setIsCreateModalOpen(false);
      setActionMessage('Custom virtual patch rule created.');
      await loadAllData();
    } catch (err: any) {
      setError(err?.response?.data?.detail || err?.message || 'Failed to create rule.');
    } finally {
      setIsProcessing(false);
    }
  };

  // ---------------------------------------------------------------------------
  // DEPLOYMENT LIFECYCLE ACTIONS
  // ---------------------------------------------------------------------------
  const handleStageDeployment = async (e: React.FormEvent) => {
    e.preventDefault();
    setIsProcessing(true);
    try {
      const dep = await virtualPatchApi.stageDeployment({
        environment: 'STAGING',
        listen_port: stagePort,
        upstream_url: stageUpstream,
      });
      setIsStageModalOpen(false);
      setActionMessage(`Deployment staged successfully with status: ${dep.status}`);
      await loadAllData();
    } catch (err: any) {
      setError(err?.response?.data?.detail || err?.message || 'Failed to stage deployment.');
    } finally {
      setIsProcessing(false);
    }
  };

  const handleApproveDeployment = async (id: string) => {
    setIsProcessing(true);
    try {
      await virtualPatchApi.approveDeployment(id);
      setActionMessage('Deployment signed off and approved for production.');
      await loadAllData();
    } catch (err: any) {
      setError(err?.response?.data?.detail || err?.message || 'Approval failed.');
    } finally {
      setIsProcessing(false);
    }
  };

  const handleDeployToProduction = async (id: string) => {
    setIsProcessing(true);
    try {
      await virtualPatchApi.deployToProduction(id);
      setActionMessage('Virtual patches successfully enforced on live Nginx reverse proxy.');
      await loadAllData();
    } catch (err: any) {
      setError(err?.response?.data?.detail || err?.message || 'Production deployment failed.');
    } finally {
      setIsProcessing(false);
    }
  };

  const handleRollbackDeployment = async (id: string) => {
    if (!window.confirm('Roll back reverse proxy configuration immediately?')) return;
    setIsProcessing(true);
    try {
      await virtualPatchApi.rollbackDeployment(id);
      setActionMessage('Emergency rollback completed.');
      await loadAllData();
    } catch (err: any) {
      setError(err?.response?.data?.detail || err?.message || 'Rollback failed.');
    } finally {
      setIsProcessing(false);
    }
  };

  // ---------------------------------------------------------------------------
  // WAF LOGS & FALSE POSITIVES
  // ---------------------------------------------------------------------------
  const handleReportFalsePositiveSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!selectedLogForFP) return;
    setIsProcessing(true);
    try {
      await virtualPatchApi.reportFalsePositive(selectedLogForFP.id, fpNotes);
      setIsFalsePositiveModalOpen(false);
      setSelectedLogForFP(null);
      setFpNotes('');
      setActionMessage('False-positive reported. Metric incremented for rule tuning.');
      await loadAllData();
    } catch (err: any) {
      setError(err?.response?.data?.detail || err?.message || 'Failed to report false positive.');
    } finally {
      setIsProcessing(false);
    }
  };

  // Helper Badge Colors
  const getAttackTypeBadge = (type: string) => {
    switch (type) {
      case 'SQLI':
        return 'bg-red-500/10 text-red-400 border-red-500/20';
      case 'XSS':
        return 'bg-amber-500/10 text-amber-400 border-amber-500/20';
      case 'PATH_TRAVERSAL':
        return 'bg-purple-500/10 text-purple-400 border-purple-500/20';
      case 'CMDI':
        return 'bg-rose-500/10 text-rose-400 border-rose-500/20';
      case 'PATTERN_BLOCK':
        return 'bg-blue-500/10 text-blue-400 border-blue-500/20';
      default:
        return 'bg-slate-500/10 text-slate-400 border-slate-500/20';
    }
  };

  const getStatusBadge = (status: string) => {
    switch (status) {
      case 'PRODUCTION':
      case 'DEPLOYED':
      case 'APPROVED':
        return 'bg-emerald-500/10 text-emerald-400 border-emerald-500/20';
      case 'STAGING':
      case 'VALIDATING':
      case 'PENDING_APPROVAL':
        return 'bg-amber-500/10 text-amber-400 border-amber-500/20';
      case 'ROLLED_BACK':
      case 'FAILED':
      case 'REJECTED':
        return 'bg-red-500/10 text-red-400 border-red-500/20';
      default:
        return 'bg-slate-500/10 text-slate-400 border-slate-500/20';
    }
  };

  const filteredRules = (rules || []).filter((r) => {
    if (attackTypeFilter === 'ALL') return true;
    return r.attack_type === attackTypeFilter;
  });

  const filteredLogs = (logs || []).filter((l) => {
    if (logDecisionFilter === 'ALL') return true;
    return l.decision === logDecisionFilter;
  });

  return (
    <div className="p-6 max-w-7xl mx-auto space-y-6">
      {/* Header */}
      <div className="flex flex-col md:flex-row md:items-center justify-between gap-4">
        <div>
          <div className="flex items-center gap-3">
            <div className="p-2.5 rounded-xl bg-gradient-to-br from-indigo-500/20 to-cyan-500/20 border border-indigo-500/30 text-indigo-400">
              <ShieldAlert className="w-6 h-6" />
            </div>
            <div>
              <h1 className="text-2xl font-bold text-slate-100 flex items-center gap-2">
                Intelligent Virtual Patching Engine
                <span className="text-xs font-mono uppercase px-2 py-0.5 rounded-full bg-indigo-500/10 text-indigo-400 border border-indigo-500/20">
                  MOD-06 / MOD-08
                </span>
              </h1>
              <p className="text-sm text-slate-400">
                AI-era compensating security controls and Nginx reverse proxy enforcement for Indian SMB digital infrastructure.
              </p>
            </div>
          </div>
        </div>

        {/* Global Control Bar */}
        <div className="flex items-center gap-3">
          <button
            onClick={loadAllData}
            disabled={isLoading || isProcessing}
            className="flex items-center gap-2 px-3.5 py-2 text-sm font-medium rounded-lg bg-slate-800 text-slate-200 hover:bg-slate-700 transition border border-slate-700 disabled:opacity-50"
          >
            <RefreshCw className={`w-4 h-4 ${isLoading ? 'animate-spin' : ''}`} />
            Refresh
          </button>
          <button
            onClick={() => setIsStageModalOpen(true)}
            disabled={isProcessing}
            className="flex items-center gap-2 px-4 py-2 text-sm font-medium rounded-lg bg-gradient-to-r from-indigo-600 to-cyan-600 text-white hover:from-indigo-500 hover:to-cyan-500 transition shadow-lg shadow-indigo-500/20 disabled:opacity-50"
          >
            <Zap className="w-4 h-4" />
            Stage Deployment
          </button>
        </div>
      </div>

      {/* Notifications */}
      {error && (
        <div className="p-4 rounded-xl bg-red-500/10 border border-red-500/20 text-red-400 flex items-center justify-between">
          <div className="flex items-center gap-2">
            <AlertCircle className="w-5 h-5 flex-shrink-0" />
            <span className="text-sm">{typeof error === 'string' ? error : formatErrorMessage(error)}</span>
          </div>
          <button onClick={() => setError(null)} className="text-slate-400 hover:text-slate-200">
            <X className="w-4 h-4" />
          </button>
        </div>
      )}

      {actionMessage && (
        <div className="p-4 rounded-xl bg-emerald-500/10 border border-emerald-500/20 text-emerald-400 flex items-center justify-between">
          <div className="flex items-center gap-2">
            <CheckCircle2 className="w-5 h-5 flex-shrink-0" />
            <span className="text-sm">{actionMessage}</span>
          </div>
          <button onClick={() => setActionMessage(null)} className="text-slate-400 hover:text-slate-200">
            <X className="w-4 h-4" />
          </button>
        </div>
      )}

      {/* Overview KPI Cards */}
      {overview && (
        <div className="grid grid-cols-2 md:grid-cols-3 lg:grid-cols-6 gap-4">
          <div className="p-4 rounded-xl bg-slate-900 border border-slate-800">
            <div className="text-xs font-medium text-slate-400 mb-1 flex items-center justify-between">
              <span>Active Rules</span>
              <Shield className="w-4 h-4 text-indigo-400" />
            </div>
            <div className="text-2xl font-bold text-slate-100">
              {overview.active_rules}{' '}
              <span className="text-xs font-normal text-slate-500">/ {overview.total_rules}</span>
            </div>
          </div>

          <div className="p-4 rounded-xl bg-slate-900 border border-slate-800">
            <div className="text-xs font-medium text-slate-400 mb-1 flex items-center justify-between">
              <span>Reverse Proxy</span>
              <Server className="w-4 h-4 text-cyan-400" />
            </div>
            <div className="flex items-center gap-2">
              <span
                className={`inline-block w-2.5 h-2.5 rounded-full ${overview.proxy_status === 'ACTIVE' ? 'bg-emerald-500 animate-pulse' : 'bg-red-500'
                  }`}
              />
              <span className="text-lg font-bold text-slate-100">
                {overview.proxy_status === 'ACTIVE' ? `Port ${overview.proxy_listen_port}` : 'STOPPED'}
              </span>
            </div>
          </div>

          <div className="p-4 rounded-xl bg-slate-900 border border-slate-800">
            <div className="text-xs font-medium text-slate-400 mb-1 flex items-center justify-between">
              <span>Total Blocks</span>
              <ShieldAlert className="w-4 h-4 text-red-400" />
            </div>
            <div className="text-2xl font-bold text-red-400">{overview.total_blocks_recorded}</div>
          </div>

          <div className="p-4 rounded-xl bg-slate-900 border border-slate-800">
            <div className="text-xs font-medium text-slate-400 mb-1 flex items-center justify-between">
              <span>Pending Sign-Off</span>
              <Clock className="w-4 h-4 text-amber-400" />
            </div>
            <div className="text-2xl font-bold text-amber-400">
              {overview.pending_approval_deployments}
            </div>
          </div>

          <div className="p-4 rounded-xl bg-slate-900 border border-slate-800">
            <div className="text-xs font-medium text-slate-400 mb-1 flex items-center justify-between">
              <span>Proposals Ready</span>
              <Zap className="w-4 h-4 text-cyan-400" />
            </div>
            <div className="text-2xl font-bold text-cyan-400">
              {overview.active_recommendations_count}
            </div>
          </div>

          <div className="p-4 rounded-xl bg-slate-900 border border-slate-800">
            <div className="text-xs font-medium text-slate-400 mb-1 flex items-center justify-between">
              <span>False Positives</span>
              <AlertTriangle className="w-4 h-4 text-yellow-400" />
            </div>
            <div className="text-2xl font-bold text-yellow-400">
              {overview.false_positives_reported}
            </div>
          </div>
        </div>
      )}

      {/* Tabs Navigation */}
      <div className="border-b border-slate-800 flex gap-6">
        <button
          onClick={() => setActiveTab('recommendations')}
          className={`pb-3 text-sm font-medium transition border-b-2 flex items-center gap-2 ${activeTab === 'recommendations'
            ? 'border-indigo-500 text-indigo-400'
            : 'border-transparent text-slate-400 hover:text-slate-200'
            }`}
        >
          <Zap className="w-4 h-4" />
          AI Patch Proposals ({recommendations.filter((r) => r.status === 'PROPOSED').length})
        </button>

        <button
          onClick={() => setActiveTab('rules')}
          className={`pb-3 text-sm font-medium transition border-b-2 flex items-center gap-2 ${activeTab === 'rules'
            ? 'border-indigo-500 text-indigo-400'
            : 'border-transparent text-slate-400 hover:text-slate-200'
            }`}
        >
          <Code2 className="w-4 h-4" />
          WAF Rules & Versioning ({rules.length})
        </button>

        <button
          onClick={() => setActiveTab('deployments')}
          className={`pb-3 text-sm font-medium transition border-b-2 flex items-center gap-2 ${activeTab === 'deployments'
            ? 'border-indigo-500 text-indigo-400'
            : 'border-transparent text-slate-400 hover:text-slate-200'
            }`}
        >
          <Layers className="w-4 h-4" />
          Deployments & Human Sign-Off ({deployments.length})
        </button>

        <button
          onClick={() => setActiveTab('logs')}
          className={`pb-3 text-sm font-medium transition border-b-2 flex items-center gap-2 ${activeTab === 'logs'
            ? 'border-indigo-500 text-indigo-400'
            : 'border-transparent text-slate-400 hover:text-slate-200'
            }`}
        >
          <History className="w-4 h-4" />
          Reverse Proxy Audit Logs ({logs.length})
        </button>
      </div>

      {/* TAB 1: AI RECOMMENDATIONS TRIAGE */}
      {activeTab === 'recommendations' && (
        <div className="space-y-4">
          <div className="flex items-center justify-between">
            <div>
              <h2 className="text-lg font-semibold text-slate-100">
                Explainable Virtual Patch Recommendations
              </h2>
              <p className="text-xs text-slate-400">
                Synthesized directly from unpatched tenant CVEs and attack paths. Strict mandate: recommendations require human approval before deployment.
              </p>
            </div>
            <button
              onClick={handleGenerateRecommendations}
              disabled={isProcessing}
              className="flex items-center gap-2 px-3.5 py-2 text-sm font-medium rounded-lg bg-indigo-600/20 text-indigo-300 hover:bg-indigo-600/30 border border-indigo-500/30 transition disabled:opacity-50"
            >
              <Zap className="w-4 h-4" />
              Analyze Exposures & Propose Patches
            </button>
          </div>

          {recommendations.length === 0 ? (
            <div className="p-12 text-center rounded-xl bg-slate-900 border border-slate-800 text-slate-400 space-y-3">
              <Zap className="w-10 h-10 mx-auto text-slate-600" />
              <p className="text-sm">No active patch recommendations pending review.</p>
              <button
                onClick={handleGenerateRecommendations}
                className="px-4 py-2 text-xs font-semibold rounded-lg bg-indigo-600 text-white hover:bg-indigo-500 transition"
              >
                Scan Vulnerabilities for Patch Opportunities
              </button>
            </div>
          ) : (
            <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
              {recommendations.map((rec) => (
                <div
                  key={rec.id}
                  className="p-5 rounded-xl bg-slate-900 border border-slate-800 space-y-3 flex flex-col justify-between"
                >
                  <div className="space-y-2">
                    <div className="flex items-center justify-between gap-2">
                      <span
                        className={`text-xs px-2 py-0.5 rounded-full border font-mono font-medium ${getAttackTypeBadge(
                          rec.attack_type
                        )}`}
                      >
                        {rec.attack_type}
                      </span>
                      <div className="flex items-center gap-2">
                        <span className="text-xs text-slate-400 font-mono">
                          Confidence: {rec.confidence}%
                        </span>
                        <span
                          className={`text-xs px-2 py-0.5 rounded-full border font-mono ${getStatusBadge(
                            rec.status
                          )}`}
                        >
                          {rec.status}
                        </span>
                      </div>
                    </div>

                    <h3 className="text-base font-semibold text-slate-100">
                      {rec.suggested_rule_name}
                    </h3>
                    <p className="text-xs text-slate-400 leading-relaxed">{rec.rationale}</p>

                    <div className="p-2.5 rounded-lg bg-slate-950 border border-slate-800 font-mono text-xs text-slate-300 overflow-x-auto">
                      <div className="text-slate-500 text-[10px] uppercase font-bold mb-1">
                        Compensating Signature Pattern:
                      </div>
                      <code>{rec.suggested_pattern}</code>
                    </div>
                  </div>

                  {rec.status === 'PROPOSED' && (
                    <div className="pt-3 border-t border-slate-800 flex items-center justify-end gap-2">
                      <button
                        onClick={() => handleRejectRecommendation(rec.id)}
                        disabled={isProcessing}
                        className="px-3 py-1.5 text-xs font-medium rounded-lg text-slate-400 hover:text-red-400 hover:bg-red-500/10 transition"
                      >
                        Reject
                      </button>
                      <button
                        onClick={() => handleAcceptRecommendation(rec.id)}
                        disabled={isProcessing}
                        className="flex items-center gap-1.5 px-3 py-1.5 text-xs font-medium rounded-lg bg-indigo-600 text-white hover:bg-indigo-500 transition shadow-sm"
                      >
                        <CheckCircle2 className="w-3.5 h-3.5" />
                        Accept & Create Draft Rule
                      </button>
                    </div>
                  )}
                </div>
              ))}
            </div>
          )}
        </div>
      )}

      {/* TAB 2: RULES CATALOG & VERSIONING */}
      {activeTab === 'rules' && (
        <div className="space-y-4">
          <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4">
            <div className="flex items-center gap-3">
              <select
                value={attackTypeFilter}
                onChange={(e) => setAttackTypeFilter(e.target.value)}
                className="px-3 py-1.5 text-xs rounded-lg bg-slate-900 border border-slate-700 text-slate-200"
              >
                <option value="ALL">All Attack Types</option>
                <option value="SQLI">SQL Injection</option>
                <option value="XSS">Cross-Site Scripting</option>
                <option value="PATH_TRAVERSAL">Path Traversal</option>
                <option value="CMDI">Command Injection</option>
                <option value="PATTERN_BLOCK">Reconnaissance Scanners</option>
                <option value="METHOD_RESTRICTION">HTTP Method Restrictions</option>
              </select>
            </div>

            <div className="flex items-center gap-2">
              <button
                onClick={handleSeedBaselineRules}
                disabled={isProcessing}
                className="flex items-center gap-2 px-3 py-2 text-xs font-medium rounded-lg bg-slate-800 text-slate-200 hover:bg-slate-700 border border-slate-700 transition"
              >
                <ShieldCheck className="w-3.5 h-3.5 text-emerald-400" />
                Seed SMB Baseline
              </button>
              <button
                onClick={() => setIsCreateModalOpen(true)}
                disabled={isProcessing}
                className="flex items-center gap-2 px-3 py-2 text-xs font-medium rounded-lg bg-indigo-600 text-white hover:bg-indigo-500 transition"
              >
                <Plus className="w-3.5 h-3.5" />
                Add Custom Rule
              </button>
            </div>
          </div>

          <div className="rounded-xl bg-slate-900 border border-slate-800 overflow-hidden">
            <table className="w-full text-left text-xs text-slate-300">
              <thead className="bg-slate-950/60 text-slate-400 uppercase text-[10px] tracking-wider border-b border-slate-800">
                <tr>
                  <th className="p-3">Priority</th>
                  <th className="p-3">Rule Name & Details</th>
                  <th className="p-3">Category</th>
                  <th className="p-3">Action</th>
                  <th className="p-3">Version</th>
                  <th className="p-3">Blocks</th>
                  <th className="p-3">Status</th>
                  <th className="p-3 text-right">Actions</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-800">
                {filteredRules.length === 0 ? (
                  <tr>
                    <td colSpan={8} className="p-8 text-center text-slate-500">
                      No virtual patch rules registered. Click "Seed SMB Baseline" or accept a proposal.
                    </td>
                  </tr>
                ) : (
                  filteredRules.map((rule) => (
                    <tr key={rule.id} className="hover:bg-slate-800/40 transition">
                      <td className="p-3 font-mono font-bold text-slate-400">#{rule.priority}</td>
                      <td className="p-3 space-y-0.5">
                        <div className="font-semibold text-slate-100 flex items-center gap-2">
                          {rule.rule_name}
                          {rule.cve_id && (
                            <span className="text-[10px] font-mono px-1.5 py-0.2 rounded bg-indigo-500/10 text-indigo-400 border border-indigo-500/20">
                              {rule.cve_id}
                            </span>
                          )}
                        </div>
                        <div className="text-slate-400 text-[11px] line-clamp-1">
                          {rule.description}
                        </div>
                      </td>
                      <td className="p-3">
                        <span
                          className={`text-[10px] px-2 py-0.5 rounded-full border font-mono font-medium ${getAttackTypeBadge(
                            rule.attack_type
                          )}`}
                        >
                          {rule.attack_type}
                        </span>
                      </td>
                      <td className="p-3">
                        <span className="font-mono text-xs font-bold text-red-400">
                          {rule.action}
                        </span>
                      </td>
                      <td className="p-3">
                        <button
                          onClick={() => handleViewVersions(rule)}
                          className="flex items-center gap-1 font-mono text-[11px] text-indigo-400 hover:underline"
                        >
                          <History className="w-3 h-3" />
                          v{rule.version}
                        </button>
                      </td>
                      <td className="p-3 font-mono text-slate-300">{rule.enforcement_count}</td>
                      <td className="p-3">
                        <span
                          className={`text-[10px] px-2 py-0.5 rounded-full border font-mono ${getStatusBadge(
                            rule.is_active ? rule.status : 'DISABLED'
                          )}`}
                        >
                          {rule.is_active ? rule.status : 'DISABLED'}
                        </span>
                      </td>
                      <td className="p-3 text-right space-x-2">
                        <button
                          onClick={() => handleToggleRule(rule)}
                          className={`px-2 py-1 rounded text-[11px] font-medium transition ${rule.is_active
                            ? 'bg-amber-500/10 text-amber-400 hover:bg-amber-500/20'
                            : 'bg-emerald-500/10 text-emerald-400 hover:bg-emerald-500/20'
                            }`}
                        >
                          {rule.is_active ? 'Disable' : 'Enable'}
                        </button>
                        <button
                          onClick={() => handleDeleteRule(rule.id)}
                          className="p-1 rounded text-slate-400 hover:text-red-400 hover:bg-red-500/10 transition"
                        >
                          <Trash2 className="w-3.5 h-3.5" />
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

      {/* TAB 3: REVERSE PROXY DEPLOYMENTS & HUMAN APPROVAL WORKFLOW */}
      {activeTab === 'deployments' && (
        <div className="space-y-4">
          <div className="p-4 rounded-xl bg-indigo-500/10 border border-indigo-500/20 text-indigo-300 text-xs flex items-center justify-between">
            <div className="flex items-center gap-2">
              <Lock className="w-4 h-4 flex-shrink-0" />
              <span>
                <strong>Human Authorization Invariant:</strong> Staged WAF configurations strictly require OrgAdmin review and digital signature before production deployment.
              </span>
            </div>
            <button
              onClick={() => setIsStageModalOpen(true)}
              className="px-3 py-1.5 text-xs font-semibold rounded-lg bg-indigo-600 text-white hover:bg-indigo-500 transition"
            >
              Stage New Set
            </button>
          </div>

          <div className="rounded-xl bg-slate-900 border border-slate-800 overflow-hidden">
            <table className="w-full text-left text-xs text-slate-300">
              <thead className="bg-slate-950/60 text-slate-400 uppercase text-[10px] tracking-wider border-b border-slate-800">
                <tr>
                  <th className="p-3">Environment</th>
                  <th className="p-3">Rules Count</th>
                  <th className="p-3">Config Hash (SHA-256)</th>
                  <th className="p-3">Gateway Port</th>
                  <th className="p-3">Status</th>
                  <th className="p-3">Sign-Off Status</th>
                  <th className="p-3 text-right">Lifecycle Actions</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-800">
                {deployments.length === 0 ? (
                  <tr>
                    <td colSpan={7} className="p-8 text-center text-slate-500">
                      No reverse proxy deployments recorded. Click "Stage Deployment" to compile active rules.
                    </td>
                  </tr>
                ) : (
                  deployments.map((dep) => (
                    <tr key={dep.id} className="hover:bg-slate-800/40 transition">
                      <td className="p-3 font-mono font-semibold text-slate-200">
                        {dep.environment}
                      </td>
                      <td className="p-3 font-mono">{dep.deployed_rules_count} rules</td>
                      <td className="p-3 font-mono text-[11px] text-slate-400">
                        {dep.config_hash.substring(0, 12)}...
                      </td>
                      <td className="p-3 font-mono text-cyan-400">
                        :{dep.listen_port} &rarr; {dep.upstream_url}
                      </td>
                      <td className="p-3">
                        <span
                          className={`text-[10px] px-2 py-0.5 rounded-full border font-mono ${getStatusBadge(
                            dep.status
                          )}`}
                        >
                          {dep.status}
                        </span>
                      </td>
                      <td className="p-3 text-[11px] text-slate-400">
                        {dep.approved_by_user_email ? (
                          <span className="flex items-center gap-1 text-emerald-400 font-medium">
                            <UserCheck className="w-3.5 h-3.5" />
                            {dep.approved_by_user_email}
                          </span>
                        ) : (
                          <span className="text-amber-400 italic">Pending Admin Review</span>
                        )}
                      </td>
                      <td className="p-3 text-right space-x-2">
                        {dep.status === 'PENDING_APPROVAL' && (
                          <button
                            onClick={() => handleApproveDeployment(dep.id)}
                            disabled={isProcessing}
                            className="px-2.5 py-1 rounded text-xs font-medium bg-emerald-500/10 text-emerald-400 hover:bg-emerald-500/20 transition"
                          >
                            Approve
                          </button>
                        )}
                        {dep.status === 'APPROVED' && (
                          <button
                            onClick={() => handleDeployToProduction(dep.id)}
                            disabled={isProcessing}
                            className="px-2.5 py-1 rounded text-xs font-medium bg-indigo-600 text-white hover:bg-indigo-500 transition shadow-sm"
                          >
                            Deploy to Production
                          </button>
                        )}
                        {dep.status === 'DEPLOYED' && (
                          <button
                            onClick={() => handleRollbackDeployment(dep.id)}
                            disabled={isProcessing}
                            className="px-2.5 py-1 rounded text-xs font-medium bg-red-500/10 text-red-400 hover:bg-red-500/20 transition flex items-center gap-1 inline-flex"
                          >
                            <RotateCcw className="w-3 h-3" />
                            Rollback
                          </button>
                        )}
                      </td>
                    </tr>
                  ))
                )}
              </tbody>
            </table>
          </div>
        </div>
      )}

      {/* TAB 4: REVERSE PROXY WAF LOGS & FALSE POSITIVES */}
      {activeTab === 'logs' && (
        <div className="space-y-4">
          <div className="flex items-center justify-between">
            <div className="flex items-center gap-3">
              <select
                value={logDecisionFilter}
                onChange={(e) => setLogDecisionFilter(e.target.value)}
                className="px-3 py-1.5 text-xs rounded-lg bg-slate-900 border border-slate-700 text-slate-200"
              >
                <option value="ALL">All Decisions</option>
                <option value="BLOCKED">Blocked Only (403)</option>
                <option value="ALLOWED">Allowed Only (200)</option>
              </select>
            </div>
            <div className="text-xs text-slate-400">
              Showing last {filteredLogs.length} gateway evaluation events
            </div>
          </div>

          <div className="rounded-xl bg-slate-900 border border-slate-800 overflow-hidden">
            <table className="w-full text-left text-xs text-slate-300">
              <thead className="bg-slate-950/60 text-slate-400 uppercase text-[10px] tracking-wider border-b border-slate-800">
                <tr>
                  <th className="p-3">Timestamp</th>
                  <th className="p-3">Client IP</th>
                  <th className="p-3">Request URI</th>
                  <th className="p-3">Decision</th>
                  <th className="p-3">Triggered Reason</th>
                  <th className="p-3 text-right">Feedback</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-800">
                {filteredLogs.length === 0 ? (
                  <tr>
                    <td colSpan={6} className="p-8 text-center text-slate-500">
                      No reverse proxy telemetry logs recorded yet. Send HTTP traffic through the proxy to observe live evaluation.
                    </td>
                  </tr>
                ) : (
                  filteredLogs.map((log) => (
                    <tr key={log.id} className="hover:bg-slate-800/40 transition">
                      <td className="p-3 font-mono text-[11px] text-slate-400">
                        {new Date(log.created_at).toLocaleTimeString()}
                      </td>
                      <td className="p-3 font-mono text-slate-300">{log.client_ip}</td>
                      <td className="p-3 font-mono text-slate-200">
                        <span className="font-bold text-indigo-400">{log.http_method}</span>{' '}
                        {log.uri}
                      </td>
                      <td className="p-3">
                        <span
                          className={`text-[10px] px-2 py-0.5 rounded-full border font-mono font-bold ${log.decision === 'BLOCKED'
                            ? 'bg-red-500/10 text-red-400 border-red-500/20'
                            : 'bg-emerald-500/10 text-emerald-400 border-emerald-500/20'
                            }`}
                        >
                          {log.decision} ({log.response_status_code})
                        </span>
                      </td>
                      <td className="p-3 text-slate-400 text-[11px]">{log.block_reason}</td>
                      <td className="p-3 text-right">
                        {log.is_false_positive_reported ? (
                          <span className="text-[11px] text-amber-400 italic">Reported FP</span>
                        ) : (
                          <button
                            onClick={() => {
                              setSelectedLogForFP(log);
                              setIsFalsePositiveModalOpen(true);
                            }}
                            className="px-2 py-1 text-[11px] text-slate-400 hover:text-amber-400 hover:bg-amber-500/10 rounded transition"
                          >
                            Flag False Positive
                          </button>
                        )}
                      </td>
                    </tr>
                  ))
                )}
              </tbody>
            </table>
          </div>
        </div>
      )}

      {/* MODAL 1: RULE VERSIONS AUDIT TRAIL */}
      {selectedRuleForVersions && (
        <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-black/60 backdrop-blur-sm">
          <div className="w-full max-w-2xl bg-slate-900 border border-slate-800 rounded-2xl shadow-2xl p-6 space-y-4">
            <div className="flex items-center justify-between border-b border-slate-800 pb-3">
              <div className="flex items-center gap-2">
                <History className="w-5 h-5 text-indigo-400" />
                <h3 className="text-base font-bold text-slate-100">
                  Version History: {selectedRuleForVersions.rule_name}
                </h3>
              </div>
              <button
                onClick={() => setSelectedRuleForVersions(null)}
                className="text-slate-400 hover:text-slate-200"
              >
                <X className="w-5 h-5" />
              </button>
            </div>

            {isVersionsLoading ? (
              <div className="p-8 text-center text-slate-400">
                <Loader2 className="w-6 h-6 animate-spin mx-auto mb-2" />
                Loading version history...
              </div>
            ) : (
              <div className="space-y-3 max-h-96 overflow-y-auto pr-1">
                {ruleVersions.map((v) => (
                  <div
                    key={v.id}
                    className="p-3.5 rounded-xl bg-slate-950 border border-slate-800 space-y-2 text-xs"
                  >
                    <div className="flex items-center justify-between text-slate-400 font-mono">
                      <span className="font-bold text-indigo-400">Version {v.version_number}</span>
                      <span>{new Date(v.created_at).toLocaleString()}</span>
                    </div>
                    <div className="text-slate-300 font-medium">{v.change_summary}</div>
                    {v.config_snippet && (
                      <pre className="p-2.5 rounded bg-slate-900 text-slate-400 text-[10px] font-mono overflow-x-auto">
                        {v.config_snippet}
                      </pre>
                    )}
                  </div>
                ))}
              </div>
            )}
          </div>
        </div>
      )}

      {/* MODAL 2: STAGE DEPLOYMENT MODAL */}
      {isStageModalOpen && (
        <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-black/60 backdrop-blur-sm">
          <form
            onSubmit={handleStageDeployment}
            className="w-full max-w-md bg-slate-900 border border-slate-800 rounded-2xl shadow-2xl p-6 space-y-4"
          >
            <div className="flex items-center justify-between border-b border-slate-800 pb-3">
              <div className="flex items-center gap-2">
                <Server className="w-5 h-5 text-cyan-400" />
                <h3 className="text-base font-bold text-slate-100">Stage Virtual Patch Set</h3>
              </div>
              <button
                type="button"
                onClick={() => setIsStageModalOpen(false)}
                className="text-slate-400 hover:text-slate-200"
              >
                <X className="w-5 h-5" />
              </button>
            </div>

            <div className="space-y-3 text-xs">
              <div>
                <label className="block text-slate-300 font-medium mb-1">Gateway Listen Port</label>
                <input
                  type="number"
                  value={stagePort}
                  onChange={(e) => setStagePort(parseInt(e.target.value))}
                  className="w-full px-3 py-2 rounded-lg bg-slate-950 border border-slate-800 text-slate-200 font-mono"
                  required
                />
                <span className="text-slate-500 text-[10px]">
                  Port on which the reverse proxy will listen (default: 8085).
                </span>
              </div>

              <div>
                <label className="block text-slate-300 font-medium mb-1">
                  Upstream Application Target
                </label>
                <input
                  type="text"
                  value={stageUpstream}
                  onChange={(e) => setStageUpstream(e.target.value)}
                  className="w-full px-3 py-2 rounded-lg bg-slate-950 border border-slate-800 text-slate-200 font-mono"
                  required
                />
                <span className="text-slate-500 text-[10px]">
                  Protected target backend URL (default: http://127.0.0.1:8086).
                </span>
              </div>
            </div>

            <div className="pt-3 border-t border-slate-800 flex justify-end gap-2">
              <button
                type="button"
                onClick={() => setIsStageModalOpen(false)}
                className="px-3 py-1.5 text-xs text-slate-400 hover:text-slate-200"
              >
                Cancel
              </button>
              <button
                type="submit"
                disabled={isProcessing}
                className="px-4 py-1.5 text-xs font-semibold rounded-lg bg-gradient-to-r from-indigo-600 to-cyan-600 text-white hover:from-indigo-500 hover:to-cyan-500 transition"
              >
                Validate Syntax & Stage
              </button>
            </div>
          </form>
        </div>
      )}

      {/* MODAL 3: CREATE CUSTOM RULE */}
      {isCreateModalOpen && (
        <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-black/60 backdrop-blur-sm">
          <form
            onSubmit={handleCreateRuleSubmit}
            className="w-full max-w-lg bg-slate-900 border border-slate-800 rounded-2xl shadow-2xl p-6 space-y-4"
          >
            <div className="flex items-center justify-between border-b border-slate-800 pb-3">
              <div className="flex items-center gap-2">
                <Plus className="w-5 h-5 text-indigo-400" />
                <h3 className="text-base font-bold text-slate-100">Create Custom Virtual Patch</h3>
              </div>
              <button
                type="button"
                onClick={() => setIsCreateModalOpen(false)}
                className="text-slate-400 hover:text-slate-200"
              >
                <X className="w-5 h-5" />
              </button>
            </div>

            <div className="space-y-3 text-xs">
              <div>
                <label className="block text-slate-300 font-medium mb-1">Rule Name</label>
                <input
                  type="text"
                  value={newRule.rule_name}
                  onChange={(e) => setNewRule({ ...newRule, rule_name: e.target.value })}
                  placeholder="e.g. Virtual Patch: Block SQL Injection in Search"
                  className="w-full px-3 py-2 rounded-lg bg-slate-950 border border-slate-800 text-slate-200"
                  required
                />
              </div>

              <div className="grid grid-cols-2 gap-3">
                <div>
                  <label className="block text-slate-300 font-medium mb-1">Attack Type</label>
                  <select
                    value={newRule.attack_type}
                    onChange={(e) => setNewRule({ ...newRule, attack_type: e.target.value })}
                    className="w-full px-3 py-2 rounded-lg bg-slate-950 border border-slate-800 text-slate-200"
                  >
                    <option value="SQLI">SQL Injection</option>
                    <option value="XSS">Cross-Site Scripting</option>
                    <option value="PATH_TRAVERSAL">Path Traversal</option>
                    <option value="CMDI">Command Injection</option>
                    <option value="PATTERN_BLOCK">Reconnaissance Scanners</option>
                  </select>
                </div>
                <div>
                  <label className="block text-slate-300 font-medium mb-1">Priority</label>
                  <input
                    type="number"
                    value={newRule.priority}
                    onChange={(e) => setNewRule({ ...newRule, priority: parseInt(e.target.value) })}
                    className="w-full px-3 py-2 rounded-lg bg-slate-950 border border-slate-800 text-slate-200 font-mono"
                    required
                  />
                </div>
              </div>

              <div>
                <label className="block text-slate-300 font-medium mb-1">Match Pattern (Regex)</label>
                <input
                  type="text"
                  value={newRule.match_conditions[0]?.pattern || ''}
                  onChange={(e) => {
                    const cond = [...newRule.match_conditions];
                    cond[0] = { ...cond[0], pattern: e.target.value };
                    setNewRule({ ...newRule, match_conditions: cond });
                  }}
                  className="w-full px-3 py-2 rounded-lg bg-slate-950 border border-slate-800 text-slate-200 font-mono"
                  required
                />
              </div>

              <div>
                <label className="block text-slate-300 font-medium mb-1">Rationale / Description</label>
                <textarea
                  value={newRule.description}
                  onChange={(e) => setNewRule({ ...newRule, description: e.target.value })}
                  placeholder="Explain the vulnerability this virtual patch mitigates."
                  className="w-full px-3 py-2 rounded-lg bg-slate-950 border border-slate-800 text-slate-200 h-20"
                  required
                />
              </div>
            </div>

            <div className="pt-3 border-t border-slate-800 flex justify-end gap-2">
              <button
                type="button"
                onClick={() => setIsCreateModalOpen(false)}
                className="px-3 py-1.5 text-xs text-slate-400 hover:text-slate-200"
              >
                Cancel
              </button>
              <button
                type="submit"
                disabled={isProcessing}
                className="px-4 py-1.5 text-xs font-semibold rounded-lg bg-indigo-600 text-white hover:bg-indigo-500 transition"
              >
                Save & Register Rule
              </button>
            </div>
          </form>
        </div>
      )}

      {/* MODAL 4: REPORT FALSE POSITIVE */}
      {isFalsePositiveModalOpen && selectedLogForFP && (
        <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-black/60 backdrop-blur-sm">
          <form
            onSubmit={handleReportFalsePositiveSubmit}
            className="w-full max-w-md bg-slate-900 border border-slate-800 rounded-2xl shadow-2xl p-6 space-y-4"
          >
            <div className="flex items-center justify-between border-b border-slate-800 pb-3">
              <div className="flex items-center gap-2">
                <AlertTriangle className="w-5 h-5 text-amber-400" />
                <h3 className="text-base font-bold text-slate-100">Report False Positive</h3>
              </div>
              <button
                type="button"
                onClick={() => setIsFalsePositiveModalOpen(false)}
                className="text-slate-400 hover:text-slate-200"
              >
                <X className="w-5 h-5" />
              </button>
            </div>

            <div className="space-y-3 text-xs">
              <div className="p-3 rounded-lg bg-slate-950 border border-slate-800 space-y-1 font-mono text-[11px] text-slate-400">
                <div>
                  <strong>URI:</strong> {selectedLogForFP.uri}
                </div>
                <div>
                  <strong>Client:</strong> {selectedLogForFP.client_ip}
                </div>
                <div>
                  <strong>Triggered:</strong> {selectedLogForFP.block_reason}
                </div>
              </div>

              <div>
                <label className="block text-slate-300 font-medium mb-1">
                  Analyst Commentary / Reason for Exemption
                </label>
                <textarea
                  value={fpNotes}
                  onChange={(e) => setFpNotes(e.target.value)}
                  placeholder="Explain why this request is benign and how the regex should be adjusted."
                  className="w-full px-3 py-2 rounded-lg bg-slate-950 border border-slate-800 text-slate-200 h-24"
                  required
                />
              </div>
            </div>

            <div className="pt-3 border-t border-slate-800 flex justify-end gap-2">
              <button
                type="button"
                onClick={() => setIsFalsePositiveModalOpen(false)}
                className="px-3 py-1.5 text-xs text-slate-400 hover:text-slate-200"
              >
                Cancel
              </button>
              <button
                type="submit"
                disabled={isProcessing}
                className="px-4 py-1.5 text-xs font-semibold rounded-lg bg-amber-600 text-white hover:bg-amber-500 transition"
              >
                Submit Feedback
              </button>
            </div>
          </form>
        </div>
      )}
    </div>
  );
};
export default VirtualPatchingPage;
