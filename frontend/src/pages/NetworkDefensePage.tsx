/**
 * PREVENT-X Advanced Network Defense & Detection Layer Dashboard
 * Provides comprehensive UI for Windows Defender Firewall, Dynamic IP Blocking,
 * Rate Limiting, Payload Normalization, Advanced Attack Detection, Traffic Replay,
 * Honeypots, GeoIP Policies, and ML Classification.
 */

import React, { useEffect, useState } from 'react';
import {
  Activity,
  AlertCircle,
  Bot,
  CheckCircle2,
  Cpu,
  FileCode,
  Flame,
  Globe,
  Loader2,
  Lock,
  Play,
  Plus,
  RefreshCw,
  RotateCcw,
  Search,
  Shield,
  ShieldAlert,
  ShieldCheck,
  Terminal,
  Zap,
} from 'lucide-react';
import { useAuth } from '@/contexts/AuthContext';
import { networkDefenseApi } from '@/services/networkDefenseApi';
import { formatErrorMessage } from '@/utils/formatError';
import {
  AttackDetectionResult,
  DynamicIPBlock,
  FirewallRule,
  FirewallStatus,
  GeoIPLookupResult,
  GeoIPPolicy,
  HoneypotProbe,
  HoneypotStats,
  MLClassificationResult,
  MLModelStatus,
  NormalizationResult,
  RateLimitAlgorithm,
  RateLimitEvaluationResult,
  RateLimitPolicy,
  RateLimitScope,
  TrafficReplayReport,
} from '@/types/networkDefense';

export const NetworkDefensePage: React.FC = () => {
  const { hasPermission } = useAuth();

  // RBAC Permission Gates (matching backend role-permission requirements)
  const canExecuteResponse = hasPermission('response_action:execute');
  const canApproveResponse = hasPermission('response_action:approve');
  const canRollback = hasPermission('rollback:execute');
  const canWriteZeroTrust = hasPermission('zero_trust:write');
  const canRunValidation = hasPermission('validation:run');

  const [activeTab, setActiveTab] = useState<
    'firewall' | 'blocking' | 'rate_limiting' | 'normalization' | 'detection' | 'replay' | 'honeypot' | 'geoip' | 'ml'
  >('firewall');

  const [isLoading, setIsLoading] = useState(true);
  const [actionMessage, setActionMessage] = useState<string | null>(null);
  const [actionError, setActionError] = useState<string | null>(null);

  // 1. Firewall State
  const [fwStatus, setFwStatus] = useState<FirewallStatus | null>(null);
  const [fwRules, setFwRules] = useState<FirewallRule[]>([]);
  const [newRuleIp, setNewRuleIp] = useState('');
  const [newRuleName, setNewRuleName] = useState('');
  const [newRulePort, setNewRulePort] = useState('80,443');
  const [newRuleAction, setNewRuleAction] = useState('block');
  const [isFwSubmitting, setIsFwSubmitting] = useState(false);

  // 2. Dynamic Blocking State
  const [blocks, setBlocks] = useState<DynamicIPBlock[]>([]);
  const [newBlockIp, setNewBlockIp] = useState('');
  const [newBlockReason, setNewBlockReason] = useState('');
  const [newBlockDuration, setNewBlockDuration] = useState(60);
  const [newBlockRequireApproval, setNewBlockRequireApproval] = useState(false);

  // 3. Rate Limiting State
  const [ratePolicies, setRatePolicies] = useState<RateLimitPolicy[]>([]);
  const [testRateIp, setTestRateIp] = useState('192.168.1.100');
  const [testRatePath, setTestRatePath] = useState('/api/v1/auth/login');
  const [testRateResult, setTestRateResult] = useState<RateLimitEvaluationResult | any>(null);
  const [newPolicyName, setNewPolicyName] = useState('');
  const [newPolicyPattern, setNewPolicyPattern] = useState('');
  const [newPolicyScope, setNewPolicyScope] = useState<RateLimitScope>('IP');
  const [newPolicyAlgorithm, setNewPolicyAlgorithm] = useState<RateLimitAlgorithm>('SLIDING_WINDOW');
  const [newPolicyMaxRequests, setNewPolicyMaxRequests] = useState(60);
  const [newPolicyWindowSeconds, setNewPolicyWindowSeconds] = useState(60);
  const [newPolicyBurst, setNewPolicyBurst] = useState(10);
  const [isPolicySubmitting, setIsPolicySubmitting] = useState(false);

  // 4. Normalization State
  const [rawPayloadInput, setRawPayloadInput] = useState('%252e%252e%252f&lt;script&gt;\\u0027 OR 1=1');
  const [normResult, setNormResult] = useState<NormalizationResult | null>(null);

  // 5. Detection State
  const [detectPath, setDetectPath] = useState('/api/v1/search');
  const [detectBody, setDetectBody] = useState('{"query": "admin\' OR 1=1 --"}');
  const [detectResult, setDetectResult] = useState<AttackDetectionResult | null>(null);

  // 6. Traffic Replay State
  const [replayReports, setReplayReports] = useState<TrafficReplayReport[]>([]);
  const [isReplaying, setIsReplaying] = useState(false);

  // 7. Honeypot State
  const [honeypotStats, setHoneypotStats] = useState<HoneypotStats | null>(null);
  const [honeypotProbes, setHoneypotProbes] = useState<HoneypotProbe[]>([]);
  const [honeypotTraps, setHoneypotTraps] = useState<string[]>([]);
  const [newTrapPath, setNewTrapPath] = useState('');

  // 8. GeoIP State
  const [geoPolicies, setGeoPolicies] = useState<GeoIPPolicy[]>([]);
  const [lookupIpInput, setLookupIpInput] = useState('103.21.244.1');
  const [lookupResult, setLookupResult] = useState<GeoIPLookupResult | null>(null);
  const [newGeoCountryCode, setNewGeoCountryCode] = useState('');
  const [newGeoCountryName, setNewGeoCountryName] = useState('');
  const [newGeoAction, setNewGeoAction] = useState<'ALLOW' | 'DENY'>('DENY');
  const [newGeoExceptions, setNewGeoExceptions] = useState('');
  const [newGeoRiskModifier, setNewGeoRiskModifier] = useState(30);
  const [isGeoSubmitting, setIsGeoSubmitting] = useState(false);

  // 9. ML Classification State
  const [mlStatus, setMlStatus] = useState<MLModelStatus | null>(null);
  const [mlTestBody, setMlTestBody] = useState('{"comment": "Excellent service and fast support!"}');
  const [mlResult, setMlResult] = useState<MLClassificationResult | null>(null);

  const loadAllData = async () => {
    setIsLoading(true);
    setActionError(null);
    try {
      const [status, rules, blockList, policies, reports, hpStats, hpProbes, hpTraps, geoList, mlStat] =
        await Promise.all([
          networkDefenseApi.getFirewallStatus().catch(() => null),
          networkDefenseApi.getFirewallRules().catch(() => []),
          networkDefenseApi.getDynamicBlocks().catch(() => []),
          networkDefenseApi.getRateLimitPolicies().catch(() => []),
          networkDefenseApi.getReplayReports().catch(() => []),
          networkDefenseApi.getHoneypotStats().catch(() => null),
          networkDefenseApi.getHoneypotProbes(20).catch(() => []),
          networkDefenseApi.getHoneypotTraps().catch(() => []),
          networkDefenseApi.getGeoIPPolicies().catch(() => []),
          networkDefenseApi.getMLStatus().catch(() => null),
        ]);

      setFwStatus(status);
      setFwRules(rules);
      setBlocks(blockList);
      setRatePolicies(policies);
      setReplayReports(reports);
      setHoneypotStats(hpStats);
      setHoneypotProbes(hpProbes);
      setHoneypotTraps(hpTraps);
      setGeoPolicies(geoList);
      setMlStatus(mlStat);
    } catch (err: any) {
      setActionError(err.message || 'Failed to load network defense telemetry');
    } finally {
      setIsLoading(false);
    }
  };

  useEffect(() => {
    loadAllData();
  }, []);

  const handleCreateFirewallRule = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!newRuleIp || !newRuleName) return;
    setIsFwSubmitting(true);
    try {
      await networkDefenseApi.createFirewallRule({
        remote_ip_or_cidr: newRuleIp,
        display_name: newRuleName,
        local_ports: newRulePort,
        action: newRuleAction,
        direction: 'in',
      });
      setActionMessage(`Firewall rule created for ${newRuleIp}.`);
      setNewRuleIp('');
      setNewRuleName('');
      const updatedRules = await networkDefenseApi.getFirewallRules();
      setFwRules(updatedRules);
    } catch (err: any) {
      setActionError(err.response?.data?.detail || err.message);
    } finally {
      setIsFwSubmitting(false);
    }
  };

  const handleRollbackRule = async (ruleId: string) => {
    try {
      await networkDefenseApi.rollbackFirewallRule(ruleId);
      setActionMessage('Firewall rule successfully rolled back.');
      const updatedRules = await networkDefenseApi.getFirewallRules();
      setFwRules(updatedRules);
    } catch (err: any) {
      setActionError(err.response?.data?.detail || err.message);
    }
  };

  const handleCreateBlock = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!newBlockIp || !newBlockReason) return;
    try {
      await networkDefenseApi.createDynamicBlock({
        ip_or_cidr: newBlockIp,
        reason: newBlockReason,
        duration_minutes: Number(newBlockDuration),
        require_approval: newBlockRequireApproval,
      });
      setActionMessage(`Dynamic block created for ${newBlockIp}.`);
      setNewBlockIp('');
      setNewBlockReason('');
      const updatedBlocks = await networkDefenseApi.getDynamicBlocks();
      setBlocks(updatedBlocks);
    } catch (err: any) {
      setActionError(err.response?.data?.detail || err.message);
    }
  };

  const handleApproveBlock = async (blockId: string) => {
    try {
      await networkDefenseApi.approveDynamicBlock(blockId, 'Approved from Dashboard');
      setActionMessage('Dynamic block approved and synchronized with OS Firewall.');
      const updatedBlocks = await networkDefenseApi.getDynamicBlocks();
      setBlocks(updatedBlocks);
    } catch (err: any) {
      setActionError(err.response?.data?.detail || err.message);
    }
  };

  const handleUnblock = async (blockId: string) => {
    try {
      await networkDefenseApi.unblockDynamicIP(blockId, 'Manual unblock from Dashboard');
      setActionMessage('IP unblocked and removed from OS Firewall.');
      const updatedBlocks = await networkDefenseApi.getDynamicBlocks();
      setBlocks(updatedBlocks);
    } catch (err: any) {
      setActionError(err.response?.data?.detail || err.message);
    }
  };

  const handleCreateRateLimitPolicy = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!newPolicyName || !newPolicyPattern) return;
    setIsPolicySubmitting(true);
    try {
      await networkDefenseApi.createRateLimitPolicy({
        name: newPolicyName.trim(),
        endpoint_pattern: newPolicyPattern.trim(),
        scope: newPolicyScope,
        algorithm: newPolicyAlgorithm,
        max_requests: Number(newPolicyMaxRequests),
        window_seconds: Number(newPolicyWindowSeconds),
        burst_capacity: Number(newPolicyBurst),
        refill_rate_per_sec: 1.0,
      });
      setActionMessage(`Rate limit policy '${newPolicyName}' created.`);
      setNewPolicyName('');
      setNewPolicyPattern('');
      const updated = await networkDefenseApi.getRateLimitPolicies();
      setRatePolicies(updated);
    } catch (err: any) {
      setActionError(err.response?.data?.detail || err.message);
    } finally {
      setIsPolicySubmitting(false);
    }
  };

  const handleDeleteRateLimitPolicy = async (policyId: string, policyName: string) => {
    try {
      await networkDefenseApi.deleteRateLimitPolicy(policyId);
      setActionMessage(`Rate limit policy '${policyName}' deleted.`);
      const updated = await networkDefenseApi.getRateLimitPolicies();
      setRatePolicies(updated);
    } catch (err: any) {
      setActionError(err.response?.data?.detail || err.message);
    }
  };

  const handleCreateGeoIPPolicy = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!newGeoCountryCode || !newGeoCountryName) return;
    setIsGeoSubmitting(true);
    try {
      await networkDefenseApi.createGeoIPPolicy({
        country_code: newGeoCountryCode.trim().toUpperCase(),
        country_name: newGeoCountryName.trim(),
        action: newGeoAction,
        exception_cidrs: newGeoExceptions.trim() || undefined,
        risk_score_modifier: Number(newGeoRiskModifier),
      });
      setActionMessage(`GeoIP policy for ${newGeoCountryName} (${newGeoCountryCode.toUpperCase()}) created.`);
      setNewGeoCountryCode('');
      setNewGeoCountryName('');
      setNewGeoExceptions('');
      const updated = await networkDefenseApi.getGeoIPPolicies();
      setGeoPolicies(updated);
    } catch (err: any) {
      setActionError(err.response?.data?.detail || err.message);
    } finally {
      setIsGeoSubmitting(false);
    }
  };

  const handleDeleteGeoIPPolicy = async (policyId: string, countryName: string) => {
    try {
      await networkDefenseApi.deleteGeoIPPolicy(policyId);
      setActionMessage(`GeoIP policy for '${countryName}' deleted.`);
      const updated = await networkDefenseApi.getGeoIPPolicies();
      setGeoPolicies(updated);
    } catch (err: any) {
      setActionError(err.response?.data?.detail || err.message);
    }
  };

  const handleRunNormalization = async () => {
    try {
      const res = await networkDefenseApi.normalizePayload(rawPayloadInput);
      setNormResult(res);
    } catch (err: any) {
      setActionError(err.message);
    }
  };

  const handleRunDetection = async () => {
    try {
      const res = await networkDefenseApi.detectAttack({
        method: 'POST',
        path: detectPath,
        body: detectBody,
      });
      setDetectResult(res);
    } catch (err: any) {
      setActionError(err.message);
    }
  };

  const handleRunReplay = async () => {
    setIsReplaying(true);
    try {
      const report = await networkDefenseApi.runTrafficReplay({});
      setActionMessage(`Replay validation completed: ${report.total_replayed} fixtures replayed. FP Rate: ${(report.fp_rate * 100).toFixed(1)}%`);
      const updatedReports = await networkDefenseApi.getReplayReports();
      setReplayReports(updatedReports);
    } catch (err: any) {
      setActionError(err.response?.data?.detail || err.message);
    } finally {
      setIsReplaying(false);
    }
  };

  const handleAddTrap = async () => {
    if (!newTrapPath) return;
    try {
      await networkDefenseApi.addHoneypotTrap(newTrapPath);
      setActionMessage(`Custom decoy trap '${newTrapPath}' added.`);
      setNewTrapPath('');
      const traps = await networkDefenseApi.getHoneypotTraps();
      setHoneypotTraps(traps);
    } catch (err: any) {
      setActionError(err.message);
    }
  };

  const handleEvaluateGeoIP = async () => {
    try {
      const res = await networkDefenseApi.evaluateGeoIP(lookupIpInput);
      setLookupResult(res);
    } catch (err: any) {
      setActionError(err.message);
    }
  };

  const handleClassifyML = async () => {
    try {
      const res = await networkDefenseApi.classifyTraffic({
        method: 'POST',
        path: '/api/v1/inspect',
        body: mlTestBody,
      });
      setMlResult(res);
    } catch (err: any) {
      setActionError(err.message);
    }
  };

  return (
    <div className="space-y-6 max-w-7xl mx-auto pb-12">
      {/* Top Banner Header */}
      <div className="flex flex-col md:flex-row md:items-center justify-between gap-4 border-b border-navy-800 pb-5">
        <div>
          <div className="flex items-center gap-3">
            <div className="p-2.5 rounded-xl bg-gradient-to-br from-cyan-500/20 to-blue-600/20 border border-cyan-500/30 text-cyan-400">
              <ShieldAlert className="w-6 h-6" />
            </div>
            <div>
              <h1 className="text-2xl font-bold text-white tracking-tight">
                Advanced Network Defense & Detection Layer
              </h1>
              <p className="text-xs text-slate-400 font-mono">
                Genuine OS Firewall Integration • Dynamic IP Blocking • Rate Limiting • ML Telemetry
              </p>
            </div>
          </div>
        </div>

        <div className="flex items-center gap-3">
          <button
            onClick={loadAllData}
            disabled={isLoading}
            className="flex items-center gap-2 px-3 py-1.5 rounded-lg bg-navy-850 hover:bg-navy-800 border border-navy-700 text-xs font-mono text-slate-300 transition-colors"
          >
            <RefreshCw className={`w-3.5 h-3.5 ${isLoading ? 'animate-spin text-cyan-400' : ''}`} />
            Refresh Telemetry
          </button>
        </div>
      </div>

      {/* Notifications */}
      {actionMessage && (
        <div className="p-3 rounded-lg bg-emerald-500/10 border border-emerald-500/30 text-emerald-400 text-xs flex items-center justify-between">
          <div className="flex items-center gap-2">
            <CheckCircle2 className="w-4 h-4 flex-shrink-0" />
            <span>{actionMessage}</span>
          </div>
          <button onClick={() => setActionMessage(null)} className="text-slate-400 hover:text-white">✕</button>
        </div>
      )}
      {actionError && (
        <div className="p-3 rounded-lg bg-rose-500/10 border border-rose-500/30 text-rose-400 text-xs flex items-center justify-between">
          <div className="flex items-center gap-2">
            <AlertCircle className="w-4 h-4 flex-shrink-0" />
            <span>{typeof actionError === 'string' ? actionError : formatErrorMessage(actionError)}</span>
          </div>
          <button onClick={() => setActionError(null)} className="text-slate-400 hover:text-white">✕</button>
        </div>
      )}

      {/* Global Defense Telemetry Metrics Bar */}
      <div className="grid grid-cols-2 md:grid-cols-4 lg:grid-cols-6 gap-3">
        <div className="p-3.5 rounded-xl bg-navy-900 border border-navy-800">
          <div className="text-[11px] font-mono text-slate-400 uppercase">OS Firewall</div>
          <div className="text-lg font-bold text-white mt-1 flex items-center gap-2">
            <span>{fwStatus?.os_type || 'Windows'}</span>
            <span className={`w-2 h-2 rounded-full ${fwStatus?.is_elevated ? 'bg-emerald-400' : 'bg-amber-400 animate-pulse'}`} />
          </div>
          <div className="text-[10px] text-slate-500 font-mono mt-0.5">
            {fwStatus?.is_elevated ? 'Elevated Administrator' : 'Restricted Privilege Mode'}
          </div>
        </div>

        <div className="p-3.5 rounded-xl bg-navy-900 border border-navy-800">
          <div className="text-[11px] font-mono text-slate-400 uppercase">Active Bans</div>
          <div className="text-lg font-bold text-cyan-400 mt-1">
            {blocks.filter((b) => b.status === 'ACTIVE').length}
          </div>
          <div className="text-[10px] text-slate-500 font-mono mt-0.5">
            {blocks.filter((b) => b.status === 'PENDING_APPROVAL').length} Pending Approval
          </div>
        </div>

        <div className="p-3.5 rounded-xl bg-navy-900 border border-navy-800">
          <div className="text-[11px] font-mono text-slate-400 uppercase">Rate Policies</div>
          <div className="text-lg font-bold text-indigo-400 mt-1">
            {ratePolicies.length} Active
          </div>
          <div className="text-[10px] text-slate-500 font-mono mt-0.5">Sliding Window / Token Bucket</div>
        </div>

        <div className="p-3.5 rounded-xl bg-navy-900 border border-navy-800">
          <div className="text-[11px] font-mono text-slate-400 uppercase">Honeypot Traps</div>
          <div className="text-lg font-bold text-amber-400 mt-1">
            {honeypotStats?.active_decoy_count || honeypotTraps.length}
          </div>
          <div className="text-[10px] text-slate-500 font-mono mt-0.5">
            {honeypotStats?.total_probes || 0} Probes Captured
          </div>
        </div>

        <div className="p-3.5 rounded-xl bg-navy-900 border border-navy-800">
          <div className="text-[11px] font-mono text-slate-400 uppercase">GeoIP Policies</div>
          <div className="text-lg font-bold text-rose-400 mt-1">
            {geoPolicies.length} Rules
          </div>
          <div className="text-[10px] text-slate-500 font-mono mt-0.5">Offline Geolocation</div>
        </div>

        <div className="p-3.5 rounded-xl bg-navy-900 border border-navy-800">
          <div className="text-[11px] font-mono text-slate-400 uppercase">ML Model</div>
          <div className="text-lg font-bold text-emerald-400 mt-1">
            {mlStatus?.f1_score ? `${(mlStatus.f1_score * 100).toFixed(0)}% F1` : 'Active'}
          </div>
          <div className="text-[10px] text-slate-500 font-mono mt-0.5">
            {mlStatus?.model_version || 'Random Forest'}
          </div>
        </div>
      </div>

      {/* Main Tab Navigation */}
      <div className="border-b border-navy-800 flex overflow-x-auto gap-2">
        {[
          { id: 'firewall', label: 'Firewall Management', icon: Shield },
          { id: 'blocking', label: 'Dynamic IP Blocking', icon: Lock },
          { id: 'rate_limiting', label: 'Rate Limiting', icon: Activity },
          { id: 'normalization', label: 'Payload Normalization', icon: FileCode },
          { id: 'detection', label: 'Attack Detection', icon: Terminal },
          { id: 'replay', label: 'Traffic Replay', icon: RotateCcw },
          { id: 'honeypot', label: 'Honeypot Decoys', icon: Flame },
          { id: 'geoip', label: 'GeoIP Policies', icon: Globe },
          { id: 'ml', label: 'ML Classification', icon: Cpu },
        ].map((tab) => {
          const Icon = tab.icon;
          const isActive = activeTab === tab.id;
          return (
            <button
              key={tab.id}
              onClick={() => setActiveTab(tab.id as any)}
              className={`flex items-center gap-2 px-4 py-2.5 text-xs font-medium border-b-2 whitespace-nowrap transition-colors ${isActive
                ? 'border-cyan-500 text-cyan-400 bg-cyan-500/5'
                : 'border-transparent text-slate-400 hover:text-slate-200 hover:border-slate-700'
                }`}
            >
              <Icon className="w-4 h-4" />
              <span>{tab.label}</span>
            </button>
          );
        })}
      </div>

      {/* Tab 1: Firewall Management */}
      {activeTab === 'firewall' && (
        <div className="space-y-5">
          <div className="grid grid-cols-1 lg:grid-cols-3 gap-5">
            <div className="lg:col-span-2 space-y-4">
              <div className="p-5 rounded-xl bg-navy-900 border border-navy-800">
                <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 mb-4">
                  <div>
                    <h3 className="text-sm font-semibold text-white">Host Firewall Rules & Policies</h3>
                    <p className="text-xs text-slate-400 font-mono mt-0.5">
                      Windows Defender Firewall packet filtering with kernel-verified enforcement
                    </p>
                  </div>
                  <div className="flex items-center gap-2">
                    <span className="text-xs font-mono text-emerald-400 px-2 py-0.5 rounded bg-emerald-500/10 border border-emerald-500/20">
                      {fwRules.filter((r) => r.verified_active && r.enforcement_status === 'VERIFIED').length} OS Enforced
                    </span>
                    {fwRules.some((r) => r.enforcement_status === 'FAILED') && (
                      <span className="text-xs font-mono text-amber-400 px-2 py-0.5 rounded bg-amber-500/10 border border-amber-500/20">
                        {fwRules.filter((r) => r.enforcement_status === 'FAILED').length} Failed
                      </span>
                    )}
                    <span className="text-xs font-mono text-cyan-400 px-2 py-0.5 rounded bg-cyan-500/10 border border-cyan-500/20">
                      {fwRules.length} Registered Rules
                    </span>
                  </div>
                </div>

                <div className="overflow-x-auto">
                  <table className="w-full text-left text-xs font-mono">
                    <thead className="bg-navy-950 text-slate-400 uppercase tracking-wider text-[10px]">
                      <tr>
                        <th className="p-3">Rule Name</th>
                        <th className="p-3">Remote IP / CIDR</th>
                        <th className="p-3">Target Policy</th>
                        <th className="p-3">OS Enforcement State</th>
                        <th className="p-3 text-right">Actions</th>
                      </tr>
                    </thead>
                    <tbody className="divide-y divide-navy-800 text-slate-300">
                      {fwRules.length === 0 ? (
                        <tr>
                          <td colSpan={5} className="p-6 text-center text-slate-500 font-sans text-xs">
                            No firewall rules created yet. Use the form to configure a rule.
                          </td>
                        </tr>
                      ) : (
                        fwRules.map((r) => {
                          const isOsEnforced = r.verified_active && r.enforcement_status === 'VERIFIED';
                          const isFailed = r.enforcement_status === 'FAILED';
                          const isRolledBack = r.enforcement_status === 'ROLLED_BACK' || r.enforcement_status === 'REMOVED';

                          return (
                            <tr key={r.id} className="hover:bg-navy-850/50 transition-colors">
                              <td className="p-3">
                                <div className="font-semibold text-white">{r.display_name}</div>
                                <div className="text-[10px] text-slate-500 font-mono">{r.name}</div>
                              </td>
                              <td className="p-3 text-cyan-400">{r.remote_ip_or_cidr}</td>
                              <td className="p-3">
                                {isOsEnforced ? (
                                  <span
                                    className={`px-2 py-0.5 rounded text-[10px] font-semibold ${r.action.toLowerCase() === 'block'
                                      ? 'bg-rose-500/10 text-rose-400 border border-rose-500/20'
                                      : 'bg-emerald-500/10 text-emerald-400 border border-emerald-500/20'
                                      }`}
                                  >
                                    {r.action.toUpperCase()} ({r.direction})
                                  </span>
                                ) : (
                                  <span
                                    className="px-2 py-0.5 rounded text-[10px] bg-slate-800 text-slate-400 border border-slate-700"
                                    title="Policy defined in database; not actively dropping packets in OS"
                                  >
                                    {r.action.toUpperCase()} ({r.direction}) - NOT ENFORCED
                                  </span>
                                )}
                              </td>
                              <td className="p-3">
                                {isOsEnforced ? (
                                  <span className="inline-flex items-center gap-1.5 px-2 py-0.5 rounded text-[10px] bg-emerald-500/10 text-emerald-400 border border-emerald-500/20 font-semibold">
                                    <span className="w-1.5 h-1.5 rounded-full bg-emerald-400" />
                                    <span>VERIFIED</span>
                                    <span className="text-[9px] text-emerald-300 font-normal">(OS Enforced)</span>
                                  </span>
                                ) : isFailed ? (
                                  <div className="space-y-0.5">
                                    <span className="inline-flex items-center gap-1.5 px-2 py-0.5 rounded text-[10px] bg-amber-500/10 text-amber-400 border border-amber-500/20 font-semibold">
                                      <span className="w-1.5 h-1.5 rounded-full bg-amber-400 animate-pulse" />
                                      <span>FAILED</span>
                                      <span className="text-[9px] text-amber-300 font-normal">(Un-enforced)</span>
                                    </span>
                                    {r.error_message && (
                                      <div className="text-[10px] text-amber-500/80 font-mono truncate max-w-xs" title={r.error_message}>
                                        {r.error_message}
                                      </div>
                                    )}
                                  </div>
                                ) : isRolledBack ? (
                                  <span className="px-2 py-0.5 rounded text-[10px] bg-slate-800 text-slate-400 border border-slate-700">
                                    ROLLED_BACK
                                  </span>
                                ) : (
                                  <span className="px-2 py-0.5 rounded text-[10px] bg-cyan-500/10 text-cyan-400 border border-cyan-500/20">
                                    {r.enforcement_status}
                                  </span>
                                )}
                              </td>
                              <td className="p-3 text-right">
                                {r.is_active && !isRolledBack && canRollback && (
                                  <button
                                    onClick={() => handleRollbackRule(r.id)}
                                    className={`px-2 py-1 rounded text-[11px] transition-colors border ${isFailed
                                      ? 'bg-amber-500/10 hover:bg-amber-500/20 text-amber-400 border-amber-500/30'
                                      : 'bg-rose-500/10 hover:bg-rose-500/20 text-rose-400 border-rose-500/30'
                                      }`}
                                    title={isFailed ? 'Clear un-enforced database record' : 'Rollback rule from Windows Defender Firewall'}
                                  >
                                    {isFailed ? 'Dismiss / Cleanup' : 'Rollback'}
                                  </button>
                                )}
                                {isRolledBack && (
                                  <span className="text-[11px] text-slate-500 font-mono">Rolled Back</span>
                                )}
                              </td>
                            </tr>
                          );
                        })
                      )}
                    </tbody>
                  </table>
                </div>
              </div>
            </div>

            {/* Create Rule Card */}
            <div>
              <div className="p-5 rounded-xl bg-navy-900 border border-navy-800">
                <h3 className="text-sm font-semibold text-white mb-1">Create OS Firewall Rule</h3>
                <p className="text-xs text-slate-400 mb-4 font-mono">
                  Enforce strict host-level filtering on Windows Defender Firewall.
                </p>

                <form onSubmit={handleCreateFirewallRule} className="space-y-3 text-xs">
                  <div>
                    <label className="block text-slate-300 mb-1 font-mono text-[11px]">Remote IP or CIDR</label>
                    <input
                      type="text"
                      placeholder="e.g. 198.51.100.99 or 10.0.0.0/24"
                      value={newRuleIp}
                      onChange={(e) => setNewRuleIp(e.target.value)}
                      className="w-full p-2.5 rounded-lg bg-navy-950 border border-navy-700 text-white font-mono focus:border-cyan-500 outline-none"
                      required
                    />
                  </div>

                  <div>
                    <label className="block text-slate-300 mb-1 font-mono text-[11px]">Display Rule Name</label>
                    <input
                      type="text"
                      placeholder="e.g. Block Recon Attacker"
                      value={newRuleName}
                      onChange={(e) => setNewRuleName(e.target.value)}
                      className="w-full p-2.5 rounded-lg bg-navy-950 border border-navy-700 text-white font-mono focus:border-cyan-500 outline-none"
                      required
                    />
                  </div>

                  <div className="grid grid-cols-2 gap-3">
                    <div>
                      <label className="block text-slate-300 mb-1 font-mono text-[11px]">Local Ports</label>
                      <input
                        type="text"
                        value={newRulePort}
                        onChange={(e) => setNewRulePort(e.target.value)}
                        className="w-full p-2.5 rounded-lg bg-navy-950 border border-navy-700 text-white font-mono focus:border-cyan-500 outline-none"
                      />
                    </div>
                    <div>
                      <label className="block text-slate-300 mb-1 font-mono text-[11px]">Action</label>
                      <select
                        value={newRuleAction}
                        onChange={(e) => setNewRuleAction(e.target.value)}
                        className="w-full p-2.5 rounded-lg bg-navy-950 border border-navy-700 text-white font-mono focus:border-cyan-500 outline-none"
                      >
                        <option value="block">BLOCK</option>
                        <option value="allow">ALLOW</option>
                      </select>
                    </div>
                  </div>

                  <button
                    type="submit"
                    disabled={isFwSubmitting || !canExecuteResponse}
                    className={`w-full mt-2 py-2.5 rounded-lg text-white font-semibold transition-colors flex items-center justify-center gap-2 ${!canExecuteResponse ? 'bg-slate-700 cursor-not-allowed opacity-60' : 'bg-cyan-600 hover:bg-cyan-500'
                      }`}
                  >
                    {isFwSubmitting ? <Loader2 className="w-4 h-4 animate-spin" /> : <ShieldCheck className="w-4 h-4" />}
                    Enforce Rule on OS
                  </button>
                  {!canExecuteResponse && (
                    <div className="text-[10px] text-amber-400/90 font-mono mt-1 text-center">
                      Requires 'response_action:execute' permission to enforce rules.
                    </div>
                  )}
                </form>
              </div>
            </div>
          </div>
        </div>
      )}

      {/* Tab 2: Dynamic IP Blocking */}
      {activeTab === 'blocking' && (
        <div className="space-y-5">
          <div className="grid grid-cols-1 lg:grid-cols-3 gap-5">
            <div className="lg:col-span-2 space-y-4">
              <div className="p-5 rounded-xl bg-navy-900 border border-navy-800">
                <div className="flex items-center justify-between mb-4">
                  <div>
                    <h3 className="text-sm font-semibold text-white">Dynamic IP Containment Bans</h3>
                    <p className="text-xs text-slate-400 font-mono mt-0.5">
                      Temporary containment bans with automatic unblocking and approval workflows
                    </p>
                  </div>
                  <span className="text-xs font-mono text-cyan-400 px-2 py-0.5 rounded bg-cyan-500/10 border border-cyan-500/20">
                    {blocks.length} Total Blocks
                  </span>
                </div>

                <div className="overflow-x-auto">
                  <table className="w-full text-left text-xs font-mono">
                    <thead className="bg-navy-950 text-slate-400 uppercase tracking-wider text-[10px]">
                      <tr>
                        <th className="p-3">Target IP</th>
                        <th className="p-3">Reason</th>
                        <th className="p-3">Status</th>
                        <th className="p-3">Expires</th>
                        <th className="p-3 text-right">Actions</th>
                      </tr>
                    </thead>
                    <tbody className="divide-y divide-navy-800 text-slate-300">
                      {blocks.length === 0 ? (
                        <tr>
                          <td colSpan={5} className="p-6 text-center text-slate-500 font-sans text-xs">
                            No dynamic blocks recorded.
                          </td>
                        </tr>
                      ) : (
                        blocks.map((b) => (
                          <tr key={b.id} className="hover:bg-navy-850/50 transition-colors">
                            <td className="p-3 font-semibold text-cyan-400">{b.ip_or_cidr}</td>
                            <td className="p-3 text-slate-300 max-w-xs truncate">{b.reason}</td>
                            <td className="p-3">
                              <span
                                className={`px-2 py-0.5 rounded text-[10px] ${b.status === 'ACTIVE'
                                  ? 'bg-emerald-500/10 text-emerald-400 border border-emerald-500/20'
                                  : b.status === 'PENDING_APPROVAL'
                                    ? 'bg-amber-500/10 text-amber-400 border border-amber-500/20'
                                    : 'bg-slate-700 text-slate-400'
                                  }`}
                              >
                                {b.status}
                              </span>
                            </td>
                            <td className="p-3 text-slate-400 text-[11px]">
                              {new Date(b.expires_at).toLocaleTimeString()}
                            </td>
                            <td className="p-3 text-right space-x-2">
                              {b.status === 'PENDING_APPROVAL' && canApproveResponse && (
                                <button
                                  onClick={() => handleApproveBlock(b.id)}
                                  className="px-2 py-1 rounded bg-cyan-600 hover:bg-cyan-500 text-white text-[11px]"
                                >
                                  Approve
                                </button>
                              )}
                              {b.status === 'ACTIVE' && canExecuteResponse && (
                                <button
                                  onClick={() => handleUnblock(b.id)}
                                  className="px-2 py-1 rounded bg-rose-500/10 hover:bg-rose-500/20 text-rose-400 border border-rose-500/30 text-[11px]"
                                >
                                  Unblock
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
            </div>

            <div>
              <div className="p-5 rounded-xl bg-navy-900 border border-navy-800">
                <h3 className="text-sm font-semibold text-white mb-1">Issue Dynamic IP Block</h3>
                <p className="text-xs text-slate-400 mb-4 font-mono">
                  Enact containment ban with automatic expiry.
                </p>

                <form onSubmit={handleCreateBlock} className="space-y-3 text-xs">
                  <div>
                    <label className="block text-slate-300 mb-1 font-mono text-[11px]">Target IP Address</label>
                    <input
                      type="text"
                      placeholder="e.g. 203.0.113.88"
                      value={newBlockIp}
                      onChange={(e) => setNewBlockIp(e.target.value)}
                      className="w-full p-2.5 rounded-lg bg-navy-950 border border-navy-700 text-white font-mono focus:border-cyan-500 outline-none"
                      required
                    />
                  </div>

                  <div>
                    <label className="block text-slate-300 mb-1 font-mono text-[11px]">Reason / Justification</label>
                    <input
                      type="text"
                      placeholder="e.g. Suspicious credential stuffing"
                      value={newBlockReason}
                      onChange={(e) => setNewBlockReason(e.target.value)}
                      className="w-full p-2.5 rounded-lg bg-navy-950 border border-navy-700 text-white font-mono focus:border-cyan-500 outline-none"
                      required
                    />
                  </div>

                  <div>
                    <label className="block text-slate-300 mb-1 font-mono text-[11px]">Duration (Minutes)</label>
                    <input
                      type="number"
                      min={1}
                      max={1440}
                      value={newBlockDuration}
                      onChange={(e) => setNewBlockDuration(Number(e.target.value))}
                      className="w-full p-2.5 rounded-lg bg-navy-950 border border-navy-700 text-white font-mono focus:border-cyan-500 outline-none"
                    />
                  </div>

                  <div className="flex items-center gap-2 pt-1">
                    <input
                      type="checkbox"
                      id="approval_chk"
                      checked={newBlockRequireApproval}
                      onChange={(e) => setNewBlockRequireApproval(e.target.checked)}
                      className="rounded bg-navy-950 border-navy-700 text-cyan-500 focus:ring-0"
                    />
                    <label htmlFor="approval_chk" className="text-slate-300 text-[11px]">
                      Require Admin Approval
                    </label>
                  </div>

                  <button
                    type="submit"
                    disabled={!canExecuteResponse}
                    className={`w-full mt-2 py-2.5 rounded-lg text-white font-semibold transition-colors flex items-center justify-center gap-2 ${!canExecuteResponse ? 'bg-slate-700 cursor-not-allowed opacity-60' : 'bg-rose-600 hover:bg-rose-500'
                      }`}
                  >
                    <Lock className="w-4 h-4" />
                    Place Dynamic Ban
                  </button>
                  {!canExecuteResponse && (
                    <div className="text-[10px] text-amber-400/90 font-mono mt-1 text-center">
                      Requires 'response_action:execute' permission to issue bans.
                    </div>
                  )}
                </form>
              </div>
            </div>
          </div>
        </div>
      )}

      {/* Tab 3: Rate Limiting */}
      {activeTab === 'rate_limiting' && (
        <div className="space-y-5">
          <div className="grid grid-cols-1 lg:grid-cols-3 gap-5">
            <div className="lg:col-span-2 space-y-4">
              <div className="p-5 rounded-xl bg-navy-900 border border-navy-800">
                <h3 className="text-sm font-semibold text-white mb-1">Active Rate Limit Policies</h3>
                <p className="text-xs text-slate-400 font-mono mb-4">
                  Multi-dimensional quotas backed by distributed Redis sorted-sets and token-buckets
                </p>

                <div className="overflow-x-auto">
                  <table className="w-full text-left text-xs font-mono">
                    <thead className="bg-navy-950 text-slate-400 uppercase tracking-wider text-[10px]">
                      <tr>
                        <th className="p-3">Policy Name</th>
                        <th className="p-3">Pattern</th>
                        <th className="p-3">Algorithm</th>
                        <th className="p-3">Quota</th>
                        <th className="p-3">Scope</th>
                        <th className="p-3 text-right">Actions</th>
                      </tr>
                    </thead>
                    <tbody className="divide-y divide-navy-800 text-slate-300">
                      {ratePolicies.length === 0 ? (
                        <tr>
                          <td colSpan={6} className="p-6 text-center text-slate-500 font-sans text-xs">
                            No rate limit policies configured. Use the form to define rate limit quotas.
                          </td>
                        </tr>
                      ) : (
                        ratePolicies.map((p) => (
                          <tr key={p.id} className="hover:bg-navy-850/50">
                            <td className="p-3 font-semibold text-white">{p.name}</td>
                            <td className="p-3 text-cyan-400">{p.endpoint_pattern}</td>
                            <td className="p-3 text-indigo-400">{p.algorithm}</td>
                            <td className="p-3">
                              {p.max_requests} req / {p.window_seconds}s
                            </td>
                            <td className="p-3">
                              <span className="px-2 py-0.5 rounded bg-slate-800 text-slate-300 text-[10px]">
                                {p.scope}
                              </span>
                            </td>
                            <td className="p-3 text-right">
                              {canExecuteResponse && (
                                <button
                                  onClick={() => handleDeleteRateLimitPolicy(p.id, p.name)}
                                  className="px-2 py-1 rounded bg-rose-500/10 hover:bg-rose-500/20 text-rose-400 border border-rose-500/30 text-[11px] transition-colors"
                                  title="Delete Policy"
                                >
                                  Delete
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
            </div>

            {/* Live Rate Limiting Test */}
            <div>
              <div className="p-5 rounded-xl bg-navy-900 border border-navy-800">
                <h3 className="text-sm font-semibold text-white mb-1">Rate Limit Test Sandbox</h3>
                <p className="text-xs text-slate-400 mb-4 font-mono">
                  Evaluate quota counters and verify HTTP 429 response simulation.
                </p>

                <div className="space-y-3 text-xs">
                  <div>
                    <label className="block text-slate-300 mb-1 font-mono text-[11px]">Client IP</label>
                    <input
                      type="text"
                      value={testRateIp}
                      onChange={(e) => setTestRateIp(e.target.value)}
                      className="w-full p-2.5 rounded-lg bg-navy-950 border border-navy-700 text-white font-mono"
                    />
                  </div>

                  <div>
                    <label className="block text-slate-300 mb-1 font-mono text-[11px]">Target Path</label>
                    <input
                      type="text"
                      value={testRatePath}
                      onChange={(e) => setTestRatePath(e.target.value)}
                      className="w-full p-2.5 rounded-lg bg-navy-950 border border-navy-700 text-white font-mono"
                    />
                  </div>

                  <button
                    onClick={async () => {
                      try {
                        const res = await networkDefenseApi.testRateLimit(testRateIp, testRatePath);
                        setTestRateResult(res);
                      } catch (err: any) {
                        setTestRateResult({ error: err.response?.data?.detail || err.message });
                      }
                    }}
                    className="w-full py-2.5 rounded-lg bg-indigo-600 hover:bg-indigo-500 text-white font-semibold transition-colors flex items-center justify-center gap-2"
                  >
                    <Zap className="w-4 h-4" />
                    Send Rate Test Probe
                  </button>

                  {testRateResult && (
                    <div className="p-3 rounded-lg bg-navy-950 border border-navy-700 text-xs font-mono space-y-1 mt-3">
                      <div className="text-slate-400">Result:</div>
                      <div className={testRateResult.error ? 'text-rose-400' : 'text-emerald-400'}>
                        {testRateResult.error
                          ? testRateResult.error
                          : `Quota Allowed! Remaining: ${testRateResult.remaining} / ${testRateResult.limit || 1000}`}
                      </div>
                    </div>
                  )}
                </div>
              </div>

              {/* Create Policy Card */}
              <div className="p-5 rounded-xl bg-navy-900 border border-navy-800 mt-4">
                <h3 className="text-sm font-semibold text-white mb-1">Create Rate Limit Policy</h3>
                <p className="text-xs text-slate-400 mb-4 font-mono">
                  Define multi-dimensional request throttling thresholds.
                </p>

                <form onSubmit={handleCreateRateLimitPolicy} className="space-y-3 text-xs">
                  <div>
                    <label className="block text-slate-300 mb-1 font-mono text-[11px]">Policy Name</label>
                    <input
                      type="text"
                      placeholder="e.g. Auth Login Throttling"
                      value={newPolicyName}
                      onChange={(e) => setNewPolicyName(e.target.value)}
                      className="w-full p-2.5 rounded-lg bg-navy-950 border border-navy-700 text-white font-mono focus:border-cyan-500 outline-none"
                      required
                    />
                  </div>

                  <div>
                    <label className="block text-slate-300 mb-1 font-mono text-[11px]">Endpoint Pattern (Regex)</label>
                    <input
                      type="text"
                      placeholder="e.g. /api/v1/auth/.*"
                      value={newPolicyPattern}
                      onChange={(e) => setNewPolicyPattern(e.target.value)}
                      className="w-full p-2.5 rounded-lg bg-navy-950 border border-navy-700 text-white font-mono focus:border-cyan-500 outline-none"
                      required
                    />
                  </div>

                  <div className="grid grid-cols-2 gap-3">
                    <div>
                      <label className="block text-slate-300 mb-1 font-mono text-[11px]">Scope</label>
                      <select
                        value={newPolicyScope}
                        onChange={(e) => setNewPolicyScope(e.target.value as RateLimitScope)}
                        className="w-full p-2.5 rounded-lg bg-navy-950 border border-navy-700 text-white font-mono focus:border-cyan-500 outline-none"
                      >
                        <option value="IP">IP</option>
                        <option value="ENDPOINT">ENDPOINT</option>
                        <option value="TENANT">TENANT</option>
                        <option value="API_KEY">API_KEY</option>
                      </select>
                    </div>
                    <div>
                      <label className="block text-slate-300 mb-1 font-mono text-[11px]">Algorithm</label>
                      <select
                        value={newPolicyAlgorithm}
                        onChange={(e) => setNewPolicyAlgorithm(e.target.value as RateLimitAlgorithm)}
                        className="w-full p-2.5 rounded-lg bg-navy-950 border border-navy-700 text-white font-mono focus:border-cyan-500 outline-none"
                      >
                        <option value="SLIDING_WINDOW">SLIDING_WINDOW</option>
                        <option value="TOKEN_BUCKET">TOKEN_BUCKET</option>
                      </select>
                    </div>
                  </div>

                  <div className="grid grid-cols-3 gap-2">
                    <div>
                      <label className="block text-slate-300 mb-1 font-mono text-[11px]">Max Requests</label>
                      <input
                        type="number"
                        min={1}
                        max={100000}
                        value={newPolicyMaxRequests}
                        onChange={(e) => setNewPolicyMaxRequests(Number(e.target.value))}
                        className="w-full p-2.5 rounded-lg bg-navy-950 border border-navy-700 text-white font-mono focus:border-cyan-500 outline-none"
                        required
                      />
                    </div>
                    <div>
                      <label className="block text-slate-300 mb-1 font-mono text-[11px]">Window (Sec)</label>
                      <input
                        type="number"
                        min={1}
                        max={86400}
                        value={newPolicyWindowSeconds}
                        onChange={(e) => setNewPolicyWindowSeconds(Number(e.target.value))}
                        className="w-full p-2.5 rounded-lg bg-navy-950 border border-navy-700 text-white font-mono focus:border-cyan-500 outline-none"
                        required
                      />
                    </div>
                    <div>
                      <label className="block text-slate-300 mb-1 font-mono text-[11px]">Burst Capacity</label>
                      <input
                        type="number"
                        min={1}
                        max={10000}
                        value={newPolicyBurst}
                        onChange={(e) => setNewPolicyBurst(Number(e.target.value))}
                        className="w-full p-2.5 rounded-lg bg-navy-950 border border-navy-700 text-white font-mono focus:border-cyan-500 outline-none"
                      />
                    </div>
                  </div>

                  <button
                    type="submit"
                    disabled={isPolicySubmitting || !canExecuteResponse}
                    className={`w-full mt-2 py-2.5 rounded-lg text-white font-semibold transition-colors flex items-center justify-center gap-2 ${!canExecuteResponse ? 'bg-slate-700 cursor-not-allowed opacity-60' : 'bg-cyan-600 hover:bg-cyan-500'
                      }`}
                  >
                    {isPolicySubmitting ? <Loader2 className="w-4 h-4 animate-spin" /> : <Plus className="w-4 h-4" />}
                    Create Policy
                  </button>
                  {!canExecuteResponse && (
                    <div className="text-[10px] text-amber-400/90 font-mono mt-1 text-center">
                      Requires 'response_action:execute' permission to create policies.
                    </div>
                  )}
                </form>
              </div>
            </div>
          </div>
        </div>
      )}

      {/* Tab 4: Payload Normalization */}
      {activeTab === 'normalization' && (
        <div className="space-y-4">
          <div className="p-5 rounded-xl bg-navy-900 border border-navy-800">
            <h3 className="text-sm font-semibold text-white mb-1">Multi-Layer Payload De-Obfuscator</h3>
            <p className="text-xs text-slate-400 font-mono mb-4">
              Recursively resolves double-URL, HTML entities, Unicode, Hex, JSON escapes, and Base64 inspection.
            </p>

            <div className="space-y-4">
              <div>
                <label className="block text-slate-300 mb-1 font-mono text-xs">Raw Obfuscated Input String</label>
                <textarea
                  rows={3}
                  value={rawPayloadInput}
                  onChange={(e) => setRawPayloadInput(e.target.value)}
                  className="w-full p-3 rounded-lg bg-navy-950 border border-navy-700 text-cyan-300 font-mono text-xs outline-none focus:border-cyan-500"
                />
              </div>

              <button
                onClick={handleRunNormalization}
                className="px-5 py-2.5 rounded-lg bg-cyan-600 hover:bg-cyan-500 text-white font-semibold text-xs transition-colors flex items-center gap-2"
              >
                <FileCode className="w-4 h-4" />
                Execute De-Obfuscation Passes
              </button>

              {normResult && (
                <div className="p-4 rounded-xl bg-navy-950 border border-navy-700 space-y-3 font-mono text-xs">
                  <div className="flex items-center gap-3">
                    <span className="text-slate-400">Obfuscation Status:</span>
                    <span
                      className={`px-2 py-0.5 rounded text-[11px] font-bold ${normResult.obfuscation_detected ? 'bg-amber-500/20 text-amber-400 border border-amber-500/30' : 'bg-emerald-500/20 text-emerald-400'
                        }`}
                    >
                      {normResult.obfuscation_detected ? 'EVASION DETECTED' : 'CLEAN / STANDARD'}
                    </span>
                  </div>

                  <div>
                    <span className="text-slate-400 block mb-1">Detected Evasion Layers:</span>
                    <div className="flex flex-wrap gap-2">
                      {normResult.detected_techniques.map((t, idx) => (
                        <span key={idx} className="px-2 py-1 rounded bg-navy-850 text-cyan-400 border border-navy-700 text-[10px]">
                          {t}
                        </span>
                      ))}
                    </div>
                  </div>

                  <div>
                    <span className="text-slate-400 block mb-1">Clean Normalized Representation:</span>
                    <div className="p-3 rounded bg-navy-900 border border-navy-800 text-emerald-400 font-mono">
                      {normResult.normalized_text}
                    </div>
                  </div>
                </div>
              )}
            </div>
          </div>
        </div>
      )}

      {/* Tab 5: Advanced Attack Detection */}
      {activeTab === 'detection' && (
        <div className="space-y-4">
          <div className="p-5 rounded-xl bg-navy-900 border border-navy-800">
            <h3 className="text-sm font-semibold text-white mb-1">Advanced 10-Category Attack Detection Bench</h3>
            <p className="text-xs text-slate-400 font-mono mb-4">
              Real-time inspection for SSRF, XXE, SSTI, NoSQLi, LDAPi, Open Redirect, Smuggling, GraphQL Abuse, Mass Assignment, and JWT Misuse.
            </p>

            <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
              <div>
                <label className="block text-slate-300 mb-1 font-mono text-xs">Target Request Path</label>
                <input
                  type="text"
                  value={detectPath}
                  onChange={(e) => setDetectPath(e.target.value)}
                  className="w-full p-2.5 rounded-lg bg-navy-950 border border-navy-700 text-white font-mono text-xs"
                />
              </div>

              <div>
                <label className="block text-slate-300 mb-1 font-mono text-xs">Simulated Request Body</label>
                <input
                  type="text"
                  value={detectBody}
                  onChange={(e) => setDetectBody(e.target.value)}
                  className="w-full p-2.5 rounded-lg bg-navy-950 border border-navy-700 text-white font-mono text-xs"
                />
              </div>
            </div>

            <button
              onClick={handleRunDetection}
              className="mt-4 px-5 py-2.5 rounded-lg bg-cyan-600 hover:bg-cyan-500 text-white font-semibold text-xs transition-colors flex items-center gap-2"
            >
              <Terminal className="w-4 h-4" />
              Evaluate Attack Signatures
            </button>

            {detectResult && (
              <div className="mt-4 p-4 rounded-xl bg-navy-950 border border-navy-700 space-y-3 font-mono text-xs">
                <div className="flex items-center gap-3">
                  <span className="text-slate-400">Detection Verdict:</span>
                  <span
                    className={`px-2 py-0.5 rounded text-[11px] font-bold ${detectResult.detected ? 'bg-rose-500/20 text-rose-400 border border-rose-500/30' : 'bg-emerald-500/20 text-emerald-400'
                      }`}
                  >
                    {detectResult.detected ? `ATTACK DETECTED: ${detectResult.category}` : 'CLEAN REQUEST'}
                  </span>
                  {detectResult.detected && (
                    <span className="text-amber-400 text-xs">
                      Confidence: {(detectResult.confidence * 100).toFixed(0)}% • Severity: {detectResult.severity}
                    </span>
                  )}
                </div>

                <div className="text-slate-300">{detectResult.explanation}</div>

                {detectResult.mitre_attack_id && (
                  <div className="text-cyan-400 text-[11px]">
                    MITRE ATT&CK: {detectResult.mitre_attack_id} • CWE: {detectResult.cwe_id}
                  </div>
                )}
              </div>
            )}
          </div>
        </div>
      )}

      {/* Tab 6: Traffic Replay */}
      {activeTab === 'replay' && (
        <div className="space-y-4">
          <div className="p-5 rounded-xl bg-navy-900 border border-navy-800">
            <div className="flex flex-col md:flex-row md:items-center justify-between gap-4 mb-4">
              <div>
                <h3 className="text-sm font-semibold text-white">Differential Traffic Replay Engine</h3>
                <p className="text-xs text-slate-400 font-mono mt-0.5">
                  Validates virtual patches against sanitized business fixtures to guarantee 0% false positives
                </p>
              </div>
              <button
                onClick={handleRunReplay}
                disabled={isReplaying || !canRunValidation}
                className={`flex items-center gap-2 px-4 py-2 rounded-lg font-semibold text-xs transition-colors ${!canRunValidation
                  ? 'bg-slate-700 text-slate-400 cursor-not-allowed opacity-60'
                  : 'bg-cyan-600 hover:bg-cyan-500 text-white'
                  }`}
                title={!canRunValidation ? "Requires 'validation:run' permission" : "Run differential traffic replay"}
              >
                {isReplaying ? <Loader2 className="w-4 h-4 animate-spin" /> : <Play className="w-4 h-4" />}
                Execute Replay Validation Run
              </button>
            </div>

            <div className="overflow-x-auto">
              <table className="w-full text-left text-xs font-mono">
                <thead className="bg-navy-950 text-slate-400 uppercase tracking-wider text-[10px]">
                  <tr>
                    <th className="p-3">Report ID</th>
                    <th className="p-3">Fixtures Replayed</th>
                    <th className="p-3">False Positives</th>
                    <th className="p-3">FP Rate</th>
                    <th className="p-3">Verdict</th>
                    <th className="p-3">Timestamp</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-navy-800 text-slate-300">
                  {replayReports.length === 0 ? (
                    <tr>
                      <td colSpan={6} className="p-6 text-center text-slate-500 font-sans text-xs">
                        No traffic replay validation runs executed yet. Execute a replay run to validate virtual patches against benign fixtures.
                      </td>
                    </tr>
                  ) : (
                    replayReports.map((r) => (
                      <tr key={r.id} className="hover:bg-navy-850/50">
                        <td className="p-3 font-semibold text-white">{r.id.slice(0, 8)}...</td>
                        <td className="p-3 text-cyan-400">{r.total_replayed}</td>
                        <td className="p-3">{r.false_positives}</td>
                        <td className="p-3">{(r.fp_rate * 100).toFixed(1)}%</td>
                        <td className="p-3">
                          <span
                            className={`px-2 py-0.5 rounded text-[10px] ${r.is_regression_free ? 'bg-emerald-500/10 text-emerald-400' : 'bg-rose-500/10 text-rose-400'
                              }`}
                          >
                            {r.is_regression_free ? 'REGRESSION FREE' : 'REGRESSION DETECTED'}
                          </span>
                        </td>
                        <td className="p-3 text-slate-400">{new Date(r.created_at).toLocaleString()}</td>
                      </tr>
                    ))
                  )}
                </tbody>
              </table>
            </div>
          </div>
        </div>
      )}

      {/* Tab 7: Honeypot Decoys */}
      {activeTab === 'honeypot' && (
        <div className="space-y-5">
          <div className="grid grid-cols-1 lg:grid-cols-3 gap-5">
            <div className="lg:col-span-2 space-y-4">
              <div className="p-5 rounded-xl bg-navy-900 border border-navy-800">
                <h3 className="text-sm font-semibold text-white mb-1">Captured Reconnaissance Probes</h3>
                <p className="text-xs text-slate-400 font-mono mb-4">
                  Adversary scanners intercepted by deceptive decoy tripwires
                </p>

                <div className="overflow-x-auto">
                  <table className="w-full text-left text-xs font-mono">
                    <thead className="bg-navy-950 text-slate-400 uppercase tracking-wider text-[10px]">
                      <tr>
                        <th className="p-3">Attacker IP</th>
                        <th className="p-3">Trap Path</th>
                        <th className="p-3">Method</th>
                        <th className="p-3">Incident Link</th>
                        <th className="p-3">Timestamp</th>
                      </tr>
                    </thead>
                    <tbody className="divide-y divide-navy-800 text-slate-300">
                      {honeypotProbes.length === 0 ? (
                        <tr>
                          <td colSpan={5} className="p-6 text-center text-slate-500 font-sans text-xs">
                            No reconnaissance probes captured yet. Active decoy tripwires are monitoring for scanner traffic.
                          </td>
                        </tr>
                      ) : (
                        honeypotProbes.map((hp) => (
                          <tr key={hp.id} className="hover:bg-navy-850/50">
                            <td className="p-3 text-rose-400 font-bold">{hp.source_ip}</td>
                            <td className="p-3 text-amber-400">{hp.trap_path}</td>
                            <td className="p-3 text-slate-300">{hp.http_method}</td>
                            <td className="p-3 text-cyan-400 truncate max-w-xs">{hp.correlated_incident_id || 'Auto-correlated'}</td>
                            <td className="p-3 text-slate-400">{new Date(hp.created_at).toLocaleTimeString()}</td>
                          </tr>
                        ))
                      )}
                    </tbody>
                  </table>
                </div>
              </div>
            </div>

            <div>
              <div className="p-5 rounded-xl bg-navy-900 border border-navy-800">
                <h3 className="text-sm font-semibold text-white mb-1">Register Custom Decoy Trap</h3>
                <p className="text-xs text-slate-400 mb-4 font-mono">
                  Deploy custom deceptive URI traps for this organization.
                </p>

                <div className="space-y-3 text-xs">
                  <div>
                    <label className="block text-slate-300 mb-1 font-mono text-[11px]">Decoy URI Path</label>
                    <input
                      type="text"
                      placeholder="e.g. /admin/backup.tar.gz"
                      value={newTrapPath}
                      onChange={(e) => setNewTrapPath(e.target.value)}
                      className="w-full p-2.5 rounded-lg bg-navy-950 border border-navy-700 text-white font-mono"
                    />
                  </div>

                  <button
                    onClick={handleAddTrap}
                    disabled={!canWriteZeroTrust}
                    className={`w-full py-2.5 rounded-lg text-white font-semibold transition-colors flex items-center justify-center gap-2 ${!canWriteZeroTrust ? 'bg-slate-700 cursor-not-allowed opacity-60' : 'bg-amber-600 hover:bg-amber-500'
                      }`}
                  >
                    <Plus className="w-4 h-4" />
                    Register Decoy Path
                  </button>
                  {!canWriteZeroTrust && (
                    <div className="text-[10px] text-amber-400/90 font-mono mt-1 text-center">
                      Requires 'zero_trust:write' permission to register traps.
                    </div>
                  )}
                </div>
              </div>
            </div>
          </div>
        </div>
      )}

      {/* Tab 8: GeoIP Policies */}
      {activeTab === 'geoip' && (
        <div className="space-y-5">
          <div className="grid grid-cols-1 lg:grid-cols-3 gap-5">
            <div className="lg:col-span-2 space-y-4">
              <div className="p-5 rounded-xl bg-navy-900 border border-navy-800">
                <h3 className="text-sm font-semibold text-white mb-1">Geographic Access Policies</h3>
                <p className="text-xs text-slate-400 font-mono mb-4">
                  ISO-3166-1 country-level risk modifiers with explicit CIDR exception overrides
                </p>

                <div className="overflow-x-auto">
                  <table className="w-full text-left text-xs font-mono">
                    <thead className="bg-navy-950 text-slate-400 uppercase tracking-wider text-[10px]">
                      <tr>
                        <th className="p-3">Country</th>
                        <th className="p-3">Code</th>
                        <th className="p-3">Action</th>
                        <th className="p-3">Exceptions</th>
                        <th className="p-3">Risk Modifier</th>
                        <th className="p-3 text-right">Actions</th>
                      </tr>
                    </thead>
                    <tbody className="divide-y divide-navy-800 text-slate-300">
                      {geoPolicies.length === 0 ? (
                        <tr>
                          <td colSpan={6} className="p-6 text-center text-slate-500 font-sans text-xs">
                            No GeoIP access policies defined. Create a policy to restrict or score traffic by country.
                          </td>
                        </tr>
                      ) : (
                        geoPolicies.map((gp) => (
                          <tr key={gp.id} className="hover:bg-navy-850/50">
                            <td className="p-3 font-semibold text-white">{gp.country_name}</td>
                            <td className="p-3 text-cyan-400">{gp.country_code}</td>
                            <td className="p-3">
                              <span
                                className={`px-2 py-0.5 rounded text-[10px] ${gp.action === 'DENY' ? 'bg-rose-500/10 text-rose-400' : 'bg-emerald-500/10 text-emerald-400'
                                  }`}
                              >
                                {gp.action}
                              </span>
                            </td>
                            <td className="p-3 text-slate-400">{gp.exception_cidrs || 'None'}</td>
                            <td className="p-3 text-amber-400">+{gp.risk_score_modifier} pts</td>
                            <td className="p-3 text-right">
                              {canWriteZeroTrust && (
                                <button
                                  onClick={() => handleDeleteGeoIPPolicy(gp.id, gp.country_name)}
                                  className="px-2 py-1 rounded bg-rose-500/10 hover:bg-rose-500/20 text-rose-400 border border-rose-500/30 text-[11px] transition-colors"
                                  title="Delete Policy"
                                >
                                  Delete
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
            </div>

            <div>
              <div className="p-5 rounded-xl bg-navy-900 border border-navy-800">
                <h3 className="text-sm font-semibold text-white mb-1">Evaluate IP Geolocation</h3>
                <p className="text-xs text-slate-400 mb-4 font-mono">
                  Test offline IP resolution and verify CIDR bypasses.
                </p>

                <div className="space-y-3 text-xs">
                  <div>
                    <label className="block text-slate-300 mb-1 font-mono text-[11px]">IP Address</label>
                    <input
                      type="text"
                      value={lookupIpInput}
                      onChange={(e) => setLookupIpInput(e.target.value)}
                      className="w-full p-2.5 rounded-lg bg-navy-950 border border-navy-700 text-white font-mono"
                    />
                  </div>

                  <button
                    onClick={handleEvaluateGeoIP}
                    className="w-full py-2.5 rounded-lg bg-cyan-600 hover:bg-cyan-500 text-white font-semibold transition-colors flex items-center justify-center gap-2"
                  >
                    <Search className="w-4 h-4" />
                    Lookup Geolocation
                  </button>

                  {lookupResult && (
                    <div className="p-3 rounded-lg bg-navy-950 border border-navy-700 text-xs font-mono space-y-1 mt-3">
                      <div className="text-slate-300">
                        Country: <span className="text-white font-bold">{lookupResult.country_name} ({lookupResult.country_code})</span>
                      </div>
                      <div className={lookupResult.is_denied ? 'text-rose-400' : 'text-emerald-400'}>
                        {lookupResult.is_denied ? 'DENIED BY POLICY' : 'PERMITTED'}
                      </div>
                      <div className="text-slate-500 text-[10px]">
                        DB Version: {lookupResult.database_version} • Advisory Only: Yes
                      </div>
                    </div>
                  )}
                </div>
              </div>

              {/* Create GeoIP Policy Card */}
              <div className="p-5 rounded-xl bg-navy-900 border border-navy-800 mt-4">
                <h3 className="text-sm font-semibold text-white mb-1">Create GeoIP Policy</h3>
                <p className="text-xs text-slate-400 mb-4 font-mono">
                  Define ISO-3166-1 geographic filtering rules.
                </p>

                <form onSubmit={handleCreateGeoIPPolicy} className="space-y-3 text-xs">
                  <div className="grid grid-cols-2 gap-3">
                    <div>
                      <label className="block text-slate-300 mb-1 font-mono text-[11px]">Country Code</label>
                      <input
                        type="text"
                        placeholder="e.g. KP"
                        maxLength={2}
                        value={newGeoCountryCode}
                        onChange={(e) => setNewGeoCountryCode(e.target.value.toUpperCase())}
                        className="w-full p-2.5 rounded-lg bg-navy-950 border border-navy-700 text-white font-mono uppercase focus:border-cyan-500 outline-none"
                        required
                      />
                    </div>
                    <div>
                      <label className="block text-slate-300 mb-1 font-mono text-[11px]">Action</label>
                      <select
                        value={newGeoAction}
                        onChange={(e) => setNewGeoAction(e.target.value as 'ALLOW' | 'DENY')}
                        className="w-full p-2.5 rounded-lg bg-navy-950 border border-navy-700 text-white font-mono focus:border-cyan-500 outline-none"
                      >
                        <option value="DENY">DENY</option>
                        <option value="ALLOW">ALLOW</option>
                      </select>
                    </div>
                  </div>

                  <div>
                    <label className="block text-slate-300 mb-1 font-mono text-[11px]">Country Name</label>
                    <input
                      type="text"
                      placeholder="e.g. North Korea"
                      value={newGeoCountryName}
                      onChange={(e) => setNewGeoCountryName(e.target.value)}
                      className="w-full p-2.5 rounded-lg bg-navy-950 border border-navy-700 text-white font-mono focus:border-cyan-500 outline-none"
                      required
                    />
                  </div>

                  <div>
                    <label className="block text-slate-300 mb-1 font-mono text-[11px]">Exception CIDRs (Optional)</label>
                    <input
                      type="text"
                      placeholder="e.g. 198.51.100.0/24"
                      value={newGeoExceptions}
                      onChange={(e) => setNewGeoExceptions(e.target.value)}
                      className="w-full p-2.5 rounded-lg bg-navy-950 border border-navy-700 text-white font-mono focus:border-cyan-500 outline-none"
                    />
                  </div>

                  <div>
                    <label className="block text-slate-300 mb-1 font-mono text-[11px]">Risk Score Modifier</label>
                    <input
                      type="number"
                      min={0}
                      max={100}
                      value={newGeoRiskModifier}
                      onChange={(e) => setNewGeoRiskModifier(Number(e.target.value))}
                      className="w-full p-2.5 rounded-lg bg-navy-950 border border-navy-700 text-white font-mono focus:border-cyan-500 outline-none"
                      required
                    />
                  </div>

                  <button
                    type="submit"
                    disabled={isGeoSubmitting || !canWriteZeroTrust}
                    className={`w-full mt-2 py-2.5 rounded-lg text-white font-semibold transition-colors flex items-center justify-center gap-2 ${!canWriteZeroTrust ? 'bg-slate-700 cursor-not-allowed opacity-60' : 'bg-cyan-600 hover:bg-cyan-500'
                      }`}
                  >
                    {isGeoSubmitting ? <Loader2 className="w-4 h-4 animate-spin" /> : <Plus className="w-4 h-4" />}
                    Create GeoIP Policy
                  </button>
                  {!canWriteZeroTrust && (
                    <div className="text-[10px] text-amber-400/90 font-mono mt-1 text-center">
                      Requires 'zero_trust:write' permission to create GeoIP policies.
                    </div>
                  )}
                </form>
              </div>
            </div>
          </div>
        </div>
      )}

      {/* Tab 9: ML Traffic Classification */}
      {activeTab === 'ml' && (
        <div className="space-y-5">
          <div className="grid grid-cols-1 lg:grid-cols-3 gap-5">
            <div className="lg:col-span-2 space-y-4">
              <div className="p-5 rounded-xl bg-navy-900 border border-navy-800">
                <h3 className="text-sm font-semibold text-white mb-1">Advisory ML Traffic Classifier</h3>
                <p className="text-xs text-slate-400 font-mono mb-4">
                  Random Forest ensemble running in advisory mode with explainable feature importances
                </p>

                <div className="space-y-3">
                  <div>
                    <label className="block text-slate-300 mb-1 font-mono text-xs">Test Request Body</label>
                    <textarea
                      rows={3}
                      value={mlTestBody}
                      onChange={(e) => setMlTestBody(e.target.value)}
                      className="w-full p-3 rounded-lg bg-navy-950 border border-navy-700 text-white font-mono text-xs"
                    />
                  </div>

                  <button
                    onClick={handleClassifyML}
                    className="px-5 py-2.5 rounded-lg bg-emerald-600 hover:bg-emerald-500 text-white font-semibold text-xs transition-colors flex items-center gap-2"
                  >
                    <Bot className="w-4 h-4" />
                    Compute Advisory Prediction
                  </button>

                  {mlResult && (
                    <div className="p-4 rounded-xl bg-navy-950 border border-navy-700 space-y-3 font-mono text-xs mt-3">
                      <div className="flex items-center gap-3">
                        <span className="text-slate-400">Classification:</span>
                        <span
                          className={`px-2 py-0.5 rounded text-[11px] font-bold ${mlResult.is_anomalous ? 'bg-rose-500/20 text-rose-400 border border-rose-500/30' : 'bg-emerald-500/20 text-emerald-400'
                            }`}
                        >
                          {mlResult.predicted_class} (Anomaly Score: {mlResult.anomaly_score})
                        </span>
                      </div>

                      <div className="text-slate-300">{mlResult.recommendation}</div>

                      <div>
                        <span className="text-slate-400 block mb-1">Top Contributing Features:</span>
                        <div className="grid grid-cols-2 gap-2 text-[11px]">
                          {Object.entries(mlResult.top_feature_importances).map(([feat, val]) => (
                            <div key={feat} className="p-2 rounded bg-navy-900 border border-navy-800 flex justify-between">
                              <span className="text-slate-400">{feat}</span>
                              <span className="text-cyan-400 font-bold">{val}</span>
                            </div>
                          ))}
                        </div>
                      </div>
                    </div>
                  )}
                </div>
              </div>
            </div>

            <div>
              <div className="p-5 rounded-xl bg-navy-900 border border-navy-800 space-y-3">
                <h3 className="text-sm font-semibold text-white mb-1">Model Architecture Telemetry</h3>
                <div className="space-y-2 text-xs font-mono text-slate-300">
                  <div className="flex justify-between border-b border-navy-800 pb-1.5">
                    <span className="text-slate-500">Algorithm:</span>
                    <span className="text-white">Random Forest (Pure-Python)</span>
                  </div>
                  <div className="flex justify-between border-b border-navy-800 pb-1.5">
                    <span className="text-slate-500">Version:</span>
                    <span className="text-cyan-400">{mlStatus?.model_version || 'v1.0.0-rf-ensemble'}</span>
                  </div>
                  <div className="flex justify-between border-b border-navy-800 pb-1.5">
                    <span className="text-slate-500">Features:</span>
                    <span className="text-white">{mlStatus?.features_count || 16} Dimension Vector</span>
                  </div>
                  <div className="flex justify-between border-b border-navy-800 pb-1.5">
                    <span className="text-slate-500">Holdout Precision:</span>
                    <span className="text-emerald-400">{mlStatus?.precision ? `${(mlStatus.precision * 100).toFixed(1)}%` : '75.0%'}</span>
                  </div>
                  <div className="flex justify-between border-b border-navy-800 pb-1.5">
                    <span className="text-slate-500">Holdout Recall:</span>
                    <span className="text-emerald-400">{mlStatus?.recall ? `${(mlStatus.recall * 100).toFixed(1)}%` : '75.0%'}</span>
                  </div>
                  <div className="flex justify-between border-b border-navy-800 pb-1.5">
                    <span className="text-slate-500">Holdout F1 Score:</span>
                    <span className="text-emerald-400 font-bold">{mlStatus?.f1_score ? `${(mlStatus.f1_score * 100).toFixed(1)}%` : '75.0%'}</span>
                  </div>
                  <div className="flex justify-between pt-1">
                    <span className="text-slate-500">Operating Mode:</span>
                    <span className="text-amber-400">Advisory Only (No Auto-Block)</span>
                  </div>
                </div>
              </div>
            </div>
          </div>
        </div>
      )}
    </div>
  );
};
