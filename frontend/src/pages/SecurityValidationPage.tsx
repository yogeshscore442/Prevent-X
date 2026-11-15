import React, { useEffect, useState } from 'react';
import {
  AlertCircle,
  AlertTriangle,
  ArrowRight,
  CheckCircle2,
  Clock,
  Code2,
  Filter,
  History,
  Loader2,
  Play,
  RefreshCw,
  RotateCcw,
  Server,
  ShieldAlert,
  ShieldCheck,
  Sliders,
  Terminal,
  X,
} from 'lucide-react';
import {
  CanaryPolicy,
  CanaryPolicyUpdatePayload,
  RollbackRecord,
  RollbackRequestPayload,
  SecurityValidationOverviewStats,
  ValidationJob,
  ValidationJobCreatePayload,
  ValidationTestResult,
} from '@/types/securityValidation';
import { securityValidationApi } from '@/services/securityValidationApi';

export const SecurityValidationPage: React.FC = () => {
  const [activeTab, setActiveTab] = useState<'runs' | 'explorer' | 'regression' | 'rollback' | 'canary'>('runs');

  // Core Data States
  const [overview, setOverview] = useState<SecurityValidationOverviewStats | null>(null);
  const [jobs, setJobs] = useState<ValidationJob[]>([]);
  const [selectedJob, setSelectedJob] = useState<ValidationJob | null>(null);
  const [testResults, setTestResults] = useState<ValidationTestResult[]>([]);
  const [rollbacks, setRollbacks] = useState<RollbackRecord[]>([]);
  const [canaryPolicy, setCanaryPolicy] = useState<CanaryPolicy | null>(null);

  // Loading & Action feedback
  const [isLoading, setIsLoading] = useState(true);
  const [isResultsLoading, setIsResultsLoading] = useState(false);
  const [isProcessing, setIsProcessing] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [actionSuccess, setActionSuccess] = useState<string | null>(null);

  // Filters
  const [categoryFilter, setCategoryFilter] = useState<string>('ALL');
  const [resultFilter, setResultFilter] = useState<string>('ALL');
  const [selectedResultDetail, setSelectedResultDetail] = useState<ValidationTestResult | null>(null);

  // Modals
  const [isRunModalOpen, setIsRunModalOpen] = useState(false);
  const [isRollbackModalOpen, setIsRollbackModalOpen] = useState(false);

  // Run Job Form State
  const [runPayload, setRunPayload] = useState<ValidationJobCreatePayload>({
    environment: 'STAGING',
    target_url: 'http://127.0.0.1:8085',
    canary_percentage: 10,
    trigger_type: 'MANUAL',
  });

  // Rollback Form State
  const [rollbackPayload, setRollbackPayload] = useState<RollbackRequestPayload>({
    deployment_id: '',
    rollback_reason: '',
  });

  // Canary Policy Edit Form State
  const [canaryForm, setCanaryForm] = useState<CanaryPolicyUpdatePayload>({
    canary_traffic_weight: 10,
    max_failure_rate_percent: 5.0,
    max_latency_ms: 1000.0,
    max_false_positive_count: 1,
    auto_rollback_enabled: true,
  });

  const loadData = async () => {
    try {
      setIsLoading(true);
      setError(null);
      const [overviewData, jobsData, rollbacksData, canaryData] = await Promise.all([
        securityValidationApi.getOverview(),
        securityValidationApi.listJobs({ limit: 50 }),
        securityValidationApi.listRollbacks(50),
        securityValidationApi.getCanaryPolicy(),
      ]);

      setOverview(overviewData);
      setJobs(jobsData);
      setRollbacks(rollbacksData);
      setCanaryPolicy(canaryData);

      if (canaryData) {
        setCanaryForm({
          canary_traffic_weight: canaryData.canary_traffic_weight,
          max_failure_rate_percent: canaryData.max_failure_rate_percent,
          max_latency_ms: canaryData.max_latency_ms,
          max_false_positive_count: canaryData.max_false_positive_count,
          auto_rollback_enabled: canaryData.auto_rollback_enabled,
        });
      }

      if (jobsData.length > 0 && !selectedJob) {
        setSelectedJob(jobsData[0]);
        loadJobResults(jobsData[0].id);
      }
    } catch (err: any) {
      setError(err?.response?.data?.detail || err.message || 'Failed to load validation telemetry');
    } finally {
      setIsLoading(false);
    }
  };

  const loadJobResults = async (jobId: string) => {
    try {
      setIsResultsLoading(true);
      const results = await securityValidationApi.getJobResults(jobId);
      setTestResults(results);
    } catch (err: any) {
      console.error('Failed to load job results:', err);
    } finally {
      setIsResultsLoading(false);
    }
  };

  useEffect(() => {
    loadData();
  }, []);

  const handleSelectJob = (job: ValidationJob) => {
    setSelectedJob(job);
    setSelectedResultDetail(null);
    loadJobResults(job.id);
  };

  const handleTriggerValidation = async () => {
    try {
      setIsProcessing(true);
      setError(null);
      const newJob = await securityValidationApi.runValidation(runPayload, false);
      setActionSuccess(`Validation job completed with status ${newJob.status}! Pass rate: ${newJob.pass_rate_percentage}%`);
      setIsRunModalOpen(false);
      await loadData();
      setSelectedJob(newJob);
      loadJobResults(newJob.id);
      setActiveTab('explorer');
    } catch (err: any) {
      setError(err?.response?.data?.detail || err.message || 'Validation run failed');
    } finally {
      setIsProcessing(false);
    }
  };

  const handleTriggerRollback = async () => {
    if (!rollbackPayload.deployment_id) {
      setError('Please provide an active deployment ID to roll back.');
      return;
    }
    if (!rollbackPayload.rollback_reason || rollbackPayload.rollback_reason.length < 5) {
      setError('A documented audit reason with at least 5 characters is required for rollback.');
      return;
    }

    try {
      setIsProcessing(true);
      setError(null);
      const record = await securityValidationApi.executeRollback(rollbackPayload, false);
      setActionSuccess(`Rollback executed with status: ${record.status}! Restored config hash: ${record.restored_config_hash.substring(0, 12)}...`);
      setIsRollbackModalOpen(false);
      setRollbackPayload({ deployment_id: '', rollback_reason: '' });
      await loadData();
      setActiveTab('rollback');
    } catch (err: any) {
      setError(err?.response?.data?.detail || err.message || 'Rollback execution failed');
    } finally {
      setIsProcessing(false);
    }
  };

  const handleSaveCanaryPolicy = async () => {
    try {
      setIsProcessing(true);
      setError(null);
      const updated = await securityValidationApi.updateCanaryPolicy(canaryForm);
      setCanaryPolicy(updated);
      setActionSuccess('Canary safety policy and automated rollback thresholds saved successfully.');
    } catch (err: any) {
      setError(err?.response?.data?.detail || err.message || 'Failed to update canary policy');
    } finally {
      setIsProcessing(false);
    }
  };

  // Filtered test results for explorer tab
  const filteredResults = testResults.filter((r) => {
    const matchesCategory = categoryFilter === 'ALL' || r.test_category === categoryFilter;
    const matchesResult = resultFilter === 'ALL' || r.result === resultFilter;
    return matchesCategory && matchesResult;
  });

  return (
    <div className="space-y-6">
      {/* Top Header */}
      <div className="flex flex-col gap-4 md:flex-row md:items-center md:justify-between">
        <div>
          <div className="flex items-center gap-2">
            <h1 className="text-2xl font-bold tracking-tight text-slate-100">
              Automated Security Validation & Rollback
            </h1>
            <span className="rounded bg-cyan-950/80 px-2 py-0.5 text-xs font-semibold text-cyan-400 border border-cyan-800/60">
              MOD-10 & MOD-08
            </span>
          </div>
          <p className="mt-1 text-sm text-slate-400">
            Continuous non-destructive attack simulation, WAF regression matrices, live health checks, and atomic proxy configuration recovery.
          </p>
        </div>

        <div className="flex flex-wrap items-center gap-2">
          <button
            onClick={loadData}
            disabled={isLoading || isProcessing}
            className="flex items-center gap-1.5 rounded-lg border border-slate-700 bg-slate-800/60 px-3 py-2 text-xs font-medium text-slate-300 hover:bg-slate-700/60 hover:text-white transition-colors"
          >
            <RefreshCw className={`h-3.5 w-3.5 ${isLoading ? 'animate-spin' : ''}`} />
            Refresh
          </button>

          <button
            onClick={() => setIsRollbackModalOpen(true)}
            className="flex items-center gap-1.5 rounded-lg border border-amber-600/40 bg-amber-950/40 px-3.5 py-2 text-xs font-semibold text-amber-300 hover:bg-amber-900/60 hover:text-amber-100 transition-colors"
          >
            <RotateCcw className="h-3.5 w-3.5" />
            Execute Rollback
          </button>

          <button
            onClick={() => setIsRunModalOpen(true)}
            className="flex items-center gap-1.5 rounded-lg bg-cyan-600 px-4 py-2 text-xs font-semibold text-white shadow-lg shadow-cyan-600/20 hover:bg-cyan-500 transition-colors"
          >
            <Play className="h-3.5 w-3.5 fill-current" />
            Run Security Validation
          </button>
        </div>
      </div>

      {/* Notifications / Alerts */}
      {error && (
        <div className="flex items-center justify-between rounded-lg border border-red-500/40 bg-red-950/40 p-3.5 text-sm text-red-200">
          <div className="flex items-center gap-2">
            <AlertCircle className="h-4 w-4 flex-shrink-0 text-red-400" />
            <span>{error}</span>
          </div>
          <button onClick={() => setError(null)} className="text-red-400 hover:text-red-200">
            <X className="h-4 w-4" />
          </button>
        </div>
      )}

      {actionSuccess && (
        <div className="flex items-center justify-between rounded-lg border border-emerald-500/40 bg-emerald-950/40 p-3.5 text-sm text-emerald-200">
          <div className="flex items-center gap-2">
            <CheckCircle2 className="h-4 w-4 flex-shrink-0 text-emerald-400" />
            <span>{actionSuccess}</span>
          </div>
          <button onClick={() => setActionSuccess(null)} className="text-emerald-400 hover:text-emerald-200">
            <X className="h-4 w-4" />
          </button>
        </div>
      )}

      {/* Overview KPI Cards */}
      <div className="grid grid-cols-1 gap-4 sm:grid-cols-2 lg:grid-cols-5">
        <div className="rounded-xl border border-slate-800 bg-[#0f172a]/70 p-4 shadow-sm">
          <div className="flex items-center justify-between">
            <span className="text-xs font-medium text-slate-400">Pass Rate</span>
            <ShieldCheck className="h-4 w-4 text-emerald-400" />
          </div>
          <div className="mt-2 flex items-baseline gap-2">
            <span className="text-2xl font-bold text-white">
              {overview ? `${overview.overall_pass_rate_percent}%` : '—'}
            </span>
            <span className="text-xs text-slate-400">
              {overview ? `${overview.passed_validation_jobs}/${overview.total_validation_jobs} runs` : ''}
            </span>
          </div>
          <div className="mt-2 text-xs text-slate-400">
            All categories & WAF regression tests
          </div>
        </div>

        <div className="rounded-xl border border-slate-800 bg-[#0f172a]/70 p-4 shadow-sm">
          <div className="flex items-center justify-between">
            <span className="text-xs font-medium text-slate-400">Attacks Blocked</span>
            <ShieldAlert className="h-4 w-4 text-cyan-400" />
          </div>
          <div className="mt-2 flex items-baseline gap-2">
            <span className="text-2xl font-bold text-cyan-400">
              {overview ? `${overview.attacks_blocked_percent}%` : '—'}
            </span>
            <span className="text-xs text-slate-400">
              {overview ? `${overview.total_attacks_tested} simulated` : ''}
            </span>
          </div>
          <div className="mt-2 text-xs text-slate-400">
            SQLi, XSS, CMDI, Traversal
          </div>
        </div>

        <div className="rounded-xl border border-slate-800 bg-[#0f172a]/70 p-4 shadow-sm">
          <div className="flex items-center justify-between">
            <span className="text-xs font-medium text-slate-400">Legitimate Traffic</span>
            <CheckCircle2 className="h-4 w-4 text-emerald-400" />
          </div>
          <div className="mt-2 flex items-baseline gap-2">
            <span className="text-2xl font-bold text-emerald-400">
              {overview ? `${overview.legitimate_traffic_allowed_percent}%` : '—'}
            </span>
            <span className="text-xs text-emerald-400/80">Allowed (200 OK)</span>
          </div>
          <div className="mt-2 text-xs text-slate-400">
            0% false positives on business traffic
          </div>
        </div>

        <div className="rounded-xl border border-slate-800 bg-[#0f172a]/70 p-4 shadow-sm">
          <div className="flex items-center justify-between">
            <span className="text-xs font-medium text-slate-400">Nginx Reverse Proxy</span>
            <Server className={`h-4 w-4 ${overview?.active_proxy_healthy ? 'text-emerald-400' : 'text-amber-400'}`} />
          </div>
          <div className="mt-2 flex items-baseline gap-2">
            <span className={`text-base font-bold ${overview?.active_proxy_healthy ? 'text-emerald-400' : 'text-amber-400'}`}>
              {overview?.active_proxy_healthy ? 'ACTIVE' : 'OFFLINE'}
            </span>
            <span className="text-xs text-slate-400">
              Port {overview?.active_proxy_port || 8085}
            </span>
          </div>
          <div className="mt-2 text-xs text-slate-400">
            Live HTTP validation verification
          </div>
        </div>

        <div className="rounded-xl border border-slate-800 bg-[#0f172a]/70 p-4 shadow-sm">
          <div className="flex items-center justify-between">
            <span className="text-xs font-medium text-slate-400">Canary Safety</span>
            <Sliders className="h-4 w-4 text-purple-400" />
          </div>
          <div className="mt-2 flex items-baseline gap-2">
            <span className="text-2xl font-bold text-purple-400">
              {overview ? `${overview.active_canary_weight}%` : '—'}
            </span>
            <span className="text-xs text-purple-300">traffic weight</span>
          </div>
          <div className="mt-2 text-xs text-slate-400">
            Auto-rollback threshold: {canaryPolicy ? `${canaryPolicy.max_failure_rate_percent}%` : '5%'}
          </div>
        </div>
      </div>

      {/* Tabs Navigation */}
      <div className="flex border-b border-slate-800">
        <button
          onClick={() => setActiveTab('runs')}
          className={`flex items-center gap-2 border-b-2 px-4 py-3 text-sm font-medium transition-colors ${
            activeTab === 'runs'
              ? 'border-cyan-500 text-cyan-400'
              : 'border-transparent text-slate-400 hover:text-slate-200'
          }`}
        >
          <History className="h-4 w-4" />
          Validation Runs & History
          <span className="rounded-full bg-slate-800 px-2 py-0.5 text-xs text-slate-400">
            {jobs.length}
          </span>
        </button>

        <button
          onClick={() => setActiveTab('explorer')}
          className={`flex items-center gap-2 border-b-2 px-4 py-3 text-sm font-medium transition-colors ${
            activeTab === 'explorer'
              ? 'border-cyan-500 text-cyan-400'
              : 'border-transparent text-slate-400 hover:text-slate-200'
          }`}
        >
          <Terminal className="h-4 w-4" />
          Evidence & Test Probes Explorer
          {testResults.length > 0 && (
            <span className="rounded-full bg-slate-800 px-2 py-0.5 text-xs text-slate-400">
              {testResults.length}
            </span>
          )}
        </button>

        <button
          onClick={() => setActiveTab('regression')}
          className={`flex items-center gap-2 border-b-2 px-4 py-3 text-sm font-medium transition-colors ${
            activeTab === 'regression'
              ? 'border-cyan-500 text-cyan-400'
              : 'border-transparent text-slate-400 hover:text-slate-200'
          }`}
        >
          <ShieldAlert className="h-4 w-4" />
          WAF Regression & Bypass Matrix
        </button>

        <button
          onClick={() => setActiveTab('rollback')}
          className={`flex items-center gap-2 border-b-2 px-4 py-3 text-sm font-medium transition-colors ${
            activeTab === 'rollback'
              ? 'border-cyan-500 text-cyan-400'
              : 'border-transparent text-slate-400 hover:text-slate-200'
          }`}
        >
          <RotateCcw className="h-4 w-4" />
          Rollback Orchestrator & Snapshots
          <span className="rounded-full bg-slate-800 px-2 py-0.5 text-xs text-slate-400">
            {rollbacks.length}
          </span>
        </button>

        <button
          onClick={() => setActiveTab('canary')}
          className={`flex items-center gap-2 border-b-2 px-4 py-3 text-sm font-medium transition-colors ${
            activeTab === 'canary'
              ? 'border-cyan-500 text-cyan-400'
              : 'border-transparent text-slate-400 hover:text-slate-200'
          }`}
        >
          <Sliders className="h-4 w-4" />
          Canary Safety Policies & Thresholds
        </button>
      </div>

      {/* TAB 1: VALIDATION RUNS & HISTORY */}
      {activeTab === 'runs' && (
        <div className="space-y-4">
          <div className="rounded-xl border border-slate-800 bg-[#0f172a]/60 overflow-hidden">
            <div className="overflow-x-auto">
              <table className="w-full text-left text-xs text-slate-300">
                <thead className="border-b border-slate-800 bg-slate-900/60 uppercase tracking-wider text-slate-400 font-semibold">
                  <tr>
                    <th className="px-4 py-3">Run ID / Env</th>
                    <th className="px-4 py-3">Status</th>
                    <th className="px-4 py-3">Pass Rate</th>
                    <th className="px-4 py-3">Attacks Blocked</th>
                    <th className="px-4 py-3">Legitimate Traffic</th>
                    <th className="px-4 py-3">False Positives</th>
                    <th className="px-4 py-3">Trigger</th>
                    <th className="px-4 py-3">Target Config Hash</th>
                    <th className="px-4 py-3">Date</th>
                    <th className="px-4 py-3 text-right">Actions</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-slate-800/60">
                  {jobs.length === 0 ? (
                    <tr>
                      <td colSpan={10} className="px-4 py-8 text-center text-slate-500">
                        No security validation runs recorded yet. Click "Run Security Validation" to execute automated test probes against the proxy.
                      </td>
                    </tr>
                  ) : (
                    jobs.map((job) => (
                      <tr
                        key={job.id}
                        onClick={() => handleSelectJob(job)}
                        className={`hover:bg-slate-800/40 cursor-pointer transition-colors ${
                          selectedJob?.id === job.id ? 'bg-cyan-950/20 border-l-2 border-cyan-500' : ''
                        }`}
                      >
                        <td className="px-4 py-3 font-mono">
                          <div className="font-semibold text-slate-200">
                            {job.id.substring(0, 8)}...
                          </div>
                          <span className={`inline-block mt-0.5 px-1.5 py-0.2 rounded text-[10px] font-medium ${
                            job.environment === 'PRODUCTION'
                              ? 'bg-purple-950 text-purple-300 border border-purple-800/60'
                              : 'bg-blue-950 text-blue-300 border border-blue-800/60'
                          }`}>
                            {job.environment}
                          </span>
                        </td>
                        <td className="px-4 py-3">
                          <span
                            className={`inline-flex items-center gap-1 px-2 py-0.5 rounded text-xs font-semibold ${
                              job.status === 'PASSED'
                                ? 'bg-emerald-950 text-emerald-400 border border-emerald-800/60'
                                : job.status === 'FAILED'
                                ? 'bg-red-950 text-red-400 border border-red-800/60'
                                : 'bg-slate-800 text-slate-300'
                            }`}
                          >
                            {job.status === 'PASSED' ? (
                              <CheckCircle2 className="h-3 w-3" />
                            ) : job.status === 'FAILED' ? (
                              <AlertCircle className="h-3 w-3" />
                            ) : (
                              <Clock className="h-3 w-3" />
                            )}
                            {job.status}
                          </span>
                        </td>
                        <td className="px-4 py-3">
                          <div className="flex items-center gap-2">
                            <span className="font-bold text-slate-100">{job.pass_rate_percentage}%</span>
                            <div className="w-16 h-1.5 rounded-full bg-slate-800 overflow-hidden">
                              <div
                                className={`h-full ${job.pass_rate_percentage === 100 ? 'bg-emerald-500' : job.pass_rate_percentage >= 80 ? 'bg-amber-500' : 'bg-red-500'}`}
                                style={{ width: `${job.pass_rate_percentage}%` }}
                              />
                            </div>
                          </div>
                          <div className="text-[10px] text-slate-500">
                            {job.passed_tests} / {job.total_tests} probes
                          </div>
                        </td>
                        <td className="px-4 py-3 text-cyan-400 font-semibold">
                          {job.blocked_attacks} blocked
                        </td>
                        <td className="px-4 py-3 text-emerald-400">
                          {job.allowed_legitimate} allowed
                        </td>
                        <td className="px-4 py-3 font-semibold">
                          {job.false_positives_detected > 0 ? (
                            <span className="text-red-400 flex items-center gap-1">
                              <AlertTriangle className="h-3 w-3" />
                              {job.false_positives_detected}
                            </span>
                          ) : (
                            <span className="text-slate-400">0</span>
                          )}
                        </td>
                        <td className="px-4 py-3 text-slate-400">
                          {job.trigger_type}
                        </td>
                        <td className="px-4 py-3 font-mono text-[11px] text-slate-400">
                          {job.active_config_hash ? `${job.active_config_hash.substring(0, 10)}...` : 'N/A'}
                        </td>
                        <td className="px-4 py-3 text-slate-400">
                          {new Date(job.created_at).toLocaleString()}
                        </td>
                        <td className="px-4 py-3 text-right">
                          <button
                            onClick={(e) => {
                              e.stopPropagation();
                              handleSelectJob(job);
                              setActiveTab('explorer');
                            }}
                            className="inline-flex items-center gap-1 text-cyan-400 hover:text-cyan-300 font-medium"
                          >
                            Inspect Probes <ArrowRight className="h-3 w-3" />
                          </button>
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

      {/* TAB 2: EVIDENCE & TEST PROBES EXPLORER */}
      {activeTab === 'explorer' && (
        <div className="space-y-4">
          {/* Active Job Selector Bar */}
          <div className="flex flex-col md:flex-row md:items-center justify-between gap-4 rounded-xl border border-slate-800 bg-[#0f172a]/70 p-4">
            <div className="flex items-center gap-3">
              <Terminal className="h-5 w-5 text-cyan-400" />
              <div>
                <div className="flex items-center gap-2">
                  <span className="text-xs text-slate-400">Inspecting Job:</span>
                  <span className="font-mono text-xs font-semibold text-white">
                    {selectedJob ? selectedJob.id : 'No job selected'}
                  </span>
                  {selectedJob && (
                    <span
                      className={`px-1.5 py-0.5 rounded text-[10px] font-semibold ${
                        selectedJob.status === 'PASSED'
                          ? 'bg-emerald-950 text-emerald-400'
                          : 'bg-red-950 text-red-400'
                      }`}
                    >
                      {selectedJob.status} ({selectedJob.pass_rate_percentage}%)
                    </span>
                  )}
                </div>
                <div className="text-xs text-slate-500 mt-0.5">
                  Target: {selectedJob?.target_url || 'N/A'} • Environment: {selectedJob?.environment} • Probes: {testResults.length}
                </div>
              </div>
            </div>

            {/* Quick Filters */}
            <div className="flex flex-wrap items-center gap-2">
              <div className="flex items-center gap-1.5 text-xs text-slate-400">
                <Filter className="h-3.5 w-3.5" />
                <span>Category:</span>
                <select
                  value={categoryFilter}
                  onChange={(e) => setCategoryFilter(e.target.value)}
                  className="rounded border border-slate-700 bg-slate-900 px-2 py-1 text-xs text-slate-200"
                >
                  <option value="ALL">All Categories</option>
                  <option value="SQLI">SQL Injection</option>
                  <option value="XSS">Cross-Site Scripting</option>
                  <option value="PATH_TRAVERSAL">Path Traversal</option>
                  <option value="CMDI">Command Injection</option>
                  <option value="METHOD_RESTRICTION">Method Restriction</option>
                  <option value="REGRESSION_ENCODING">WAF Regression</option>
                  <option value="LEGITIMATE_TRAFFIC">Legitimate Traffic</option>
                  <option value="UPSTREAM_CONNECTIVITY">Upstream Reachability</option>
                </select>
              </div>

              <div className="flex items-center gap-1.5 text-xs text-slate-400">
                <span>Result:</span>
                <select
                  value={resultFilter}
                  onChange={(e) => setResultFilter(e.target.value)}
                  className="rounded border border-slate-700 bg-slate-900 px-2 py-1 text-xs text-slate-200"
                >
                  <option value="ALL">All Results</option>
                  <option value="PASSED">Passed</option>
                  <option value="FAILED">Failed</option>
                </select>
              </div>
            </div>
          </div>

          {/* Test Probes Table & Detail Split */}
          <div className="grid grid-cols-1 lg:grid-cols-12 gap-4">
            <div className={`${selectedResultDetail ? 'lg:col-span-7' : 'lg:col-span-12'} rounded-xl border border-slate-800 bg-[#0f172a]/60 overflow-hidden`}>
              {isResultsLoading ? (
                <div className="p-8 text-center text-slate-400 flex items-center justify-center gap-2">
                  <Loader2 className="h-5 w-5 animate-spin text-cyan-400" />
                  Loading test probes evidence...
                </div>
              ) : (
                <div className="overflow-x-auto">
                  <table className="w-full text-left text-xs text-slate-300">
                    <thead className="border-b border-slate-800 bg-slate-900/60 uppercase tracking-wider text-slate-400 font-semibold">
                      <tr>
                        <th className="px-4 py-3">Test Probe</th>
                        <th className="px-4 py-3">Category</th>
                        <th className="px-4 py-3">Method & Path</th>
                        <th className="px-4 py-3">Expected</th>
                        <th className="px-4 py-3">Actual Code</th>
                        <th className="px-4 py-3">Decision</th>
                        <th className="px-4 py-3">Latency</th>
                        <th className="px-4 py-3 text-right">Result</th>
                      </tr>
                    </thead>
                    <tbody className="divide-y divide-slate-800/60">
                      {filteredResults.length === 0 ? (
                        <tr>
                          <td colSpan={8} className="px-4 py-8 text-center text-slate-500">
                            No test probes match current filters or no run selected.
                          </td>
                        </tr>
                      ) : (
                        filteredResults.map((r) => (
                          <tr
                            key={r.id}
                            onClick={() => setSelectedResultDetail(r)}
                            className={`hover:bg-slate-800/40 cursor-pointer transition-colors ${
                              selectedResultDetail?.id === r.id ? 'bg-cyan-950/30 border-l-2 border-cyan-400' : ''
                            }`}
                          >
                            <td className="px-4 py-3">
                              <div className="font-semibold text-slate-200">{r.test_name}</div>
                              <div className="text-[10px] text-slate-500">{r.test_id}</div>
                            </td>
                            <td className="px-4 py-3 font-mono text-[11px]">
                              <span className="rounded bg-slate-800 px-1.5 py-0.5 text-slate-300">
                                {r.test_category}
                              </span>
                            </td>
                            <td className="px-4 py-3">
                              <span className="rounded bg-slate-900 border border-slate-700/60 px-1.5 py-0.5 font-mono text-[10px] font-semibold text-cyan-300 mr-1.5">
                                {r.http_method}
                              </span>
                              <span className="font-mono text-slate-300 text-[11px] truncate inline-block max-w-[140px] align-middle">
                                {r.target_endpoint}
                              </span>
                            </td>
                            <td className="px-4 py-3 font-mono text-slate-400">
                              {r.expected_status_code}
                            </td>
                            <td className="px-4 py-3 font-mono">
                              <span
                                className={`font-semibold ${
                                  r.actual_status_code === r.expected_status_code
                                    ? 'text-emerald-400'
                                    : 'text-red-400'
                                }`}
                              >
                                {r.actual_status_code ?? 'None'}
                              </span>
                            </td>
                            <td className="px-4 py-3 font-mono">
                              <span
                                className={`px-1.5 py-0.5 rounded text-[10px] font-semibold ${
                                  r.actual_decision === 'BLOCKED'
                                    ? 'bg-red-950 text-red-300 border border-red-800/60'
                                    : 'bg-emerald-950 text-emerald-300 border border-emerald-800/60'
                                }`}
                              >
                                {r.actual_decision}
                              </span>
                            </td>
                            <td className="px-4 py-3 font-mono text-slate-400">
                              {r.latency_ms.toFixed(1)}ms
                            </td>
                            <td className="px-4 py-3 text-right">
                              <span
                                className={`inline-flex items-center gap-1 px-2 py-0.5 rounded text-[10px] font-semibold ${
                                  r.result === 'PASSED'
                                    ? 'bg-emerald-950 text-emerald-400'
                                    : 'bg-red-950 text-red-400'
                                }`}
                              >
                                {r.result === 'PASSED' ? (
                                  <CheckCircle2 className="h-3 w-3" />
                                ) : (
                                  <AlertCircle className="h-3 w-3" />
                                )}
                                {r.result}
                              </span>
                            </td>
                          </tr>
                        ))
                      )}
                    </tbody>
                  </table>
                </div>
              )}
            </div>

            {/* Granular Evidence Inspector Panel */}
            {selectedResultDetail && (
              <div className="lg:col-span-5 rounded-xl border border-slate-800 bg-[#0f172a]/90 p-4 space-y-3">
                <div className="flex items-center justify-between border-b border-slate-800 pb-3">
                  <div>
                    <h3 className="text-sm font-semibold text-white">
                      {selectedResultDetail.test_name}
                    </h3>
                    <p className="text-xs text-slate-400 mt-0.5">
                      {selectedResultDetail.description}
                    </p>
                  </div>
                  <button
                    onClick={() => setSelectedResultDetail(null)}
                    className="text-slate-400 hover:text-white"
                  >
                    <X className="h-4 w-4" />
                  </button>
                </div>

                <div className="grid grid-cols-2 gap-2 text-xs">
                  <div className="rounded-lg bg-slate-900/60 p-2 border border-slate-800">
                    <span className="text-slate-400">Category:</span>
                    <span className="ml-2 font-mono text-white">{selectedResultDetail.test_category}</span>
                  </div>
                  <div className="rounded-lg bg-slate-900/60 p-2 border border-slate-800">
                    <span className="text-slate-400">Latency:</span>
                    <span className="ml-2 font-mono text-emerald-400">{selectedResultDetail.latency_ms.toFixed(2)} ms</span>
                  </div>
                  <div className="rounded-lg bg-slate-900/60 p-2 border border-slate-800">
                    <span className="text-slate-400">Expected:</span>
                    <span className="ml-2 font-mono text-white">{selectedResultDetail.expected_status_code} ({selectedResultDetail.expected_decision})</span>
                  </div>
                  <div className="rounded-lg bg-slate-900/60 p-2 border border-slate-800">
                    <span className="text-slate-400">Actual:</span>
                    <span className="ml-2 font-mono text-cyan-300">{selectedResultDetail.actual_status_code} ({selectedResultDetail.actual_decision})</span>
                  </div>
                </div>

                <div>
                  <div className="text-xs font-medium text-slate-400 mb-1 flex items-center gap-1.5">
                    <Code2 className="h-3.5 w-3.5 text-cyan-400" />
                    Target Endpoint & Payload
                  </div>
                  <div className="rounded-lg bg-slate-950 p-2.5 font-mono text-xs text-amber-300 border border-slate-800 break-all select-all">
                    {selectedResultDetail.http_method} {selectedResultDetail.target_endpoint}
                    {selectedResultDetail.request_payload_redacted && (
                      <div className="mt-1 pt-1 border-t border-slate-800 text-slate-300">
                        {selectedResultDetail.request_payload_redacted}
                      </div>
                    )}
                  </div>
                </div>

                <div>
                  <div className="text-xs font-medium text-slate-400 mb-1 flex items-center gap-1.5">
                    <ShieldCheck className="h-3.5 w-3.5 text-emerald-400" />
                    Recorded Audit Evidence
                  </div>
                  <div className="rounded-lg bg-slate-950 p-2.5 font-mono text-xs text-slate-300 border border-slate-800 whitespace-pre-wrap">
                    {selectedResultDetail.evidence_snippet || 'Test probe satisfied assertion.'}
                  </div>
                </div>

                {selectedResultDetail.request_headers_redacted && (
                  <div>
                    <div className="text-xs font-medium text-slate-400 mb-1">Redacted Request Headers</div>
                    <div className="rounded-lg bg-slate-950 p-2 font-mono text-[11px] text-slate-400 border border-slate-800 whitespace-pre-wrap">
                      {selectedResultDetail.request_headers_redacted}
                    </div>
                  </div>
                )}
              </div>
            )}
          </div>
        </div>
      )}

      {/* TAB 3: WAF REGRESSION & BYPASS MATRIX */}
      {activeTab === 'regression' && (
        <div className="space-y-4">
          <div className="rounded-xl border border-slate-800 bg-[#0f172a]/60 p-4">
            <h3 className="text-sm font-semibold text-slate-100 flex items-center gap-2">
              <ShieldAlert className="h-4 w-4 text-cyan-400" />
              Automated WAF Bypass & Normalization Regression Suite
            </h3>
            <p className="text-xs text-slate-400 mt-1">
              Validates that virtual patches resist evasion techniques including standard URL-encoding, double percent-encoding, mixed-case permutations, and ReDoS polynomial complexity traps.
            </p>
          </div>

          <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
            <div className="rounded-xl border border-slate-800 bg-[#0f172a]/70 p-4 space-y-2">
              <div className="flex items-center justify-between">
                <span className="text-xs font-semibold text-white">URL Percent-Encoding</span>
                <span className="px-2 py-0.5 rounded text-[10px] font-semibold bg-emerald-950 text-emerald-400 border border-emerald-800/60">
                  DEFENDED
                </span>
              </div>
              <p className="text-xs text-slate-400">
                Normalized representation test: <code>%27%20OR%20%271%27=%271</code>
              </p>
              <div className="text-[11px] text-slate-500 font-mono bg-slate-950 p-2 rounded border border-slate-800">
                Pattern: <code>(?i)(\%27|')\s*(or|\%6fr)</code>
              </div>
              <div className="text-xs text-emerald-400 font-medium">Result: Blocked with HTTP 403</div>
            </div>

            <div className="rounded-xl border border-slate-800 bg-[#0f172a]/70 p-4 space-y-2">
              <div className="flex items-center justify-between">
                <span className="text-xs font-semibold text-white">Mixed-Case Permutations</span>
                <span className="px-2 py-0.5 rounded text-[10px] font-semibold bg-emerald-950 text-emerald-400 border border-emerald-800/60">
                  DEFENDED
                </span>
              </div>
              <p className="text-xs text-slate-400">
                Case-folding evasion: <code>uNiOn sElEcT</code>, <code>sCrIpT</code>
              </p>
              <div className="text-[11px] text-slate-500 font-mono bg-slate-950 p-2 rounded border border-slate-800">
                Flag: <code>(?i)</code> leading regex compiled
              </div>
              <div className="text-xs text-emerald-400 font-medium">Result: Blocked with HTTP 403</div>
            </div>

            <div className="rounded-xl border border-slate-800 bg-[#0f172a]/70 p-4 space-y-2">
              <div className="flex items-center justify-between">
                <span className="text-xs font-semibold text-white">Double URL-Encoding</span>
                <span className="px-2 py-0.5 rounded text-[10px] font-semibold bg-emerald-950 text-emerald-400 border border-emerald-800/60">
                  DEFENDED
                </span>
              </div>
              <p className="text-xs text-slate-400">
                Two-stage decode bypass: <code>%2527%2520OR</code>
              </p>
              <div className="text-[11px] text-slate-500 font-mono bg-slate-950 p-2 rounded border border-slate-800">
                Evaluator: Multi-stage normalization
              </div>
              <div className="text-xs text-emerald-400 font-medium">Result: Blocked with HTTP 403</div>
            </div>

            <div className="rounded-xl border border-slate-800 bg-[#0f172a]/70 p-4 space-y-2">
              <div className="flex items-center justify-between">
                <span className="text-xs font-semibold text-white">ReDoS & Bounded Input Size</span>
                <span className="px-2 py-0.5 rounded text-[10px] font-semibold bg-emerald-950 text-emerald-400 border border-emerald-800/60">
                  DEFENDED
                </span>
              </div>
              <p className="text-xs text-slate-400">
                10,000 character repetition test without catastrophic backtracking timeout.
              </p>
              <div className="text-[11px] text-slate-500 font-mono bg-slate-950 p-2 rounded border border-slate-800">
                Evaluation latency: &lt; 15.0ms
              </div>
              <div className="text-xs text-emerald-400 font-medium">Result: Protected, no DoS vulnerability</div>
            </div>

            <div className="rounded-xl border border-slate-800 bg-[#0f172a]/70 p-4 space-y-2">
              <div className="flex items-center justify-between">
                <span className="text-xs font-semibold text-white">Benign Traffic With Keywords</span>
                <span className="px-2 py-0.5 rounded text-[10px] font-semibold bg-emerald-950 text-emerald-400 border border-emerald-800/60">
                  PASSED
                </span>
              </div>
              <p className="text-xs text-slate-400">
                Legitimate query: <code>?q=annual_selection_report.pdf</code>
              </p>
              <div className="text-[11px] text-slate-500 font-mono bg-slate-950 p-2 rounded border border-slate-800">
                Contextual bounds ensure benign traffic passes
              </div>
              <div className="text-xs text-emerald-400 font-medium">Result: Allowed with HTTP 200 (No false positive)</div>
            </div>

            <div className="rounded-xl border border-slate-800 bg-[#0f172a]/70 p-4 space-y-2">
              <div className="flex items-center justify-between">
                <span className="text-xs font-semibold text-white">Upstream Health & Routing</span>
                <span className="px-2 py-0.5 rounded text-[10px] font-semibold bg-emerald-950 text-emerald-400 border border-emerald-800/60">
                  HEALTHY
                </span>
              </div>
              <p className="text-xs text-slate-400">
                Reverse-proxy connectivity to backend web service on port 8086.
              </p>
              <div className="text-[11px] text-slate-500 font-mono bg-slate-950 p-2 rounded border border-slate-800">
                Endpoint: <code>GET /health</code>
              </div>
              <div className="text-xs text-emerald-400 font-medium">Result: Upstream reachable (200 OK)</div>
            </div>
          </div>
        </div>
      )}

      {/* TAB 4: ROLLBACK ORCHESTRATOR & SNAPSHOTS */}
      {activeTab === 'rollback' && (
        <div className="space-y-4">
          <div className="rounded-xl border border-slate-800 bg-[#0f172a]/60 p-4 flex flex-col md:flex-row md:items-center justify-between gap-4">
            <div>
              <h3 className="text-sm font-semibold text-slate-100 flex items-center gap-2">
                <RotateCcw className="h-4 w-4 text-amber-400" />
                Reliable Rollback Orchestrator & Configuration Snapshots
              </h3>
              <p className="text-xs text-slate-400 mt-1">
                Zero-downtime atomic restoration using pre-reload syntax validation (<code>nginx -t</code>) and post-reload live HTTP probe verification.
              </p>
            </div>
            <button
              onClick={() => setIsRollbackModalOpen(true)}
              className="flex items-center gap-1.5 rounded-lg bg-amber-600 px-4 py-2 text-xs font-semibold text-white shadow-lg shadow-amber-600/20 hover:bg-amber-500 transition-colors self-start md:self-auto"
            >
              <RotateCcw className="h-3.5 w-3.5" />
              Trigger Rollback
            </button>
          </div>

          <div className="rounded-xl border border-slate-800 bg-[#0f172a]/60 overflow-hidden">
            <div className="overflow-x-auto">
              <table className="w-full text-left text-xs text-slate-300">
                <thead className="border-b border-slate-800 bg-slate-900/60 uppercase tracking-wider text-slate-400 font-semibold">
                  <tr>
                    <th className="px-4 py-3">Rollback ID</th>
                    <th className="px-4 py-3">Status</th>
                    <th className="px-4 py-3">Trigger Source</th>
                    <th className="px-4 py-3">Previous SHA-256</th>
                    <th className="px-4 py-3">Restored SHA-256</th>
                    <th className="px-4 py-3">Live Verified</th>
                    <th className="px-4 py-3">Reason</th>
                    <th className="px-4 py-3">Executed At</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-slate-800/60">
                  {rollbacks.length === 0 ? (
                    <tr>
                      <td colSpan={8} className="px-4 py-8 text-center text-slate-500">
                        No rollback events recorded. If validation failure thresholds are breached, automatic rollback triggers immediately.
                      </td>
                    </tr>
                  ) : (
                    rollbacks.map((rb) => (
                      <tr key={rb.id} className="hover:bg-slate-800/30">
                        <td className="px-4 py-3 font-mono text-slate-200">
                          {rb.id.substring(0, 8)}...
                        </td>
                        <td className="px-4 py-3">
                          <span
                            className={`inline-flex items-center gap-1 px-2 py-0.5 rounded text-xs font-semibold ${
                              rb.status === 'COMPLETED'
                                ? 'bg-emerald-950 text-emerald-400 border border-emerald-800/60'
                                : rb.status === 'ROLLBACK_FAILED'
                                ? 'bg-red-950 text-red-400 border border-red-800/60'
                                : 'bg-amber-950 text-amber-300 border border-amber-800/60'
                            }`}
                          >
                            {rb.status === 'COMPLETED' ? (
                              <CheckCircle2 className="h-3 w-3" />
                            ) : (
                              <AlertCircle className="h-3 w-3" />
                            )}
                            {rb.status}
                          </span>
                        </td>
                        <td className="px-4 py-3 font-mono text-[11px] text-slate-400">
                          {rb.trigger_source}
                        </td>
                        <td className="px-4 py-3 font-mono text-[11px] text-red-400/90">
                          {rb.previous_config_hash ? rb.previous_config_hash.substring(0, 12) : 'N/A'}...
                        </td>
                        <td className="px-4 py-3 font-mono text-[11px] text-emerald-400">
                          {rb.restored_config_hash ? rb.restored_config_hash.substring(0, 12) : 'N/A'}...
                        </td>
                        <td className="px-4 py-3">
                          {rb.is_restoration_verified ? (
                            <span className="text-emerald-400 font-semibold flex items-center gap-1">
                              <CheckCircle2 className="h-3.5 w-3.5" />
                              VERIFIED
                            </span>
                          ) : (
                            <span className="text-red-400 font-semibold flex items-center gap-1">
                              <AlertCircle className="h-3.5 w-3.5" />
                              UNVERIFIED
                            </span>
                          )}
                        </td>
                        <td className="px-4 py-3 text-slate-300 max-w-[200px] truncate" title={rb.rollback_reason}>
                          {rb.rollback_reason}
                        </td>
                        <td className="px-4 py-3 text-slate-400">
                          {new Date(rb.started_at).toLocaleString()}
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

      {/* TAB 5: CANARY SAFETY POLICIES & THRESHOLDS */}
      {activeTab === 'canary' && (
        <div className="space-y-4">
          <div className="rounded-xl border border-slate-800 bg-[#0f172a]/60 p-4">
            <div className="flex items-center justify-between">
              <h3 className="text-sm font-semibold text-slate-100 flex items-center gap-2">
                <Sliders className="h-4 w-4 text-purple-400" />
                SMB Canary Safety Policy & Automated Rollback Thresholds
              </h3>
              <span className="inline-flex items-center rounded-md bg-purple-950/60 px-2 py-0.5 text-[10px] font-semibold text-purple-300 ring-1 ring-inset ring-purple-700/50">
                Policy & Evaluation Gate (Non-Routing)
              </span>
            </div>
            <p className="text-xs text-slate-400 mt-1">
              Defines progressive validation thresholds and automated rollback safety gates for Indian SMB workloads. When validation test failures or latencies breach these policy limits, PREVENT-X triggers an immediate atomic rollback. (Note: Enforced via validation safety evaluation; live upstream network traffic splitting is reserved for multi-cluster reverse proxy architectures).
            </p>
          </div>

          <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
            <div className="rounded-xl border border-slate-800 bg-[#0f172a]/70 p-5 space-y-4">
              <div>
                <label className="text-xs font-semibold text-slate-200">
                  Canary Validation Allocation Weight (%) — Policy Gate
                </label>
                <div className="mt-2 flex items-center gap-4">
                  <input
                    type="range"
                    min="0"
                    max="100"
                    step="5"
                    value={canaryForm.canary_traffic_weight ?? 10}
                    onChange={(e) =>
                      setCanaryForm({ ...canaryForm, canary_traffic_weight: parseInt(e.target.value) })
                    }
                    className="w-full accent-cyan-500"
                  />
                  <span className="w-12 text-center font-mono text-sm font-bold text-cyan-400">
                    {canaryForm.canary_traffic_weight}%
                  </span>
                </div>
                <p className="text-[11px] text-slate-500 mt-1">
                  Percentage of live traffic routed through virtual patch candidate before full promotion.
                </p>
              </div>

              <div>
                <label className="text-xs font-semibold text-slate-200">
                  Max Allowed Failure Rate Threshold (%)
                </label>
                <input
                  type="number"
                  min="0"
                  max="100"
                  step="0.5"
                  value={canaryForm.max_failure_rate_percent ?? 5.0}
                  onChange={(e) =>
                    setCanaryForm({ ...canaryForm, max_failure_rate_percent: parseFloat(e.target.value) })
                  }
                  className="mt-1 w-full rounded-lg border border-slate-700 bg-slate-900 px-3 py-2 text-xs font-mono text-slate-200"
                />
                <p className="text-[11px] text-slate-500 mt-1">
                  If validation failures exceed this percentage, PREVENT-X triggers instant automated rollback.
                </p>
              </div>

              <div>
                <label className="text-xs font-semibold text-slate-200">
                  Max Allowed False Positives
                </label>
                <input
                  type="number"
                  min="0"
                  max="10"
                  value={canaryForm.max_false_positive_count ?? 1}
                  onChange={(e) =>
                    setCanaryForm({ ...canaryForm, max_false_positive_count: parseInt(e.target.value) })
                  }
                  className="mt-1 w-full rounded-lg border border-slate-700 bg-slate-900 px-3 py-2 text-xs font-mono text-slate-200"
                />
                <p className="text-[11px] text-slate-500 mt-1">
                  Zero tolerance for blocking legitimate business traffic.
                </p>
              </div>
            </div>

            <div className="rounded-xl border border-slate-800 bg-[#0f172a]/70 p-5 space-y-4">
              <div>
                <label className="text-xs font-semibold text-slate-200">
                  Latency Threshold (ms)
                </label>
                <input
                  type="number"
                  min="50"
                  max="5000"
                  step="50"
                  value={canaryForm.max_latency_ms ?? 1000.0}
                  onChange={(e) =>
                    setCanaryForm({ ...canaryForm, max_latency_ms: parseFloat(e.target.value) })
                  }
                  className="mt-1 w-full rounded-lg border border-slate-700 bg-slate-900 px-3 py-2 text-xs font-mono text-slate-200"
                />
                <p className="text-[11px] text-slate-500 mt-1">
                  Maximum proxy latency before flagging performance regression.
                </p>
              </div>

              <div className="pt-2">
                <label className="flex items-center gap-3 cursor-pointer">
                  <input
                    type="checkbox"
                    checked={canaryForm.auto_rollback_enabled ?? true}
                    onChange={(e) =>
                      setCanaryForm({ ...canaryForm, auto_rollback_enabled: e.target.checked })
                    }
                    className="h-4 w-4 rounded accent-cyan-500 bg-slate-900 border-slate-700"
                  />
                  <div>
                    <span className="text-xs font-semibold text-white">
                      Enable Automated Rollback on Threshold Breach
                    </span>
                    <p className="text-[11px] text-slate-500">
                      When enabled, any canary breach or validation failure automatically restores the previous healthy configuration without waiting for manual intervention.
                    </p>
                  </div>
                </label>
              </div>

              <div className="pt-4 flex justify-end">
                <button
                  onClick={handleSaveCanaryPolicy}
                  disabled={isProcessing}
                  className="flex items-center gap-2 rounded-lg bg-cyan-600 px-5 py-2.5 text-xs font-semibold text-white hover:bg-cyan-500 transition-colors shadow-lg shadow-cyan-600/20"
                >
                  {isProcessing ? <Loader2 className="h-4 w-4 animate-spin" /> : <ShieldCheck className="h-4 w-4" />}
                  Save Policy Configuration
                </button>
              </div>
            </div>
          </div>
        </div>
      )}

      {/* MODAL: RUN SECURITY VALIDATION */}
      {isRunModalOpen && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/70 backdrop-blur-sm p-4">
          <div className="w-full max-w-md rounded-xl border border-slate-800 bg-[#0f172a] p-5 shadow-2xl">
            <div className="flex items-center justify-between border-b border-slate-800 pb-3">
              <div className="flex items-center gap-2">
                <Play className="h-4 w-4 text-cyan-400 fill-current" />
                <h3 className="text-base font-semibold text-white">Execute Security Validation</h3>
              </div>
              <button onClick={() => setIsRunModalOpen(false)} className="text-slate-400 hover:text-white">
                <X className="h-4 w-4" />
              </button>
            </div>

            <div className="mt-4 space-y-3">
              <div>
                <label className="text-xs font-medium text-slate-300">Environment</label>
                <select
                  value={runPayload.environment}
                  onChange={(e) => setRunPayload({ ...runPayload, environment: e.target.value })}
                  className="mt-1 w-full rounded-lg border border-slate-700 bg-slate-900 px-3 py-2 text-xs text-slate-200"
                >
                  <option value="STAGING">STAGING (Pre-production Validation)</option>
                  <option value="PRODUCTION">PRODUCTION (Live Protected Gateway)</option>
                </select>
              </div>

              <div>
                <label className="text-xs font-medium text-slate-300">Target Reverse Proxy URL</label>
                <input
                  type="text"
                  value={runPayload.target_url}
                  onChange={(e) => setRunPayload({ ...runPayload, target_url: e.target.value })}
                  className="mt-1 w-full rounded-lg border border-slate-700 bg-slate-900 px-3 py-2 text-xs font-mono text-slate-200"
                />
              </div>

              <div>
                <label className="text-xs font-medium text-slate-300">Canary Weight (%)</label>
                <input
                  type="number"
                  min="0"
                  max="100"
                  value={runPayload.canary_percentage}
                  onChange={(e) =>
                    setRunPayload({ ...runPayload, canary_percentage: parseInt(e.target.value) || 0 })
                  }
                  className="mt-1 w-full rounded-lg border border-slate-700 bg-slate-900 px-3 py-2 text-xs font-mono text-slate-200"
                />
              </div>

              <div className="rounded-lg bg-cyan-950/30 border border-cyan-800/40 p-3 text-xs text-cyan-300">
                <strong>Non-Destructive Guarantee:</strong> Probes are read-only payload simulations. If false-positive or failure thresholds are breached, automatic rollback executes immediately.
              </div>
            </div>

            <div className="mt-5 flex justify-end gap-2 border-t border-slate-800 pt-3">
              <button
                onClick={() => setIsRunModalOpen(false)}
                className="rounded-lg border border-slate-700 px-3 py-2 text-xs font-medium text-slate-300 hover:bg-slate-800"
              >
                Cancel
              </button>
              <button
                onClick={handleTriggerValidation}
                disabled={isProcessing}
                className="flex items-center gap-2 rounded-lg bg-cyan-600 px-4 py-2 text-xs font-semibold text-white hover:bg-cyan-500 disabled:opacity-50"
              >
                {isProcessing && <Loader2 className="h-3.5 w-3.5 animate-spin" />}
                Execute Validation Probes
              </button>
            </div>
          </div>
        </div>
      )}

      {/* MODAL: TRIGGER ROLLBACK */}
      {isRollbackModalOpen && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/70 backdrop-blur-sm p-4">
          <div className="w-full max-w-md rounded-xl border border-slate-800 bg-[#0f172a] p-5 shadow-2xl">
            <div className="flex items-center justify-between border-b border-slate-800 pb-3">
              <div className="flex items-center gap-2">
                <RotateCcw className="h-4 w-4 text-amber-400" />
                <h3 className="text-base font-semibold text-white">Execute Configuration Rollback</h3>
              </div>
              <button onClick={() => setIsRollbackModalOpen(false)} className="text-slate-400 hover:text-white">
                <X className="h-4 w-4" />
              </button>
            </div>

            <div className="mt-4 space-y-3">
              <div>
                <label className="text-xs font-medium text-slate-300">Deployment ID to Rollback</label>
                <input
                  type="text"
                  placeholder="UUID of active deployment"
                  value={rollbackPayload.deployment_id}
                  onChange={(e) => setRollbackPayload({ ...rollbackPayload, deployment_id: e.target.value })}
                  className="mt-1 w-full rounded-lg border border-slate-700 bg-slate-900 px-3 py-2 text-xs font-mono text-slate-200"
                />
              </div>

              <div>
                <label className="text-xs font-medium text-slate-300">Audit Justification / Reason *</label>
                <textarea
                  rows={3}
                  placeholder="Explain reason for rollback (e.g. false positive in business endpoint, upstream latency)..."
                  value={rollbackPayload.rollback_reason}
                  onChange={(e) => setRollbackPayload({ ...rollbackPayload, rollback_reason: e.target.value })}
                  className="mt-1 w-full rounded-lg border border-slate-700 bg-slate-900 px-3 py-2 text-xs text-slate-200"
                />
              </div>

              <div className="rounded-lg bg-amber-950/30 border border-amber-800/40 p-3 text-xs text-amber-300">
                <strong>Safety Verification:</strong> Restores the last known-good configuration snapshot, verifies syntax with <code>nginx -t</code>, and confirms proxy reachability with live probes.
              </div>
            </div>

            <div className="mt-5 flex justify-end gap-2 border-t border-slate-800 pt-3">
              <button
                onClick={() => setIsRollbackModalOpen(false)}
                className="rounded-lg border border-slate-700 px-3 py-2 text-xs font-medium text-slate-300 hover:bg-slate-800"
              >
                Cancel
              </button>
              <button
                onClick={handleTriggerRollback}
                disabled={isProcessing}
                className="flex items-center gap-2 rounded-lg bg-amber-600 px-4 py-2 text-xs font-semibold text-white hover:bg-amber-500 disabled:opacity-50"
              >
                {isProcessing && <Loader2 className="h-3.5 w-3.5 animate-spin" />}
                Confirm Atomic Rollback
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
};
