import React, { useEffect, useRef, useState } from 'react';
import {
  Activity,
  AlertCircle,
  CheckCircle2,
  Clock,
  Eye,
  Lock,
  Pause,
  Play,
  Plus,
  Radio,
  RefreshCw,
  Search,
  Send,
  Shield,
  ShieldAlert,
  ShieldCheck,
  Sliders,
  Trash2,
  X,
} from 'lucide-react';
import {
  EventRetentionPolicy,
  SecurityCenterOverviewStats,
  SecurityAlert,
  SecurityEvent,
  SecurityIncident,
  SecurityIncidentDetail,
} from '@/types/monitoring';
import { monitoringApi } from '@/services/monitoringApi';
import { formatErrorMessage } from '@/utils/formatError';

export const SecurityCenterPage: React.FC = () => {
  const [activeTab, setActiveTab] = useState<'overview' | 'events' | 'incidents' | 'alerts_retention'>('overview');

  // Core Data States
  const [overview, setOverview] = useState<SecurityCenterOverviewStats | null>(null);
  const [events, setEvents] = useState<SecurityEvent[]>([]);
  const [incidents, setIncidents] = useState<SecurityIncident[]>([]);
  const [alerts, setAlerts] = useState<SecurityAlert[]>([]);
  const [retentionPolicy, setRetentionPolicy] = useState<EventRetentionPolicy | null>(null);

  // Detail & Selection States
  const [selectedIncidentId, setSelectedIncidentId] = useState<string | null>(null);
  const [incidentDetail, setIncidentDetail] = useState<SecurityIncidentDetail | null>(null);
  const [selectedEvent, setSelectedEvent] = useState<SecurityEvent | null>(null);

  // Loading & Feedback
  const [isLoading, setIsLoading] = useState(true);
  const [isDetailLoading, setIsDetailLoading] = useState(false);
  const [actionSuccess, setActionSuccess] = useState<string | null>(null);
  const [errorMessage, setErrorMessage] = useState<string | null>(null);

  // SSE Real-Time Stream States
  const [sseConnected, setSseConnected] = useState(false);
  const [isStreamPaused, setIsStreamPaused] = useState(false);
  const eventSourceRef = useRef<EventSource | null>(null);
  const lastEventIdRef = useRef<string | undefined>(undefined);

  // Filters & Search
  const [eventSearch, setEventSearch] = useState('');
  const [eventCategoryFilter, setEventCategoryFilter] = useState<string>('ALL');
  const [eventSeverityFilter, setEventSeverityFilter] = useState<string>('ALL');

  const [incidentStatusFilter, setIncidentStatusFilter] = useState<string>('ALL');
  const [incidentSeverityFilter, setIncidentSeverityFilter] = useState<string>('ALL');

  // Modal / Form States
  const [isCreateIncidentModalOpen, setIsCreateIncidentModalOpen] = useState(false);
  const [newIncidentTitle, setNewIncidentTitle] = useState('');
  const [newIncidentDesc, setNewIncidentDesc] = useState('');
  const [newIncidentSeverity, setNewIncidentSeverity] = useState('MEDIUM');
  const [newIncidentMitre, setNewIncidentMitre] = useState('');

  // Analyst Note Form
  const [newAnalystNote, setNewAnalystNote] = useState('');
  const [isSubmittingNote, setIsSubmittingNote] = useState(false);

  // Containment Form
  const [containmentAction, setContainmentAction] = useState('BLOCK_SOURCE_IP');
  const [containmentNotes, setContainmentNotes] = useState('');
  const [containmentApproved, setContainmentApproved] = useState(false);
  const [isExecutingContainment, setIsExecutingContainment] = useState(false);

  // Retention Form
  const [retentionDays, setRetentionDays] = useState(30);
  const [maxStoredEvents, setMaxStoredEvents] = useState(50000);
  const [autoPrune, setAutoPrune] = useState(true);
  const [isSavingRetention, setIsSavingRetention] = useState(false);

  // Clear toast feedback
  useEffect(() => {
    if (actionSuccess || errorMessage) {
      const timer = setTimeout(() => {
        setActionSuccess(null);
        setErrorMessage(null);
      }, 5000);
      return () => clearTimeout(timer);
    }
  }, [actionSuccess, errorMessage]);

  // Initial Data Load
  const loadInitialData = async () => {
    setIsLoading(true);
    try {
      const [overviewData, incidentsRes, alertsData, retentionData] = await Promise.all([
        monitoringApi.getOverview().catch(() => null),
        monitoringApi.getIncidents({ size: 50 }).catch(() => ({ items: [], total: 0, page: 1, size: 50 })),
        monitoringApi.getAlerts({ limit: 50 }).catch(() => []),
        monitoringApi.getRetentionPolicy().catch(() => null),
      ]);

      setOverview(overviewData);
      setIncidents(incidentsRes.items || []);
      setAlerts(alertsData || []);
      if (retentionData) {
        setRetentionPolicy(retentionData);
        setRetentionDays(retentionData.retention_days);
        setMaxStoredEvents(retentionData.max_stored_events);
        setAutoPrune(retentionData.auto_prune_enabled);
      }

      // Initial events load
      const eventsRes = await monitoringApi.getEvents({ size: 100 }).catch(() => ({ items: [], total: 0, page: 1, size: 100 }));
      setEvents(eventsRes.items || []);
      if (eventsRes.items && eventsRes.items.length > 0) {
        lastEventIdRef.current = eventsRes.items[0].id;
      }
    } catch (err: any) {
      setErrorMessage(err.message || 'Failed to load Security Center data.');
    } finally {
      setIsLoading(false);
    }
  };

  useEffect(() => {
    loadInitialData();
  }, []);

  // SSE Stream Management
  useEffect(() => {
    if (isStreamPaused) {
      if (eventSourceRef.current) {
        eventSourceRef.current.close();
        eventSourceRef.current = null;
        setSseConnected(false);
      }
      return;
    }

    const sseUrl = monitoringApi.getSSEUrl(lastEventIdRef.current);
    const es = new EventSource(sseUrl);
    eventSourceRef.current = es;

    es.onopen = () => {
      setSseConnected(true);
    };

    es.addEventListener('security_event', (e: MessageEvent) => {
      try {
        const newEvent: SecurityEvent = JSON.parse(e.data);
        lastEventIdRef.current = newEvent.id;
        setEvents((prev) => [newEvent, ...prev.slice(0, 199)]);
      } catch (err) {
        console.error('Failed to parse incoming SSE security_event:', err);
      }
    });

    es.addEventListener('security_incident', (e: MessageEvent) => {
      try {
        const newIncident: SecurityIncident = JSON.parse(e.data);
        setIncidents((prev) => {
          const exists = prev.some((inc) => inc.id === newIncident.id);
          if (exists) {
            return prev.map((inc) => (inc.id === newIncident.id ? newIncident : inc));
          }
          return [newIncident, ...prev];
        });
      } catch (err) {
        console.error('Failed to parse incoming SSE security_incident:', err);
      }
    });

    es.addEventListener('security_alert', (e: MessageEvent) => {
      try {
        const newAlert: SecurityAlert = JSON.parse(e.data);
        setAlerts((prev) => [newAlert, ...prev]);
      } catch (err) {
        console.error('Failed to parse incoming SSE security_alert:', err);
      }
    });

    es.onerror = () => {
      setSseConnected(false);
    };

    return () => {
      es.close();
      eventSourceRef.current = null;
      setSseConnected(false);
    };
  }, [isStreamPaused]);

  // Load Incident Detail
  const handleSelectIncident = async (id: string) => {
    setSelectedIncidentId(id);
    setIsDetailLoading(true);
    try {
      const detail = await monitoringApi.getIncidentDetail(id);
      setIncidentDetail(detail);
    } catch (err: any) {
      setErrorMessage(err.message || 'Failed to load incident details.');
    } finally {
      setIsDetailLoading(false);
    }
  };

  // Add Note to Incident
  const handleAddAnalystNote = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!selectedIncidentId || !newAnalystNote.trim()) return;

    setIsSubmittingNote(true);
    try {
      const noteEntry = await monitoringApi.addIncidentNote(selectedIncidentId, {
        message: newAnalystNote.trim(),
        entry_type: 'ANALYST_NOTE',
      });
      if (incidentDetail) {
        setIncidentDetail({
          ...incidentDetail,
          timeline_entries: [...incidentDetail.timeline_entries, noteEntry],
        });
      }
      setNewAnalystNote('');
      setActionSuccess('Analyst note appended to incident timeline.');
    } catch (err: any) {
      setErrorMessage(err.message || 'Failed to add analyst note.');
    } finally {
      setIsSubmittingNote(false);
    }
  };

  // Update Incident Status
  const handleUpdateStatus = async (newStatus: string) => {
    if (!selectedIncidentId) return;
    try {
      const updated = await monitoringApi.updateIncident(selectedIncidentId, {
        status: newStatus,
      });
      setIncidents((prev) => prev.map((inc) => (inc.id === updated.id ? updated : inc)));
      if (incidentDetail) {
        setIncidentDetail({ ...incidentDetail, status: updated.status, updated_at: updated.updated_at });
      }
      setActionSuccess(`Incident marked as ${newStatus}.`);
    } catch (err: any) {
      setErrorMessage(err.message || 'Failed to update incident status.');
    }
  };

  // Containment Execution
  const handleExecuteContainment = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!selectedIncidentId) return;

    setIsExecutingContainment(true);
    try {
      const updated = await monitoringApi.executeContainment(selectedIncidentId, {
        containment_action: containmentAction,
        notes: containmentNotes.trim() || undefined,
        is_approved: containmentApproved,
      });
      setIncidents((prev) => prev.map((inc) => (inc.id === updated.id ? updated : inc)));
      if (incidentDetail) {
        setIncidentDetail({
          ...incidentDetail,
          containment_action_taken: updated.containment_action_taken,
          containment_requires_approval: updated.containment_requires_approval,
          status: updated.status,
        });
      }
      setActionSuccess(
        updated.containment_requires_approval
          ? 'Containment proposed. Requires approval from Organization Administrator.'
          : 'Disruptive containment action executed successfully.'
      );
    } catch (err: any) {
      setErrorMessage(err.message || 'Failed to execute containment.');
    } finally {
      setIsExecutingContainment(false);
    }
  };

  // Create Manual Incident
  const handleCreateIncident = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!newIncidentTitle.trim() || !newIncidentDesc.trim()) return;

    try {
      const created = await monitoringApi.createIncident({
        title: newIncidentTitle.trim(),
        description: newIncidentDesc.trim(),
        severity: newIncidentSeverity,
        mitre_technique: newIncidentMitre.trim() || undefined,
      });
      setIncidents((prev) => [created, ...prev]);
      setIsCreateIncidentModalOpen(false);
      setNewIncidentTitle('');
      setNewIncidentDesc('');
      setActionSuccess(`Incident ${created.incident_number} created.`);
    } catch (err: any) {
      setErrorMessage(err.message || 'Failed to create incident.');
    }
  };

  // Acknowledge Alert
  const handleAcknowledgeAlert = async (alertId: string) => {
    try {
      const acknowledged = await monitoringApi.acknowledgeAlert(alertId);
      setAlerts((prev) => prev.map((a) => (a.id === acknowledged.id ? acknowledged : a)));
      setActionSuccess('Alert acknowledged.');
    } catch (err: any) {
      setErrorMessage(err.message || 'Failed to acknowledge alert.');
    }
  };

  // Save Retention Policy
  const handleSaveRetention = async (e: React.FormEvent) => {
    e.preventDefault();
    setIsSavingRetention(true);
    try {
      const updated = await monitoringApi.updateRetentionPolicy({
        retention_days: retentionDays,
        max_stored_events: maxStoredEvents,
        auto_prune_enabled: autoPrune,
      });
      setRetentionPolicy(updated);
      setActionSuccess('Retention policy updated successfully.');
    } catch (err: any) {
      setErrorMessage(err.message || 'Failed to update retention policy.');
    } finally {
      setIsSavingRetention(false);
    }
  };

  // Prune Expired Events Now
  const handlePruneNow = async () => {
    try {
      const res = await monitoringApi.pruneEventsNow();
      setActionSuccess(`Pruned ${res.deleted_events_count} expired events from database.`);
      loadInitialData();
    } catch (err: any) {
      setErrorMessage(err.message || 'Failed to prune events.');
    }
  };

  // Helpers for badge styles
  const getSeverityBadgeClass = (severity: string) => {
    switch (severity.toUpperCase()) {
      case 'CRITICAL':
        return 'bg-red-500/15 text-red-400 border border-red-500/30';
      case 'HIGH':
        return 'bg-orange-500/15 text-orange-400 border border-orange-500/30';
      case 'MEDIUM':
        return 'bg-amber-500/15 text-amber-400 border border-amber-500/30';
      case 'LOW':
        return 'bg-blue-500/15 text-blue-400 border border-blue-500/30';
      default:
        return 'bg-gray-500/15 text-gray-400 border border-gray-500/30';
    }
  };

  const getStatusBadgeClass = (status: string) => {
    switch (status.toUpperCase()) {
      case 'OPEN':
        return 'bg-red-500/20 text-red-300 border border-red-500/30';
      case 'ACKNOWLEDGED':
        return 'bg-amber-500/20 text-amber-300 border border-amber-500/30';
      case 'INVESTIGATING':
        return 'bg-blue-500/20 text-blue-300 border border-blue-500/30';
      case 'CONTAINED':
        return 'bg-purple-500/20 text-purple-300 border border-purple-500/30';
      case 'RESOLVED':
        return 'bg-emerald-500/20 text-emerald-300 border border-emerald-500/30';
      case 'CLOSED':
        return 'bg-gray-500/20 text-gray-300 border border-gray-500/30';
      default:
        return 'bg-gray-500/20 text-gray-300 border border-gray-500/30';
    }
  };

  // Filtered Events
  const filteredEvents = (events || []).filter((ev) => {
    if (eventCategoryFilter !== 'ALL' && ev.category !== eventCategoryFilter) return false;
    if (eventSeverityFilter !== 'ALL' && ev.severity !== eventSeverityFilter) return false;
    if (eventSearch.trim()) {
      const q = eventSearch.toLowerCase();
      const matchTitle = ev.title?.toLowerCase().includes(q);
      const matchIp = ev.source_ip?.toLowerCase().includes(q);
      const matchUri = ev.target_uri?.toLowerCase().includes(q);
      if (!matchTitle && !matchIp && !matchUri) return false;
    }
    return true;
  });

  // Filtered Incidents
  const filteredIncidents = (incidents || []).filter((inc) => {
    if (incidentStatusFilter !== 'ALL' && inc.status !== incidentStatusFilter) return false;
    if (incidentSeverityFilter !== 'ALL' && inc.severity !== incidentSeverityFilter) return false;
    return true;
  });

  return (
    <div className="space-y-6">
      {/* Page Header */}
      <div className="flex flex-col md:flex-row md:items-center md:justify-between gap-4">
        <div>
          <div className="flex items-center gap-2">
            <h1 className="text-2xl font-bold tracking-tight text-white">Centralized Security Center</h1>
            <span className="px-2 py-0.5 text-xs font-semibold rounded bg-cyan-500/10 text-cyan-400 border border-cyan-500/20">
              MOD-09 & MOD-12
            </span>
          </div>
          <p className="text-sm text-gray-400 mt-1">
            Real-time security telemetry, automated attack correlation, incident containment, and SMB posture management.
          </p>
        </div>

        {/* Global Action / Stream Status Pill */}
        <div className="flex items-center gap-3">
          <div className="flex items-center gap-2 px-3 py-1.5 rounded-lg bg-gray-900/80 border border-gray-800 text-xs">
            <Radio
              className={`w-3.5 h-3.5 ${sseConnected && !isStreamPaused ? 'text-emerald-400 animate-pulse' : 'text-gray-500'
                }`}
            />
            <span className={sseConnected && !isStreamPaused ? 'text-emerald-400 font-medium' : 'text-gray-400'}>
              {isStreamPaused ? 'Stream Paused' : sseConnected ? 'Live Stream Active' : 'Connecting Stream...'}
            </span>
            <button
              onClick={() => setIsStreamPaused(!isStreamPaused)}
              className="ml-1 text-gray-400 hover:text-white transition-colors"
              title={isStreamPaused ? 'Resume live SSE stream' : 'Pause live SSE stream'}
            >
              {isStreamPaused ? <Play className="w-3.5 h-3.5" /> : <Pause className="w-3.5 h-3.5" />}
            </button>
          </div>

          <button
            onClick={loadInitialData}
            disabled={isLoading}
            className="flex items-center gap-1.5 px-3 py-1.5 text-xs font-medium bg-gray-800 hover:bg-gray-700 text-gray-200 rounded-lg border border-gray-700 transition-colors"
          >
            <RefreshCw className={`w-3.5 h-3.5 ${isLoading ? 'animate-spin' : ''}`} />
            Refresh
          </button>
        </div>
      </div>

      {/* Notifications */}
      {actionSuccess && (
        <div className="flex items-center gap-2 p-3 bg-emerald-500/10 border border-emerald-500/30 text-emerald-400 text-xs rounded-lg animate-in fade-in">
          <CheckCircle2 className="w-4 h-4 flex-shrink-0" />
          <span>{actionSuccess}</span>
        </div>
      )}
      {errorMessage && (
        <div className="flex items-center gap-2 p-3 bg-red-500/10 border border-red-500/30 text-red-400 text-xs rounded-lg animate-in fade-in">
          <AlertCircle className="w-4 h-4 flex-shrink-0" />
          <span>{typeof errorMessage === 'string' ? errorMessage : formatErrorMessage(errorMessage)}</span>
        </div>
      )}

      {/* Top Navigation Tabs */}
      <div className="border-b border-gray-800">
        <nav className="flex space-x-6">
          <button
            onClick={() => setActiveTab('overview')}
            className={`pb-3 text-sm font-medium transition-colors border-b-2 ${activeTab === 'overview'
              ? 'border-cyan-500 text-cyan-400'
              : 'border-transparent text-gray-400 hover:text-gray-200'
              }`}
          >
            SMB Posture Overview
          </button>
          <button
            onClick={() => setActiveTab('events')}
            className={`pb-3 text-sm font-medium transition-colors border-b-2 flex items-center gap-1.5 ${activeTab === 'events'
              ? 'border-cyan-500 text-cyan-400'
              : 'border-transparent text-gray-400 hover:text-gray-200'
              }`}
          >
            Live Security Events
            {events.length > 0 && (
              <span className="px-1.5 py-0.2 rounded-full text-[10px] bg-cyan-500/20 text-cyan-300">
                {events.length}
              </span>
            )}
          </button>
          <button
            onClick={() => setActiveTab('incidents')}
            className={`pb-3 text-sm font-medium transition-colors border-b-2 flex items-center gap-1.5 ${activeTab === 'incidents'
              ? 'border-cyan-500 text-cyan-400'
              : 'border-transparent text-gray-400 hover:text-gray-200'
              }`}
          >
            Correlated Incidents
            {overview && overview.open_incidents_total > 0 && (
              <span className="px-1.5 py-0.2 rounded-full text-[10px] bg-red-500/20 text-red-300">
                {overview.open_incidents_total}
              </span>
            )}
          </button>
          <button
            onClick={() => setActiveTab('alerts_retention')}
            className={`pb-3 text-sm font-medium transition-colors border-b-2 flex items-center gap-1.5 ${activeTab === 'alerts_retention'
              ? 'border-cyan-500 text-cyan-400'
              : 'border-transparent text-gray-400 hover:text-gray-200'
              }`}
          >
            In-App Alerts & Retention
            {(alerts || []).filter((a) => !a.is_acknowledged).length > 0 && (
              <span className="px-1.5 py-0.2 rounded-full text-[10px] bg-amber-500/20 text-amber-300">
                {(alerts || []).filter((a) => !a.is_acknowledged).length}
              </span>
            )}
          </button>
        </nav>
      </div>

      {/* ========================================================================= */}
      {/* TAB 1: EXECUTIVE SMB POSTURE OVERVIEW */}
      {/* ========================================================================= */}
      {activeTab === 'overview' && (
        <div className="space-y-6">
          {/* Posture Score Banner */}
          <div className="grid grid-cols-1 md:grid-cols-4 gap-4">
            <div className="md:col-span-1 p-5 rounded-xl bg-gray-900 border border-gray-800 flex flex-col justify-between items-center text-center">
              <span className="text-xs font-medium text-gray-400 uppercase tracking-wider">
                Overall Security Posture
              </span>
              <div className="my-3 flex items-center justify-center">
                <div className="relative flex items-center justify-center w-24 h-24 rounded-full border-4 border-cyan-500/30">
                  <div className="text-center">
                    <span className="text-3xl font-extrabold text-white">
                      {overview ? overview.security_score : '--'}
                    </span>
                    <span className="text-xs text-gray-400 block">/ 100</span>
                  </div>
                </div>
              </div>
              <div className="flex items-center gap-2">
                <span className="text-xs text-gray-400">Rating Grade:</span>
                <span
                  className={`px-2 py-0.5 text-xs font-bold rounded ${overview?.security_grade === 'A+' || overview?.security_grade === 'A'
                    ? 'bg-emerald-500/20 text-emerald-400'
                    : overview?.security_grade === 'B'
                      ? 'bg-blue-500/20 text-blue-400'
                      : overview?.security_grade === 'C'
                        ? 'bg-amber-500/20 text-amber-400'
                        : 'bg-red-500/20 text-red-400'
                    }`}
                >
                  Grade {overview ? overview.security_grade : '--'}
                </span>
              </div>
            </div>

            {/* 6 Core KPI Cards */}
            <div className="md:col-span-3 grid grid-cols-2 md:grid-cols-3 gap-4">
              {/* Card 1: Open Incidents */}
              <div className="p-4 rounded-xl bg-gray-900 border border-gray-800 flex flex-col justify-between">
                <div className="flex items-center justify-between text-gray-400 text-xs">
                  <span>Open Incidents</span>
                  <ShieldAlert className="w-4 h-4 text-red-400" />
                </div>
                <div className="mt-2">
                  <div className="text-2xl font-bold text-white">
                    {overview ? overview.open_incidents_total : 0}
                  </div>
                  <div className="flex items-center gap-2 mt-1 text-[11px] text-gray-400">
                    <span className="text-red-400 font-medium">
                      {overview ? overview.critical_incidents_count : 0} Critical
                    </span>
                    <span>•</span>
                    <span className="text-orange-400 font-medium">
                      {overview ? overview.high_incidents_count : 0} High
                    </span>
                  </div>
                </div>
              </div>

              {/* Card 2: 24h Ingested Events */}
              <div className="p-4 rounded-xl bg-gray-900 border border-gray-800 flex flex-col justify-between">
                <div className="flex items-center justify-between text-gray-400 text-xs">
                  <span>24h Ingested Events</span>
                  <Activity className="w-4 h-4 text-cyan-400" />
                </div>
                <div className="mt-2">
                  <div className="text-2xl font-bold text-white">
                    {overview ? overview.events_24h_count.toLocaleString() : 0}
                  </div>
                  <div className="text-[11px] text-gray-400 mt-1">Real-time telemetry stream</div>
                </div>
              </div>

              {/* Card 3: WAF Telemetry */}
              <div className="p-4 rounded-xl bg-gray-900 border border-gray-800 flex flex-col justify-between">
                <div className="flex items-center justify-between text-gray-400 text-xs">
                  <span>WAF Traffic (24h)</span>
                  <ShieldCheck className="w-4 h-4 text-emerald-400" />
                </div>
                <div className="mt-2">
                  <div className="text-2xl font-bold text-white">
                    {overview ? overview.waf_blocked_24h.toLocaleString() : 0}
                  </div>
                  <div className="text-[11px] text-gray-400 mt-1">
                    Blocked attacks ({overview ? overview.waf_allowed_24h.toLocaleString() : 0} allowed)
                  </div>
                </div>
              </div>

              {/* Card 4: Exposed Assets */}
              <div className="p-4 rounded-xl bg-gray-900 border border-gray-800 flex flex-col justify-between">
                <div className="flex items-center justify-between text-gray-400 text-xs">
                  <span>Monitored Assets</span>
                  <Shield className="w-4 h-4 text-indigo-400" />
                </div>
                <div className="mt-2">
                  <div className="text-2xl font-bold text-white">
                    {overview ? overview.exposed_assets_count : 0}
                  </div>
                  <div className="text-[11px] text-gray-400 mt-1">Active network endpoints</div>
                </div>
              </div>

              {/* Card 5: Virtual Patches */}
              <div className="p-4 rounded-xl bg-gray-900 border border-gray-800 flex flex-col justify-between">
                <div className="flex items-center justify-between text-gray-400 text-xs">
                  <span>Active Virtual Patches</span>
                  <Lock className="w-4 h-4 text-purple-400" />
                </div>
                <div className="mt-2">
                  <div className="text-2xl font-bold text-white">
                    {overview ? overview.active_virtual_patches_count : 0}
                  </div>
                  <div className="text-[11px] text-gray-400 mt-1">Live Nginx WAF mitigations</div>
                </div>
              </div>

              {/* Card 6: Rollback & Validation Health */}
              <div className="p-4 rounded-xl bg-gray-900 border border-gray-800 flex flex-col justify-between">
                <div className="flex items-center justify-between text-gray-400 text-xs">
                  <span>Recent Rollbacks</span>
                  <Sliders className="w-4 h-4 text-amber-400" />
                </div>
                <div className="mt-2">
                  <div className="text-2xl font-bold text-white">
                    {overview ? overview.recent_rollbacks_count : 0}
                  </div>
                  <div className="text-[11px] text-gray-400 mt-1">
                    {overview?.validation_failures_24h || 0} validation failures
                  </div>
                </div>
              </div>
            </div>
          </div>

          {/* Zero Trust Distribution & Security Health Cards */}
          <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
            {/* Zero Trust Posture Breakdown */}
            <div className="p-5 rounded-xl bg-gray-900 border border-gray-800">
              <h3 className="text-sm font-semibold text-white mb-3 flex items-center gap-2">
                <Shield className="w-4 h-4 text-cyan-400" />
                Zero Trust Asset Posture Breakdown
              </h3>
              {overview?.trust_distribution &&
                Object.values(overview.trust_distribution).reduce((a, b) => a + b, 0) > 0 ? (
                <div className="space-y-3">
                  {Object.entries(overview.trust_distribution).map(([status, count]) => (
                    <div key={status} className="flex items-center justify-between text-xs">
                      <span className="text-gray-300 font-medium">{status}</span>
                      <div className="flex items-center gap-2">
                        <span className="text-gray-400">{count} assets</span>
                        <span
                          className={`w-2.5 h-2.5 rounded-full ${status === 'TRUSTED'
                            ? 'bg-emerald-400'
                            : status === 'RESTRICTED'
                              ? 'bg-amber-400'
                              : status === 'UNTRUSTED'
                                ? 'bg-red-400'
                                : 'bg-gray-500'
                            }`}
                        />
                      </div>
                    </div>
                  ))}
                </div>
              ) : (
                <div className="py-8 text-center text-xs text-gray-500">
                  No Zero Trust asset assessments evaluated yet.
                </div>
              )}
            </div>

            {/* Quick Actions & SMB Security Operations Guidance */}
            <div className="p-5 rounded-xl bg-gray-900 border border-gray-800 flex flex-col justify-between">
              <div>
                <h3 className="text-sm font-semibold text-white mb-2 flex items-center gap-2">
                  <Sliders className="w-4 h-4 text-cyan-400" />
                  SMB Security Operations Guidance
                </h3>
                <p className="text-xs text-gray-400 mb-4 leading-relaxed">
                  Real-time events from Nginx reverse proxy and WAF rules are automatically ingested,
                  sanitized, and correlated. High and critical alerts generate immediate incident records
                  requiring containment.
                </p>
                <div className="space-y-2">
                  <div className="flex items-center justify-between p-2.5 rounded-lg bg-gray-800/60 border border-gray-700/50 text-xs">
                    <span className="text-gray-300">Unacknowledged Alerts</span>
                    <span className="font-semibold text-amber-400">
                      {overview ? overview.unacknowledged_alerts_count : 0}
                    </span>
                  </div>
                  <div className="flex items-center justify-between p-2.5 rounded-lg bg-gray-800/60 border border-gray-700/50 text-xs">
                    <span className="text-gray-300">Correlated Open Incidents</span>
                    <span className="font-semibold text-red-400">
                      {overview ? overview.open_incidents_total : 0}
                    </span>
                  </div>
                </div>
              </div>
              <div className="pt-4 flex items-center gap-3">
                <button
                  onClick={() => setActiveTab('incidents')}
                  className="flex-1 py-2 px-3 text-xs font-medium text-center rounded-lg bg-cyan-600 hover:bg-cyan-500 text-white transition-colors"
                >
                  Manage Incidents
                </button>
                <button
                  onClick={() => setActiveTab('events')}
                  className="flex-1 py-2 px-3 text-xs font-medium text-center rounded-lg bg-gray-800 hover:bg-gray-700 text-gray-200 border border-gray-700 transition-colors"
                >
                  View Event Stream
                </button>
              </div>
            </div>
          </div>
        </div>
      )}

      {/* ========================================================================= */}
      {/* TAB 2: LIVE SECURITY EVENT STREAM (SSE) */}
      {/* ========================================================================= */}
      {activeTab === 'events' && (
        <div className="space-y-4">
          {/* Filters Bar */}
          <div className="flex flex-col md:flex-row md:items-center justify-between gap-3 p-3 bg-gray-900 border border-gray-800 rounded-xl">
            <div className="flex items-center gap-2 flex-1">
              <Search className="w-4 h-4 text-gray-500 ml-1" />
              <input
                type="text"
                placeholder="Search events by title, IP address, or URI..."
                value={eventSearch}
                onChange={(e) => setEventSearch(e.target.value)}
                className="w-full bg-transparent text-xs text-white placeholder-gray-500 focus:outline-none"
              />
              {eventSearch && (
                <button onClick={() => setEventSearch('')} className="text-gray-500 hover:text-white">
                  <X className="w-3.5 h-3.5" />
                </button>
              )}
            </div>

            <div className="flex items-center gap-2">
              <select
                value={eventCategoryFilter}
                onChange={(e) => setEventCategoryFilter(e.target.value)}
                className="bg-gray-800 border border-gray-700 rounded-lg px-2.5 py-1.5 text-xs text-gray-200 focus:outline-none"
              >
                <option value="ALL">All Categories</option>
                <option value="SECURITY">Security</option>
                <option value="TRAFFIC">Traffic</option>
                <option value="ERROR">Error</option>
                <option value="AUTH">Authentication</option>
                <option value="SYSTEM">System</option>
                <option value="ROLLBACK">Rollback</option>
              </select>

              <select
                value={eventSeverityFilter}
                onChange={(e) => setEventSeverityFilter(e.target.value)}
                className="bg-gray-800 border border-gray-700 rounded-lg px-2.5 py-1.5 text-xs text-gray-200 focus:outline-none"
              >
                <option value="ALL">All Severities</option>
                <option value="CRITICAL">Critical</option>
                <option value="HIGH">High</option>
                <option value="MEDIUM">Medium</option>
                <option value="LOW">Low</option>
                <option value="INFO">Info</option>
              </select>
            </div>
          </div>

          {/* Events Table */}
          <div className="overflow-x-auto rounded-xl border border-gray-800 bg-gray-900">
            <table className="w-full text-left text-xs text-gray-300">
              <thead className="bg-gray-800/80 text-gray-400 uppercase text-[10px] tracking-wider border-b border-gray-800">
                <tr>
                  <th className="py-3 px-4">Timestamp</th>
                  <th className="py-3 px-4">Severity</th>
                  <th className="py-3 px-4">Source & Category</th>
                  <th className="py-3 px-4">Event Details</th>
                  <th className="py-3 px-4">Source IP</th>
                  <th className="py-3 px-4">HTTP Target</th>
                  <th className="py-3 px-4 text-right">Inspect</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-gray-800/50">
                {filteredEvents.length > 0 ? (
                  filteredEvents.map((ev) => (
                    <tr key={ev.id} className="hover:bg-gray-800/40 transition-colors">
                      <td className="py-3 px-4 font-mono text-[11px] text-gray-400 whitespace-nowrap">
                        {new Date(ev.timestamp).toLocaleTimeString()}
                      </td>
                      <td className="py-3 px-4">
                        <span className={`px-2 py-0.5 rounded text-[10px] font-bold ${getSeverityBadgeClass(ev.severity)}`}>
                          {ev.severity}
                        </span>
                      </td>
                      <td className="py-3 px-4">
                        <div className="font-medium text-white">{ev.source}</div>
                        <div className="text-[10px] text-gray-400">{ev.category}</div>
                      </td>
                      <td className="py-3 px-4 max-w-xs">
                        <div className="font-medium text-gray-200 truncate">{ev.title}</div>
                        <div className="text-[10px] text-gray-400 truncate">{ev.description}</div>
                      </td>
                      <td className="py-3 px-4 font-mono text-[11px] text-cyan-400">
                        {ev.source_ip || '--'}
                      </td>
                      <td className="py-3 px-4 font-mono text-[11px] text-gray-300 max-w-xs truncate">
                        {ev.http_method && <span className="text-amber-400 font-bold mr-1">{ev.http_method}</span>}
                        {ev.target_uri || '--'}
                        {ev.status_code && (
                          <span
                            className={`ml-1 px-1 py-0.2 rounded text-[10px] ${ev.status_code >= 400 ? 'bg-red-500/20 text-red-300' : 'bg-green-500/20 text-green-300'
                              }`}
                          >
                            {ev.status_code}
                          </span>
                        )}
                      </td>
                      <td className="py-3 px-4 text-right">
                        <button
                          onClick={() => setSelectedEvent(ev)}
                          className="px-2 py-1 rounded bg-gray-800 hover:bg-gray-700 text-gray-300 text-[11px] transition-colors"
                        >
                          <Eye className="w-3.5 h-3.5 inline mr-1" />
                          View
                        </button>
                      </td>
                    </tr>
                  ))
                ) : (
                  <tr>
                    <td colSpan={7} className="py-12 text-center text-xs text-gray-500">
                      No security events recorded matching the current filters.
                    </td>
                  </tr>
                )}
              </tbody>
            </table>
          </div>
        </div>
      )}

      {/* ========================================================================= */}
      {/* TAB 3: CORRELATED SECURITY INCIDENTS */}
      {/* ========================================================================= */}
      {activeTab === 'incidents' && (
        <div className="space-y-4">
          {/* Header & Controls */}
          <div className="flex flex-col md:flex-row md:items-center justify-between gap-3 p-3 bg-gray-900 border border-gray-800 rounded-xl">
            <div className="flex items-center gap-2">
              <select
                value={incidentStatusFilter}
                onChange={(e) => setIncidentStatusFilter(e.target.value)}
                className="bg-gray-800 border border-gray-700 rounded-lg px-2.5 py-1.5 text-xs text-gray-200 focus:outline-none"
              >
                <option value="ALL">All Statuses</option>
                <option value="OPEN">Open</option>
                <option value="ACKNOWLEDGED">Acknowledged</option>
                <option value="INVESTIGATING">Investigating</option>
                <option value="CONTAINED">Contained</option>
                <option value="RESOLVED">Resolved</option>
                <option value="CLOSED">Closed</option>
              </select>

              <select
                value={incidentSeverityFilter}
                onChange={(e) => setIncidentSeverityFilter(e.target.value)}
                className="bg-gray-800 border border-gray-700 rounded-lg px-2.5 py-1.5 text-xs text-gray-200 focus:outline-none"
              >
                <option value="ALL">All Severities</option>
                <option value="CRITICAL">Critical</option>
                <option value="HIGH">High</option>
                <option value="MEDIUM">Medium</option>
                <option value="LOW">Low</option>
              </select>
            </div>

            <button
              onClick={() => setIsCreateIncidentModalOpen(true)}
              className="flex items-center gap-1.5 px-3 py-1.5 text-xs font-medium rounded-lg bg-cyan-600 hover:bg-cyan-500 text-white transition-colors"
            >
              <Plus className="w-3.5 h-3.5" />
              New Incident
            </button>
          </div>

          {/* Incidents List & Drawer Layout */}
          <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
            {/* Left 2 Cols: Incidents Table */}
            <div className="lg:col-span-2 overflow-x-auto rounded-xl border border-gray-800 bg-gray-900">
              <table className="w-full text-left text-xs text-gray-300">
                <thead className="bg-gray-800/80 text-gray-400 uppercase text-[10px] tracking-wider border-b border-gray-800">
                  <tr>
                    <th className="py-3 px-4">Incident #</th>
                    <th className="py-3 px-4">Severity</th>
                    <th className="py-3 px-4">Title & Description</th>
                    <th className="py-3 px-4">MITRE Technique</th>
                    <th className="py-3 px-4">Status</th>
                    <th className="py-3 px-4 text-right">Action</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-gray-800/50">
                  {filteredIncidents.length > 0 ? (
                    filteredIncidents.map((inc) => (
                      <tr
                        key={inc.id}
                        onClick={() => handleSelectIncident(inc.id)}
                        className={`cursor-pointer transition-colors ${selectedIncidentId === inc.id ? 'bg-cyan-950/30 border-l-2 border-cyan-400' : 'hover:bg-gray-800/40'
                          }`}
                      >
                        <td className="py-3 px-4 font-mono font-bold text-cyan-400 whitespace-nowrap">
                          {inc.incident_number}
                        </td>
                        <td className="py-3 px-4">
                          <span className={`px-2 py-0.5 rounded text-[10px] font-bold ${getSeverityBadgeClass(inc.severity)}`}>
                            {inc.severity}
                          </span>
                        </td>
                        <td className="py-3 px-4 max-w-xs">
                          <div className="font-semibold text-white truncate">{inc.title}</div>
                          <div className="text-[10px] text-gray-400 truncate">{inc.description}</div>
                        </td>
                        <td className="py-3 px-4">
                          {inc.mitre_attack_id ? (
                            <span className="px-2 py-0.5 rounded text-[10px] font-mono bg-indigo-500/20 text-indigo-300 border border-indigo-500/30">
                              {inc.mitre_attack_id}
                            </span>
                          ) : (
                            <span className="text-gray-500 text-[10px]">--</span>
                          )}
                        </td>
                        <td className="py-3 px-4">
                          <span className={`px-2 py-0.5 rounded text-[10px] font-semibold ${getStatusBadgeClass(inc.status)}`}>
                            {inc.status}
                          </span>
                        </td>
                        <td className="py-3 px-4 text-right">
                          <button
                            onClick={(e) => {
                              e.stopPropagation();
                              handleSelectIncident(inc.id);
                            }}
                            className="px-2 py-1 rounded bg-gray-800 hover:bg-gray-700 text-gray-300 text-[11px]"
                          >
                            Details
                          </button>
                        </td>
                      </tr>
                    ))
                  ) : (
                    <tr>
                      <td colSpan={6} className="py-12 text-center text-xs text-gray-500">
                        No security incidents found.
                      </td>
                    </tr>
                  )}
                </tbody>
              </table>
            </div>

            {/* Right Col: Incident Details & Containment Drawer */}
            <div className="lg:col-span-1 p-4 rounded-xl bg-gray-900 border border-gray-800 flex flex-col justify-between">
              {isDetailLoading ? (
                <div className="py-24 text-center text-xs text-cyan-400 animate-pulse">
                  Loading incident details...
                </div>
              ) : selectedIncidentId && incidentDetail ? (
                <div className="space-y-4">
                  {/* Incident Header */}
                  <div>
                    <div className="flex items-center justify-between">
                      <span className="font-mono text-xs font-bold text-cyan-400">
                        {incidentDetail.incident_number}
                      </span>
                      <span className={`px-2 py-0.5 rounded text-[10px] font-bold ${getSeverityBadgeClass(incidentDetail.severity)}`}>
                        {incidentDetail.severity}
                      </span>
                    </div>
                    <h3 className="text-sm font-bold text-white mt-1">{incidentDetail.title}</h3>
                    <p className="text-xs text-gray-400 mt-1">{incidentDetail.description}</p>
                  </div>

                  {/* Status Lifecycle Selector */}
                  <div>
                    <label className="text-[10px] uppercase tracking-wider text-gray-400 block mb-1">
                      Incident Status
                    </label>
                    <select
                      value={incidentDetail.status}
                      onChange={(e) => handleUpdateStatus(e.target.value)}
                      className="w-full bg-gray-800 border border-gray-700 rounded-lg p-2 text-xs text-white focus:outline-none"
                    >
                      <option value="OPEN">OPEN</option>
                      <option value="ACKNOWLEDGED">ACKNOWLEDGED</option>
                      <option value="INVESTIGATING">INVESTIGATING</option>
                      <option value="CONTAINED">CONTAINED</option>
                      <option value="RESOLVED">RESOLVED</option>
                      <option value="CLOSED">CLOSED</option>
                    </select>
                  </div>

                  {/* Containment Section */}
                  <div className="p-3 rounded-lg bg-gray-800/80 border border-gray-700/60">
                    <h4 className="text-xs font-semibold text-white flex items-center gap-1.5 mb-2">
                      <Lock className="w-3.5 h-3.5 text-purple-400" />
                      Containment Workflow
                    </h4>
                    {incidentDetail.containment_action_taken ? (
                      <div className="p-2 bg-purple-500/10 border border-purple-500/30 text-purple-300 text-[11px] rounded">
                        Action Taken: {incidentDetail.containment_action_taken}
                      </div>
                    ) : (
                      <form onSubmit={handleExecuteContainment} className="space-y-2">
                        <select
                          value={containmentAction}
                          onChange={(e) => setContainmentAction(e.target.value)}
                          className="w-full bg-gray-900 border border-gray-700 rounded px-2 py-1 text-xs text-white"
                        >
                          <option value="BLOCK_SOURCE_IP">Block Source IP at WAF</option>
                          <option value="DEPLOY_VIRTUAL_PATCH">Generate & Stage Virtual Patch</option>
                          <option value="ISOLATE_ASSET">Isolate Vulnerable Asset</option>
                          <option value="REVOKE_SESSIONS">Revoke Compromised Sessions</option>
                        </select>
                        <input
                          type="text"
                          placeholder="Containment rationale / notes..."
                          value={containmentNotes}
                          onChange={(e) => setContainmentNotes(e.target.value)}
                          className="w-full bg-gray-900 border border-gray-700 rounded px-2 py-1 text-xs text-white placeholder-gray-500"
                        />
                        <div className="flex items-center gap-2">
                          <input
                            type="checkbox"
                            id="containmentApproval"
                            checked={containmentApproved}
                            onChange={(e) => setContainmentApproved(e.target.checked)}
                            className="rounded border-gray-700 bg-gray-900 text-cyan-500"
                          />
                          <label htmlFor="containmentApproval" className="text-[11px] text-gray-300">
                            I am authorized to execute disruptive containment
                          </label>
                        </div>
                        <button
                          type="submit"
                          disabled={isExecutingContainment}
                          className="w-full py-1.5 text-xs font-medium rounded bg-purple-600 hover:bg-purple-500 text-white transition-colors"
                        >
                          {isExecutingContainment ? 'Executing...' : 'Execute Containment'}
                        </button>
                      </form>
                    )}
                  </div>

                  {/* Timeline & Notes */}
                  <div>
                    <h4 className="text-xs font-semibold text-white mb-2 flex items-center gap-1.5">
                      <Clock className="w-3.5 h-3.5 text-cyan-400" />
                      Investigation Timeline ({(incidentDetail.timeline_entries || []).length})
                    </h4>
                    <div className="max-h-48 overflow-y-auto space-y-2 pr-1">
                      {(incidentDetail.timeline_entries || []).map((entry) => (
                        <div key={entry.id} className="p-2 rounded bg-gray-800/50 border border-gray-800 text-[11px]">
                          <div className="flex items-center justify-between text-gray-400 text-[10px]">
                            <span>{entry.entry_type}</span>
                            <span>{new Date(entry.created_at).toLocaleTimeString()}</span>
                          </div>
                          <div className="text-gray-200 mt-1">{entry.message}</div>
                        </div>
                      ))}
                    </div>

                    {/* Add Analyst Note Form */}
                    <form onSubmit={handleAddAnalystNote} className="mt-3 flex gap-2">
                      <input
                        type="text"
                        placeholder="Add analyst note..."
                        value={newAnalystNote}
                        onChange={(e) => setNewAnalystNote(e.target.value)}
                        className="flex-1 bg-gray-800 border border-gray-700 rounded px-2.5 py-1 text-xs text-white placeholder-gray-500 focus:outline-none"
                      />
                      <button
                        type="submit"
                        disabled={isSubmittingNote || !newAnalystNote.trim()}
                        className="px-3 py-1 bg-cyan-600 hover:bg-cyan-500 text-white text-xs rounded transition-colors disabled:opacity-50"
                      >
                        <Send className="w-3.5 h-3.5" />
                      </button>
                    </form>
                  </div>
                </div>
              ) : (
                <div className="py-24 text-center text-xs text-gray-500">
                  Select an incident from the table to inspect details, containment workflows, and investigation notes.
                </div>
              )}
            </div>
          </div>
        </div>
      )}

      {/* ========================================================================= */}
      {/* TAB 4: IN-APP ALERTS & RETENTION MANAGEMENT */}
      {/* ========================================================================= */}
      {activeTab === 'alerts_retention' && (
        <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
          {/* Alerts List */}
          <div className="p-5 rounded-xl bg-gray-900 border border-gray-800">
            <h3 className="text-sm font-semibold text-white mb-3 flex items-center justify-between">
              <span className="flex items-center gap-2">
                <AlertCircle className="w-4 h-4 text-amber-400" />
                Operational In-App Alerts
              </span>
              <span className="text-xs font-normal text-gray-400">
                {(alerts || []).filter((a) => !a.is_acknowledged).length} unacknowledged
              </span>
            </h3>

            <div className="space-y-3 max-h-96 overflow-y-auto pr-1">
              {(alerts || []).length > 0 ? (
                (alerts || []).map((alert) => (
                  <div
                    key={alert.id}
                    className={`p-3 rounded-lg border text-xs transition-colors flex items-start justify-between gap-3 ${alert.is_acknowledged
                      ? 'bg-gray-800/30 border-gray-800/60 opacity-60'
                      : 'bg-gray-800/80 border-gray-700'
                      }`}
                  >
                    <div>
                      <div className="flex items-center gap-2">
                        <span className={`px-1.5 py-0.2 rounded text-[10px] font-bold ${getSeverityBadgeClass(alert.severity)}`}>
                          {alert.severity}
                        </span>
                        <span className="font-semibold text-white">{alert.title}</span>
                      </div>
                      <p className="text-gray-300 text-[11px] mt-1">{alert.message}</p>
                      <div className="text-[10px] text-gray-500 mt-1">
                        {new Date(alert.created_at).toLocaleString()}
                      </div>
                    </div>

                    {!alert.is_acknowledged && (
                      <button
                        onClick={() => handleAcknowledgeAlert(alert.id)}
                        className="px-2 py-1 rounded bg-gray-700 hover:bg-gray-600 text-gray-200 text-[10px] whitespace-nowrap transition-colors"
                      >
                        Acknowledge
                      </button>
                    )}
                  </div>
                ))
              ) : (
                <div className="py-12 text-center text-xs text-gray-500">
                  No active security alerts recorded.
                </div>
              )}
            </div>
          </div>

          {/* Retention Policy Settings */}
          <div className="p-5 rounded-xl bg-gray-900 border border-gray-800">
            <h3 className="text-sm font-semibold text-white mb-3 flex items-center gap-2">
              <Sliders className="w-4 h-4 text-cyan-400" />
              Event Retention & Database Hygiene
            </h3>
            <p className="text-xs text-gray-400 mb-4">
              Configure tenant retention policies to automatically prune telemetry events and prevent unbounded database growth.
            </p>

            <form onSubmit={handleSaveRetention} className="space-y-4 text-xs">
              <div>
                <label className="text-gray-300 block mb-1">
                  Retention Window (Days): <span className="text-cyan-400 font-semibold">{retentionDays} days</span>
                </label>
                <input
                  type="range"
                  min={1}
                  max={365}
                  value={retentionDays}
                  onChange={(e) => setRetentionDays(Number(e.target.value))}
                  className="w-full accent-cyan-500"
                />
              </div>

              <div>
                <label className="text-gray-300 block mb-1">
                  Maximum Stored Events Limit: <span className="text-cyan-400 font-semibold">{maxStoredEvents.toLocaleString()}</span>
                </label>
                <input
                  type="range"
                  min={1000}
                  max={500000}
                  step={1000}
                  value={maxStoredEvents}
                  onChange={(e) => setMaxStoredEvents(Number(e.target.value))}
                  className="w-full accent-cyan-500"
                />
              </div>

              <div className="flex items-center gap-2 pt-2">
                <input
                  type="checkbox"
                  id="autoPruneSwitch"
                  checked={autoPrune}
                  onChange={(e) => setAutoPrune(e.target.checked)}
                  className="rounded border-gray-700 bg-gray-800 text-cyan-500"
                />
                <label htmlFor="autoPruneSwitch" className="text-gray-300">
                  Enable automated background retention pruning (Celery task)
                </label>
              </div>

              {retentionPolicy?.last_pruned_at && (
                <div className="text-[11px] text-gray-400">
                  Last automated prune: {new Date(retentionPolicy.last_pruned_at).toLocaleString()}
                </div>
              )}

              <div className="pt-4 flex items-center gap-3">
                <button
                  type="submit"
                  disabled={isSavingRetention}
                  className="flex-1 py-2 text-xs font-medium rounded-lg bg-cyan-600 hover:bg-cyan-500 text-white transition-colors"
                >
                  {isSavingRetention ? 'Saving...' : 'Save Retention Policy'}
                </button>
                <button
                  type="button"
                  onClick={handlePruneNow}
                  className="py-2 px-3 text-xs font-medium rounded-lg bg-gray-800 hover:bg-gray-700 text-red-400 border border-gray-700 transition-colors flex items-center gap-1.5"
                >
                  <Trash2 className="w-3.5 h-3.5" />
                  Prune Now
                </button>
              </div>
            </form>
          </div>
        </div>
      )}

      {/* ========================================================================= */}
      {/* EVENT DETAIL INSPECTION MODAL */}
      {/* ========================================================================= */}
      {selectedEvent && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/70 backdrop-blur-sm p-4">
          <div className="bg-gray-900 border border-gray-800 rounded-xl max-w-2xl w-full p-6 space-y-4">
            <div className="flex items-center justify-between border-b border-gray-800 pb-3">
              <div>
                <span className="text-xs font-mono text-cyan-400">Event #{selectedEvent.id.slice(0, 8)}</span>
                <h3 className="text-sm font-bold text-white mt-0.5">{selectedEvent.title}</h3>
              </div>
              <button onClick={() => setSelectedEvent(null)} className="text-gray-400 hover:text-white">
                <X className="w-5 h-5" />
              </button>
            </div>

            <div className="space-y-3 text-xs">
              <div className="grid grid-cols-2 gap-2 text-gray-400">
                <div>
                  <span className="block text-[10px] uppercase">Source / Category</span>
                  <span className="text-white font-medium">{selectedEvent.source} / {selectedEvent.category}</span>
                </div>
                <div>
                  <span className="block text-[10px] uppercase">Severity</span>
                  <span className={`px-2 py-0.5 rounded text-[10px] font-bold ${getSeverityBadgeClass(selectedEvent.severity)}`}>
                    {selectedEvent.severity}
                  </span>
                </div>
                <div>
                  <span className="block text-[10px] uppercase">Source IP</span>
                  <span className="text-cyan-400 font-mono">{selectedEvent.source_ip || '--'}</span>
                </div>
                <div>
                  <span className="block text-[10px] uppercase">Target URI</span>
                  <span className="text-gray-300 font-mono truncate">{selectedEvent.target_uri || '--'}</span>
                </div>
              </div>

              <div>
                <span className="block text-[10px] uppercase text-gray-400 mb-1">Fingerprint (SHA256)</span>
                <code className="block p-2 rounded bg-gray-950 font-mono text-[10px] text-gray-400 break-all">
                  {selectedEvent.fingerprint}
                </code>
              </div>

              {selectedEvent.raw_payload && (
                <div>
                  <span className="block text-[10px] uppercase text-gray-400 mb-1">Sanitized Raw Payload</span>
                  <pre className="p-3 rounded bg-gray-950 font-mono text-[10px] text-gray-300 max-h-40 overflow-y-auto whitespace-pre-wrap">
                    {selectedEvent.raw_payload}
                  </pre>
                </div>
              )}

              {selectedEvent.event_metadata && Object.keys(selectedEvent.event_metadata).length > 0 && (
                <div>
                  <span className="block text-[10px] uppercase text-gray-400 mb-1">Event Metadata</span>
                  <pre className="p-3 rounded bg-gray-950 font-mono text-[10px] text-cyan-300 max-h-36 overflow-y-auto">
                    {JSON.stringify(selectedEvent.event_metadata, null, 2)}
                  </pre>
                </div>
              )}
            </div>

            <div className="pt-2 flex justify-end">
              <button
                onClick={() => setSelectedEvent(null)}
                className="px-4 py-1.5 rounded-lg bg-gray-800 hover:bg-gray-700 text-xs text-white"
              >
                Close
              </button>
            </div>
          </div>
        </div>
      )}

      {/* ========================================================================= */}
      {/* CREATE MANUAL INCIDENT MODAL */}
      {/* ========================================================================= */}
      {isCreateIncidentModalOpen && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/70 backdrop-blur-sm p-4">
          <div className="bg-gray-900 border border-gray-800 rounded-xl max-w-lg w-full p-6 space-y-4">
            <div className="flex items-center justify-between border-b border-gray-800 pb-3">
              <h3 className="text-sm font-bold text-white">Create Security Incident</h3>
              <button onClick={() => setIsCreateIncidentModalOpen(false)} className="text-gray-400 hover:text-white">
                <X className="w-5 h-5" />
              </button>
            </div>

            <form onSubmit={handleCreateIncident} className="space-y-3 text-xs">
              <div>
                <label className="text-gray-300 block mb-1">Incident Title *</label>
                <input
                  type="text"
                  required
                  placeholder="e.g. Repeated SQL Injection attack against Payment Gateway"
                  value={newIncidentTitle}
                  onChange={(e) => setNewIncidentTitle(e.target.value)}
                  className="w-full bg-gray-800 border border-gray-700 rounded-lg p-2 text-white placeholder-gray-500 focus:outline-none"
                />
              </div>

              <div>
                <label className="text-gray-300 block mb-1">Description *</label>
                <textarea
                  required
                  rows={3}
                  placeholder="Describe observed attacker behavior, affected components, and risk..."
                  value={newIncidentDesc}
                  onChange={(e) => setNewIncidentDesc(e.target.value)}
                  className="w-full bg-gray-800 border border-gray-700 rounded-lg p-2 text-white placeholder-gray-500 focus:outline-none"
                />
              </div>

              <div className="grid grid-cols-2 gap-3">
                <div>
                  <label className="text-gray-300 block mb-1">Severity</label>
                  <select
                    value={newIncidentSeverity}
                    onChange={(e) => setNewIncidentSeverity(e.target.value)}
                    className="w-full bg-gray-800 border border-gray-700 rounded-lg p-2 text-white"
                  >
                    <option value="CRITICAL">CRITICAL</option>
                    <option value="HIGH">HIGH</option>
                    <option value="MEDIUM">MEDIUM</option>
                    <option value="LOW">LOW</option>
                  </select>
                </div>
                <div>
                  <label className="text-gray-300 block mb-1">MITRE ATT&CK Technique</label>
                  <input
                    type="text"
                    placeholder="e.g. T1190 - Exploit Public-Facing App"
                    value={newIncidentMitre}
                    onChange={(e) => setNewIncidentMitre(e.target.value)}
                    className="w-full bg-gray-800 border border-gray-700 rounded-lg p-2 text-white placeholder-gray-500"
                  />
                </div>
              </div>

              <div className="pt-3 flex justify-end gap-2">
                <button
                  type="button"
                  onClick={() => setIsCreateIncidentModalOpen(false)}
                  className="px-3 py-1.5 rounded-lg bg-gray-800 hover:bg-gray-700 text-xs text-gray-300"
                >
                  Cancel
                </button>
                <button
                  type="submit"
                  className="px-4 py-1.5 rounded-lg bg-cyan-600 hover:bg-cyan-500 text-xs font-medium text-white"
                >
                  Create Incident
                </button>
              </div>
            </form>
          </div>
        </div>
      )}
    </div>
  );
};
