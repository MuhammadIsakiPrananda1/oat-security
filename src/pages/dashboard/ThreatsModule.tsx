import React, { useState, useEffect, useCallback, useMemo } from 'react';
import { 
  Bug, 
  ShieldCheck, 
  Search, 
  Download, 
  CheckCircle2, 
  AlertTriangle,
  RefreshCw,
  Ban,
  Eye,
  Target,
  WifiOff,
  Siren,
  ArrowUpRight
} from 'lucide-react';
import { securityApi, globalRealtimeClient, RealtimeStreamStatus } from '../../services/api';
import { ThreatItem, SecurityEvent } from '../../types';
import { StatusBadge } from '../../components/common/StatusBadge';
import { BackendOfflineBanner } from '../../components/common/BackendOfflineBanner';
import { FontAwesomeIcon } from '@fortawesome/react-fontawesome';
import { faBug } from '@fortawesome/free-solid-svg-icons';
import { ModulePageHeader } from '../../components/common/ModulePageHeader';
import { useAuth } from '../../context/AuthContext';
import { formatTime } from '../../utils/dateTime';
import { DashboardView } from '../../components/layout/DashboardSidebar';
import { incidentToThreatItem, isClosedIncident } from '../../utils/incidentFeed';

interface ThreatsModuleProps {
  onNavigate?: (view: DashboardView) => void;
}

/** Status colour shared by the table and the detail drawer. */
function statusTone(status: string): string {
  const value = String(status || '').toUpperCase();
  if (['BLOCKED', 'MITIGATED', 'RESOLVED', 'CLOSED', 'CONTAINED'].includes(value)) {
    return 'bg-emerald-500/10 text-emerald-600 dark:text-emerald-400 border-emerald-500/20';
  }
  if (['INVESTIGATING', 'INVESTIGATION'].includes(value)) {
    return 'bg-zinc-100 dark:bg-zinc-800/60 text-zinc-600 dark:text-slate-300 border-zinc-200 dark:border-zinc-800';
  }
  return 'bg-rose-500/10 text-rose-600 dark:text-rose-400 border-rose-500/20 animate-pulse';
}

export const ThreatsModule: React.FC<ThreatsModuleProps> = ({ onNavigate }) => {
  const { isBackendOffline } = useAuth();
  const [threats, setThreats] = useState<ThreatItem[]>([]);
  // SOC incidents are surfaced in the same feed as correlated threats.
  const [incidents, setIncidents] = useState<ThreatItem[]>([]);

  const [, setTotalCount] = useState<number>(0);
  const [metrics, setMetrics] = useState<{
    total: number;
    critical: number;
    high: number;
    medium: number;
    low: number;
    unresolved: number;
  }>({
    total: 0,
    critical: 0,
    high: 0,
    medium: 0,
    low: 0,
    unresolved: 0
  });

  const [loading, setLoading] = useState(true);
  const [search, setSearch] = useState('');
  const [filterSeverity, setFilterSeverity] = useState('ALL');
  const [filterStatus, setFilterStatus] = useState('ALL');
  const [filterCategory] = useState('ALL');
  const [feedback, setFeedback] = useState<string | null>(null);
  const [realtimeStatus, setRealtimeStatus] = useState<RealtimeStreamStatus>('CONNECTED');

  // Real-time tracking of recent threats arriving from agents
  const [recentThreatIds, setRecentThreatIds] = useState<Set<string>>(new Set());

  const [selectedThreat, setSelectedThreat] = useState<ThreatItem | null>(null);
  const [threatDetail, setThreatDetail] = useState<(ThreatItem & { relatedEventsDetails?: SecurityEvent[] }) | null>(null);
  const [, setLoadingDetail] = useState(false);
  const [mitigatingId, setMitigatingId] = useState<string | null>(null);

  const fetchThreats = useCallback(async () => {
    setLoading(true);
    try {
      const res = await securityApi.getThreats({
        severity: filterSeverity !== 'ALL' ? filterSeverity : undefined,
        status: filterStatus !== 'ALL' ? filterStatus : undefined,
        category: filterCategory !== 'ALL' ? filterCategory : undefined,
        search: search.trim() ? search.trim() : undefined
      });

      const loadedThreats = res.threats || [];
      setThreats(loadedThreats);
      setTotalCount(res.total || loadedThreats.length);
      if (res.metrics) {
        setMetrics(res.metrics);
      }
    } catch (e) {
      console.error('[ThreatsModule] Fetch error:', e);
    } finally {
      setLoading(false);
    }
  }, [filterSeverity, filterStatus, filterCategory, search]);

  const fetchIncidents = useCallback(async () => {
    try {
      const res = await securityApi.getIncidents();
      setIncidents((res.incidents || []).map(incidentToThreatItem));
    } catch (e) {
      console.error('[ThreatsModule] Incident feed fetch error:', e);
    }
  }, []);

  useEffect(() => {
    fetchThreats();
  }, [fetchThreats, isBackendOffline]);

  useEffect(() => {
    void fetchIncidents();
  }, [fetchIncidents, isBackendOffline]);

  /**
   * The server filters `threats` at query time, but the incident feed arrives
   * as a full snapshot, so incidents are filtered here with the same rules and
   * then merged chronologically into one correlated view.
   */
  const displayRows = useMemo(() => {
    const term = search.trim().toLowerCase();
    const severity = filterSeverity.toLowerCase();
    const status = filterStatus.toLowerCase();

    const matchesIncident = (item: ThreatItem) => {
      if (severity !== 'all' && String(item.severity || '').toLowerCase() !== severity) return false;
      if (status !== 'all' && String(item.status || '').toLowerCase() !== status) return false;
      if (!term) return true;
      return [
        item.id,
        item.attackType,
        item.summary,
        item.affectedApplication,
        item.sourceIp,
        item.tier,
        item.assignedAnalyst
      ]
        .filter(Boolean)
        .some(value => String(value).toLowerCase().includes(term));
    };

    return [...threats, ...incidents.filter(matchesIncident)].sort(
      (a, b) => new Date(b.timestamp).getTime() - new Date(a.timestamp).getTime()
    );
  }, [threats, incidents, filterSeverity, filterStatus, search]);

  const openIncidentCount = useMemo(
    () => incidents.filter(item => !isClosedIncident(item.status)).length,
    [incidents]
  );

  // Real-time WebSocket listener for live threats from agents
  useEffect(() => {
    const unsubStatus = globalRealtimeClient.onStatusChange((status) => {
      setRealtimeStatus(status);
    });

    const unsubEvents = globalRealtimeClient.subscribe((msg: any) => {
      if (!msg) return;
      const type = msg.type || '';
      const data = msg.data || msg;

      if (type === 'incident.snapshot') {
        const snapshot = Array.isArray(data.incidents) ? data.incidents : [];
        setIncidents(snapshot.map(incidentToThreatItem));
      } else if (type === 'incident.created') {
        const item = data.data || data;
        if (!item?.id) return;

        const newIncident = incidentToThreatItem(item);

        setRecentThreatIds(prev => new Set(prev).add(newIncident.id));
        setTimeout(() => {
          setRecentThreatIds(prev => {
            const next = new Set(prev);
            next.delete(newIncident.id);
            return next;
          });
        }, 15000);

        setIncidents(prev => {
          if (prev.some(i => i.id === newIncident.id)) return prev;
          return [newIncident, ...prev];
        });

        setFeedback(`New incident received in real time: ${newIncident.attackType}`);
        setTimeout(() => setFeedback(null), 6000);
      } else if (type === 'incident.updated') {
        const incidentId = data.incidentId || data.id;
        if (!incidentId) return;

        setIncidents(prev => prev.map(item => {
          if (item.id !== incidentId) return item;
          return {
            ...item,
            ...(data.status ? { status: String(data.status).toUpperCase() } : {}),
            ...(data.tier ? { tier: data.tier } : {}),
            ...(data.assignedTo ? { assignedAnalyst: data.assignedTo } : {})
          };
        }));

        if (selectedThreat?.kind === 'incident' && selectedThreat.id === incidentId) {
          setSelectedThreat(prev => prev ? {
            ...prev,
            ...(data.status ? { status: String(data.status).toUpperCase() } : {}),
            ...(data.tier ? { tier: data.tier } : {}),
            ...(data.assignedTo ? { assignedAnalyst: data.assignedTo } : {})
          } : null);
        }
      } else if (type === 'incident.deleted') {
        const incidentId = data.incidentId || data.id;
        if (incidentId) {
          setIncidents(prev => prev.filter(item => item.id !== incidentId));
        }
      } else if (type === 'threat.snapshot') {
        if (filterSeverity === 'ALL' && filterStatus === 'ALL' && !search.trim()) {
          setThreats(data.threats || []);
          setTotalCount(data.total || 0);
          if (data.metrics) setMetrics(data.metrics);
        } else {
          void fetchThreats();
        }
      } else if (type === 'threat.created' || type === 'security.alert') {
        const item = data.data || data;
        if (!item || !item.id) return;

        const newThreat: ThreatItem = {
          id: item.id,
          timestamp: item.timestamp || new Date().toISOString(),
          sourceIp: item.sourceIp || item.source_ip || '0.0.0.0',
          target: item.target || 'Core Service',
          attackType: item.attackType || item.attack_type || 'Perimeter Attack',
          category: item.category || item.attack_type || 'Perimeter Attack',
          severity: item.severity || 'High',
          confidence: item.confidence || 95,
          action: item.action || 'DETECT',
          status: item.status || 'ACTIVE',
          summary: item.summary || 'Correlated security threat',
          detectionReason: item.detectionReason || item.detection_reason,
          affectedApplication: item.affectedApplication || item.affected_application || 'Edge Gateway',
          destination: item.destination,
          timeline: item.timeline || [{ time: new Date().toISOString(), event: 'Threat detected by Correlation Engine' }],
          relatedEvents: item.relatedEvents || item.related_events || [],
          recommendedAction: item.recommendedAction || item.recommended_action || 'Block ingress IP',
          mitre: item.mitre
        };

        // Highlight newly ingested threat
        setRecentThreatIds(prev => new Set(prev).add(newThreat.id));
        setTimeout(() => {
          setRecentThreatIds(prev => {
            const next = new Set(prev);
            next.delete(newThreat.id);
            return next;
          });
        }, 15000);

        // Prepend new threat to table
        setThreats(prev => {
          if (prev.some(t => t.id === newThreat.id)) return prev;
          return [newThreat, ...prev];
        });

        setTotalCount(prev => prev + 1);
        setMetrics(prev => ({
          ...prev,
          total: prev.total + 1,
          unresolved: prev.unresolved + 1,
          critical: String(newThreat.severity).toLowerCase() === 'critical' ? prev.critical + 1 : prev.critical,
          high: String(newThreat.severity).toLowerCase() === 'high' ? prev.high + 1 : prev.high
        }));
      } else if (type === 'threat.updated') {
        const threatId = data.threatId || data.id;
        const newStatus = data.status;
        const newTimestamp = data.timestamp;
        const related = data.relatedEvents || data.related_events;

        if (threatId) {
          setThreats(prev => {
            const idx = prev.findIndex(t => t.id === threatId);
            if (idx === -1) return prev;
            const updated: ThreatItem = {
              ...prev[idx],
              ...(newStatus ? { status: newStatus } : {}),
              ...(newTimestamp ? { timestamp: newTimestamp } : {}),
              ...(related ? { relatedEvents: related } : {})
            };
            const nextList = [...prev];
            nextList.splice(idx, 1);
            return [updated, ...nextList];
          });

          setRecentThreatIds(prev => new Set(prev).add(threatId));
          setTimeout(() => {
            setRecentThreatIds(prev => {
              const next = new Set(prev);
              next.delete(threatId);
              return next;
            });
          }, 10000);

          if (selectedThreat?.id === threatId) {
            setSelectedThreat(prev => prev ? {
              ...prev,
              ...(newStatus ? { status: newStatus } : {}),
              ...(newTimestamp ? { timestamp: newTimestamp } : {})
            } : null);
          }
        }
      }
    });

    return () => {
      unsubStatus();
      unsubEvents();
    };
  }, [selectedThreat, filterSeverity, filterStatus, search, fetchThreats]);

  // Open threat / incident detail modal
  const handleOpenDetail = async (threat: ThreatItem) => {
    setSelectedThreat(threat);
    if (threat.kind === 'incident') {
      setThreatDetail(threat);
      return;
    }
    setLoadingDetail(true);
    try {
      const detail = await securityApi.getThreatDetail(threat.id);
      setThreatDetail(detail);
    } catch {
      setThreatDetail(threat);
    } finally {
      setLoadingDetail(false);
    }
  };

  // Mitigate threat action (BLOCK / QUARANTINE / RESOLVE)
  const handleMitigate = async (id: string, action: 'BLOCK' | 'RESOLVE' = 'BLOCK') => {
    setMitigatingId(id);
    try {
      await securityApi.mitigateThreat(id, action);
      setFeedback(`Threat ${id} mitigated: Origin IP quarantined in Firewall & status updated.`);
      
      // Update local state immediately
      setThreats(prev => prev.map(t => t.id === id ? { ...t, status: action === 'BLOCK' ? 'BLOCKED' : 'RESOLVED' } : t));
      if (selectedThreat?.id === id) {
        setSelectedThreat(prev => prev ? { ...prev, status: action === 'BLOCK' ? 'BLOCKED' : 'RESOLVED' } : null);
      }
      setMetrics(prev => ({
        ...prev,
        unresolved: Math.max(0, prev.unresolved - 1)
      }));

      setTimeout(() => setFeedback(null), 5000);
    } catch {
      alert('Failed to apply threat mitigation rule.');
    } finally {
      setMitigatingId(null);
    }
  };

  if (isBackendOffline) {
    return <BackendOfflineBanner onRetry={fetchThreats} />;
  }

  return (
    <div className="space-y-6" id="threats-module-container">
      {/* Real-time Connection Banner (If connection lost) */}
      {realtimeStatus === 'REAL-TIME CONNECTION LOST' && (
        <div className="rounded-xl border border-rose-500/40 bg-rose-500/10 p-4 flex flex-col sm:flex-row sm:items-center justify-between gap-3 text-rose-700 dark:text-rose-200 animate-fadeIn">
          <div className="flex items-center gap-3">
            <WifiOff className="w-5 h-5 text-rose-600 dark:text-rose-400 animate-pulse" />
            <div>
              <div className="text-xs font-bold uppercase tracking-wider text-rose-600 dark:text-rose-400">REAL-TIME CONNECTION LOST</div>
              <div className="text-xs text-rose-600 dark:text-rose-400 mt-0.5">
                Threat correlation engine feed interrupted. Background reconnecting...
              </div>
            </div>
          </div>
          <button
            onClick={() => globalRealtimeClient.connect()}
            className="px-3 py-1.5 rounded-lg bg-rose-600 hover:bg-rose-500 text-white text-xs font-semibold cursor-pointer"
          >
            Reconnect
          </button>
        </div>
      )}

      {/* Action Notification Banner */}
      {feedback && (
        <div className="rounded-xl border border-emerald-500/40 bg-emerald-500/10 p-4 flex items-center gap-3 text-emerald-700 dark:text-emerald-200 animate-fadeIn">
          <CheckCircle2 className="w-5 h-5 text-emerald-600 dark:text-emerald-400 flex-shrink-0" />
          <div className="text-xs font-medium">{feedback}</div>
        </div>
      )}

      {/* Header */}
      <ModulePageHeader
        icon={<FontAwesomeIcon icon={faBug} />}
        title="Correlated"
        titleTail="Threat Intelligence"
        subtitle="Live automated threat correlation engine. Detected threats and the SOC incidents opened from them stream into this feed in real time."
        actions={
          <div className="flex flex-wrap items-center gap-2">
            <button
              onClick={() => { void fetchThreats(); void fetchIncidents(); }}
              title="Refresh correlated feed"
              className="inline-flex h-8 w-8 shrink-0 items-center justify-center rounded-lg border border-zinc-200/80 bg-white text-zinc-500 transition hover:border-zinc-300 hover:text-zinc-900 cursor-pointer dark:border-zinc-800 dark:bg-zinc-900 dark:text-zinc-400 dark:hover:border-zinc-600 dark:hover:text-zinc-100"
            >
              <RefreshCw className={`w-3.5 h-3.5 ${loading ? 'animate-spin' : ''}`} />
            </button>
            <button
              onClick={() => {
                const dataStr = "data:text/json;charset=utf-8," + encodeURIComponent(JSON.stringify(displayRows, null, 2));
                const downloadAnchor = document.createElement('a');
                downloadAnchor.setAttribute("href", dataStr);
                downloadAnchor.setAttribute("download", `oat_threats_export_${new Date().toISOString().slice(0, 10)}.json`);
                document.body.appendChild(downloadAnchor);
                downloadAnchor.click();
                downloadAnchor.remove();
              }}
              className="inline-flex h-8 items-center gap-1.5 rounded-lg border border-zinc-200/80 bg-white px-2.5 text-xs font-medium text-zinc-600 transition hover:border-zinc-300 hover:text-zinc-900 cursor-pointer dark:border-zinc-800 dark:bg-zinc-900 dark:text-zinc-300 dark:hover:border-zinc-600 dark:hover:text-zinc-100"
            >
              <Download className="w-3.5 h-3.5" />
              <span className="hidden sm:inline">Export</span>
            </button>
          </div>
        }
      />

      {/* Metrics Row (Direct from SQL calculation & live-synced) */}
      <div className="grid grid-cols-2 sm:grid-cols-3 lg:grid-cols-6 gap-3">
        <div className="p-3.5 rounded-xl border border-zinc-200/80 dark:border-zinc-800 bg-white dark:bg-[#0c0c0e]">
          <div className="text-[11px] font-medium text-zinc-500 dark:text-slate-400 uppercase tracking-wider">Total Threats</div>
          <div className="text-xl font-bold font-mono text-zinc-900 dark:text-white mt-1">{metrics.total}</div>
        </div>
        <div className="p-3.5 rounded-xl border border-zinc-200/80 dark:border-zinc-800 bg-white dark:bg-[#0c0c0e]">
          <div className="text-[11px] font-medium text-rose-600 dark:text-rose-400 uppercase tracking-wider">Critical Severity</div>
          <div className="text-xl font-bold font-mono text-rose-600 dark:text-rose-400 mt-1">{metrics.critical}</div>
        </div>
        <div className="p-3.5 rounded-xl border border-zinc-200/80 dark:border-zinc-800 bg-white dark:bg-[#0c0c0e]">
          <div className="text-[11px] font-medium text-amber-600 dark:text-amber-400 uppercase tracking-wider">High Severity</div>
          <div className="text-xl font-bold font-mono text-amber-600 dark:text-amber-400 mt-1">{metrics.high}</div>
        </div>
        <div className="p-3.5 rounded-xl border border-zinc-200/80 dark:border-zinc-800 bg-white dark:bg-[#0c0c0e]">
          <div className="text-[11px] font-medium text-rose-600 dark:text-rose-400 uppercase tracking-wider">Unresolved / Active</div>
          <div className="text-xl font-bold font-mono text-rose-600 dark:text-rose-400 mt-1">{metrics.unresolved}</div>
        </div>
        <div className="p-3.5 rounded-xl border border-zinc-200/80 dark:border-zinc-800 bg-white dark:bg-[#0c0c0e]">
          <div className="text-[11px] font-medium text-emerald-600 dark:text-emerald-400 uppercase tracking-wider">Mitigated / Blocked</div>
          <div className="text-xl font-bold font-mono text-emerald-600 dark:text-emerald-400 mt-1">{Math.max(0, metrics.total - metrics.unresolved)}</div>
        </div>
        <div className="p-3.5 rounded-xl border border-zinc-200/80 dark:border-zinc-800 bg-white dark:bg-[#0c0c0e]">
          <div className="flex items-center gap-1.5 text-[11px] font-medium text-amber-600 dark:text-amber-400 uppercase tracking-wider">
            <Siren className="w-3 h-3" />
            Open Incidents
          </div>
          <div className="text-xl font-bold font-mono text-amber-600 dark:text-amber-400 mt-1">{openIncidentCount}</div>
        </div>
      </div>

      {/* Search & Filter Toolbar */}
      <div className="p-4 rounded-xl border border-zinc-200/80 dark:border-zinc-800 bg-white dark:bg-[#0c0c0e] flex flex-wrap items-center gap-3">
        <div className="relative flex-1 min-w-[240px]">
          <Search className="w-4 h-4 text-zinc-400 dark:text-slate-500 absolute left-3 top-1/2 -translate-y-1/2" />
          <input
            type="text"
            value={search}
            onChange={e => setSearch(e.target.value)}
            placeholder="Search by Attacker IP, Target, Attack Type, Threat or Incident ID..."
            className="w-full pl-9 pr-3 py-1.5 bg-zinc-50 dark:bg-zinc-900/40 border border-zinc-200 dark:border-zinc-800 rounded-lg text-xs text-zinc-900 dark:text-white placeholder-zinc-400 dark:placeholder-zinc-500 focus:outline-none focus:border-zinc-400 dark:focus:border-zinc-700 transition"
          />
        </div>

        {/* Severity */}
        <select
          value={filterSeverity}
          onChange={e => setFilterSeverity(e.target.value)}
          className="px-3 py-1.5 bg-zinc-50 dark:bg-zinc-900/40 border border-zinc-200 dark:border-zinc-800 rounded-lg text-xs text-zinc-900 dark:text-white focus:outline-none focus:border-zinc-400 dark:focus:border-zinc-700 font-mono cursor-pointer"
        >
          <option value="ALL">Severity: All</option>
          <option value="Critical">Critical</option>
          <option value="High">High</option>
          <option value="Medium">Medium</option>
          <option value="Low">Low</option>
        </select>

        {/* Status */}
        <select
          value={filterStatus}
          onChange={e => setFilterStatus(e.target.value)}
          className="px-3 py-1.5 bg-zinc-50 dark:bg-zinc-900/40 border border-zinc-200 dark:border-zinc-800 rounded-lg text-xs text-zinc-900 dark:text-white focus:outline-none focus:border-zinc-400 dark:focus:border-zinc-700 font-mono cursor-pointer"
        >
          <option value="ALL">Status: All</option>
          <option value="ACTIVE">ACTIVE</option>
          <option value="NEW">NEW (Incident)</option>
          <option value="INVESTIGATING">INVESTIGATING</option>
          <option value="CONTAINED">CONTAINED</option>
          <option value="BLOCKED">BLOCKED</option>
          <option value="MITIGATED">MITIGATED</option>
          <option value="RESOLVED">RESOLVED</option>
          <option value="CLOSED">CLOSED</option>
        </select>
      </div>

      {/* Threats Table View */}
      <div className="rounded-xl border border-zinc-200/80 dark:border-zinc-800 bg-white dark:bg-[#0c0c0e] overflow-hidden">
        <div className="overflow-x-auto custom-scrollbar">
          <table className="w-full min-w-[1040px] text-left text-xs font-mono">
            <thead>
              <tr className="border-b border-zinc-200 dark:border-zinc-800 bg-zinc-50 dark:bg-zinc-900/40 text-zinc-500 dark:text-slate-400">
                <th className="p-3 w-40 whitespace-nowrap">TIMESTAMP</th>
                <th className="p-3 w-24">SOURCE</th>
                <th className="p-3 w-36 whitespace-nowrap">ATTACKER IP</th>
                <th className="p-3 min-w-[160px]">TARGET ASSET</th>
                <th className="p-3 min-w-[200px]">ATTACK VECTOR</th>
                <th className="p-3 w-28 whitespace-nowrap">SEVERITY</th>
                <th className="p-3 w-32 whitespace-nowrap">CONFIDENCE</th>
                <th className="p-3 w-24 whitespace-nowrap">STATUS</th>
                <th className="p-3 w-32 text-right whitespace-nowrap">ACTION</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-zinc-100 dark:divide-zinc-800/60">
              {loading && displayRows.length === 0 ? (
                <tr>
                  <td colSpan={9} className="p-12 text-center text-zinc-500 dark:text-slate-400">
                    <RefreshCw className="w-6 h-6 animate-spin mx-auto text-zinc-400 dark:text-zinc-500 mb-2" />
                    <span className="font-mono text-xs">Querying correlated threats and incidents from database...</span>
                  </td>
                </tr>
              ) : displayRows.length === 0 ? (
                <tr>
                  <td colSpan={9} className="p-12 text-center text-zinc-500 dark:text-slate-400">
                    <ShieldCheck className="w-8 h-8 mx-auto text-emerald-500 mb-2" />
                    <div className="text-zinc-700 dark:text-slate-300 font-semibold">NO CORRELATED THREATS RECORDED</div>
                    <p className="text-xs text-zinc-400 dark:text-slate-500 mt-1">
                      No threats or incidents recorded for this organization in the telemetry database.
                    </p>
                  </td>
                </tr>
              ) : (
                displayRows.map((t) => {
                  const isRecent = recentThreatIds.has(t.id);
                  const isIncident = t.kind === 'incident';
                  return (
                    <tr 
                      key={t.id} 
                      className={`transition-colors duration-500 ${
                        isRecent 
                          ? 'bg-amber-500/10 dark:bg-amber-500/15 border-l-4 border-l-amber-500' 
                          : 'hover:bg-zinc-50 dark:hover:bg-zinc-800/60'
                      }`}
                    >
                      <td className="p-3 text-zinc-500 dark:text-slate-400 whitespace-nowrap">
                        <span>
                          {new Date(t.timestamp).toLocaleString('en-US', {
                            month: 'short',
                            day: '2-digit',
                            hour: '2-digit',
                            minute: '2-digit',
                            second: '2-digit',
                            hour12: false
                          })}
                        </span>
                      </td>
                      <td className="p-3">
                        <div className="flex flex-col items-start gap-1">
                          <span className={`px-1.5 py-0.5 rounded text-[9px] font-bold uppercase tracking-wider border ${
                            isIncident
                              ? 'bg-amber-500/10 text-amber-600 dark:text-amber-400 border-amber-500/20'
                              : 'bg-zinc-100 dark:bg-zinc-800/60 text-zinc-500 dark:text-slate-400 border-zinc-200 dark:border-zinc-800'
                          }`}>
                            {isIncident ? 'Incident' : 'Threat'}
                          </span>
                          {isIncident && t.tier && (
                            <span className="text-[9px] font-mono text-zinc-400 dark:text-slate-500">SOC {t.tier}</span>
                          )}
                        </div>
                      </td>
                      <td className="p-3 font-semibold text-zinc-800 dark:text-slate-200 whitespace-nowrap font-mono text-xs">
                        {t.sourceIp}
                      </td>
                      <td className="p-3 text-zinc-800 dark:text-slate-200">
                        <div className="font-mono text-xs font-medium break-all">{t.affectedApplication || t.target}</div>
                      </td>
                      <td className="p-3 text-zinc-800 dark:text-slate-200">
                        <div className="flex items-center gap-1.5 flex-wrap">
                          <span className="font-medium text-zinc-900 dark:text-white font-sans text-xs">{t.attackType}</span>
                          {t.mitre?.techniqueId && (
                            <span className="px-1.5 py-0.5 rounded text-[9px] font-mono bg-zinc-100 dark:bg-zinc-800/60 text-zinc-600 dark:text-slate-300 border border-zinc-200 dark:border-zinc-800">
                              {t.mitre.techniqueId}
                            </span>
                          )}
                        </div>
                      </td>
                      <td className="p-3 whitespace-nowrap">
                        <StatusBadge type="severity" value={t.severity} />
                      </td>
                      <td className="p-3 text-zinc-700 dark:text-slate-300 whitespace-nowrap">
                        {isIncident ? (
                          <span className="text-[11px] font-sans text-zinc-500 dark:text-slate-400" title="Assigned SOC analyst">
                            {t.assignedAnalyst || 'Unassigned'}
                          </span>
                        ) : (
                          <div className="flex items-center gap-2">
                            <div className="w-12 h-1.5 rounded-full bg-zinc-200 dark:bg-zinc-800 overflow-hidden">
                              <div
                                className="h-full bg-zinc-600 dark:bg-white/40 rounded-full"
                                style={{ width: `${Math.min(100, t.confidence || 90)}%` }}
                              />
                            </div>
                            <span className="text-[11px] font-mono text-zinc-600 dark:text-zinc-400">{t.confidence || 90}%</span>
                          </div>
                        )}
                      </td>
                      <td className="p-3 whitespace-nowrap">
                        <span className={`px-2 py-0.5 rounded text-[10px] font-bold uppercase tracking-wider border ${statusTone(t.status)}`}>
                          {t.status}
                        </span>
                      </td>
                      <td className="p-3 text-right whitespace-nowrap">
                        <div className="flex items-center justify-end gap-1.5">
                          <button
                            onClick={() => handleOpenDetail(t)}
                            className="p-1.5 rounded-lg bg-zinc-100 dark:bg-zinc-800 hover:bg-zinc-200 dark:hover:bg-zinc-700 text-zinc-600 dark:text-slate-300 hover:text-zinc-900 dark:hover:text-white transition cursor-pointer"
                            title={isIncident ? 'Inspect incident case' : 'Inspect Threat Details & ATT&CK'}
                          >
                            <Eye className="w-3.5 h-3.5" />
                          </button>
                          {isIncident ? (
                            <button
                              onClick={() => onNavigate?.('incidents')}
                              className="px-2.5 py-1 rounded-lg border border-amber-500/30 bg-amber-500/10 hover:bg-amber-500/20 text-amber-600 dark:text-amber-400 font-sans text-[11px] font-semibold flex items-center gap-1 transition cursor-pointer"
                              title="Open this case in the Incidents module"
                            >
                              <ArrowUpRight className="w-3 h-3" />
                              <span>Triage</span>
                            </button>
                          ) : (
                            t.status !== 'BLOCKED' && t.status !== 'MITIGATED' && (
                              <button
                                onClick={() => handleMitigate(t.id, 'BLOCK')}
                                disabled={mitigatingId === t.id}
                                className="px-2.5 py-1 rounded-lg bg-rose-600 hover:bg-rose-500 disabled:opacity-50 text-white font-sans text-[11px] font-semibold flex items-center gap-1 shadow-sm transition cursor-pointer"
                                title="Insert emergency firewall quarantine rule"
                              >
                                <Ban className="w-3 h-3" />
                                <span>Block IP</span>
                              </button>
                            )
                          )}
                        </div>
                      </td>
                    </tr>
                  );
                })
              )}
            </tbody>
          </table>
        </div>
      </div>

      {/* Slide-over Right Drawer: Threat Dossier & Deep Dive (Like Events Detail) */}
      {selectedThreat && (
        <div className="fixed inset-0 z-50 overflow-hidden bg-black/60 dark:bg-black/80 backdrop-blur-xs animate-in fade-in duration-200">
          {/* Backdrop click to close */}
          <div
            className="absolute inset-0 bg-transparent cursor-pointer"
            onClick={() => { setSelectedThreat(null); setThreatDetail(null); }}
          />

          <aside
            role="dialog"
            aria-modal="true"
            aria-label={selectedThreat.kind === 'incident' ? 'Incident details' : 'Threat details'}
            className="absolute inset-y-0 right-0 flex w-full flex-col border-l border-zinc-200/80 bg-white text-zinc-900 shadow-2xl animate-in slide-in-from-right duration-300 ease-out dark:border-zinc-800 dark:bg-[#0b0b0d] dark:text-zinc-100 sm:max-w-[560px] lg:max-w-[640px]"
          >
            {/* Mobile swipe grab handle */}
            <div className="sm:hidden pt-2.5 pb-0.5 flex justify-center">
              <div className="h-1 w-10 rounded-full bg-zinc-300 dark:bg-zinc-700" />
            </div>

            {/* Drawer Header */}
            <header className="shrink-0 border-b border-zinc-200/80 bg-white px-5 pb-4 pt-3.5 dark:border-zinc-800 dark:bg-[#0b0b0d] sm:px-6">
              <div className="flex min-w-0 items-center justify-between">
                <div className="flex min-w-0 items-center gap-1.5 font-mono text-[10px] uppercase tracking-[0.16em] text-zinc-400 dark:text-zinc-500">
                  <span className="shrink-0">Threat Intelligence</span>
                  <span className="shrink-0 text-zinc-300 dark:text-zinc-700">/</span>
                  <span className="truncate font-sans text-[11px] font-medium normal-case tracking-normal text-zinc-500 dark:text-zinc-400">
                    {selectedThreat.kind === 'incident' ? 'Incident Case' : 'Threat Dossier'}
                  </span>
                </div>
              </div>

              <div className="mt-3 flex items-start gap-3">
                <span className="flex h-11 w-11 shrink-0 items-center justify-center rounded-xl border border-zinc-200/80 bg-zinc-50 text-amber-600 dark:border-zinc-800 dark:bg-zinc-900/60 dark:text-amber-400">
                  {selectedThreat.kind === 'incident' ? <Siren className="w-5 h-5" /> : <Bug className="w-5 h-5" />}
                </span>
                <div className="min-w-0 flex-1">
                  <div className="flex flex-wrap items-center gap-2">
                    <h2 className="truncate text-base font-semibold tracking-tight text-zinc-900 dark:text-zinc-100 font-sans">
                      {selectedThreat.attackType}
                    </h2>
                    <StatusBadge type="severity" value={selectedThreat.severity} />
                    <span className={`px-2 py-0.5 rounded text-[10px] font-bold border font-mono ${statusTone(selectedThreat.status)}`}>
                      {selectedThreat.status}
                    </span>
                  </div>
                  <p className="mt-0.5 truncate font-mono text-[11px] text-zinc-500 dark:text-zinc-400">
                    {selectedThreat.id}
                  </p>
                </div>
              </div>

              <div className="mt-3 flex flex-wrap items-center gap-x-4 gap-y-1 font-mono text-[10px] uppercase tracking-wider text-zinc-400 dark:text-zinc-500">
                <span>Time · {formatTime(selectedThreat.timestamp)}</span>
                <span className="truncate">Attacker · {selectedThreat.sourceIp}</span>
                <span className="truncate">Target · {selectedThreat.affectedApplication || selectedThreat.target}</span>
              </div>
            </header>

            {/* Scrollable Drawer Body */}
            <div className="flex-1 space-y-5 overflow-y-auto px-5 py-5 text-xs sm:px-6 custom-scrollbar">
              {/* Threat Summary Card */}
              <div className="p-4 rounded-xl border border-zinc-200 dark:border-zinc-800 bg-zinc-50 dark:bg-zinc-900/40 space-y-3">
                <div className="flex items-center justify-between">
                  <div className="text-xs font-bold text-zinc-800 dark:text-slate-200">Incident Narrative</div>
                  <div className="flex items-center gap-1.5 font-mono text-[11px] text-zinc-500 dark:text-zinc-400">
                    <span>Confidence:</span>
                    <strong className="text-zinc-900 dark:text-white">{selectedThreat.confidence || 90}%</strong>
                  </div>
                </div>
                <p className="text-zinc-700 dark:text-slate-300 leading-relaxed font-sans text-xs">
                  {selectedThreat.summary}
                </p>
                {selectedThreat.detectionReason && (
                  <div className="p-2.5 rounded-lg bg-zinc-100 dark:bg-black/40 border border-zinc-200 dark:border-zinc-800 font-mono text-[11px] text-zinc-500 dark:text-slate-400">
                    <span className="text-zinc-700 dark:text-slate-300 font-semibold">Detection Reason:</span> {selectedThreat.detectionReason}
                  </div>
                )}
              </div>

              {/* Incident Case Metadata */}
              {selectedThreat.kind === 'incident' && (
                <div className="rounded-xl border border-amber-500/30 bg-amber-500/5 p-4 space-y-3">
                  <div className="text-[10px] font-bold uppercase tracking-[0.14em] text-amber-600 dark:text-amber-400">
                    SOC Incident Case
                  </div>
                  <div className="grid grid-cols-2 gap-3 text-xs font-mono">
                    <div>
                      <span className="text-zinc-400 text-[10px] uppercase">SOC Tier</span>
                      <div className="font-semibold text-zinc-800 dark:text-zinc-200 mt-0.5">{selectedThreat.tier || 'L1'}</div>
                    </div>
                    <div>
                      <span className="text-zinc-400 text-[10px] uppercase">Assigned Analyst</span>
                      <div className="font-sans font-semibold text-zinc-800 dark:text-zinc-200 mt-0.5">{selectedThreat.assignedAnalyst || 'Unassigned'}</div>
                    </div>
                    <div>
                      <span className="text-zinc-400 text-[10px] uppercase">Case Status</span>
                      <div className="font-semibold text-zinc-800 dark:text-zinc-200 mt-0.5">{selectedThreat.status}</div>
                    </div>
                    <div>
                      <span className="text-zinc-400 text-[10px] uppercase">Case ID</span>
                      <div className="font-semibold text-zinc-800 dark:text-zinc-200 mt-0.5">{selectedThreat.id}</div>
                    </div>
                  </div>

                  {selectedThreat.timeline && selectedThreat.timeline.length > 0 && (
                    <div className="space-y-2 pt-1">
                      <div className="text-[10px] font-bold uppercase tracking-[0.14em] text-zinc-400 dark:text-zinc-500">
                        Incident Timeline
                      </div>
                      <ol className="space-y-2">
                        {selectedThreat.timeline.map((entry, index) => (
                          <li key={`${entry.time}-${index}`} className="flex gap-2">
                            <span className="mt-1.5 h-1.5 w-1.5 shrink-0 rounded-full bg-amber-500" />
                            <div>
                              <div className="text-[10px] font-mono text-zinc-400 dark:text-zinc-500">{formatTime(entry.time)}</div>
                              <div className="text-xs font-sans text-zinc-700 dark:text-slate-300">{entry.event}</div>
                            </div>
                          </li>
                        ))}
                      </ol>
                    </div>
                  )}
                </div>
              )}

              {/* Target & Network Vector */}
              <div className="rounded-xl border border-zinc-200 dark:border-zinc-800 bg-zinc-50/50 dark:bg-zinc-900/20 p-4 space-y-3">
                <div className="text-[10px] font-bold uppercase tracking-[0.14em] text-zinc-400 dark:text-zinc-500">
                  {selectedThreat.kind === 'incident' ? 'Incident Context' : 'Target & Perimeter Parameters'}
                </div>
                <div className="grid grid-cols-2 gap-3 text-xs font-mono">
                  <div>
                    <span className="text-zinc-400 text-[10px] uppercase">
                      {selectedThreat.kind === 'incident' ? 'Source IP' : 'Attacker IP'}
                    </span>
                    <div className="font-semibold text-zinc-800 dark:text-zinc-200 mt-0.5">{selectedThreat.sourceIp}</div>
                  </div>
                  <div>
                    <span className="text-zinc-400 text-[10px] uppercase">
                      {selectedThreat.kind === 'incident' ? 'Affected Asset' : 'Target Application'}
                    </span>
                    <div className="font-semibold text-zinc-800 dark:text-zinc-200 mt-0.5">{selectedThreat.affectedApplication || selectedThreat.target}</div>
                  </div>
                  <div>
                    <span className="text-zinc-400 text-[10px] uppercase">
                      {selectedThreat.kind === 'incident' ? 'SOC Tier' : 'Destination Port'}
                    </span>
                    <div className="font-semibold text-zinc-800 dark:text-zinc-200 mt-0.5">
                      {selectedThreat.kind === 'incident' ? (selectedThreat.tier || 'L1') : (selectedThreat.destination || 'Port 443 (HTTPS)')}
                    </div>
                  </div>
                  <div>
                    <span className="text-zinc-400 text-[10px] uppercase">
                      {selectedThreat.kind === 'incident' ? 'Case Status' : 'Enforced Action'}
                    </span>
                    <div className="font-semibold text-zinc-800 dark:text-zinc-200 mt-0.5">{selectedThreat.action}</div>
                  </div>
                </div>
              </div>

              {/* MITRE ATT&CK Framework Mapping */}
              {selectedThreat.mitre && (
                <div className="p-4 rounded-xl border border-zinc-200 dark:border-zinc-800 bg-zinc-100/60 dark:bg-white/[0.04] space-y-2.5">
                  <div className="text-[11px] font-bold text-zinc-700 dark:text-slate-300 uppercase tracking-wider flex items-center gap-1.5">
                    <Target className="w-4 h-4 text-zinc-500 dark:text-slate-300" />
                    <span>MITRE ATT&CK Framework</span>
                  </div>
                  <div className="grid grid-cols-1 sm:grid-cols-2 gap-3 text-zinc-700 dark:text-slate-300">
                    <div>
                      <span className="text-zinc-400 dark:text-slate-500 font-mono text-[10px] uppercase">Technique ID</span>
                      <div className="font-mono font-bold text-zinc-800 dark:text-slate-200 mt-0.5">{selectedThreat.mitre.techniqueId}</div>
                    </div>
                    <div>
                      <span className="text-zinc-400 dark:text-slate-500 font-mono text-[10px] uppercase">Tactic</span>
                      <div className="font-semibold text-zinc-800 dark:text-slate-200 mt-0.5">{selectedThreat.mitre.tactic}</div>
                    </div>
                    <div className="col-span-full">
                      <span className="text-zinc-400 dark:text-slate-500 font-mono text-[10px] uppercase">Technique Name</span>
                      <div className="text-zinc-800 dark:text-slate-200 font-medium mt-0.5">{selectedThreat.mitre.techniqueName}</div>
                    </div>
                    <div className="col-span-full text-zinc-500 dark:text-slate-400 text-[11px] leading-relaxed">
                      {selectedThreat.mitre.description}
                    </div>
                  </div>
                </div>
              )}

              {/* Correlated Event History */}
              {threatDetail?.relatedEventsDetails && threatDetail.relatedEventsDetails.length > 0 && (
                <div>
                  <div className="text-[11px] font-bold text-zinc-700 dark:text-slate-300 uppercase tracking-wider mb-2">
                    Ingress Packet Traces from {selectedThreat.sourceIp} ({threatDetail.relatedEventsDetails.length} Events)
                  </div>
                  <div className="rounded-lg border border-zinc-200 dark:border-zinc-800 bg-zinc-50 dark:bg-zinc-900/40 overflow-hidden">
                    <div className="overflow-x-auto custom-scrollbar">
                      <table className="w-full min-w-[480px] text-left font-mono text-[11px]">
                        <thead>
                          <tr className="border-b border-zinc-200 dark:border-zinc-800 text-zinc-500 dark:text-slate-400">
                            <th className="p-2">TIME</th>
                            <th className="p-2">URI / TARGET</th>
                            <th className="p-2">ACTION</th>
                            <th className="p-2">SEVERITY</th>
                          </tr>
                        </thead>
                        <tbody className="divide-y divide-zinc-100 dark:divide-zinc-800/60">
                          {threatDetail.relatedEventsDetails.map((r: SecurityEvent) => (
                            <tr key={r.id}>
                              <td className="p-2 text-zinc-500 dark:text-slate-400">{formatTime(r.timestamp)}</td>
                              <td className="p-2 text-zinc-800 dark:text-slate-200 truncate max-w-[200px]">{r.uri || (r as any).threat || r.application}</td>
                              <td className="p-2"><StatusBadge type="action" value={r.action} /></td>
                              <td className="p-2"><StatusBadge type="severity" value={r.severity} /></td>
                            </tr>
                          ))}
                        </tbody>
                      </table>
                    </div>
                  </div>
                </div>
              )}

              {/* Recommended SOC Action */}
              {selectedThreat.recommendedAction && (
                <div className="p-3.5 rounded-lg bg-amber-500/10 border border-amber-500/20">
                  <div className="text-[11px] font-bold text-amber-600 dark:text-amber-400 uppercase tracking-wider mb-1 flex items-center gap-1.5">
                    <AlertTriangle className="w-3.5 h-3.5 text-amber-600 dark:text-amber-400" />
                    <span>Recommended SOC Action</span>
                  </div>
                  <p className="text-zinc-700 dark:text-slate-300 font-sans text-xs">
                    {selectedThreat.recommendedAction}
                  </p>
                </div>
              )}
            </div>

            {/* Drawer Fixed Footer */}
            <footer className="shrink-0 border-t border-zinc-200/80 bg-zinc-50 dark:bg-zinc-900/60 px-5 py-3 dark:border-zinc-800 sm:px-6 flex flex-wrap items-center justify-between gap-3">
              <button
                type="button"
                onClick={() => { setSelectedThreat(null); setThreatDetail(null); }}
                className="px-3 py-1.5 rounded-lg border border-zinc-200 dark:border-zinc-800 bg-white dark:bg-zinc-800 hover:bg-zinc-100 dark:hover:bg-zinc-700 text-zinc-700 dark:text-zinc-200 text-xs font-semibold cursor-pointer"
              >
                Close
              </button>

              <div className="flex items-center gap-2">
                {selectedThreat.kind === 'incident' ? (
                  <button
                    type="button"
                    onClick={() => {
                      setSelectedThreat(null);
                      setThreatDetail(null);
                      onNavigate?.('incidents');
                    }}
                    className="px-3.5 py-1.5 rounded-lg bg-amber-500 hover:bg-amber-400 text-zinc-950 text-xs font-semibold flex items-center gap-1.5 shadow-sm transition cursor-pointer"
                  >
                    <ArrowUpRight className="w-3.5 h-3.5" />
                    <span>Open in Incidents</span>
                  </button>
                ) : (
                  selectedThreat.status !== 'BLOCKED' && selectedThreat.status !== 'MITIGATED' && (
                    <>
                      <button
                        type="button"
                        onClick={() => handleMitigate(selectedThreat.id, 'RESOLVE')}
                        disabled={mitigatingId === selectedThreat.id}
                        className="px-3 py-1.5 rounded-lg border border-emerald-500/30 bg-emerald-500/10 hover:bg-emerald-500/20 text-emerald-600 dark:text-emerald-400 text-xs font-semibold cursor-pointer"
                      >
                        Mark Resolved
                      </button>
                      <button
                        type="button"
                        onClick={() => handleMitigate(selectedThreat.id, 'BLOCK')}
                        disabled={mitigatingId === selectedThreat.id}
                        className="px-3.5 py-1.5 rounded-lg bg-rose-600 hover:bg-rose-500 disabled:opacity-50 text-white text-xs font-semibold flex items-center gap-1.5 shadow-sm transition cursor-pointer"
                      >
                        <Ban className="w-3.5 h-3.5" />
                        <span>Block IP</span>
                      </button>
                    </>
                  )
                )}
              </div>
            </footer>
          </aside>
        </div>
      )}
    </div>
  );
};
