import React, { useState, useEffect, useCallback, useRef } from 'react';
import { 
  Server, 
  Plus, 
  Search, 
  ShieldCheck, 
  RefreshCw,
  AlertTriangle,
  X,
  Eye,
  WifiOff,
  Globe,
  Zap,
  Trash2,
  ChevronLeft,
  ChevronRight,
  CheckCircle2
} from 'lucide-react';
import { securityApi, globalRealtimeClient } from '../../services/api';
import { ProtectedApplication } from '../../types';
import { StatusBadge } from '../../components/common/StatusBadge';
import { BackendOfflineBanner } from '../../components/common/BackendOfflineBanner';
import { FontAwesomeIcon } from '@fortawesome/react-fontawesome';
import { faServer } from '@fortawesome/free-solid-svg-icons';
import { ModulePageHeader } from '../../components/common/ModulePageHeader';
import { useAuth } from '../../context/AuthContext';
import { formatTime } from '../../utils/dateTime';

/** "12s ago" / "3m ago" — how fresh the inventory on screen is. */
function relativeTime(timestamp: number): string {
  const seconds = Math.max(0, Math.floor((Date.now() - timestamp) / 1000));
  if (seconds < 5) return 'just now';
  if (seconds < 60) return `${seconds}s ago`;
  const minutes = Math.floor(seconds / 60);
  if (minutes < 60) return `${minutes}m ago`;
  const hours = Math.floor(minutes / 60);
  return `${hours}h ago`;
}

export const ApplicationsModule: React.FC = () => {
  const { isBackendOffline } = useAuth();
  const [apps, setApps] = useState<ProtectedApplication[]>([]);
  const [totalCount, setTotalCount] = useState<number>(0);
  const [metrics, setMetrics] = useState<{
    total: number;
    protected: number;
    monitoring: number;
    offline: number;
    unknown: number;
  }>({
    total: 0,
    protected: 0,
    monitoring: 0,
    offline: 0,
    unknown: 0
  });

  const [loading, setLoading] = useState(true);
  const [search, setSearch] = useState('');
  const [statusFilter, setStatusFilter] = useState('ALL');
  const [envFilter, setEnvFilter] = useState('ALL');
  const [showAddModal, setShowAddModal] = useState(false);
  const [lastUpdated, setLastUpdated] = useState<number>(Date.now());
  const [pulse, setPulse] = useState(false);
  const pulseTimer = useRef<number | null>(null);
  const [currentPage, setCurrentPage] = useState<number>(1);
  const pageSize = 8;

  // Form states for adding application
  const [name, setName] = useState('');
  const [domain, setDomain] = useState('');
  const [originIp, setOriginIp] = useState('');
  const [protocol, setProtocol] = useState<'HTTPS' | 'HTTP' | 'gRPC'>('HTTPS');
  const [port, setPort] = useState(443);
  const [environment, setEnvironment] = useState<'Production' | 'Staging' | 'Development'>('Production');
  const [submitting, setSubmitting] = useState(false);

  // Probing state
  const [probingId, setProbingId] = useState<string | null>(null);
  const [, setProbeResult] = useState<{ id: string; status: string; latency: number } | null>(null);

  // Detail modal state
  const [selectedApp, setSelectedApp] = useState<ProtectedApplication | null>(null);
  const [appDetail, setAppDetail] = useState<any | null>(null);
  const [, setLoadingDetail] = useState(false);

  const fetchApps = useCallback(async (quiet = false) => {
    if (!quiet) setLoading(true);
    try {
      const res = await securityApi.getApplications({
        status: statusFilter !== 'ALL' ? statusFilter : undefined,
        environment: envFilter !== 'ALL' ? envFilter : undefined,
        search: search.trim() ? search.trim() : undefined
      });

      const loadedApps = res.applications || [];
      setApps(loadedApps);
      setTotalCount(res.total || loadedApps.length);
      if (res.metrics) {
        setMetrics(res.metrics);
      }
      setLastUpdated(Date.now());
    } catch (e) {
      console.error('[ApplicationsModule] Fetch error:', e);
    } finally {
      if (!quiet) setLoading(false);
    }
  }, [statusFilter, envFilter, search]);

  useEffect(() => {
    fetchApps();
  }, [fetchApps, isBackendOffline]);

  // Keep the inventory current without a manual refresh: the endpoint agent
  // reports new websites on its heartbeat, so a quiet poll every 15 seconds
  // guarantees the list never drifts from the fleet.
  useEffect(() => {
    const timer = window.setInterval(() => {
      if (!isBackendOffline) fetchApps(true);
    }, 15_000);
    return () => window.clearInterval(timer);
  }, [fetchApps, isBackendOffline]);

  // Flash the inventory card when the server reports a change.
  const flagPulse = useCallback(() => {
    setPulse(true);
    if (pulseTimer.current) window.clearTimeout(pulseTimer.current);
    pulseTimer.current = window.setTimeout(() => setPulse(false), 1200);
  }, []);

  useEffect(() => () => {
    if (pulseTimer.current) window.clearTimeout(pulseTimer.current);
  }, []);

  // The live listener must survive filter changes, so it always calls the
  // latest fetcher through a ref instead of re-subscribing on every keystroke.
  const fetchAppsRef = useRef(fetchApps);
  useEffect(() => {
    fetchAppsRef.current = fetchApps;
  }, [fetchApps]);

  // Real-time WebSocket listener
  useEffect(() => {
    const unsubEvents = globalRealtimeClient.subscribe((msg: any) => {
      if (!msg) return;
      const type = msg.type || '';
      const data = msg.data || msg;

      if (type === 'application.created' && data.id) {
        setApps(prev => {
          if (prev.some(a => a.id === data.id)) return prev;
          return [data, ...prev];
        });
        setTotalCount(prev => prev + 1);
        setMetrics(prev => ({
          ...prev,
          total: prev.total + 1,
          monitoring: prev.monitoring + 1
        }));
        setLastUpdated(Date.now());
        flagPulse();
      } else if (type === 'application.updated') {
        // A website was bound to an endpoint agent — reload so the agent
        // counter and health reflect the new binding.
        fetchAppsRef.current(true);
        setLastUpdated(Date.now());
        flagPulse();
      } else if (type === 'application.removed') {
        // The website is gone (the agent stopped reporting it, or the agent was
        // removed): drop it from the list right away.
        setApps(prev => prev.filter(a => a.id !== data.id));
        setTotalCount(prev => Math.max(0, prev - 1));
        setMetrics(prev => ({
          ...prev,
          total: Math.max(0, prev.total - 1),
          monitoring: Math.max(0, prev.monitoring - 1)
        }));
        setLastUpdated(Date.now());
        flagPulse();
      } else if (type === 'organization.created') {
        // A new tenant was provisioned by an agent: reload the inventory.
        fetchAppsRef.current(true);
        setLastUpdated(Date.now());
      } else if (type === 'application.health_changed') {
        const appId = data.id || data.applicationId;
        const newStatus = data.status;
        const responseTime = data.responseTime;

        if (appId && newStatus) {
          setApps(prev => prev.map(a => a.id === appId ? {
            ...a,
            wafStatus: newStatus === 'ONLINE' ? 'Protected' : 'Offline',
            health: newStatus,
            responseTime: responseTime !== undefined ? responseTime : a.responseTime
          } : a));
          setLastUpdated(Date.now());
        }
      }
    });

    return () => {
      unsubEvents();
    };
  }, [flagPulse]);

  // Health probe trigger
  const handleProbeApp = async (app: ProtectedApplication) => {
    setProbingId(app.id);
    setProbeResult(null);
    try {
      const res = await securityApi.checkApplicationHealth(app.id);
      setProbeResult({
        id: app.id,
        status: res.status,
        latency: res.responseTime
      });

      // Update app in state
      setApps(prev => prev.map(a => a.id === app.id ? {
        ...a,
        health: res.status,
        responseTime: res.responseTime,
        wafStatus: res.status === 'ONLINE' ? 'Protected' : 'Offline'
      } : a));

      setTimeout(() => setProbeResult(null), 5000);
    } catch (err) {
      alert('Health probe request failed.');
    } finally {
      setProbingId(null);
    }
  };

  // Remove a website from the inventory. The server broadcasts the removal,
  // so the row disappears for every operator immediately.
  const handleRemoveApp = async (app: ProtectedApplication) => {
    if (!window.confirm(`Remove "${app.domain}" from the application inventory?`)) {
      return;
    }
    try {
      await securityApi.removeApplication(app.id);
      setApps(prev => prev.filter(a => a.id !== app.id));
      setTotalCount(prev => Math.max(0, prev - 1));
      setMetrics(prev => ({
        ...prev,
        total: Math.max(0, prev.total - 1),
        monitoring: Math.max(0, prev.monitoring - 1)
      }));
      setSelectedApp(prev => (prev && prev.id === app.id ? null : prev));
      setLastUpdated(Date.now());
      flagPulse();
    } catch (err) {
      console.error('[ApplicationsModule] Remove failed:', err);
    }
  };

  // Clear events for selected application
  const handleClearAppEvents = async (appId: string) => {
    if (!window.confirm('Clear all recorded security events for this application?')) {
      return;
    }
    try {
      await securityApi.clearApplicationEvents(appId);
      setAppDetail(prev => prev ? { ...prev, recentEvents: [] } : prev);
      fetchApps();
    } catch (err) {
      console.error('[ApplicationsModule] Clear events failed:', err);
    }
  };

  // Inspect application detail
  const handleInspectApp = async (app: ProtectedApplication) => {
    setSelectedApp(app);
    setLoadingDetail(true);
    try {
      const detail = await securityApi.getApplicationDetail(app.id);
      setAppDetail(detail);
    } catch {
      setAppDetail({ application: app, recentEvents: [], activeThreats: [], agents: [] });
    } finally {
      setLoadingDetail(false);
    }
  };

  // Add new application endpoint
  const handleAddApp = async (e: React.FormEvent) => {
    e.preventDefault();
    setSubmitting(true);
    try {
      await securityApi.createApplication({
        name,
        domain,
        originIp,
        protocol,
        port,
        environment
      });
      setShowAddModal(false);
      setName('');
      setDomain('');
      setOriginIp('');
      fetchApps();
    } catch (err) {
      alert('Failed to register application endpoint.');
    } finally {
      setSubmitting(false);
    }
  };

  if (isBackendOffline) {
    return <BackendOfflineBanner onRetry={() => fetchApps()} />;
  }


  const totalApps = totalCount || apps.length;
  const totalPages = Math.max(1, Math.ceil(apps.length / pageSize));
  const startRecord = apps.length === 0 ? 0 : (currentPage - 1) * pageSize + 1;
  const endRecord = Math.min(currentPage * pageSize, apps.length);
  const paginatedApps = apps.slice((currentPage - 1) * pageSize, currentPage * pageSize);

  const prodCount = apps.filter(a => (a.environment || '').toUpperCase() === 'PRODUCTION').length;
  const stagingCount = apps.filter(a => (a.environment || '').toUpperCase() === 'STAGING').length;
  const devCount = apps.filter(a => (a.environment || '').toUpperCase() === 'DEVELOPMENT').length;
  const httpsCount = apps.filter(a => (a.protocol || 'HTTPS').toUpperCase() === 'HTTPS').length;
  const httpCount = apps.filter(a => (a.protocol || '').toUpperCase() === 'HTTP').length;
  const linkedAgentsCount = apps.filter(a => (a.agentCount || 0) > 0).length;

  return (
    <div className="space-y-5" id="applications-inventory-container">
      {/* Header — aligned with Live Traffic & Centralized Logs */}
      <ModulePageHeader
        icon={<FontAwesomeIcon icon={faServer} />}
        title="Protected"
        titleTail="Applications"
        subtitle="Monitored web applications, APIs, and microservices protected by OAT Security agents."
        actions={
          <>
            <button
              onClick={() => fetchApps(true)}
              title="Refresh application inventory"
              className="inline-flex h-9 w-9 shrink-0 items-center justify-center rounded-xl border border-zinc-200 bg-white text-zinc-500 transition hover:border-zinc-300 hover:text-zinc-900 cursor-pointer dark:border-zinc-700 dark:bg-zinc-900 dark:text-zinc-400 dark:hover:border-zinc-600 dark:hover:text-zinc-100 shadow-2xs"
            >
              <RefreshCw className={`h-4 w-4 ${loading ? 'animate-spin' : ''}`} />
            </button>
            <button
              onClick={() => setShowAddModal(true)}
              className="inline-flex h-9 items-center gap-1.5 rounded-xl bg-zinc-900 px-3.5 text-xs font-semibold text-white transition hover:bg-zinc-800 cursor-pointer dark:bg-zinc-100 dark:text-zinc-900 dark:hover:bg-white shadow-2xs"
            >
              <Plus className="h-3.5 w-3.5" />
              Add Endpoint
            </button>
          </>
        }
      />

      {/* Real-time notice */}
      {isBackendOffline && (
        <div className="flex items-center gap-2 rounded-xl border border-amber-200/80 bg-amber-50 px-4 py-2.5 text-[11px] text-amber-700 dark:border-amber-500/30 dark:bg-amber-500/10 dark:text-amber-300">
          <WifiOff className="h-3.5 w-3.5 shrink-0" />
          <span>Live channel offline — showing the last known inventory while the console reconnects.</span>
          <button
            onClick={() => globalRealtimeClient.connect()}
            className="ml-auto shrink-0 rounded-lg border border-amber-300/70 px-2 py-0.5 text-[10px] font-semibold text-amber-700 transition hover:bg-amber-100 cursor-pointer dark:border-amber-500/40 dark:text-amber-200 dark:hover:bg-amber-500/20"
          >
            Reconnect
          </button>
        </div>
      )}

      {/* 2-Column Responsive Layout: Left Stream Table, Right Summary Rail */}
      <div className="grid items-start gap-5 lg:grid-cols-[minmax(0,1fr)_300px] xl:grid-cols-[minmax(0,1fr)_340px]">
        {/* Left Column: Stream Card with Toolbar, Table, and Pagination */}
        <div
          className={`flex min-w-0 flex-col overflow-hidden rounded-2xl border border-zinc-200/80 bg-white shadow-2xs transition-shadow dark:border-zinc-800 dark:bg-[#0c0c0e] ${
            pulse ? 'ring-1 ring-emerald-400/60 dark:ring-emerald-500/40' : ''
          }`}
        >
          {/* Top Filter Toolbar */}
          <div className="shrink-0 flex flex-wrap items-center justify-between gap-2 border-b border-zinc-100 bg-zinc-50/60 px-3.5 py-2.5 dark:border-zinc-800/80 dark:bg-zinc-900/40">
            <div className="flex flex-wrap items-center gap-2 flex-1 min-w-0">
              <div className="relative min-w-[200px] flex-1 max-w-xs">
                <Search className="pointer-events-none absolute left-2.5 top-1/2 h-3.5 w-3.5 -translate-y-1/2 text-zinc-400" />
                <input
                  type="text"
                  value={search}
                  onChange={e => { setSearch(e.target.value); setCurrentPage(1); }}
                  placeholder="Search application, domain, or IP…"
                  className="h-8 w-full rounded-lg border border-zinc-200/80 bg-white pl-8 pr-2.5 text-xs text-zinc-700 outline-none transition placeholder:text-zinc-400 focus:border-zinc-400 dark:border-zinc-700 dark:bg-zinc-900 dark:text-zinc-200 dark:placeholder:text-zinc-500 dark:focus:border-zinc-500"
                />
                {search && (
                  <button
                    onClick={() => { setSearch(''); setCurrentPage(1); }}
                    className="absolute right-2 top-1/2 -translate-y-1/2 text-zinc-400 hover:text-zinc-600 dark:hover:text-zinc-200"
                  >
                    <X className="h-3 w-3" />
                  </button>
                )}
              </div>

              <select
                value={envFilter}
                onChange={e => { setEnvFilter(e.target.value); setCurrentPage(1); }}
                className="h-8 rounded-lg border border-zinc-200/80 bg-white px-2.5 text-xs text-zinc-600 transition focus:outline-none focus:border-zinc-400 cursor-pointer dark:border-zinc-700 dark:bg-zinc-900 dark:text-zinc-300"
              >
                <option value="ALL">All Environments</option>
                <option value="Production">Production</option>
                <option value="Staging">Staging</option>
                <option value="Development">Development</option>
              </select>

              <select
                value={statusFilter}
                onChange={e => { setStatusFilter(e.target.value); setCurrentPage(1); }}
                className="h-8 rounded-lg border border-zinc-200/80 bg-white px-2.5 text-xs text-zinc-600 transition focus:outline-none focus:border-zinc-400 cursor-pointer dark:border-zinc-700 dark:bg-zinc-900 dark:text-zinc-300"
              >
                <option value="ALL">All Statuses</option>
                <option value="Protected">Protected</option>
                <option value="Monitoring">Monitoring</option>
                <option value="Offline">Offline</option>
              </select>

              {(search || envFilter !== 'ALL' || statusFilter !== 'ALL') && (
                <button
                  onClick={() => { setSearch(''); setEnvFilter('ALL'); setStatusFilter('ALL'); setCurrentPage(1); }}
                  className="h-8 px-2 text-[11px] font-medium text-zinc-500 hover:text-zinc-900 dark:text-zinc-400 dark:hover:text-zinc-100 cursor-pointer"
                >
                  Reset
                </button>
              )}
            </div>

            <div className="shrink-0 text-[11px] font-mono text-zinc-400 dark:text-zinc-500">
              updated {relativeTime(lastUpdated)}
            </div>
          </div>

          {/* Table */}
          <div className="overflow-x-auto custom-scrollbar">
            <table className="w-full text-left font-mono text-xs min-w-[760px]">
              <thead className="sticky top-0 z-10 border-b border-zinc-200/80 bg-zinc-50/90 text-[10px] font-semibold uppercase tracking-wider text-zinc-400 backdrop-blur-xs dark:border-zinc-800 dark:bg-zinc-900/90 dark:text-zinc-500">
                <tr>
                  <th className="px-3.5 py-2.5 font-medium">Application & Domain</th>
                  <th className="px-3 py-2.5 font-medium">Origin & Port</th>
                  <th className="px-3 py-2.5 font-medium">Env</th>
                  <th className="px-3 py-2.5 font-medium">WAF & Health</th>
                  <th className="px-3 py-2.5 font-medium text-right">24H Traffic</th>
                  <th className="px-3.5 py-2.5 font-medium text-right">Actions</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-zinc-100 dark:divide-zinc-800/80">
                {loading && apps.length === 0 ? (
                  <tr>
                    <td colSpan={6} className="p-12 text-center text-zinc-500 dark:text-zinc-400">
                      <RefreshCw className="w-5 h-5 animate-spin mx-auto text-zinc-500 dark:text-zinc-400 mb-2" />
                      <span className="font-mono text-xs">Loading application inventory...</span>
                    </td>
                  </tr>
                ) : apps.length === 0 ? (
                  <tr>
                    <td colSpan={6} className="p-12 text-center text-zinc-500 dark:text-zinc-400">
                      <ShieldCheck className="w-7 h-7 mx-auto text-zinc-400 dark:text-zinc-500 mb-2" />
                      <div className="text-zinc-700 dark:text-zinc-300 font-semibold text-xs uppercase tracking-wide">No Endpoints Monitored</div>
                      <p className="text-[11px] text-zinc-400 dark:text-zinc-500 mt-1 max-w-md mx-auto">
                        No applications matched your filter. Install an endpoint agent on the host server or click "Add Endpoint" to register a website manually.
                      </p>
                    </td>
                  </tr>
                ) : (
                  paginatedApps.map(app => {
                    const isHealthy = app.health === 'ONLINE' || app.wafStatus === 'Protected' || app.wafStatus === 'ACTIVE';
                    const isOffline = app.health === 'OFFLINE' || app.wafStatus === 'Offline';
                    return (
                      <tr key={app.id} className="hover:bg-zinc-50/70 dark:hover:bg-zinc-800/50 transition">
                        {/* Application & Domain */}
                        <td className="px-3.5 py-3">
                          <div className="flex items-center gap-2">
                            <span
                              className={`h-2 w-2 shrink-0 rounded-full ${
                                isHealthy
                                  ? 'bg-emerald-500 shadow-sm shadow-emerald-500/50'
                                  : isOffline
                                    ? 'bg-rose-500 shadow-sm shadow-rose-500/50'
                                    : 'bg-amber-500'
                              }`}
                            />
                            <div className="min-w-0">
                              <div className="font-sans font-semibold text-zinc-900 dark:text-zinc-100 truncate">
                                {app.name}
                              </div>
                              <div className="flex items-center gap-1.5 text-[11px] text-zinc-500 dark:text-zinc-400 font-mono mt-0.5">
                                <Globe className="w-3 h-3 text-zinc-400 shrink-0" />
                                <span className="truncate">{app.domain}</span>
                                {app.agentCount ? (
                                  <span className="rounded bg-zinc-100 dark:bg-zinc-800 px-1 py-0.2 text-[9px] text-zinc-600 dark:text-zinc-300">
                                    {app.agentCount} agent{app.agentCount === 1 ? '' : 's'}
                                  </span>
                                ) : null}
                              </div>
                            </div>
                          </div>
                        </td>

                        {/* Origin & Port */}
                        <td className="px-3 py-3 text-zinc-600 dark:text-zinc-300 font-mono text-[11px]">
                          <div>{app.originIp || '127.0.0.1'}</div>
                          <span className="inline-block mt-0.5 px-1.5 py-0.2 rounded bg-zinc-100 dark:bg-zinc-800 border border-zinc-200 dark:border-zinc-700/60 text-[10px] text-zinc-500 dark:text-zinc-400">
                            {app.protocol || 'HTTPS'}:{app.port || 443}
                          </span>
                        </td>

                        {/* Environment */}
                        <td className="px-3 py-3 font-sans">
                          <span className={`inline-flex rounded-md px-2 py-0.5 text-[10px] font-semibold ${
                            (app.environment || '').toUpperCase() === 'PRODUCTION'
                              ? 'bg-blue-50 text-blue-700 border border-blue-200/80 dark:bg-blue-500/10 dark:text-blue-300 dark:border-blue-500/30'
                              : (app.environment || '').toUpperCase() === 'STAGING'
                                ? 'bg-amber-50 text-amber-700 border border-amber-200/80 dark:bg-amber-500/10 dark:text-amber-300 dark:border-amber-500/30'
                                : 'bg-zinc-100 text-zinc-600 border border-zinc-200 dark:bg-zinc-800 dark:text-zinc-300 dark:border-zinc-700'
                          }`}>
                            {app.environment || 'Production'}
                          </span>
                        </td>

                        {/* WAF & Health */}
                        <td className="px-3 py-3">
                          <div className="flex items-center gap-1.5">
                            <StatusBadge type="health" value={app.wafStatus || 'Protected'} />
                            {app.responseTime !== undefined && (
                              <span className="text-[10px] text-zinc-400 dark:text-zinc-500 font-mono">
                                {app.responseTime}ms
                              </span>
                            )}
                          </div>
                        </td>

                        {/* 24H Activity */}
                        <td className="px-3 py-3 text-right font-mono text-[11px]">
                          <div className="text-zinc-900 dark:text-zinc-100 font-semibold">
                            {(app.requests24h || 0).toLocaleString()}
                          </div>
                          {(app.blocked24h || 0) > 0 ? (
                            <div className="text-[10px] text-rose-600 dark:text-rose-400">
                              {(app.blocked24h || 0).toLocaleString()} blocked
                            </div>
                          ) : (
                            <div className="text-[10px] text-emerald-600 dark:text-emerald-400">
                              0 attacks
                            </div>
                          )}
                        </td>

                        {/* Controls */}
                        <td className="px-3.5 py-3 text-right">
                          <div className="flex items-center justify-end gap-1.5">
                            <button
                              onClick={() => handleInspectApp(app)}
                              className="p-1.5 rounded-lg bg-zinc-100 dark:bg-zinc-800 hover:bg-zinc-200 dark:hover:bg-zinc-700 text-zinc-600 dark:text-zinc-300 hover:text-zinc-900 dark:hover:text-white transition cursor-pointer"
                              title="Inspect Application Telemetry"
                            >
                              <Eye className="w-3.5 h-3.5" />
                            </button>
                            <button
                              onClick={() => handleRemoveApp(app)}
                              className="p-1.5 rounded-lg bg-zinc-100 dark:bg-zinc-800 hover:bg-rose-100 dark:hover:bg-rose-950/50 text-zinc-600 dark:text-zinc-300 hover:text-rose-600 dark:hover:text-rose-400 transition cursor-pointer"
                              title="Remove from inventory"
                            >
                              <Trash2 className="w-3.5 h-3.5" />
                            </button>
                          </div>
                        </td>
                      </tr>
                    );
                  })
                )}
              </tbody>
            </table>
          </div>

          {/* Pagination Footer */}
          <div className="shrink-0 flex flex-wrap items-center justify-between gap-2 border-t border-zinc-100 bg-zinc-50/40 px-3.5 py-2.5 text-xs text-zinc-500 dark:border-zinc-800/80 dark:bg-zinc-900/20 dark:text-zinc-400">
            <div>
              Showing {startRecord.toLocaleString()} to {endRecord.toLocaleString()} of {apps.length.toLocaleString()} endpoints
            </div>
            <div className="flex items-center gap-1.5">
              <button
                disabled={currentPage <= 1}
                onClick={() => setCurrentPage(p => Math.max(1, p - 1))}
                className="inline-flex h-7 items-center gap-1 rounded-lg border border-zinc-200 bg-white px-2.5 text-xs font-medium text-zinc-700 transition hover:bg-zinc-50 disabled:opacity-40 disabled:cursor-not-allowed cursor-pointer dark:border-zinc-700 dark:bg-zinc-800 dark:text-zinc-200 dark:hover:bg-zinc-700"
              >
                <ChevronLeft className="h-3 w-3" />
                Previous
              </button>
              <span className="font-mono text-[11px] px-1 text-zinc-600 dark:text-zinc-300">
                {currentPage} / {totalPages}
              </span>
              <button
                disabled={currentPage >= totalPages}
                onClick={() => setCurrentPage(p => Math.min(totalPages, p + 1))}
                className="inline-flex h-7 items-center gap-1 rounded-lg border border-zinc-200 bg-white px-2.5 text-xs font-medium text-zinc-700 transition hover:bg-zinc-50 disabled:opacity-40 disabled:cursor-not-allowed cursor-pointer dark:border-zinc-700 dark:bg-zinc-800 dark:text-zinc-200 dark:hover:bg-zinc-700"
              >
                Next
                <ChevronRight className="h-3 w-3" />
              </button>
            </div>
          </div>
        </div>

        {/* Right Column: Summary Rail (Matching Live Traffic & Centralized Logs) */}
        <aside className="space-y-4">
          {/* Card 1: Fleet Protection Health */}
          <div className="rounded-2xl border border-zinc-200/80 bg-white p-4 shadow-2xs dark:border-zinc-800 dark:bg-[#0c0c0e]">
            <div className="flex items-center justify-between gap-2 mb-3">
              <h3 className="text-[11px] font-semibold uppercase tracking-wider text-zinc-400 dark:text-zinc-500">
                Fleet Protection Health
              </h3>
              <ShieldCheck className="h-3.5 w-3.5 text-zinc-400" />
            </div>

            <div className="grid grid-cols-2 gap-2">
              <div className="rounded-xl border border-zinc-100 bg-zinc-50/50 p-2.5 dark:border-zinc-800/60 dark:bg-zinc-900/40">
                <div className="text-[10px] font-medium text-zinc-400 dark:text-zinc-500">Total</div>
                <div className="mt-0.5 text-lg font-bold text-zinc-900 dark:text-zinc-100 font-mono">
                  {totalApps}
                </div>
              </div>
              <div className="rounded-xl border border-emerald-100 bg-emerald-50/40 p-2.5 dark:border-emerald-500/20 dark:bg-emerald-500/10">
                <div className="text-[10px] font-medium text-emerald-600 dark:text-emerald-400">Protected</div>
                <div className="mt-0.5 text-lg font-bold text-emerald-600 dark:text-emerald-400 font-mono">
                  {metrics.protected || apps.filter(a => a.health === 'ONLINE' || a.wafStatus === 'Protected').length}
                </div>
              </div>
              <div className="rounded-xl border border-amber-100 bg-amber-50/40 p-2.5 dark:border-amber-500/20 dark:bg-amber-500/10">
                <div className="text-[10px] font-medium text-amber-600 dark:text-amber-400">Degraded</div>
                <div className="mt-0.5 text-lg font-bold text-amber-600 dark:text-amber-400 font-mono">
                  {metrics.monitoring || apps.filter(a => a.health === 'DEGRADED' || a.wafStatus === 'Monitoring').length}
                </div>
              </div>
              <div className="rounded-xl border border-rose-100 bg-rose-50/40 p-2.5 dark:border-rose-500/20 dark:bg-rose-500/10">
                <div className="text-[10px] font-medium text-rose-600 dark:text-rose-400">Offline</div>
                <div className="mt-0.5 text-lg font-bold text-rose-600 dark:text-rose-400 font-mono">
                  {metrics.offline || apps.filter(a => a.health === 'OFFLINE' || a.wafStatus === 'Offline').length}
                </div>
              </div>
            </div>

            {/* Visual ratio bar */}
            <div className="mt-3">
              <div className="flex items-center justify-between text-[10px] text-zinc-400 dark:text-zinc-500 mb-1 font-mono">
                <span>Coverage</span>
                <span>
                  {totalApps > 0
                    ? Math.round(((metrics.protected || apps.filter(a => a.health === 'ONLINE').length) / totalApps) * 100)
                    : 100}%
                </span>
              </div>
              <div className="h-1.5 w-full rounded-full bg-zinc-100 overflow-hidden dark:bg-zinc-800 flex">
                <div
                  className="bg-emerald-500 transition-all duration-500"
                  style={{ width: `${totalApps > 0 ? ((metrics.protected || 0) / totalApps) * 100 : 0}%` }}
                />
                <div
                  className="bg-amber-500 transition-all duration-500"
                  style={{ width: `${totalApps > 0 ? ((metrics.monitoring || 0) / totalApps) * 100 : 0}%` }}
                />
                <div
                  className="bg-rose-500 transition-all duration-500"
                  style={{ width: `${totalApps > 0 ? ((metrics.offline || 0) / totalApps) * 100 : 0}%` }}
                />
              </div>
            </div>
          </div>

          {/* Card 2: Environment Distribution */}
          <div className="rounded-2xl border border-zinc-200/80 bg-white p-4 shadow-2xs dark:border-zinc-800 dark:bg-[#0c0c0e]">
            <h3 className="text-[11px] font-semibold uppercase tracking-wider text-zinc-400 dark:text-zinc-500 mb-3">
              Environment Distribution
            </h3>

            <div className="space-y-2 font-mono text-xs">
              <div className="flex items-center justify-between text-zinc-700 dark:text-zinc-300">
                <div className="flex items-center gap-1.5 font-sans">
                  <span className="h-2 w-2 rounded-full bg-blue-500" />
                  <span>Production</span>
                </div>
                <span className="font-semibold">{prodCount}</span>
              </div>
              <div className="flex items-center justify-between text-zinc-700 dark:text-zinc-300">
                <div className="flex items-center gap-1.5 font-sans">
                  <span className="h-2 w-2 rounded-full bg-amber-500" />
                  <span>Staging</span>
                </div>
                <span className="font-semibold">{stagingCount}</span>
              </div>
              <div className="flex items-center justify-between text-zinc-700 dark:text-zinc-300">
                <div className="flex items-center gap-1.5 font-sans">
                  <span className="h-2 w-2 rounded-full bg-zinc-400" />
                  <span>Development</span>
                </div>
                <span className="font-semibold">{devCount}</span>
              </div>
            </div>
          </div>

          {/* Card 3: Ingress Protocols & Agents */}
          <div className="rounded-2xl border border-zinc-200/80 bg-white p-4 shadow-2xs dark:border-zinc-800 dark:bg-[#0c0c0e]">
            <h3 className="text-[11px] font-semibold uppercase tracking-wider text-zinc-400 dark:text-zinc-500 mb-3">
              Ingress & Fleet Link
            </h3>

            <div className="space-y-2 text-xs">
              <div className="flex items-center justify-between font-mono">
                <span className="text-zinc-500 dark:text-zinc-400">HTTPS (TLS 1.3)</span>
                <span className="font-semibold text-zinc-800 dark:text-zinc-200">{httpsCount}</span>
              </div>
              <div className="flex items-center justify-between font-mono">
                <span className="text-zinc-500 dark:text-zinc-400">HTTP Clear</span>
                <span className="font-semibold text-zinc-800 dark:text-zinc-200">{httpCount}</span>
              </div>
              <div className="pt-2 border-t border-zinc-100 dark:border-zinc-800/80 flex items-center justify-between font-mono">
                <span className="text-zinc-500 dark:text-zinc-400">Linked to Agent</span>
                <span className="font-semibold text-emerald-600 dark:text-emerald-400">
                  {linkedAgentsCount} / {totalApps}
                </span>
              </div>
            </div>
          </div>

          {/* Card 4: Auto-Discovery Telemetry Tip */}
          <div className="rounded-2xl border border-zinc-200/80 bg-zinc-50/50 p-4 shadow-2xs dark:border-zinc-800/70 dark:bg-zinc-900/30 text-[11px] text-zinc-500 dark:text-zinc-400">
            <div className="flex items-center gap-1.5 font-semibold text-zinc-800 dark:text-zinc-200 mb-1">
              <CheckCircle2 className="w-3.5 h-3.5 text-emerald-500 shrink-0" />
              <span>Real-Time Fleet Discovery</span>
            </div>
            <p className="leading-relaxed">
              New virtualhosts in Nginx, Apache, or custom port listeners on registered hosts are automatically discovered and added to this inventory in real-time.
            </p>
          </div>
        </aside>
      </div>

      {/* Modal: Application Deep Dive & Telemetry */}
      {selectedApp && (
        <div className="fixed inset-0 z-50 bg-black/60 dark:bg-black/80 backdrop-blur-xs flex items-center justify-center p-4 sm:p-6 animate-fadeIn">
          <div className="relative w-full max-w-3xl max-h-[85vh] rounded-2xl border border-zinc-200/80 dark:border-zinc-800 bg-white dark:bg-[#0c0c0e] shadow-2xl overflow-hidden flex flex-col text-zinc-900 dark:text-zinc-100 transition-colors">
            <div className="p-4 border-b border-zinc-100 dark:border-zinc-800 flex items-center justify-between gap-3 bg-zinc-50/60 dark:bg-zinc-900/40">
              <div className="flex items-center gap-2.5 min-w-0">
                <Server className="w-5 h-5 text-zinc-700 dark:text-zinc-300 shrink-0" />
                <div className="min-w-0">
                  <h3 className="text-sm font-bold text-zinc-900 dark:text-white font-mono truncate">
                    Endpoint Telemetry: {selectedApp.name}
                  </h3>
                  <div className="text-[11px] text-zinc-500 dark:text-slate-400 font-mono truncate">
                    {selectedApp.domain} • Origin: {selectedApp.originIp || selectedApp.ipAddress}
                  </div>
                </div>
              </div>
              <button
                onClick={() => { setSelectedApp(null); setAppDetail(null); }}
                className="p-1.5 rounded-lg hover:bg-zinc-100 dark:hover:bg-zinc-800 text-zinc-400 dark:text-slate-400 hover:text-zinc-900 dark:hover:text-white cursor-pointer shrink-0"
              >
                <X className="w-4 h-4" />
              </button>
            </div>

            <div className="p-4 sm:p-6 overflow-y-auto custom-scrollbar space-y-5 text-xs">
              {/* Stats Grid */}
              <div className="grid grid-cols-2 sm:grid-cols-4 gap-3">
                <div className="p-3 rounded-lg bg-zinc-50 dark:bg-zinc-900/40 border border-zinc-200 dark:border-zinc-800">
                  <div className="text-[10px] text-zinc-500 dark:text-slate-400 uppercase font-mono">Protocol & Port</div>
                  <div className="font-mono text-zinc-700 dark:text-zinc-300 font-semibold mt-0.5">{selectedApp.protocol}:{selectedApp.port}</div>
                </div>
                <div className="p-3 rounded-lg bg-zinc-50 dark:bg-zinc-900/40 border border-zinc-200 dark:border-zinc-800">
                  <div className="text-[10px] text-zinc-500 dark:text-slate-400 uppercase font-mono">24h Ingress Requests</div>
                  <div className="font-mono text-zinc-900 dark:text-white font-bold mt-0.5">{(selectedApp.requests24h || 0).toLocaleString()}</div>
                </div>
                <div className="p-3 rounded-lg bg-zinc-50 dark:bg-zinc-900/40 border border-zinc-200 dark:border-zinc-800">
                  <div className="text-[10px] text-zinc-500 dark:text-slate-400 uppercase font-mono">24h Blocked Attacks</div>
                  <div className="font-mono text-rose-600 dark:text-rose-400 font-bold mt-0.5">{(selectedApp.blocked24h || 0).toLocaleString()}</div>
                </div>
                <div className="p-3 rounded-lg bg-zinc-50 dark:bg-zinc-900/40 border border-zinc-200 dark:border-zinc-800">
                  <div className="text-[10px] text-zinc-500 dark:text-slate-400 uppercase font-mono">TLS Security</div>
                  <div className="font-mono text-emerald-600 dark:text-emerald-400 font-semibold mt-0.5">{selectedApp.tlsStatus || 'TLS 1.3 Active'}</div>
                </div>
              </div>

              {/* Website-scoped endpoint agents */}
              <div>
                <div className="text-[11px] font-bold text-zinc-700 dark:text-zinc-300 uppercase tracking-wider mb-2 flex items-center justify-between gap-2">
                  <span>Endpoint Agents ({appDetail?.agents?.length || 0})</span>
                  <span className="text-[10px] font-normal normal-case tracking-normal text-zinc-400 dark:text-slate-500">
                    One website · bound at enrollment
                  </span>
                </div>
                <div className="grid gap-2 sm:grid-cols-2">
                  {appDetail?.agents?.length ? (
                    appDetail.agents.map((agent: any) => {
                      const statusClass = agent.status === 'ONLINE'
                        ? 'bg-emerald-50 text-emerald-600 border-emerald-200 dark:bg-emerald-500/10 dark:text-emerald-400 dark:border-emerald-500/20'
                        : agent.status === 'OFFLINE' || agent.status === 'STALE'
                          ? 'bg-amber-50 text-amber-600 border-amber-200 dark:bg-amber-500/10 dark:text-amber-400 dark:border-amber-500/20'
                          : 'bg-zinc-50 text-zinc-500 border-zinc-200 dark:bg-zinc-900 dark:text-slate-400 dark:border-zinc-800';
                      return (
                        <div key={agent.id} className="rounded-lg border border-zinc-200 bg-white p-3 dark:border-zinc-800 dark:bg-zinc-900/40">
                          <div className="flex items-start justify-between gap-2">
                            <div className="min-w-0">
                              <div className="truncate font-sans font-semibold text-zinc-900 dark:text-white">{agent.name}</div>
                              <div className="mt-0.5 truncate font-mono text-[10px] text-zinc-400 dark:text-slate-500">
                                {agent.hostname || 'unknown host'} · {agent.ip || 'no ip'}
                              </div>
                            </div>
                            <span className={`shrink-0 rounded border px-1.5 py-0.5 text-[9px] font-semibold ${statusClass}`}>
                              {agent.status}
                            </span>
                          </div>
                          <div className="mt-2 flex items-center justify-between gap-2 font-mono text-[10px] text-zinc-400 dark:text-slate-500">
                            <span>{agent.os || 'unknown'} {agent.arch || ''}</span>
                            <span>{agent.eventsIngested.toLocaleString()} events · {agent.logsIngested.toLocaleString()} logs</span>
                          </div>
                          <div className="mt-1 font-mono text-[10px] text-zinc-400 dark:text-slate-500">
                            Last seen {agent.lastSeen ? formatTime(agent.lastSeen) : 'never'}
                          </div>
                        </div>
                      );
                    })
                  ) : (
                    <div className="sm:col-span-2 rounded-lg border border-dashed border-zinc-200 p-4 text-center font-sans text-zinc-400 dark:border-zinc-800 dark:text-slate-500">
                      No endpoint agent is enrolled for this website yet. Deploy one from the Endpoint Agents page to
                      collect its server telemetry.
                    </div>
                  )}
                </div>
              </div>

              {/* Active Threats Correlated */}
              {appDetail?.activeThreats?.length > 0 && (
                <div>
                  <div className="text-[11px] font-bold text-rose-600 dark:text-rose-400 uppercase tracking-wider mb-2 flex items-center gap-1.5">
                    <AlertTriangle className="w-4 h-4 text-rose-600 dark:text-rose-400" />
                    <span>Active Threat Actors Targeting this Endpoint</span>
                  </div>
                  <div className="space-y-2">
                    {appDetail.activeThreats.map((t: any) => (
                      <div key={t.id} className="p-3 rounded-lg bg-rose-50 border border-rose-200 dark:bg-rose-500/10 dark:border-rose-500/20 flex items-center justify-between gap-2">
                        <div>
                          <div className="text-xs font-bold text-rose-700 dark:text-rose-200 font-mono">{t.attackType} from {t.sourceIp}</div>
                          <div className="text-[11px] text-zinc-500 dark:text-slate-400 font-sans mt-0.5">{t.summary}</div>
                        </div>
                        <StatusBadge type="severity" value={t.severity} />
                      </div>
                    ))}
                  </div>
                </div>
              )}
            </div>

            <div className="p-4 border-t border-zinc-100 dark:border-zinc-800 bg-zinc-50/60 dark:bg-zinc-900/30 flex items-center justify-end">
              <button
                onClick={() => { setSelectedApp(null); setAppDetail(null); }}
                className="px-4 py-2 rounded-lg bg-zinc-100 dark:bg-zinc-800 hover:bg-zinc-200 dark:hover:bg-zinc-700 text-zinc-700 dark:text-zinc-200 text-xs font-semibold transition cursor-pointer"
              >
                Close Inspector
              </button>
            </div>
          </div>
        </div>
      )}

      {/* Modal: Add Application Endpoint */}
      {showAddModal && (
        <div className="fixed inset-0 z-50 bg-black/60 dark:bg-black/80 backdrop-blur-xs flex items-center justify-center p-4 sm:p-6 animate-fadeIn">
          <div className="relative w-full max-w-md max-h-[85vh] rounded-2xl border border-zinc-200/80 dark:border-zinc-800 bg-white dark:bg-[#0c0c0e] shadow-2xl overflow-y-auto custom-scrollbar p-6 text-zinc-900 dark:text-zinc-100 transition-colors">
            <h3 className="text-base font-bold text-zinc-900 dark:text-white mb-1">Protect New Application Endpoint</h3>
            <p className="text-xs text-zinc-500 dark:text-slate-400 mb-4">
              Deploy OAT WAF inspection proxy in front of your upstream web server or microservice.
            </p>

            <form onSubmit={handleAddApp} className="space-y-3.5 text-left">
              <div>
                <label className="block text-xs font-semibold text-zinc-700 dark:text-zinc-300 mb-1">Application Name</label>
                <input
                  type="text"
                  required
                  value={name}
                  onChange={e => setName(e.target.value)}
                  placeholder="e.g. Payments API"
                  className="w-full px-3 py-2 bg-zinc-50 dark:bg-zinc-900/40 border border-zinc-200 dark:border-zinc-800 rounded-lg text-xs text-zinc-900 dark:text-slate-200 placeholder-zinc-400 dark:placeholder-slate-500 focus:outline-none focus:border-zinc-400 dark:focus:border-zinc-700"
                />
              </div>
              <div>
                <label className="block text-xs font-semibold text-zinc-700 dark:text-zinc-300 mb-1">Public Domain (FQDN)</label>
                <input
                  type="text"
                  required
                  value={domain}
                  onChange={e => setDomain(e.target.value)}
                  placeholder="e.g. api.example.com"
                  className="w-full px-3 py-2 bg-zinc-50 dark:bg-zinc-900/40 border border-zinc-200 dark:border-zinc-800 rounded-lg text-xs font-mono text-zinc-900 dark:text-slate-200 placeholder-zinc-400 dark:placeholder-slate-500 focus:outline-none focus:border-zinc-400 dark:focus:border-zinc-700"
                />
              </div>
              <div>
                <label className="block text-xs font-semibold text-zinc-700 dark:text-zinc-300 mb-1">Origin IP Address</label>
                <input
                  type="text"
                  required
                  value={originIp}
                  onChange={e => setOriginIp(e.target.value)}
                  placeholder="e.g. 203.0.113.10"
                  className="w-full px-3 py-2 bg-zinc-50 dark:bg-zinc-900/40 border border-zinc-200 dark:border-zinc-800 rounded-lg text-xs font-mono text-zinc-900 dark:text-slate-200 placeholder-zinc-400 dark:placeholder-slate-500 focus:outline-none focus:border-zinc-400 dark:focus:border-zinc-700"
                />
              </div>
              <div className="grid grid-cols-1 sm:grid-cols-2 gap-3">
                <div>
                  <label className="block text-xs font-semibold text-zinc-700 dark:text-zinc-300 mb-1">Protocol</label>
                  <select
                    value={protocol}
                    onChange={e => setProtocol(e.target.value as any)}
                    className="w-full px-3 py-2 bg-zinc-50 dark:bg-zinc-900/40 border border-zinc-200 dark:border-zinc-800 rounded-lg text-xs text-zinc-900 dark:text-slate-200 font-mono cursor-pointer focus:outline-none focus:border-zinc-400 dark:focus:border-zinc-700"
                  >
                    <option value="HTTPS">HTTPS (TLS 1.3)</option>
                    <option value="HTTP">HTTP (Auto Upgrade)</option>
                    <option value="gRPC">gRPC / HTTP/2</option>
                  </select>
                </div>
                <div>
                  <label className="block text-xs font-semibold text-zinc-700 dark:text-zinc-300 mb-1">Port</label>
                  <input
                    type="number"
                    value={port}
                    onChange={e => setPort(Number(e.target.value))}
                    className="w-full px-3 py-2 bg-zinc-50 dark:bg-zinc-900/40 border border-zinc-200 dark:border-zinc-800 rounded-lg text-xs font-mono text-zinc-900 dark:text-slate-200 focus:outline-none focus:border-zinc-400 dark:focus:border-zinc-700"
                  />
                </div>
              </div>

              <div>
                <label className="block text-xs font-semibold text-zinc-700 dark:text-zinc-300 mb-1">Deployment Environment</label>
                <select
                  value={environment}
                  onChange={e => setEnvironment(e.target.value as any)}
                  className="w-full px-3 py-2 bg-zinc-50 dark:bg-zinc-900/40 border border-zinc-200 dark:border-zinc-800 rounded-lg text-xs text-zinc-900 dark:text-slate-200 cursor-pointer focus:outline-none focus:border-zinc-400 dark:focus:border-zinc-700"
                >
                  <option value="Production">Production</option>
                  <option value="Staging">Staging</option>
                  <option value="Development">Development</option>
                </select>
              </div>

              <div className="pt-4 flex items-center justify-end gap-2">
                <button
                  type="button"
                  onClick={() => setShowAddModal(false)}
                  className="px-4 py-2 rounded-lg text-xs text-zinc-500 dark:text-slate-400 hover:text-zinc-800 dark:hover:text-slate-200 bg-zinc-100 dark:bg-zinc-800 transition cursor-pointer"
                >
                  Cancel
                </button>
                <button
                  type="submit"
                  disabled={submitting}
                  className="px-4 py-2 rounded-lg text-xs font-semibold text-white bg-zinc-900 hover:bg-zinc-800 dark:bg-white dark:text-black dark:hover:bg-slate-200 disabled:opacity-50 shadow-md shadow-zinc-900/20 dark:shadow-black transition cursor-pointer"
                >
                  {submitting ? 'Registering...' : 'Provision WAF Protection'}
                </button>
              </div>
            </form>
          </div>
        </div>
      )}
    </div>
  );
};
