import React, { useState, useEffect, useCallback, useRef } from 'react';
import {
  RefreshCw,
  Search,
  ChevronDown,
  ChevronLeft,
  ChevronRight,
  Filter,
  Download,
  WifiOff,
  FileCode2,
  Copy,
  Check,
  ShieldCheck,
  Cpu,
  Layers
} from 'lucide-react';
import {
  securityApi,
  telemetryStreamManager,
  globalRealtimeClient,
  normalizeRealtimeSecurityEvent,
  RealtimeStreamStatus
} from '../../services/api';
import { SecurityEvent } from '../../types';
import { StatusBadge } from '../../components/common/StatusBadge';
import { BackendOfflineBanner } from '../../components/common/BackendOfflineBanner';
import { FontAwesomeIcon } from '@fortawesome/react-fontawesome';
import { faHeartPulse } from '@fortawesome/free-solid-svg-icons';
import { ModulePageHeader } from '../../components/common/ModulePageHeader';
import { CountryFlag } from '../../components/common/CountryFlag';
import { useAuth } from '../../context/AuthContext';
import { formatDateTime, formatTime } from '../../utils/dateTime';
import { classifyLocalIp, getCountryName } from '../../utils/ip';

type ActionFilterValue = 'ALL' | 'BLOCKED' | 'ALLOWED' | 'CHALLENGED' | 'LOGGED';
type ActionGroup = 'BLOCKED' | 'ALLOWED' | 'CHALLENGED' | 'LOGGED' | 'OTHER';

const actionGroupOf = (action?: string | null): ActionGroup => {
  const value = String(action || '').toUpperCase();
  if (['BLOCK', 'BLOCKED', 'DENY', 'DROP'].includes(value)) return 'BLOCKED';
  if (['ALLOW', 'ALLOWED', 'PASS'].includes(value)) return 'ALLOWED';
  if (['CHALLENGE', 'CHALLENGED', 'RATE_LIMIT'].includes(value)) return 'CHALLENGED';
  if (['LOG', 'LOGGED'].includes(value)) return 'LOGGED';
  return 'OTHER';
};

const ACTION_FILTER_OPTIONS: {
  value: ActionFilterValue;
  label: string;
  dot: string;
  activeBg: string;
  activeText: string;
  countColor: string;
}[] = [
  { value: 'ALL', label: 'All Actions', dot: 'bg-zinc-400', activeBg: '', activeText: 'text-zinc-900 dark:text-zinc-100', countColor: 'text-zinc-400 dark:text-zinc-500' },
  { value: 'BLOCKED', label: 'Blocked', dot: 'bg-rose-500', activeBg: 'bg-rose-50 dark:bg-rose-950/40', activeText: 'text-rose-600 dark:text-rose-400', countColor: 'text-rose-500' },
  { value: 'ALLOWED', label: 'Allowed', dot: 'bg-emerald-500', activeBg: 'bg-emerald-50 dark:bg-emerald-950/40', activeText: 'text-emerald-600 dark:text-emerald-400', countColor: 'text-emerald-500' },
  { value: 'CHALLENGED', label: 'Challenged', dot: 'bg-amber-400', activeBg: 'bg-amber-50 dark:bg-amber-950/40', activeText: 'text-amber-600 dark:text-amber-400', countColor: 'text-amber-500' },
  { value: 'LOGGED', label: 'Logged Only', dot: 'bg-zinc-400', activeBg: 'bg-zinc-100 dark:bg-zinc-800', activeText: 'text-zinc-700 dark:text-zinc-200', countColor: 'text-zinc-500' },
];

type SeverityFilterValue = 'ALL' | 'Critical' | 'High' | 'Medium' | 'Low';

const SEVERITY_FILTER_OPTIONS: {
  value: SeverityFilterValue;
  label: string;
  dot: string;
  activeBg: string;
  activeText: string;
  countColor: string;
}[] = [
  { value: 'ALL', label: 'All Severities', dot: 'bg-zinc-400', activeBg: '', activeText: 'text-zinc-900 dark:text-zinc-100', countColor: 'text-zinc-400 dark:text-zinc-500' },
  { value: 'Critical', label: 'Critical', dot: 'bg-rose-500', activeBg: 'bg-rose-50 dark:bg-rose-950/40', activeText: 'text-rose-600 dark:text-rose-400', countColor: 'text-rose-500' },
  { value: 'High', label: 'High', dot: 'bg-amber-400', activeBg: 'bg-amber-50 dark:bg-amber-950/40', activeText: 'text-amber-600 dark:text-amber-400', countColor: 'text-amber-500' },
  { value: 'Medium', label: 'Medium', dot: 'bg-yellow-400', activeBg: 'bg-yellow-50 dark:bg-yellow-950/40', activeText: 'text-yellow-600 dark:text-yellow-300', countColor: 'text-yellow-500' },
  { value: 'Low', label: 'Low', dot: 'bg-sky-400', activeBg: 'bg-sky-50 dark:bg-sky-950/40', activeText: 'text-sky-600 dark:text-sky-300', countColor: 'text-sky-500' },
];

type SourceFilterValue = 'ALL' | 'waf' | 'firewall' | 'agent';

const SOURCE_FILTER_OPTIONS: { value: SourceFilterValue; label: string; dot: string }[] = [
  { value: 'ALL', label: 'All Engines', dot: 'bg-zinc-400' },
  { value: 'waf', label: 'WAF Engine', dot: 'bg-violet-500' },
  { value: 'firewall', label: 'Firewall', dot: 'bg-amber-500' },
  { value: 'agent', label: 'Endpoint Agents', dot: 'bg-cyan-500' }
];

export const SecurityEventsModule: React.FC = () => {
  const { currentOrg, isBackendOffline } = useAuth();
  const [events, setEvents] = useState<SecurityEvent[]>([]);
  const [loading, setLoading] = useState(true);
  const [exporting, setExporting] = useState(false);
  const [recordedTotal, setRecordedTotal] = useState(0);
  const [currentPage, setCurrentPage] = useState(1);
  const [pageSize, setPageSize] = useState(50);

  // Filters
  const [actionFilter, setActionFilter] = useState<ActionFilterValue>('ALL');
  const [severityFilter, setSeverityFilter] = useState<SeverityFilterValue>('ALL');
  const [sourceFilter, setSourceFilter] = useState<SourceFilterValue>('ALL');
  const [appFilter, setAppFilter] = useState<string>('ALL');
  const [search, setSearch] = useState('');
  const [searchTerm, setSearchTerm] = useState('');

  // Dropdown states
  const [showActionDropdown, setShowActionDropdown] = useState(false);
  const [showSeverityDropdown, setShowSeverityDropdown] = useState(false);
  const [showSourceDropdown, setShowSourceDropdown] = useState(false);
  const [showAppDropdown, setShowAppDropdown] = useState(false);

  // Real-time connection & inspector
  const [realtimeStatus, setRealtimeStatus] = useState<RealtimeStreamStatus>('CONNECTED');
  const [selectedEvent, setSelectedEvent] = useState<SecurityEvent | null>(null);
  const [eventDetail, setEventDetail] = useState<any | null>(null);
  const [copiedId, setCopiedId] = useState(false);
  const [copiedRaw, setCopiedRaw] = useState(false);

  // Mobile swipe-to-dismiss gesture state (mobile only)
  const [swipeTranslateX, setSwipeTranslateX] = useState(0);
  const [isSwiping, setIsSwiping] = useState(false);
  const touchStartRef = useRef<{ x: number; y: number; time: number } | null>(null);

  const handleTouchStart = (e: React.TouchEvent) => {
    if (typeof window !== 'undefined' && window.innerWidth >= 640) return;
    const touch = e.touches[0];
    touchStartRef.current = {
      x: touch.clientX,
      y: touch.clientY,
      time: Date.now()
    };
    setIsSwiping(false);
  };

  const handleTouchMove = (e: React.TouchEvent) => {
    if (!touchStartRef.current || (typeof window !== 'undefined' && window.innerWidth >= 640)) return;
    const touch = e.touches[0];
    const deltaX = touch.clientX - touchStartRef.current.x;
    const deltaY = touch.clientY - touchStartRef.current.y;

    if (deltaX > 8 && deltaX > Math.abs(deltaY) * 1.1) {
      setIsSwiping(true);
      setSwipeTranslateX(Math.max(0, deltaX));
    } else if (deltaX <= 0 && isSwiping) {
      setSwipeTranslateX(0);
    }
  };

  const handleTouchEnd = () => {
    if (!touchStartRef.current || (typeof window !== 'undefined' && window.innerWidth >= 640)) {
      touchStartRef.current = null;
      setIsSwiping(false);
      setSwipeTranslateX(0);
      return;
    }

    const elapsed = Date.now() - touchStartRef.current.time;
    const shouldDismiss = swipeTranslateX > 80 || (swipeTranslateX > 40 && elapsed < 250);

    if (shouldDismiss) {
      setSwipeTranslateX(window.innerWidth || 400);
      setTimeout(() => {
        setSelectedEvent(null);
        setEventDetail(null);
        setSwipeTranslateX(0);
        setIsSwiping(false);
      }, 150);
    } else {
      setIsSwiping(false);
      setSwipeTranslateX(0);
    }
    touchStartRef.current = null;
  };

  // Database-wide aggregates for side rail & filter badges
  const [aggregateActions, setAggregateActions] = useState<{
    blocked: number;
    allowed: number;
    challenged: number;
    logged: number;
    other: number;
    total: number;
  } | null>(null);

  const [aggregateSeverities, setAggregateSeverities] = useState<{
    critical: number;
    high: number;
    medium: number;
    low: number;
  } | null>(null);

  const [topSourceIpsAgg, setTopSourceIpsAgg] = useState<Array<{
    ip: string;
    count: number;
    sourceCountry?: string;
    sourceCountryCode?: string;
  }>>([]);
  const [topApplicationsAgg, setTopApplicationsAgg] = useState<Array<{ application: string; count: number }>>([]);

  // Debounce search input
  useEffect(() => {
    const timer = window.setTimeout(() => {
      setSearchTerm(search.trim());
      setCurrentPage(1);
    }, 300);
    return () => window.clearTimeout(timer);
  }, [search]);

  // Load events for the current page and active filters
  const fetchEvents = useCallback(async () => {
    if (isBackendOffline) return;
    setLoading(true);
    try {
      const res = await securityApi.getSecurityEvents({
        limit: pageSize,
        page: currentPage,
        action: actionFilter === 'ALL' ? undefined : actionFilter,
        severity: severityFilter === 'ALL' ? undefined : severityFilter,
        source: sourceFilter === 'ALL' ? undefined : sourceFilter,
        application: appFilter === 'ALL' ? undefined : appFilter,
        search: searchTerm || undefined
      });

      if (res.events) {
        setEvents(res.events);
      }
      if (typeof res.total === 'number') {
        setRecordedTotal(res.total);
      }
    } catch (err) {
      console.error('[SecurityEvents] Fetch failed:', err);
    } finally {
      setLoading(false);
    }
  }, [isBackendOffline, pageSize, currentPage, actionFilter, severityFilter, sourceFilter, appFilter, searchTerm]);

  useEffect(() => {
    fetchEvents();
  }, [fetchEvents]);

  // Periodic background refresh every 2.5s on page 1 so events sync without manual refresh
  useEffect(() => {
    if (isBackendOffline) return;
    const timer = window.setInterval(async () => {
      if (currentPage !== 1) return;
      try {
        const res = await securityApi.getSecurityEvents({
          limit: pageSize,
          page: 1,
          action: actionFilter === 'ALL' ? undefined : actionFilter,
          severity: severityFilter === 'ALL' ? undefined : severityFilter,
          source: sourceFilter === 'ALL' ? undefined : sourceFilter,
          application: appFilter === 'ALL' ? undefined : appFilter,
          search: searchTerm || undefined
        });
        if (res.events && res.events.length > 0) {
          setEvents(prev => {
            if (prev.length > 0 && res.events[0]?.id === prev[0]?.id && prev.length === res.events.length) {
              return prev;
            }
            return res.events;
          });
          if (typeof res.total === 'number') {
            setRecordedTotal(res.total);
          }
        }
      } catch {}
    }, 2500);
    return () => window.clearInterval(timer);
  }, [isBackendOffline, currentPage, pageSize, actionFilter, severityFilter, sourceFilter, appFilter, searchTerm]);

  // Load aggregates for the side rail from full DB
  const fetchAggregates = useCallback(async () => {
    if (isBackendOffline) return;
    try {
      const res = await securityApi.getSecurityEventsAggregates({ limit: 10 });
      setTopSourceIpsAgg(res.topSourceIps || []);
      setTopApplicationsAgg(res.topApplications || []);
      setAggregateActions(res.actions ? { ...res.actions, total: res.total } : null);
      setAggregateSeverities(res.severities || null);
    } catch (err) {
      console.error('[SecurityEvents] Aggregates fetch failed:', err);
    }
  }, [isBackendOffline]);

  useEffect(() => {
    fetchAggregates();
    const interval = window.setInterval(fetchAggregates, 60000);
    return () => window.clearInterval(interval);
  }, [fetchAggregates]);

  // Real-time WebSocket event subscription
  useEffect(() => {
    if (isBackendOffline) return;

    const unsubStatus = globalRealtimeClient.onStatusChange(status => {
      setRealtimeStatus(status);
    });

    const matchesActiveView = (evt: SecurityEvent) => {
      if (actionFilter !== 'ALL' && actionGroupOf(evt.action) !== actionFilter) return false;
      if (severityFilter !== 'ALL' && String(evt.severity || '').toLowerCase() !== severityFilter.toLowerCase()) return false;
      if (sourceFilter !== 'ALL') {
        const src = String(evt.source || evt.category || '').toLowerCase();
        if (!src.includes(sourceFilter.toLowerCase())) return false;
      }
      if (appFilter !== 'ALL' && evt.application !== appFilter) return false;
      const term = searchTerm.trim().toLowerCase();
      if (!term) return true;
      return [evt.sourceIp, evt.application, evt.threat, evt.id]
        .some(val => String(val || '').toLowerCase().includes(term));
    };

    const unsubEvents = telemetryStreamManager.subscribe((msg: any) => {
      const newEvent = normalizeRealtimeSecurityEvent(msg);
      if (!newEvent || !matchesActiveView(newEvent)) return;

      setRecordedTotal(prev => prev + 1);

      // Instantly update aggregated counts and rail metrics in real-time (0ms delay)
      const group = actionGroupOf(newEvent.action);
      setAggregateActions(prev => {
        if (!prev) return prev;
        return {
          ...prev,
          total: prev.total + 1,
          blocked: group === 'BLOCKED' ? prev.blocked + 1 : prev.blocked,
          allowed: group === 'ALLOWED' ? prev.allowed + 1 : prev.allowed,
          challenged: group === 'CHALLENGED' ? prev.challenged + 1 : prev.challenged,
          logged: group === 'LOGGED' ? prev.logged + 1 : prev.logged,
          other: group === 'OTHER' ? prev.other + 1 : prev.other
        };
      });

      const sev = String(newEvent.severity || '').toLowerCase();
      setAggregateSeverities(prev => {
        if (!prev) return prev;
        return {
          ...prev,
          critical: sev === 'critical' ? prev.critical + 1 : prev.critical,
          high: sev === 'high' ? prev.high + 1 : prev.high,
          medium: sev === 'medium' ? prev.medium + 1 : prev.medium,
          low: sev === 'low' ? prev.low + 1 : prev.low
        };
      });

      if (newEvent.sourceIp && newEvent.sourceIp !== '0.0.0.0') {
        setTopSourceIpsAgg(prev => {
          const idx = prev.findIndex(item => item.ip === newEvent.sourceIp);
          if (idx >= 0) {
            const next = [...prev];
            next[idx] = { ...next[idx], count: next[idx].count + 1 };
            return next.sort((a, b) => b.count - a.count);
          }
          return [...prev, {
            ip: newEvent.sourceIp,
            count: 1,
            sourceCountry: newEvent.sourceCountry,
            sourceCountryCode: newEvent.sourceCountryCode
          }].sort((a, b) => b.count - a.count).slice(0, 10);
        });
      }

      // Prepend event live if user is currently looking at page 1
      if (currentPage === 1) {
        setEvents(prev => {
          if (prev.some(e => e.id === newEvent.id)) return prev;
          return [newEvent, ...prev.slice(0, pageSize - 1)];
        });
      }
    });

    return () => {
      unsubStatus();
      unsubEvents();
    };
  }, [isBackendOffline, currentPage, pageSize, actionFilter, severityFilter, sourceFilter, appFilter, searchTerm]);

  // Inspect event in drawer
  const handleInspectEvent = async (evt: SecurityEvent) => {
    setSelectedEvent(evt);
    setCopiedId(false);
    setCopiedRaw(false);
    try {
      const detail = await securityApi.getSecurityEventDetail(evt.id);
      setEventDetail(detail);
    } catch {
      setEventDetail(evt);
    }
  };

  if (isBackendOffline) {
    return <BackendOfflineBanner onRetry={fetchEvents} />;
  }

  // Filter count helpers
  const actionFilterCounts: Record<ActionFilterValue, number> = {
    ALL: aggregateActions?.total ?? recordedTotal,
    BLOCKED: aggregateActions?.blocked ?? 0,
    ALLOWED: aggregateActions?.allowed ?? 0,
    CHALLENGED: aggregateActions?.challenged ?? 0,
    LOGGED: aggregateActions?.logged ?? 0
  };

  const severityFilterCounts: Record<SeverityFilterValue, number> = {
    ALL: aggregateActions?.total ?? recordedTotal,
    Critical: aggregateSeverities?.critical ?? 0,
    High: aggregateSeverities?.high ?? 0,
    Medium: aggregateSeverities?.medium ?? 0,
    Low: aggregateSeverities?.low ?? 0
  };

  // Side rail metrics
  const maxRailRows = 5;
  const topSourceIps = topSourceIpsAgg.slice(0, maxRailRows);
  const topApplications = topApplicationsAgg.slice(0, maxRailRows).map(r => [r.application, r.count] as [string, number]);
  const topSourceIpMax = topSourceIps.length > 0 ? topSourceIps[0].count : 0;
  const topApplicationMax = topApplications.length > 0 ? topApplications[0][1] : 0;

  const actionRailRows = [
    { label: 'Blocked', count: actionFilterCounts.BLOCKED, dot: 'bg-rose-500', bar: 'bg-rose-500' },
    { label: 'Allowed', count: actionFilterCounts.ALLOWED, dot: 'bg-emerald-500', bar: 'bg-emerald-500' },
    { label: 'Challenged', count: actionFilterCounts.CHALLENGED, dot: 'bg-amber-400', bar: 'bg-amber-400' },
    { label: 'Logged', count: actionFilterCounts.LOGGED, dot: 'bg-zinc-400', bar: 'bg-zinc-400' }
  ].sort((a, b) => b.count - a.count);
  const actionRailMax = actionRailRows[0]?.count ?? 0;

  const severityRailRows = [
    { label: 'Critical', count: severityFilterCounts.Critical, dot: 'bg-rose-500', bar: 'bg-rose-500' },
    { label: 'High', count: severityFilterCounts.High, dot: 'bg-amber-500', bar: 'bg-amber-500' },
    { label: 'Medium', count: severityFilterCounts.Medium, dot: 'bg-yellow-400', bar: 'bg-yellow-400' },
    { label: 'Low', count: severityFilterCounts.Low, dot: 'bg-sky-400', bar: 'bg-sky-400' }
  ];
  const severityRailMax = Math.max(...severityRailRows.map(r => r.count), 1);

  // Pagination bounds
  const totalPages = Math.max(1, Math.ceil(recordedTotal / pageSize));
  const startRecord = recordedTotal === 0 ? 0 : (currentPage - 1) * pageSize + 1;
  const endRecord = Math.min(currentPage * pageSize, recordedTotal);

  // Origin badge helper
  const getOriginBadge = (ip?: string, countryCode?: string, countryName?: string) => {
    let code = countryCode || (classifyLocalIp(ip) ? 'ID' : 'UN');
    if (code === 'LAN' || code === 'SYS') {
      code = 'ID';
    }
    return {
      badge: code,
      title: getCountryName(code, countryName),
      className: 'bg-zinc-100 dark:bg-zinc-800 text-zinc-700 dark:text-zinc-200 border-zinc-200/80 dark:border-zinc-700/80 shadow-2xs'
    };
  };

  // Security Engine badge helper
  const getEngineBadge = (source?: string, category?: string) => {
    const s = String(source || category || '').toLowerCase();
    if (s.includes('waf')) {
      return {
        label: 'Cloud WAF',
        short: 'WAF',
        className: 'bg-violet-50 text-violet-700 border-violet-200/70 dark:bg-violet-950/40 dark:text-violet-300 dark:border-violet-800/60',
        dot: 'bg-violet-500'
      };
    }
    if (s.includes('firewall')) {
      return {
        label: 'Firewall',
        short: 'Firewall',
        className: 'bg-amber-50 text-amber-700 border-amber-200/70 dark:bg-amber-950/40 dark:text-amber-300 dark:border-amber-800/60',
        dot: 'bg-amber-500'
      };
    }
    if (s.includes('agent')) {
      return {
        label: 'Endpoint Agent',
        short: 'Agent',
        className: 'bg-cyan-50 text-cyan-700 border-cyan-200/70 dark:bg-cyan-950/40 dark:text-cyan-300 dark:border-cyan-800/60',
        dot: 'bg-cyan-500'
      };
    }
    return {
      label: 'Perimeter',
      short: 'SEC',
      className: 'bg-zinc-100 text-zinc-600 border-zinc-200/70 dark:bg-zinc-800 dark:text-zinc-300 dark:border-zinc-700/60',
      dot: 'bg-zinc-400'
    };
  };

  const applicationsList = Array.from(new Set(events.map(e => e.application || '').filter(Boolean)));

  // Export the ENTIRE security event log for this tenant — not just the visible
  // page. The API caps each response at 1000 rows, so walk the pagination until
  // exhausted (safeguard: 100 pages ≈ 100k events).
  const handleExportJson = async () => {
    if (exporting) return;
    setExporting(true);
    try {
      const pageSize = 1000;
      const all: SecurityEvent[] = [];
      let page = 1;
      while (page <= 100) {
        const res = await securityApi.getSecurityEvents({ limit: pageSize, page });
        const batch = (res?.events || []) as SecurityEvent[];
        all.push(...batch);
        if (batch.length < pageSize) break;
        page += 1;
      }

      const payload = {
        exportedAt: new Date().toISOString(),
        organization: currentOrg?.name || 'Unknown Tenant',
        organizationId: currentOrg?.id || null,
        total: all.length,
        events: all
      };

      const sanitize = (name: string) => name.trim().replace(/[^\w\d.-]+/g, '-') || 'OAT-Security';
      const orgName = sanitize(currentOrg?.name || 'OAT-Security');
      const dateStamp = new Date().toISOString().slice(0, 10);

      const blob = new Blob([JSON.stringify(payload, null, 2)], { type: 'application/json;charset=utf-8' });
      const url = URL.createObjectURL(blob);
      const anchor = document.createElement('a');
      anchor.href = url;
      anchor.download = `${orgName}_security-events_${dateStamp}.json`;
      document.body.appendChild(anchor);
      anchor.click();
      anchor.remove();
      URL.revokeObjectURL(url);
    } catch {
      // Best-effort export — the live feed keeps running regardless.
    } finally {
      setExporting(false);
    }
  };

  return (
    <div className="space-y-5" id="security-events-module">
      {/* Real-time Connection Banner if Lost */}
      {realtimeStatus === 'REAL-TIME CONNECTION LOST' && (
        <div className="rounded-xl border border-rose-500/40 bg-rose-500/10 p-4 flex flex-col sm:flex-row sm:items-center justify-between gap-3 text-rose-700 dark:text-rose-200">
          <div className="flex items-center gap-3">
            <WifiOff className="w-5 h-5 text-rose-600 dark:text-rose-400 animate-pulse" />
            <div>
              <div className="text-xs font-bold uppercase tracking-wider text-rose-600 dark:text-rose-400">
                REAL-TIME TELEMETRY DISCONNECTED
              </div>
              <div className="text-xs text-rose-600 dark:text-rose-400 mt-0.5">
                Ingress security socket disconnected. Background auto-reconnect active.
              </div>
            </div>
          </div>
          <button
            onClick={() => globalRealtimeClient.connect()}
            className="px-3 py-1.5 rounded-lg bg-rose-600 hover:bg-rose-500 text-white text-xs font-semibold cursor-pointer"
          >
            Reconnect Now
          </button>
        </div>
      )}

      {/* Header — mirrors the dashboard page header style */}
      <ModulePageHeader
        icon={<FontAwesomeIcon icon={faHeartPulse} />}
        title="Security"
        titleTail="Events"
        subtitle="Unified live security telemetry captured across enrolled endpoint agents, the WAF inspection engine, and the perimeter firewall."
        actions={
          <button
            onClick={handleExportJson}
            disabled={exporting}
            title="Export the complete security event log (all pages) as JSON"
            className="inline-flex h-8 shrink-0 items-center gap-1.5 rounded-lg border border-zinc-200/80 bg-white px-2.5 text-xs font-medium text-zinc-600 transition hover:border-zinc-300 hover:text-zinc-900 cursor-pointer disabled:cursor-wait disabled:opacity-60 dark:border-zinc-800 dark:bg-zinc-900 dark:text-zinc-300 dark:hover:border-zinc-600 dark:hover:text-zinc-100"
          >
            <Download className={`w-3.5 h-3.5 ${exporting ? 'animate-pulse' : ''}`} />
            {exporting ? 'Exporting…' : 'Export JSON'}
          </button>
        }
      />

      {/* Main Grid: Live feed on the left, telemetry summary rail on the right */}
      <div className="grid items-start gap-5 lg:grid-cols-[minmax(0,1fr)_300px] xl:grid-cols-[minmax(0,1fr)_340px]">
        {/* Feed Card: Stream window and table */}
        <div className="flex min-w-0 flex-col overflow-hidden rounded-2xl border border-zinc-200/80 bg-white shadow-2xs dark:border-zinc-800 dark:bg-[#0c0c0e]">
          {/* Stream Toolbar */}
          <div className="shrink-0 flex flex-wrap items-center gap-2 border-b border-zinc-100 bg-zinc-50/60 px-3 py-2.5 dark:border-zinc-800/80 dark:bg-zinc-900/40">
            {/* Action Filter */}
            <div className="relative">
              <button
                type="button"
                onClick={() => {
                  setShowActionDropdown(prev => !prev);
                  setShowSeverityDropdown(false);
                  setShowSourceDropdown(false);
                  setShowAppDropdown(false);
                }}
                className="h-8 px-2.5 rounded-lg border border-zinc-200/80 dark:border-zinc-800 bg-white dark:bg-zinc-900 hover:bg-zinc-50 dark:hover:bg-zinc-800 text-xs font-medium text-zinc-700 dark:text-zinc-200 inline-flex items-center gap-2 transition cursor-pointer shadow-2xs"
              >
                <Filter className="w-3 h-3 text-zinc-400" />
                <span>
                  {(() => {
                    const opt = ACTION_FILTER_OPTIONS.find(o => o.value === actionFilter)!;
                    return `${opt.label} (${actionFilterCounts[actionFilter].toLocaleString()})`;
                  })()}
                </span>
                <ChevronDown className={`w-3 h-3 text-zinc-400 transition-transform ${showActionDropdown ? 'rotate-180' : ''}`} />
              </button>

              {showActionDropdown && (
                <>
                  <div className="fixed inset-0 z-20 cursor-default" onClick={() => setShowActionDropdown(false)} />
                  <div className="absolute left-0 top-full mt-1.5 w-52 max-w-[calc(100vw-32px)] rounded-xl border border-zinc-200/80 dark:border-zinc-800 bg-white dark:bg-zinc-900 shadow-xl p-1 z-30">
                    {ACTION_FILTER_OPTIONS.map(opt => {
                      const isActive = actionFilter === opt.value;
                      return (
                        <button
                          key={opt.value}
                          type="button"
                          onClick={() => {
                            setActionFilter(opt.value);
                            setCurrentPage(1);
                            setShowActionDropdown(false);
                          }}
                          className={`w-full px-2.5 py-1.5 rounded-lg text-xs text-left flex items-center justify-between transition cursor-pointer ${
                            isActive
                              ? `font-semibold ${opt.activeBg || 'bg-zinc-100 dark:bg-zinc-800'} ${opt.activeText}`
                              : 'text-zinc-600 dark:text-zinc-400 hover:bg-zinc-50 dark:hover:bg-zinc-800/60'
                          }`}
                        >
                          <span className="flex items-center gap-1.5">
                            <span className={`w-2 h-2 rounded-full shrink-0 ${opt.dot}`} />
                            <span>{opt.label}</span>
                          </span>
                          <span className={`text-[10px] tabular-nums ${isActive ? opt.countColor : 'text-zinc-400'}`}>
                            ({actionFilterCounts[opt.value].toLocaleString()})
                          </span>
                        </button>
                      );
                    })}
                  </div>
                </>
              )}
            </div>

            {/* Severity Filter */}
            <div className="relative">
              <button
                type="button"
                onClick={() => {
                  setShowSeverityDropdown(prev => !prev);
                  setShowActionDropdown(false);
                  setShowSourceDropdown(false);
                  setShowAppDropdown(false);
                }}
                className="h-8 px-2.5 rounded-lg border border-zinc-200/80 dark:border-zinc-800 bg-white dark:bg-zinc-900 hover:bg-zinc-50 dark:hover:bg-zinc-800 text-xs font-medium text-zinc-700 dark:text-zinc-200 inline-flex items-center gap-2 transition cursor-pointer shadow-2xs"
              >
                <span className={`w-2 h-2 rounded-full shrink-0 ${SEVERITY_FILTER_OPTIONS.find(o => o.value === severityFilter)?.dot || 'bg-zinc-400'}`} />
                <span>
                  {(() => {
                    const opt = SEVERITY_FILTER_OPTIONS.find(o => o.value === severityFilter)!;
                    return `${opt.label} (${severityFilterCounts[severityFilter].toLocaleString()})`;
                  })()}
                </span>
                <ChevronDown className={`w-3 h-3 text-zinc-400 transition-transform ${showSeverityDropdown ? 'rotate-180' : ''}`} />
              </button>

              {showSeverityDropdown && (
                <>
                  <div className="fixed inset-0 z-20 cursor-default" onClick={() => setShowSeverityDropdown(false)} />
                  <div className="absolute left-0 top-full mt-1.5 w-52 max-w-[calc(100vw-32px)] rounded-xl border border-zinc-200/80 dark:border-zinc-800 bg-white dark:bg-zinc-900 shadow-xl p-1 z-30">
                    {SEVERITY_FILTER_OPTIONS.map(opt => {
                      const isActive = severityFilter === opt.value;
                      return (
                        <button
                          key={opt.value}
                          type="button"
                          onClick={() => {
                            setSeverityFilter(opt.value);
                            setCurrentPage(1);
                            setShowSeverityDropdown(false);
                          }}
                          className={`w-full px-2.5 py-1.5 rounded-lg text-xs text-left flex items-center justify-between transition cursor-pointer ${
                            isActive
                              ? `font-semibold ${opt.activeBg || 'bg-zinc-100 dark:bg-zinc-800'} ${opt.activeText}`
                              : 'text-zinc-600 dark:text-zinc-400 hover:bg-zinc-50 dark:hover:bg-zinc-800/60'
                          }`}
                        >
                          <span className="flex items-center gap-1.5">
                            <span className={`w-2 h-2 rounded-full shrink-0 ${opt.dot}`} />
                            <span>{opt.label}</span>
                          </span>
                          <span className={`text-[10px] tabular-nums ${isActive ? opt.countColor : 'text-zinc-400'}`}>
                            ({severityFilterCounts[opt.value].toLocaleString()})
                          </span>
                        </button>
                      );
                    })}
                  </div>
                </>
              )}
            </div>

            {/* Source Engine Filter */}
            <div className="relative">
              <button
                type="button"
                onClick={() => {
                  setShowSourceDropdown(prev => !prev);
                  setShowActionDropdown(false);
                  setShowSeverityDropdown(false);
                  setShowAppDropdown(false);
                }}
                className="h-8 px-2.5 rounded-lg border border-zinc-200/80 dark:border-zinc-800 bg-white dark:bg-zinc-900 hover:bg-zinc-50 dark:hover:bg-zinc-800 text-xs font-medium text-zinc-700 dark:text-zinc-200 inline-flex items-center gap-2 transition cursor-pointer shadow-2xs"
              >
                <Cpu className="w-3 h-3 text-zinc-400" />
                <span>{SOURCE_FILTER_OPTIONS.find(o => o.value === sourceFilter)?.label || 'All Engines'}</span>
                <ChevronDown className={`w-3 h-3 text-zinc-400 transition-transform ${showSourceDropdown ? 'rotate-180' : ''}`} />
              </button>

              {showSourceDropdown && (
                <>
                  <div className="fixed inset-0 z-20 cursor-default" onClick={() => setShowSourceDropdown(false)} />
                  <div className="absolute left-0 top-full mt-1.5 w-44 max-w-[calc(100vw-32px)] rounded-xl border border-zinc-200/80 dark:border-zinc-800 bg-white dark:bg-zinc-900 shadow-xl p-1 z-30">
                    {SOURCE_FILTER_OPTIONS.map(opt => (
                      <button
                        key={opt.value}
                        type="button"
                        onClick={() => {
                          setSourceFilter(opt.value);
                          setCurrentPage(1);
                          setShowSourceDropdown(false);
                        }}
                        className={`w-full px-2.5 py-1.5 rounded-lg text-xs text-left flex items-center gap-2 transition cursor-pointer ${
                          sourceFilter === opt.value
                            ? 'font-semibold bg-zinc-100 dark:bg-zinc-800 text-zinc-900 dark:text-zinc-100'
                            : 'text-zinc-600 dark:text-zinc-400 hover:bg-zinc-50 dark:hover:bg-zinc-800/60'
                        }`}
                      >
                        <span className={`w-2 h-2 rounded-full shrink-0 ${opt.dot}`} />
                        <span>{opt.label}</span>
                      </button>
                    ))}
                  </div>
                </>
              )}
            </div>

            {/* Application Filter (if apps exist) */}
            {applicationsList.length > 0 && (
              <div className="relative">
                <button
                  type="button"
                  onClick={() => {
                    setShowAppDropdown(prev => !prev);
                    setShowActionDropdown(false);
                    setShowSeverityDropdown(false);
                    setShowSourceDropdown(false);
                  }}
                  className="h-8 px-2.5 rounded-lg border border-zinc-200/80 dark:border-zinc-800 bg-white dark:bg-zinc-900 hover:bg-zinc-50 dark:hover:bg-zinc-800 text-xs font-medium text-zinc-700 dark:text-zinc-200 inline-flex items-center gap-2 transition cursor-pointer shadow-2xs"
                >
                  <Layers className="w-3 h-3 text-zinc-400" />
                  <span className="max-w-[110px] truncate">{appFilter === 'ALL' ? 'All Apps' : appFilter}</span>
                  <ChevronDown className={`w-3 h-3 text-zinc-400 transition-transform ${showAppDropdown ? 'rotate-180' : ''}`} />
                </button>

                {showAppDropdown && (
                  <>
                    <div className="fixed inset-0 z-20 cursor-default" onClick={() => setShowAppDropdown(false)} />
                    <div className="absolute left-0 top-full mt-1.5 w-48 max-w-[calc(100vw-32px)] rounded-xl border border-zinc-200/80 dark:border-zinc-800 bg-white dark:bg-zinc-900 shadow-xl p-1 z-30 max-h-56 overflow-y-auto custom-scrollbar">
                      <button
                        type="button"
                        onClick={() => { setAppFilter('ALL'); setCurrentPage(1); setShowAppDropdown(false); }}
                        className={`w-full px-2.5 py-1.5 rounded-lg text-xs text-left transition cursor-pointer ${
                          appFilter === 'ALL'
                            ? 'font-semibold bg-zinc-100 dark:bg-zinc-800 text-zinc-900 dark:text-zinc-100'
                            : 'text-zinc-600 dark:text-zinc-400 hover:bg-zinc-50 dark:hover:bg-zinc-800/60'
                        }`}
                      >
                        All Applications
                      </button>
                      {applicationsList.map(app => (
                        <button
                          key={app}
                          type="button"
                          onClick={() => { setAppFilter(app); setCurrentPage(1); setShowAppDropdown(false); }}
                          className={`w-full px-2.5 py-1.5 rounded-lg text-xs text-left transition cursor-pointer truncate ${
                            appFilter === app
                              ? 'font-semibold bg-zinc-100 dark:bg-zinc-800 text-zinc-900 dark:text-zinc-100'
                              : 'text-zinc-600 dark:text-zinc-400 hover:bg-zinc-50 dark:hover:bg-zinc-800/60'
                          }`}
                        >
                          {app}
                        </button>
                      ))}
                    </div>
                  </>
                )}
              </div>
            )}

            {/* Quick Search */}
            <div className="relative w-full sm:ml-auto sm:w-auto sm:min-w-[220px]">
              <Search className="w-3.5 h-3.5 text-zinc-400 dark:text-zinc-500 absolute left-3 top-1/2 -translate-y-1/2" />
              <input
                type="text"
                value={search}
                onChange={e => setSearch(e.target.value)}
                placeholder="Search IP, threat, app, or ID"
                className="h-8 w-full rounded-lg border border-zinc-200/80 bg-white pl-8 pr-3 text-xs text-zinc-800 placeholder-zinc-400 transition focus:outline-none focus:border-zinc-400 dark:border-zinc-800 dark:bg-zinc-900 dark:text-zinc-200 dark:placeholder-zinc-500 dark:focus:border-zinc-600"
              />
            </div>
          </div>

          {/* Table Container — Live Traffic Style */}
          <div className="h-[580px] overflow-y-auto overflow-x-auto custom-scrollbar">
            <table className="min-w-[760px] w-full table-fixed border-separate border-spacing-0 text-left text-xs">
              <thead>
                <tr className="text-[11px] font-medium uppercase tracking-wider text-zinc-400 dark:text-zinc-500">
                  <th className="sticky top-0 z-20 w-[11%] min-w-[85px] border-b border-zinc-200/80 bg-zinc-50 pl-4 pr-2 py-2.5 font-medium dark:border-zinc-800 dark:bg-zinc-900">
                    Time
                  </th>
                  <th className="sticky top-0 z-20 w-[18%] min-w-[140px] border-b border-zinc-200/80 bg-zinc-50 px-3 py-2.5 font-medium dark:border-zinc-800 dark:bg-zinc-900">
                    Source IP
                  </th>
                  <th className="sticky top-0 z-20 w-[13%] min-w-[95px] border-b border-zinc-200/80 bg-zinc-50 px-2 py-2.5 font-medium text-center dark:border-zinc-800 dark:bg-zinc-900">
                    Engine
                  </th>
                  <th className="sticky top-0 z-20 w-[14%] min-w-[110px] border-b border-zinc-200/80 bg-zinc-50 px-3 py-2.5 font-medium dark:border-zinc-800 dark:bg-zinc-900">
                    Application
                  </th>
                  <th className="sticky top-0 z-20 w-[24%] min-w-[170px] border-b border-zinc-200/80 bg-zinc-50 px-3 py-2.5 font-medium dark:border-zinc-800 dark:bg-zinc-900">
                    Detected Threat
                  </th>
                  <th className="sticky top-0 z-20 w-[10%] min-w-[80px] border-b border-zinc-200/80 bg-zinc-50 px-2 py-2.5 font-medium text-center dark:border-zinc-800 dark:bg-zinc-900">
                    Severity
                  </th>
                  <th className="sticky top-0 z-20 w-[10%] min-w-[80px] border-b border-zinc-200/80 bg-zinc-50 pl-2 pr-4 sm:pr-6 py-2.5 font-medium text-right dark:border-zinc-800 dark:bg-zinc-900">
                    Action
                  </th>
                </tr>
              </thead>
              <tbody>
                {loading && events.length === 0 ? (
                  <tr>
                    <td colSpan={7} className="border-0 px-4 py-28 text-center">
                      <RefreshCw className="w-5 h-5 animate-spin mx-auto text-zinc-400 dark:text-zinc-500 mb-2" />
                      <div className="text-xs text-zinc-400 dark:text-zinc-500">Loading security events...</div>
                    </td>
                  </tr>
                ) : events.length === 0 ? (
                  <tr>
                    <td colSpan={7} className="border-0 px-4 py-28 text-center">
                      <div className="text-sm font-medium text-zinc-500 dark:text-zinc-400">
                        No security events match the current filter
                      </div>
                      <div className="mt-1 text-xs text-zinc-400 dark:text-zinc-500">
                        New incoming telemetry events appear here automatically.
                      </div>
                      {(actionFilter !== 'ALL' || severityFilter !== 'ALL' || sourceFilter !== 'ALL' || appFilter !== 'ALL' || search) && (
                        <button
                          type="button"
                          onClick={() => {
                            setActionFilter('ALL');
                            setSeverityFilter('ALL');
                            setSourceFilter('ALL');
                            setAppFilter('ALL');
                            setSearch('');
                            setCurrentPage(1);
                          }}
                          className="mt-3 px-3 py-1.5 rounded-lg border border-zinc-200 dark:border-zinc-700 bg-white dark:bg-zinc-800 text-xs font-medium text-zinc-700 dark:text-zinc-300 hover:bg-zinc-50 dark:hover:bg-zinc-700 transition cursor-pointer"
                        >
                          Reset Filters
                        </button>
                      )}
                    </td>
                  </tr>
                ) : (
                  events.map(evt => {
                    const engine = getEngineBadge(evt.source, evt.category);
                    const appLabel = (!evt.application || evt.application === 'failed') ? 'Edge Gateway' : evt.application;
                    const threatName = evt.threat || (evt as any).threatName || 'Inspection Event';

                    return (
                      <tr
                        key={evt.id}
                        onClick={() => handleInspectEvent(evt)}
                        className={`cursor-pointer transition hover:bg-zinc-50/70 dark:hover:bg-zinc-900/40 ${
                          selectedEvent?.id === evt.id ? 'bg-zinc-50 dark:bg-zinc-900/50' : ''
                        }`}
                      >
                        {/* Time */}
                        <td className="border-b border-zinc-100 pl-4 pr-2 py-2.5 font-mono text-[11px] text-zinc-400 whitespace-nowrap truncate dark:border-zinc-800/60 dark:text-zinc-500">
                          {formatTime(evt.timestamp)}
                        </td>

                        {/* Source IP — no flag per user request */}
                        <td className="border-b border-zinc-100 px-3 py-2.5 font-mono text-[11px] truncate dark:border-zinc-800/60" title={evt.sourceIp}>
                          <span className="font-medium text-zinc-700 dark:text-zinc-300 truncate">
                            {evt.sourceIp === '0.0.0.0' ? '0.0.0.0 (Internal)' : evt.sourceIp}
                          </span>
                        </td>

                        {/* Engine */}
                        <td className="border-b border-zinc-100 px-2 py-2.5 text-center dark:border-zinc-800/60">
                          <span className={`inline-flex items-center gap-1 px-1.5 py-0.5 rounded text-[10px] font-medium border ${engine.className}`}>
                            <span className={`w-1.5 h-1.5 rounded-full ${engine.dot}`} />
                            {engine.short}
                          </span>
                        </td>

                        {/* Application */}
                        <td className="border-b border-zinc-100 px-3 py-2.5 truncate dark:border-zinc-800/60" title={appLabel}>
                          <span className="text-[11px] font-medium text-zinc-700 dark:text-zinc-300">
                            {appLabel}
                          </span>
                        </td>

                        {/* Threat Description */}
                        <td className="border-b border-zinc-100 px-3 py-2.5 truncate dark:border-zinc-800/60" title={threatName}>
                          <span className="text-[11px] font-medium text-zinc-800 dark:text-zinc-200 truncate block">
                            {threatName}
                          </span>
                        </td>

                        {/* Severity */}
                        <td className="border-b border-zinc-100 px-2 py-2.5 text-center whitespace-nowrap dark:border-zinc-800/60">
                          <StatusBadge type="severity" value={evt.severity} size="sm" />
                        </td>

                        {/* Action */}
                        <td className="border-b border-zinc-100 pl-2 pr-4 sm:pr-6 py-2.5 text-right whitespace-nowrap dark:border-zinc-800/60">
                          <StatusBadge type="action" value={evt.action} size="sm" />
                        </td>
                      </tr>
                    );
                  })
                )}
              </tbody>
            </table>
          </div>

          {/* Footer — Pinned Pagination Controls */}
          <div className="mt-auto shrink-0 flex flex-col items-center justify-between gap-3 border-t border-zinc-100 bg-zinc-50/60 p-3 sm:px-4 sm:py-3 text-xs text-zinc-500 dark:border-zinc-800/80 dark:bg-zinc-900/40 sm:flex-row text-center sm:text-left">
            <div>
              Showing <span className="font-medium text-zinc-700 dark:text-zinc-200">{startRecord.toLocaleString()}</span>
              {recordedTotal > 0 && (
                <>
                  {' '}-{' '}
                  <span className="font-medium text-zinc-700 dark:text-zinc-200">{endRecord.toLocaleString()}</span>
                </>
              )}{' '}
              of <span className="font-medium text-zinc-700 dark:text-zinc-200">{recordedTotal.toLocaleString()}</span>{' '}
              {actionFilter !== 'ALL' || severityFilter !== 'ALL' || sourceFilter !== 'ALL' || appFilter !== 'ALL' || searchTerm ? 'matching events' : 'recorded events'}
            </div>

            <div className="flex flex-wrap items-center justify-center sm:justify-end gap-2.5 w-full sm:w-auto sm:ml-auto">
              <div className="relative">
                <select
                  value={pageSize}
                  onChange={e => {
                    const newSize = Number(e.target.value);
                    setPageSize(newSize);
                    setCurrentPage(1);
                  }}
                  className="h-8 appearance-none rounded-lg border border-zinc-200/80 bg-white pl-2.5 pr-8 text-xs font-medium text-zinc-700 transition focus:outline-none focus:border-zinc-400 dark:border-zinc-700 dark:bg-zinc-900 dark:text-zinc-200 cursor-pointer"
                >
                  <option value={25}>25 per page</option>
                  <option value={50}>50 per page</option>
                  <option value={100}>100 per page</option>
                  <option value={250}>250 per page</option>
                </select>
                <span className="absolute right-2 top-1/2 -translate-y-1/2 pointer-events-none text-zinc-400">
                  <ChevronDown className="w-3.5 h-3.5" />
                </span>
              </div>

              <div className="flex items-center gap-1.5">
                <button
                  type="button"
                  onClick={() => setCurrentPage(p => Math.max(1, p - 1))}
                  disabled={currentPage <= 1 || loading}
                  className="inline-flex h-8 shrink-0 items-center gap-1 rounded-lg border border-zinc-200/80 bg-white px-2.5 text-xs font-medium text-zinc-600 transition hover:border-zinc-300 hover:text-zinc-900 cursor-pointer disabled:pointer-events-none disabled:opacity-40 dark:border-zinc-700 dark:bg-zinc-900 dark:text-zinc-300 dark:hover:border-zinc-600 dark:hover:text-zinc-100"
                  title="Previous page"
                >
                  <ChevronLeft className="w-3.5 h-3.5" />
                  Return
                </button>

                <span className="px-1.5 font-mono text-[11px] text-zinc-500 dark:text-zinc-400 whitespace-nowrap">
                  Page <span className="font-semibold text-zinc-700 dark:text-zinc-200">{currentPage}</span> of{' '}
                  <span className="font-semibold text-zinc-700 dark:text-zinc-200">{totalPages.toLocaleString()}</span>
                </span>

                <button
                  type="button"
                  onClick={() => setCurrentPage(p => Math.min(totalPages, p + 1))}
                  disabled={currentPage >= totalPages || loading}
                  className="inline-flex h-8 shrink-0 items-center gap-1 rounded-lg border border-zinc-200/80 bg-white px-2.5 text-xs font-medium text-zinc-600 transition hover:border-zinc-300 hover:text-zinc-900 cursor-pointer disabled:pointer-events-none disabled:opacity-40 dark:border-zinc-700 dark:bg-zinc-900 dark:text-zinc-300 dark:hover:border-zinc-600 dark:hover:text-zinc-100"
                  title="Next page"
                >
                  Next
                  <ChevronRight className="w-3.5 h-3.5" />
                </button>
              </div>
            </div>
          </div>
        </div>

        {/* Side Rail: Summary insights like Live Traffic */}
        <aside className="grid content-start gap-5 sm:grid-cols-2 lg:grid-cols-1">
          {/* Telemetry Stream Health Card */}
          <div className="rounded-2xl border border-zinc-200/80 bg-white p-4 shadow-2xs dark:border-zinc-800 dark:bg-[#0c0c0e]">
            <div className="flex items-center justify-between text-[11px] font-medium uppercase tracking-wider text-zinc-400 dark:text-zinc-500">
              <span>Telemetry Ingestion</span>
              <span className="inline-flex items-center gap-1 text-[10px] text-emerald-600 dark:text-emerald-400 normal-case font-mono">
                <span className="w-1.5 h-1.5 rounded-full bg-emerald-500 animate-pulse" />
                Streaming
              </span>
            </div>
            <div className="mt-2.5">
              <div className="text-2xl font-bold tracking-tight text-zinc-900 dark:text-zinc-100">
                {recordedTotal.toLocaleString()}
              </div>
              <p className="text-[11px] text-zinc-500 dark:text-zinc-400 mt-0.5">
                Total events analyzed across all inspection engines.
              </p>
            </div>

            <div className="mt-3.5 pt-3 border-t border-zinc-100 dark:border-zinc-800/80 space-y-2">
              <div className="flex items-center justify-between text-xs">
                <span className="flex items-center gap-1.5 text-zinc-600 dark:text-zinc-300">
                  <ShieldCheck className="w-3.5 h-3.5 text-cyan-500" />
                  Endpoint Agent Channel
                </span>
                <span className="text-[10px] font-mono text-emerald-600 dark:text-emerald-400 font-semibold">ONLINE</span>
              </div>
              <div className="flex items-center justify-between text-xs">
                <span className="flex items-center gap-1.5 text-zinc-600 dark:text-zinc-300">
                  <ShieldCheck className="w-3.5 h-3.5 text-violet-500" />
                  Cloud WAF Engine
                </span>
                <span className="text-[10px] font-mono text-emerald-600 dark:text-emerald-400 font-semibold">ACTIVE</span>
              </div>
              <div className="flex items-center justify-between text-xs">
                <span className="flex items-center gap-1.5 text-zinc-600 dark:text-zinc-300">
                  <ShieldCheck className="w-3.5 h-3.5 text-amber-500" />
                  Perimeter Firewall
                </span>
                <span className="text-[10px] font-mono text-emerald-600 dark:text-emerald-400 font-semibold">FILTERING</span>
              </div>
            </div>
          </div>

          {/* Actions Taken Card */}
          <div className="rounded-2xl border border-zinc-200/80 bg-white p-4 shadow-2xs dark:border-zinc-800 dark:bg-[#0c0c0e]">
            <div className="text-[11px] font-medium uppercase tracking-wider text-zinc-400 dark:text-zinc-500">
              Actions Taken
            </div>
            <div className="mt-3 space-y-2.5">
              {actionRailRows.map(row => {
                const pct = actionRailMax > 0 ? Math.round((row.count / actionRailMax) * 100) : 0;
                return (
                  <div key={row.label}>
                    <div className="flex items-center justify-between gap-2">
                      <span className="flex min-w-0 items-center gap-1.5">
                        <span className={`h-1.5 w-1.5 shrink-0 rounded-full ${row.dot}`} />
                        <span className="truncate text-xs text-zinc-600 dark:text-zinc-300">{row.label}</span>
                      </span>
                      <span className="shrink-0 font-mono text-[10px] font-medium text-zinc-500 dark:text-zinc-400">
                        {row.count.toLocaleString()}
                      </span>
                    </div>
                    <div className="mt-1.5 h-1 overflow-hidden rounded-full bg-zinc-100 dark:bg-zinc-800/80">
                      <div
                        className={`h-full rounded-full ${row.bar}`}
                        style={{ width: `${row.count > 0 ? Math.max(2, pct) : 0}%` }}
                      />
                    </div>
                  </div>
                );
              })}
            </div>
          </div>

          {/* Severity Breakdown Card */}
          <div className="rounded-2xl border border-zinc-200/80 bg-white p-4 shadow-2xs dark:border-zinc-800 dark:bg-[#0c0c0e]">
            <div className="text-[11px] font-medium uppercase tracking-wider text-zinc-400 dark:text-zinc-500">
              Severity Distribution
            </div>
            <div className="mt-3 space-y-2.5">
              {severityRailRows.map(row => {
                const pct = severityRailMax > 0 ? Math.round((row.count / severityRailMax) * 100) : 0;
                return (
                  <div key={row.label}>
                    <div className="flex items-center justify-between gap-2">
                      <span className="flex min-w-0 items-center gap-1.5">
                        <span className={`h-1.5 w-1.5 shrink-0 rounded-full ${row.dot}`} />
                        <span className="truncate text-xs text-zinc-600 dark:text-zinc-300">{row.label}</span>
                      </span>
                      <span className="shrink-0 font-mono text-[10px] font-medium text-zinc-500 dark:text-zinc-400">
                        {row.count.toLocaleString()}
                      </span>
                    </div>
                    <div className="mt-1.5 h-1 overflow-hidden rounded-full bg-zinc-100 dark:bg-zinc-800/80">
                      <div
                        className={`h-full rounded-full ${row.bar}`}
                        style={{ width: `${row.count > 0 ? Math.max(2, pct) : 0}%` }}
                      />
                    </div>
                  </div>
                );
              })}
            </div>
          </div>

          {/* Busiest Source IPs Card */}
          <div className="rounded-2xl border border-zinc-200/80 bg-white p-4 shadow-2xs dark:border-zinc-800 dark:bg-[#0c0c0e]">
            <div className="text-[11px] font-medium uppercase tracking-wider text-zinc-400 dark:text-zinc-500">
              Busiest Source IPs
            </div>
            <div className="mt-3 space-y-2.5">
              {topSourceIps.length === 0 ? (
                <div className="text-xs text-zinc-400 dark:text-zinc-500">No events loaded yet.</div>
              ) : (
                topSourceIps.map(({ ip, count, sourceCountryCode }) => {
                  const origin = getOriginBadge(ip, sourceCountryCode);
                  const ipStr = String(ip);
                  let displayIp = ipStr;
                  if (ipStr.includes(':') && ipStr.length > 20) {
                    displayIp = ipStr.slice(0, 9) + '…' + ipStr.slice(-5);
                  }
                  const pct = topSourceIpMax > 0 ? Math.round((count / topSourceIpMax) * 100) : 0;

                  return (
                    <div key={ip}>
                      <div className="flex items-center justify-between gap-2">
                        <div className="flex items-center gap-1.5 min-w-0">
                          <CountryFlag
                            code={origin.badge}
                            title={origin.title}
                            width={22}
                            height={15}
                          />
                          <span className="truncate font-mono text-[11px] text-zinc-700 dark:text-zinc-200" title={ipStr}>
                            {displayIp}
                          </span>
                        </div>
                        <span className="shrink-0 font-mono text-[10px] font-medium text-zinc-500 dark:text-zinc-400">
                          {Number(count).toLocaleString()}
                        </span>
                      </div>
                      <div className="mt-1.5 h-1 overflow-hidden rounded-full bg-zinc-100 dark:bg-zinc-800/80">
                        <div
                          className="h-full rounded-full bg-blue-500 dark:bg-blue-400"
                          style={{ width: `${pct}%` }}
                        />
                      </div>
                    </div>
                  );
                })
              )}
            </div>
          </div>

          {/* Most Targeted Applications */}
          <div className="rounded-2xl border border-zinc-200/80 bg-white p-4 shadow-2xs dark:border-zinc-800 dark:bg-[#0c0c0e]">
            <div className="text-[11px] font-medium uppercase tracking-wider text-zinc-400 dark:text-zinc-500">
              Targeted Applications
            </div>
            <div className="mt-3 space-y-2.5">
              {topApplications.length === 0 ? (
                <div className="text-xs text-zinc-400 dark:text-zinc-500">No events loaded yet.</div>
              ) : (
                topApplications.map(([app, count]) => {
                  const pct = topApplicationMax > 0 ? Math.round((count / topApplicationMax) * 100) : 0;
                  return (
                    <div key={app}>
                      <div className="flex items-center justify-between gap-2">
                        <span className="truncate text-[11px] font-medium text-zinc-700 dark:text-zinc-200">{app}</span>
                        <span className="shrink-0 font-mono text-[10px] font-medium text-zinc-500 dark:text-zinc-400">
                          {Number(count).toLocaleString()}
                        </span>
                      </div>
                      <div className="mt-1.5 h-1 overflow-hidden rounded-full bg-zinc-100 dark:bg-zinc-800/80">
                        <div className="h-full rounded-full bg-emerald-400 dark:bg-emerald-500" style={{ width: `${pct}%` }} />
                      </div>
                    </div>
                  );
                })
              )}
            </div>
          </div>

          <p className="px-1 text-[11px] text-zinc-400 dark:text-zinc-500 sm:col-span-2 lg:col-span-1">
            Aggregated telemetry from the central security database.
          </p>
        </aside>
      </div>

      {/* Event Details Drawer — slides in cleanly when a row is clicked */}
      {selectedEvent && (
        <div className="fixed inset-0 z-50">
          <div
            className="absolute inset-0 bg-zinc-950/45 dark:bg-black/70 backdrop-blur-[2px] animate-in fade-in-0 duration-200 transition-opacity"
            style={{ opacity: swipeTranslateX > 0 ? Math.max(0.1, 1 - swipeTranslateX / 300) : undefined }}
            onClick={() => { setSelectedEvent(null); setEventDetail(null); }}
          />

          <aside
            role="dialog"
            aria-modal="true"
            aria-label="Security event details"
            onTouchStart={handleTouchStart}
            onTouchMove={handleTouchMove}
            onTouchEnd={handleTouchEnd}
            style={{
              transform: swipeTranslateX > 0 ? `translateX(${swipeTranslateX}px)` : undefined,
              transition: isSwiping ? 'none' : 'transform 0.2s ease-out'
            }}
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
                  <span className="shrink-0">Security Events</span>
                  <span className="shrink-0 text-zinc-300 dark:text-zinc-700">/</span>
                  <span className="truncate font-sans text-[11px] font-medium normal-case tracking-normal text-zinc-500 dark:text-zinc-400">
                    Event Details
                  </span>
                </div>
                <button
                  type="button"
                  onClick={() => { setSelectedEvent(null); setEventDetail(null); }}
                  className="rounded-lg p-1 text-zinc-400 hover:bg-zinc-100 hover:text-zinc-700 dark:hover:bg-zinc-800 dark:hover:text-zinc-200 transition cursor-pointer"
                >
                  <span className="sr-only">Close</span>
                  ✕
                </button>
              </div>

              <div className="mt-3 flex items-start gap-3">
                <span className="flex h-11 w-11 shrink-0 items-center justify-center rounded-xl border border-zinc-200/80 bg-zinc-50 text-zinc-500 dark:border-zinc-800 dark:bg-zinc-900/60 dark:text-zinc-400">
                  <FileCode2 className="w-5 h-5" />
                </span>
                <div className="min-w-0 flex-1">
                  <div className="flex flex-wrap items-center gap-2">
                    <h2 className="truncate text-base font-semibold tracking-tight text-zinc-900 dark:text-zinc-100">
                      {selectedEvent.threat || 'Security Incident'}
                    </h2>
                    <StatusBadge type="severity" value={selectedEvent.severity} />
                    <StatusBadge type="action" value={selectedEvent.action} />
                  </div>
                  <p className="mt-0.5 truncate text-[11px] text-zinc-500 dark:text-zinc-400">
                    Full inspection record for this security telemetry event.
                  </p>
                </div>
              </div>

              <div className="mt-3 flex flex-wrap items-center gap-x-4 gap-y-1 font-mono text-[10px] uppercase tracking-wider text-zinc-400 dark:text-zinc-500">
                <span>Time · {formatTime(selectedEvent.timestamp)}</span>
                <span className="truncate">Source · {selectedEvent.sourceIp}</span>
                <span className="truncate">Engine · {selectedEvent.category || selectedEvent.source || 'SEC'}</span>
              </div>
            </header>

            {/* Scrollable Body */}
            <div className="flex-1 space-y-5 overflow-y-auto px-5 py-5 text-xs sm:px-6 custom-scrollbar">
              {/* Event Overview */}
              <section>
                <div className="mb-2 text-[10px] font-bold uppercase tracking-[0.14em] text-zinc-400 dark:text-zinc-500">
                  Event Overview
                </div>
                <div className="grid grid-cols-1 gap-2.5 sm:grid-cols-2">
                  <div className="rounded-xl border border-zinc-200/80 bg-zinc-50/60 p-3 dark:border-zinc-800 dark:bg-zinc-900/40">
                    <div className="font-mono text-[10px] uppercase tracking-wider text-zinc-400 dark:text-zinc-500">Timestamp</div>
                    <div className="mt-1.5 font-mono text-[11px] text-zinc-700 dark:text-zinc-300">
                      {formatDateTime(selectedEvent.timestamp)}
                    </div>
                  </div>

                  <div className="rounded-xl border border-zinc-200/80 bg-zinc-50/60 p-3 dark:border-zinc-800 dark:bg-zinc-900/40">
                    <div className="flex items-center justify-between">
                      <span className="font-mono text-[10px] uppercase tracking-wider text-zinc-400 dark:text-zinc-500">Event ID</span>
                      <button
                        type="button"
                        onClick={() => {
                          navigator.clipboard.writeText(selectedEvent.id);
                          setCopiedId(true);
                          setTimeout(() => setCopiedId(false), 2000);
                        }}
                        className="text-zinc-400 hover:text-zinc-600 dark:hover:text-zinc-200"
                        title="Copy Event ID"
                      >
                        {copiedId ? <Check className="w-3 h-3 text-emerald-500" /> : <Copy className="w-3 h-3" />}
                      </button>
                    </div>
                    <div className="mt-1.5 break-all font-mono text-[11px] text-zinc-700 dark:text-zinc-300">
                      {selectedEvent.id}
                    </div>
                  </div>

                  <div className="rounded-xl border border-zinc-200/80 bg-zinc-50/60 p-3 dark:border-zinc-800 dark:bg-zinc-900/40">
                    <div className="font-mono text-[10px] uppercase tracking-wider text-zinc-400 dark:text-zinc-500">Source Host</div>
                    <div className="mt-1.5 flex flex-wrap items-center gap-2">
                      <span className="break-all font-mono text-[11px] text-zinc-700 dark:text-zinc-300">{selectedEvent.sourceIp}</span>
                      <span className="rounded border border-zinc-200 bg-white px-1.5 py-0.5 font-mono text-[10px] text-zinc-500 dark:border-zinc-700 dark:bg-zinc-900 dark:text-zinc-400">
                        {selectedEvent.sourceCountry || 'Unknown'} ({selectedEvent.sourceCountryCode || 'UN'})
                      </span>
                    </div>
                  </div>

                  <div className="rounded-xl border border-zinc-200/80 bg-zinc-50/60 p-3 dark:border-zinc-800 dark:bg-zinc-900/40">
                    <div className="font-mono text-[10px] uppercase tracking-wider text-zinc-400 dark:text-zinc-500">Target Application</div>
                    <div className="mt-1.5 break-all text-[11px] text-zinc-700 dark:text-zinc-300">
                      {selectedEvent.application || 'Edge Gateway'} ({selectedEvent.destination || '10.240.10.1'})
                    </div>
                  </div>
                </div>
              </section>

              {/* Log Message / Threat Name Box */}
              <section>
                <div className="mb-2 text-[10px] font-bold uppercase tracking-[0.14em] text-zinc-400 dark:text-zinc-500">
                  Log Message
                </div>
                <div className="whitespace-pre-wrap break-all rounded-xl border border-zinc-200/80 bg-zinc-50 p-3.5 font-mono text-[11px] leading-relaxed text-zinc-700 dark:border-zinc-800 dark:bg-zinc-900/40 dark:text-zinc-300">
                  {selectedEvent.rawLog || (selectedEvent.metadata && (selectedEvent.metadata.rawLog || selectedEvent.metadata.logMessage)) || selectedEvent.payloadSnippet || selectedEvent.threat}
                </div>
              </section>

              {/* Inspection Result */}
              <section>
                <div className="mb-2 text-[10px] font-bold uppercase tracking-[0.14em] text-zinc-400 dark:text-zinc-500">
                  Inspection Verdict
                </div>
                <dl className="overflow-hidden rounded-xl border border-zinc-200/80 bg-white divide-y divide-zinc-100 dark:border-zinc-800 dark:bg-zinc-900/20 dark:divide-zinc-800/70">
                  <div className="grid grid-cols-[112px_1fr] gap-3 px-3.5 py-2.5 sm:grid-cols-[136px_1fr]">
                    <dt className="font-mono text-[10px] uppercase tracking-wider text-zinc-400 dark:text-zinc-500">Threat</dt>
                    <dd className="break-words text-[11px] font-semibold text-rose-600 dark:text-rose-400">
                      {selectedEvent.threat}
                    </dd>
                  </div>
                  <div className="grid grid-cols-[112px_1fr] gap-3 px-3.5 py-2.5 sm:grid-cols-[136px_1fr]">
                    <dt className="font-mono text-[10px] uppercase tracking-wider text-zinc-400 dark:text-zinc-500">Engine / Sensor</dt>
                    <dd className="text-[11px] font-medium text-zinc-700 dark:text-zinc-300">
                      {selectedEvent.category || selectedEvent.source || 'Security'}
                    </dd>
                  </div>
                  <div className="grid grid-cols-[112px_1fr] gap-3 px-3.5 py-2.5 sm:grid-cols-[136px_1fr]">
                    <dt className="font-mono text-[10px] uppercase tracking-wider text-zinc-400 dark:text-zinc-500">Enforcement</dt>
                    <dd className="text-[11px] leading-relaxed text-zinc-500 dark:text-zinc-400">
                      The ingress traffic matched a threat pattern during continuous inspection. The policy engine applied{' '}
                      <span className="font-semibold text-zinc-800 dark:text-zinc-200">{selectedEvent.action}</span> action.
                    </dd>
                  </div>
                </dl>
              </section>

              {/* Request Details */}
              <section>
                <div className="mb-2 text-[10px] font-bold uppercase tracking-[0.14em] text-zinc-400 dark:text-zinc-500">
                  Request Telemetry
                </div>
                <dl className="overflow-hidden rounded-xl border border-zinc-200/80 bg-white divide-y divide-zinc-100 dark:border-zinc-800 dark:bg-zinc-900/20 dark:divide-zinc-800/70">
                  <div className="grid grid-cols-[112px_1fr] gap-3 px-3.5 py-2.5 sm:grid-cols-[136px_1fr]">
                    <dt className="font-mono text-[10px] uppercase tracking-wider text-zinc-400 dark:text-zinc-500">Destination</dt>
                    <dd className="break-all font-mono text-[11px] text-zinc-700 dark:text-zinc-300">
                      {selectedEvent.destination || '10.240.10.1'}
                    </dd>
                  </div>
                  <div className="grid grid-cols-[112px_1fr] gap-3 px-3.5 py-2.5 sm:grid-cols-[136px_1fr]">
                    <dt className="font-mono text-[10px] uppercase tracking-wider text-zinc-400 dark:text-zinc-500">Protocol / Port</dt>
                    <dd className="font-mono text-[11px] text-zinc-700 dark:text-zinc-300">
                      {selectedEvent.protocol || 'TCP'}:{selectedEvent.port || 443}
                    </dd>
                  </div>
                  {selectedEvent.method && (
                    <div className="grid grid-cols-[112px_1fr] gap-3 px-3.5 py-2.5 sm:grid-cols-[136px_1fr]">
                      <dt className="font-mono text-[10px] uppercase tracking-wider text-zinc-400 dark:text-zinc-500">HTTP Method</dt>
                      <dd className="font-mono text-[11px] font-semibold text-zinc-800 dark:text-zinc-200">{selectedEvent.method}</dd>
                    </div>
                  )}
                  {selectedEvent.statusCode && (
                    <div className="grid grid-cols-[112px_1fr] gap-3 px-3.5 py-2.5 sm:grid-cols-[136px_1fr]">
                      <dt className="font-mono text-[10px] uppercase tracking-wider text-zinc-400 dark:text-zinc-500">Status Code</dt>
                      <dd className="font-mono text-[11px] text-zinc-700 dark:text-zinc-300">{selectedEvent.statusCode}</dd>
                    </div>
                  )}
                  {selectedEvent.uri && (
                    <div className="grid grid-cols-[112px_1fr] gap-3 px-3.5 py-2.5 sm:grid-cols-[136px_1fr]">
                      <dt className="font-mono text-[10px] uppercase tracking-wider text-zinc-400 dark:text-zinc-500">Request Path</dt>
                      <dd className="break-all font-mono text-[11px] text-zinc-700 dark:text-zinc-300">{selectedEvent.uri}</dd>
                    </div>
                  )}
                </dl>
              </section>

              {/* Matched Payload Snippet */}
              {selectedEvent.payloadSnippet && (
                <section>
                  <div className="mb-2 text-[10px] font-bold uppercase tracking-[0.14em] text-zinc-400 dark:text-zinc-500">
                    Matched Payload Signature
                  </div>
                  <pre className="overflow-x-auto whitespace-pre-wrap break-all rounded-xl border border-rose-200 bg-rose-50/60 p-3 font-mono text-[11px] text-rose-600 dark:border-rose-900/40 dark:bg-rose-950/20 dark:text-rose-400">
                    {selectedEvent.payloadSnippet}
                  </pre>
                  <p className="mt-1.5 text-[11px] text-zinc-400 dark:text-zinc-500">
                    Inspected payload slice that triggered perimeter rule match.
                  </p>
                </section>
              )}

              {/* Related Events */}
              {eventDetail?.relatedEvents && eventDetail.relatedEvents.length > 0 && (
                <section>
                  <div className="mb-2 text-[10px] font-bold uppercase tracking-[0.14em] text-zinc-400 dark:text-zinc-500">
                    Correlated Events from {selectedEvent.sourceIp} ({eventDetail.relatedEvents.length})
                  </div>
                  <div className="overflow-hidden rounded-xl border border-zinc-200/80 bg-white divide-y divide-zinc-100 dark:border-zinc-800 dark:bg-zinc-900/20 dark:divide-zinc-800/60">
                    {eventDetail.relatedEvents.map((r: any) => (
                      <div key={r.id} className="flex flex-wrap items-center gap-x-3 gap-y-1.5 px-3.5 py-2.5 text-[11px]">
                        <span className="w-16 shrink-0 font-mono text-zinc-400 dark:text-zinc-500">
                          {formatTime(r.timestamp)}
                        </span>
                        <span className="min-w-0 flex-1 truncate text-zinc-700 dark:text-zinc-200">
                          {r.threat_name || r.threat}
                        </span>
                        <StatusBadge type="severity" value={r.severity} size="sm" />
                        <StatusBadge type="action" value={r.action} size="sm" />
                      </div>
                    ))}
                  </div>
                </section>
              )}

              {/* Raw JSON Record */}
              <section>
                <div className="mb-2 flex items-center justify-between">
                  <span className="text-[10px] font-bold uppercase tracking-[0.14em] text-zinc-400 dark:text-zinc-500">
                    Raw Telemetry Record
                  </span>
                  <button
                    type="button"
                    onClick={() => {
                      navigator.clipboard.writeText(JSON.stringify(eventDetail || selectedEvent, null, 2));
                      setCopiedRaw(true);
                      setTimeout(() => setCopiedRaw(false), 2000);
                    }}
                    className="inline-flex items-center gap-1 text-[11px] text-zinc-500 hover:text-zinc-800 dark:text-zinc-400 dark:hover:text-zinc-200 cursor-pointer"
                  >
                    {copiedRaw ? (
                      <>
                        <Check className="w-3 h-3 text-emerald-500" />
                        <span className="text-emerald-500">Copied</span>
                      </>
                    ) : (
                      <>
                        <Copy className="w-3 h-3" />
                        <span>Copy JSON</span>
                      </>
                    )}
                  </button>
                </div>
                <pre className="max-h-56 overflow-auto custom-scrollbar rounded-xl border border-zinc-200/80 bg-zinc-50 p-3 font-mono text-[11px] text-zinc-600 dark:border-zinc-800 dark:bg-zinc-900/40 dark:text-zinc-300">
                  {JSON.stringify(eventDetail || selectedEvent, null, 2)}
                </pre>
              </section>
            </div>

            {/* Drawer Footer */}
            <footer className="shrink-0 border-t border-zinc-200/80 bg-zinc-50/60 px-5 py-3 dark:border-zinc-800 dark:bg-zinc-900/30 sm:px-6">
              <div className="flex flex-wrap items-center justify-between gap-2 font-mono text-[10px] uppercase tracking-wider text-zinc-400 dark:text-zinc-500">
                <span>Security Events · Telemetry Inspector</span>
                <span className="normal-case tracking-normal">
                  <span className="sm:hidden">Geser ke samping untuk keluar</span>
                  <span className="hidden sm:inline">Click outside or ✕ to close</span>
                </span>
              </div>
            </footer>
          </aside>
        </div>
      )}
    </div>
  );
};
