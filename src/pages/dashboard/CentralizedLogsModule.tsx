import React, { useState, useEffect, useRef, useCallback } from 'react';
import { Terminal, Search, RefreshCw, CheckCircle2, WifiOff, Copy, ChevronDown, ChevronLeft, ChevronRight, Filter } from 'lucide-react';
import { FontAwesomeIcon } from '@fortawesome/react-fontawesome';
import { faTerminal } from '@fortawesome/free-solid-svg-icons';
import { ModulePageHeader } from '../../components/common/ModulePageHeader';
import { securityApi, globalRealtimeClient, RealtimeStreamStatus, getRealtimeStreamUrl } from '../../services/api';
import { LogEntry } from '../../types';
import { BackendOfflineBanner } from '../../components/common/BackendOfflineBanner';
import { useAuth } from '../../context/AuthContext';
import { formatDateTime, formatTime } from '../../utils/dateTime';
import { classifyLocalIp, getCountryName, extractIpOnly } from '../../utils/ip';
import { CountryFlag } from '../../components/common/CountryFlag';
import { getLanguage } from '../../i18n/translator';

type LevelFilterValue = 'ALL' | 'CRITICAL' | 'ERROR' | 'WARN' | 'INFO' | 'DEBUG';

const LEVEL_FILTER_OPTIONS: { value: LevelFilterValue; label: string; dot: string; activeBg: string; activeText: string; countColor: string }[] = [
  { value: 'ALL',      label: 'All levels', dot: 'bg-zinc-400',   activeBg: '',                               activeText: 'text-zinc-900 dark:text-zinc-100',   countColor: 'text-zinc-400 dark:text-zinc-500' },
  { value: 'CRITICAL', label: 'Critical',   dot: 'bg-rose-500',   activeBg: 'bg-rose-50 dark:bg-rose-950/40', activeText: 'text-rose-600 dark:text-rose-400',  countColor: 'text-rose-500' },
  { value: 'ERROR',    label: 'Error',      dot: 'bg-orange-400', activeBg: 'bg-orange-50 dark:bg-orange-950/40', activeText: 'text-orange-600 dark:text-orange-400', countColor: 'text-orange-500' },
  { value: 'WARN',     label: 'Warning',    dot: 'bg-amber-400',  activeBg: 'bg-amber-50 dark:bg-amber-950/40',  activeText: 'text-amber-600 dark:text-amber-400', countColor: 'text-amber-500' },
  { value: 'INFO',     label: 'Info',       dot: 'bg-sky-400',    activeBg: 'bg-sky-50 dark:bg-sky-950/40',    activeText: 'text-sky-600 dark:text-sky-300',    countColor: 'text-sky-500' },
  { value: 'DEBUG',    label: 'Debug',      dot: 'bg-zinc-300',   activeBg: 'bg-zinc-100 dark:bg-zinc-800',   activeText: 'text-zinc-500 dark:text-zinc-400',  countColor: 'text-zinc-400' },
];

type SourceFilterValue = 'ALL' | 'waf' | 'agent' | 'firewall' | 'system' | 'auth';

const SOURCE_FILTER_OPTIONS: { value: SourceFilterValue; label: string; dot: string; activeBg: string }[] = [
  { value: 'ALL',      label: 'All sources',     dot: 'bg-zinc-400', activeBg: '' },
  { value: 'waf',      label: 'WAF Edge',        dot: 'bg-violet-500', activeBg: 'bg-violet-50 dark:bg-violet-950/40' },
  { value: 'agent',    label: 'Endpoint Agents', dot: 'bg-cyan-500',   activeBg: 'bg-cyan-50 dark:bg-cyan-950/40' },
  { value: 'firewall', label: 'Perimeter FW',    dot: 'bg-amber-400',  activeBg: 'bg-amber-50 dark:bg-amber-950/40' },
  { value: 'system',   label: 'System Core',     dot: 'bg-zinc-400',   activeBg: 'bg-zinc-100 dark:bg-zinc-800' },
  { value: 'auth',     label: 'IAM / Auth',      dot: 'bg-emerald-500', activeBg: 'bg-emerald-50 dark:bg-emerald-950/40' },
];

const formatSourceName = (src: string) => {
  const s = String(src).toLowerCase();
  if (s === 'waf') return 'WAF Edge';
  if (s === 'agent') return 'Endpoint Agent';
  if (s === 'firewall') return 'Perimeter Firewall';
  if (s === 'system') return 'System Core';
  if (s === 'auth') return 'IAM / Auth';
  return src;
};

const getSourceDot = (src: string) => {
  const s = String(src).toLowerCase();
  if (s === 'waf') return 'bg-violet-500';
  if (s === 'agent') return 'bg-cyan-500';
  if (s === 'firewall') return 'bg-amber-400';
  if (s === 'auth') return 'bg-emerald-500';
  return 'bg-zinc-400';
};

const getLevelBadgeClass = (level: string) => {
  switch (String(level).toUpperCase()) {
    case 'CRITICAL':
      return 'bg-rose-50 text-rose-700 border-rose-200/80 dark:bg-rose-950/40 dark:text-rose-400 dark:border-rose-900/50';
    case 'ERROR':
      return 'bg-orange-50 text-orange-700 border-orange-200/80 dark:bg-orange-950/40 dark:text-orange-400 dark:border-orange-900/50';
    case 'WARN':
    case 'WARNING':
      return 'bg-amber-50 text-amber-700 border-amber-200/80 dark:bg-amber-950/40 dark:text-amber-400 dark:border-amber-900/50';
    case 'INFO':
      return 'bg-sky-50 text-sky-700 border-sky-200/80 dark:bg-sky-950/40 dark:text-sky-300 dark:border-sky-900/50';
    case 'DEBUG':
      return 'bg-zinc-100 text-zinc-600 border-zinc-200/80 dark:bg-zinc-800 dark:text-zinc-400 dark:border-zinc-700/60';
    default:
      return 'bg-zinc-100 text-zinc-600 border-zinc-200/80 dark:bg-zinc-800 dark:text-zinc-400 dark:border-zinc-700/60';
  }
};

export const CentralizedLogsModule: React.FC = () => {
  const { isBackendOffline, currentOrg } = useAuth();
  const [logs, setLogs] = useState<LogEntry[]>([]);
  const [recordedTotal, setRecordedTotal] = useState<number>(0);
  const [metrics, setMetrics] = useState<{
    total: number;
    critical: number;
    error: number;
    warn: number;
    info: number;
    debug: number;
  }>({
    total: 0,
    critical: 0,
    error: 0,
    warn: 0,
    info: 0,
    debug: 0
  });

  const [topSourceIpsAgg, setTopSourceIpsAgg] = useState<Array<{
    ip: string;
    count: number;
    sourceCountry?: string;
    sourceCountryCode?: string;
    sourceCountryFlag?: string;
  }>>([]);
  const [topSourcesAgg, setTopSourcesAgg] = useState<Array<{ source: string; count: number }>>([]);

  const [loading, setLoading] = useState(true);
  const [search, setSearch] = useState('');
  const [searchTerm, setSearchTerm] = useState('');
  const [levelFilter, setLevelFilter] = useState<LevelFilterValue>('ALL');
  const [sourceFilter, setSourceFilter] = useState<SourceFilterValue>('ALL');
  const [realtimeStatus, setRealtimeStatus] = useState<RealtimeStreamStatus>('CONNECTED');
  const [currentPage, setCurrentPage] = useState(1);
  const [pageSize, setPageSize] = useState(100);

  const [selectedLog, setSelectedLog] = useState<LogEntry | null>(null);
  const [copiedId, setCopiedId] = useState<string | null>(null);
  const [userScrolledUp, setUserScrolledUp] = useState(false);
  const [showLevelDd, setShowLevelDd] = useState(false);
  const [showSourceDd, setShowSourceDd] = useState(false);
  const levelDropdownRef = useRef<HTMLDivElement>(null);
  const sourceDropdownRef = useRef<HTMLDivElement>(null);
  const scrollContainerRef = useRef<HTMLDivElement>(null);
  const eventSourceRef = useRef<EventSource | null>(null);

  // Mobile swipe-to-dismiss gesture state
  const [swipeTranslateX, setSwipeTranslateX] = useState(0);
  const [isSwiping, setIsSwiping] = useState(false);
  const touchStartRef = useRef<{ x: number; y: number; time: number } | null>(null);

  const handleLogTouchStart = (e: React.TouchEvent) => {
    if (typeof window !== 'undefined' && window.innerWidth >= 640) return;
    const touch = e.touches[0];
    touchStartRef.current = { x: touch.clientX, y: touch.clientY, time: Date.now() };
    setIsSwiping(false);
  };

  const handleLogTouchMove = (e: React.TouchEvent) => {
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

  const handleLogTouchEnd = () => {
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
        setSelectedLog(null);
        setSwipeTranslateX(0);
        setIsSwiping(false);
      }, 150);
    } else {
      setIsSwiping(false);
      setSwipeTranslateX(0);
    }
    touchStartRef.current = null;
  };

  // Debounce search
  useEffect(() => {
    const timer = window.setTimeout(() => {
      setSearchTerm(search.trim());
      setCurrentPage(1);
    }, 300);
    return () => window.clearTimeout(timer);
  }, [search]);

  // Fetch logs
  const fetchLogs = useCallback(async () => {
    setLoading(true);
    try {
      const res = await securityApi.getLogs({
        level: levelFilter !== 'ALL' ? levelFilter : undefined,
        source: sourceFilter !== 'ALL' ? sourceFilter : undefined,
        search: searchTerm || undefined,
        page: currentPage,
        limit: pageSize
      });

      const loadedLogs = res.logs || [];
      setLogs(loadedLogs);
      setRecordedTotal(typeof res.total === 'number' ? res.total : loadedLogs.length);
      if (res.metrics) {
        setMetrics(res.metrics);
      }
      if (res.topSourceIps) {
        setTopSourceIpsAgg(res.topSourceIps);
      }
      if (res.topSources) {
        setTopSourcesAgg(res.topSources);
      }
    } catch (e) {
      console.error('[CentralizedLogs] Fetch error:', e);
    } finally {
      setLoading(false);
    }
  }, [levelFilter, sourceFilter, searchTerm, currentPage, pageSize]);

  useEffect(() => {
    fetchLogs();
  }, [fetchLogs, isBackendOffline]);

  // Periodic live sync every 2.5s on page 1 so logs stream in without user refresh
  useEffect(() => {
    if (isBackendOffline) return;
    const timer = window.setInterval(async () => {
      if (currentPage !== 1) return;
      try {
        const res = await securityApi.getLogs({
          level: levelFilter !== 'ALL' ? levelFilter : undefined,
          source: sourceFilter !== 'ALL' ? sourceFilter : undefined,
          search: searchTerm || undefined,
          page: 1,
          limit: pageSize
        });
        const loadedLogs = res.logs || [];
        if (loadedLogs.length > 0) {
          setLogs(prev => {
            if (prev.length > 0 && loadedLogs[0]?.id === prev[0]?.id && prev.length === loadedLogs.length) {
              return prev;
            }
            return loadedLogs;
          });
          setRecordedTotal(typeof res.total === 'number' ? res.total : loadedLogs.length);
          if (res.metrics) setMetrics(res.metrics);
          if (res.topSourceIps) setTopSourceIpsAgg(res.topSourceIps);
          if (res.topSources) setTopSourcesAgg(res.topSources);
        }
      } catch {}
    }, 2500);
    return () => window.clearInterval(timer);
  }, [isBackendOffline, currentPage, pageSize, levelFilter, sourceFilter, searchTerm]);

  const activeFiltersRef = useRef({ levelFilter, sourceFilter, search: searchTerm });
  useEffect(() => {
    activeFiltersRef.current = { levelFilter, sourceFilter, search: searchTerm };
  }, [levelFilter, sourceFilter, searchTerm]);

  const logMatchesActiveFilters = useCallback((log: LogEntry) => {
    const { levelFilter: curLevel, sourceFilter: curSource, search: curSearch } = activeFiltersRef.current;
    
    if (curLevel !== 'ALL' && (log.level || '').toUpperCase() !== curLevel.toUpperCase()) {
      return false;
    }
    if (curSource !== 'ALL' && (log.source || '').toLowerCase() !== curSource.toLowerCase()) {
      return false;
    }
    if (curSearch && curSearch.trim()) {
      const term = curSearch.trim().toLowerCase();
      const match = (log.message || '').toLowerCase().includes(term) ||
                    (log.ip || '').toLowerCase().includes(term) ||
                    (log.host || '').toLowerCase().includes(term) ||
                    (log.correlationId || '').toLowerCase().includes(term) ||
                    (log.eventType || '').toLowerCase().includes(term);
      if (!match) return false;
    }
    return true;
  }, []);

  // Real-time log streaming via SSE & WebSocket
  useEffect(() => {
    if (isBackendOffline) {
      setRealtimeStatus('REAL-TIME CONNECTION LOST');
      return;
    }

    const unsubStatus = globalRealtimeClient.onStatusChange((status) => {
      setRealtimeStatus(status);
    });

    const unsubWs = globalRealtimeClient.subscribe((msg: any) => {
      if (!msg) return;

      const type = msg.type || '';
      const data = msg.data || msg;

      if (type === 'log.created' || type === 'log' || type === 'security_event' || type === 'security_event.created' || (data.level && data.message)) {
        const newLog: LogEntry = {
          id: data.id || `LOG-${Date.now()}-${Math.floor(Math.random()*1000)}`,
          timestamp: data.timestamp || new Date().toISOString(),
          level: data.level || 'INFO',
          source: data.source || 'system',
          eventType: data.eventType || data.event_type || 'audit',
          message: data.message || '',
          host: data.host,
          ip: data.ip,
          correlationId: data.correlationId || data.correlation_id,
          metadata: data.metadata,
          rawLog: data.rawLog || data.raw_log
        };

        setRecordedTotal(prev => prev + 1);
        setMetrics(prev => ({
          ...prev,
          total: prev.total + 1,
          critical: newLog.level === 'CRITICAL' ? prev.critical + 1 : prev.critical,
          error: newLog.level === 'ERROR' ? prev.error + 1 : prev.error,
          warn: newLog.level === 'WARN' ? prev.warn + 1 : prev.warn,
          info: newLog.level === 'INFO' ? prev.info + 1 : prev.info,
          debug: newLog.level === 'DEBUG' ? prev.debug + 1 : prev.debug
        }));

        if (currentPage === 1 && logMatchesActiveFilters(newLog)) {
          setLogs(prev => {
            if (prev.some(l => l.id === newLog.id)) return prev;
            return [newLog, ...prev.slice(0, pageSize - 1)];
          });
        }
      }
    });

    try {
      const sse = new EventSource(getRealtimeStreamUrl('/api/logs/stream'));
      eventSourceRef.current = sse;

      sse.onmessage = (event) => {
        try {
          const payload = JSON.parse(event.data);
          const data = payload.data || payload;
          if (data && data.message) {
            const newLog: LogEntry = {
              id: data.id || `LOG-${Date.now()}`,
              timestamp: data.timestamp || new Date().toISOString(),
              level: data.level || 'INFO',
              source: data.source || 'system',
              eventType: data.eventType || data.event_type || 'audit',
              message: data.message,
              host: data.host,
              ip: data.ip,
              correlationId: data.correlationId || data.correlation_id,
              metadata: data.metadata
            };

            if (currentPage === 1 && logMatchesActiveFilters(newLog)) {
              setLogs(prev => {
                if (prev.some(l => l.id === newLog.id)) return prev;
                return [newLog, ...prev.slice(0, pageSize - 1)];
              });
            }
          }
        } catch {
          // ignore parsing error on ping
        }
      };
    } catch (e) {
      console.warn('[Logs SSE] init error', e);
    }

    return () => {
      unsubStatus();
      unsubWs();
      if (eventSourceRef.current) {
        eventSourceRef.current.close();
        eventSourceRef.current = null;
      }
    };
  }, [isBackendOffline, currentOrg, currentPage, pageSize, logMatchesActiveFilters]);

  const handleScroll = () => {
    const el = scrollContainerRef.current;
    if (!el) return;
    const distanceFromBottom = el.scrollHeight - el.scrollTop - el.clientHeight;
    if (distanceFromBottom > 60) {
      setUserScrolledUp(true);
    } else {
      setUserScrolledUp(false);
    }
  };

  useEffect(() => {
    setUserScrolledUp(false);
    if (scrollContainerRef.current) {
      scrollContainerRef.current.scrollTop = 0;
    }
  }, [currentPage]);

  const copyToClipboard = (text: string, id: string) => {
    navigator.clipboard.writeText(text);
    setCopiedId(id);
    setTimeout(() => setCopiedId(null), 2000);
  };


  if (isBackendOffline) {
    return <BackendOfflineBanner onRetry={fetchLogs} />;
  }

  // Side-rail summaries — mirrors Live Traffic
  const maxRailRows = 5;

  const levelFilterCounts: Record<LevelFilterValue, number> = {
    ALL: metrics.total,
    CRITICAL: metrics.critical,
    ERROR: metrics.error,
    WARN: metrics.warn,
    INFO: metrics.info,
    DEBUG: metrics.debug
  };

  const levelRailRows = [
    { label: 'Critical', count: metrics.critical, dot: 'bg-rose-500', bar: 'bg-rose-500' },
    { label: 'Error',    count: metrics.error,    dot: 'bg-orange-400', bar: 'bg-orange-400' },
    { label: 'Warning',  count: metrics.warn,     dot: 'bg-amber-400', bar: 'bg-amber-400' },
    { label: 'Info',     count: metrics.info,     dot: 'bg-sky-400',   bar: 'bg-sky-400' },
    { label: 'Debug',    count: metrics.debug,    dot: 'bg-zinc-400',  bar: 'bg-zinc-400' }
  ].sort((a, b) => b.count - a.count);
  const levelRailMax = levelRailRows[0]?.count ?? 0;

  // Fallback to logs in view if backend aggregates are still empty
  const topSourceIps = (topSourceIpsAgg.length > 0 ? topSourceIpsAgg : (() => {
    const counts: Record<string, number> = {};
    for (const l of logs) {
      if (l.ip && l.ip !== '—') counts[l.ip] = (counts[l.ip] || 0) + 1;
    }
    return Object.entries(counts).map(([ip, count]) => ({ ip, count })).sort((a, b) => b.count - a.count);
  })()).slice(0, maxRailRows);
  const topSourceIpMax = topSourceIps.length > 0 ? topSourceIps[0].count : 0;

  const topSources = (topSourcesAgg.length > 0 ? topSourcesAgg.map(r => [r.source, r.count] as [string, number]) : (() => {
    const counts: Record<string, number> = {};
    for (const l of logs) {
      if (l.source) counts[l.source] = (counts[l.source] || 0) + 1;
    }
    return Object.entries(counts).sort((a, b) => b[1] - a[1]);
  })()).slice(0, maxRailRows);
  const topSourceMax = topSources.length > 0 ? topSources[0][1] : 0;

  const totalPages = Math.max(1, Math.ceil(recordedTotal / pageSize));
  const startRecord = recordedTotal === 0 ? 0 : (currentPage - 1) * pageSize + 1;
  const endRecord = Math.min(currentPage * pageSize, recordedTotal);

  return (
    <div className="space-y-5" id="centralized-logs-container">
      {/* Real-time Connection Banner if Lost */}
      {realtimeStatus === 'REAL-TIME CONNECTION LOST' && (
        <div className="rounded-xl border border-rose-500/40 bg-rose-500/10 p-4 flex flex-col sm:flex-row sm:items-center justify-between gap-3 text-rose-700 dark:text-rose-200">
          <div className="flex items-center gap-3">
            <WifiOff className="w-5 h-5 text-rose-600 dark:text-rose-400 animate-pulse" />
            <div>
              <div className="text-xs font-bold uppercase tracking-wider text-rose-600 dark:text-rose-400">REAL-TIME CONNECTION LOST</div>
              <div className="text-xs text-rose-600 dark:text-rose-400 mt-0.5">
                Centralized log streaming daemon disconnected. Automatic reconnection active.
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

      {/* Header — dashboard page header style, identical to Live Traffic */}
      <ModulePageHeader
        icon={<FontAwesomeIcon icon={faTerminal} />}
        title="Centralized"
        titleTail="Logs"
        subtitle="Every log from every layer in one place — WAF edge logs, endpoint agent telemetry, host security audits, and firewall drops."
      />

      {/* Live feed on the left, summary rail on the right — identical to Live Traffic layout */}
      <div className="grid items-start gap-5 lg:grid-cols-[minmax(0,1fr)_300px] xl:grid-cols-[minmax(0,1fr)_340px]">
        {/* Feed — toolbar and table share one card so it reads like a stream window */}
        <div className="flex min-w-0 flex-col overflow-hidden rounded-2xl border border-zinc-200/80 bg-white shadow-2xs dark:border-zinc-800 dark:bg-[#0c0c0e]">
          {/* Top toolbar */}
          <div className="shrink-0 flex flex-wrap items-center gap-2 border-b border-zinc-100 bg-zinc-50/60 px-3 py-2.5 dark:border-zinc-800/80 dark:bg-zinc-900/40">
            {/* Level filter dropdown */}
            <div className="relative" ref={levelDropdownRef}>
              <button
                type="button"
                onClick={() => { setShowLevelDd(prev => !prev); setShowSourceDd(false); }}
                className="h-8 px-3 rounded-lg border border-zinc-200/80 dark:border-zinc-800 bg-white dark:bg-zinc-900 hover:bg-zinc-50 dark:hover:bg-zinc-800 text-xs font-medium text-zinc-700 dark:text-zinc-200 inline-flex items-center gap-2 transition cursor-pointer shadow-2xs"
              >
                <Filter className="w-3 h-3 text-zinc-400" />
                <span>
                  {(() => {
                    const opt = LEVEL_FILTER_OPTIONS.find(o => o.value === levelFilter)!;
                    return `${opt.label} (${levelFilterCounts[levelFilter].toLocaleString()})`;
                  })()}
                </span>
                <ChevronDown className={`w-3 h-3 text-zinc-400 transition-transform ${showLevelDd ? 'rotate-180' : ''}`} />
              </button>

              {showLevelDd && (
                <>
                  <div className="fixed inset-0 z-20 cursor-default" onClick={() => setShowLevelDd(false)} />
                  <div className="absolute left-0 top-full mt-1.5 w-52 max-w-[calc(100vw-32px)] rounded-xl border border-zinc-200/80 dark:border-zinc-800 bg-white dark:bg-zinc-900 shadow-xl p-1 z-30">
                    {LEVEL_FILTER_OPTIONS.map((opt) => {
                      const isActive = levelFilter === opt.value;
                      return (
                        <button
                          key={opt.value}
                          type="button"
                          onClick={() => { setLevelFilter(opt.value); setCurrentPage(1); setShowLevelDd(false); }}
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
                            ({levelFilterCounts[opt.value].toLocaleString()})
                          </span>
                        </button>
                      );
                    })}
                  </div>
                </>
              )}
            </div>

            {/* Source filter dropdown */}
            <div className="relative" ref={sourceDropdownRef}>
              <button
                type="button"
                onClick={() => { setShowSourceDd(prev => !prev); setShowLevelDd(false); }}
                className="h-8 px-3 rounded-lg border border-zinc-200/80 dark:border-zinc-800 bg-white dark:bg-zinc-900 hover:bg-zinc-50 dark:hover:bg-zinc-800 text-xs font-medium text-zinc-700 dark:text-zinc-200 inline-flex items-center gap-2 transition cursor-pointer shadow-2xs"
              >
                <Filter className="w-3 h-3 text-zinc-400" />
                <span>
                  {(() => {
                    const opt = SOURCE_FILTER_OPTIONS.find(o => o.value === sourceFilter)!;
                    return opt.label;
                  })()}
                </span>
                <ChevronDown className={`w-3 h-3 text-zinc-400 transition-transform ${showSourceDd ? 'rotate-180' : ''}`} />
              </button>

              {showSourceDd && (
                <>
                  <div className="fixed inset-0 z-20 cursor-default" onClick={() => setShowSourceDd(false)} />
                  <div className="absolute left-0 top-full mt-1.5 w-48 max-w-[calc(100vw-32px)] rounded-xl border border-zinc-200/80 dark:border-zinc-800 bg-white dark:bg-zinc-900 shadow-xl p-1 z-30">
                    {SOURCE_FILTER_OPTIONS.map((opt) => {
                      const isActive = sourceFilter === opt.value;
                      return (
                        <button
                          key={opt.value}
                          type="button"
                          onClick={() => { setSourceFilter(opt.value); setCurrentPage(1); setShowSourceDd(false); }}
                          className={`w-full px-2.5 py-1.5 rounded-lg text-xs text-left flex items-center gap-2 transition cursor-pointer ${
                            isActive
                              ? `font-semibold ${opt.activeBg || 'bg-zinc-100 dark:bg-zinc-800'} text-zinc-900 dark:text-zinc-100`
                              : 'text-zinc-600 dark:text-zinc-400 hover:bg-zinc-50 dark:hover:bg-zinc-800/60'
                          }`}
                        >
                          <span className={`w-2 h-2 rounded-full shrink-0 ${opt.dot}`} />
                          <span>{opt.label}</span>
                        </button>
                      );
                    })}
                  </div>
                </>
              )}
            </div>

            {/* Search Input */}
            <div className="relative flex-1 min-w-[200px]">
              <Search className="w-3.5 h-3.5 text-zinc-400 dark:text-zinc-500 absolute left-3 top-1/2 -translate-y-1/2 pointer-events-none" />
              <input
                type="text"
                value={search}
                onChange={e => setSearch(e.target.value)}
                placeholder={getLanguage() === 'id' ? 'Cari...' : 'Search...'}
                className="h-8 w-full rounded-lg border border-zinc-200/80 bg-white pl-8 pr-3 text-xs text-zinc-800 placeholder-zinc-400 transition focus:outline-none focus:border-zinc-400 dark:border-zinc-800 dark:bg-zinc-900 dark:text-zinc-200 dark:placeholder-zinc-500 dark:focus:border-zinc-600"
              />
            </div>


          </div>

          {/* Table Container — fixed height, rows scroll inside, identical to Live Traffic */}
          <div
            ref={scrollContainerRef}
            onScroll={handleScroll}
            className="h-[580px] overflow-y-auto overflow-x-auto custom-scrollbar relative"
          >
            <table className="min-w-[720px] w-full table-fixed border-separate border-spacing-0 text-left text-xs">
              <thead>
                <tr className="text-[11px] font-medium uppercase tracking-wider text-zinc-400 dark:text-zinc-500">
                  <th className="sticky top-0 z-20 w-[13%] min-w-[85px] border-b border-zinc-200/80 bg-zinc-50 pl-4 pr-2 py-2.5 font-medium dark:border-zinc-800 dark:bg-zinc-900">Time</th>
                  <th className="sticky top-0 z-20 w-[11%] min-w-[75px] border-b border-zinc-200/80 bg-zinc-50 px-2.5 py-2.5 font-medium text-center dark:border-zinc-800 dark:bg-zinc-900">Level</th>
                  <th className="sticky top-0 z-20 w-[13%] min-w-[85px] border-b border-zinc-200/80 bg-zinc-50 px-3 py-2.5 font-medium dark:border-zinc-800 dark:bg-zinc-900">Source</th>
                  <th className="sticky top-0 z-20 w-[45%] min-w-[220px] border-b border-zinc-200/80 bg-zinc-50 px-3 py-2.5 font-medium dark:border-zinc-800 dark:bg-zinc-900">Message</th>
                  <th className="sticky top-0 z-20 w-[18%] min-w-[120px] border-b border-zinc-200/80 bg-zinc-50 pl-2 pr-6 sm:pr-8 py-2.5 font-medium text-right dark:border-zinc-800 dark:bg-zinc-900">Source IP</th>
                </tr>
              </thead>
              <tbody>
                {loading && logs.length === 0 ? (
                  <tr>
                    <td colSpan={5} className="border-0 px-4 py-28 text-center">
                      <RefreshCw className="w-5 h-5 animate-spin mx-auto text-zinc-400 dark:text-zinc-500 mb-2" />
                      <div className="text-xs text-zinc-400 dark:text-zinc-500">Loading logs…</div>
                    </td>
                  </tr>
                ) : logs.length === 0 ? (
                  <tr>
                    <td colSpan={5} className="border-0 px-4 py-28 text-center">
                      <div className="text-sm font-medium text-zinc-500 dark:text-zinc-400">
                        No logs match the current filters
                      </div>
                      <div className="mt-1 text-xs text-zinc-400 dark:text-zinc-500">
                        New logs appear automatically as they are ingested.
                      </div>
                    </td>
                  </tr>
                ) : (
                  logs.map((log, idx) => {
                    const levelUp = String(log.level || 'INFO').toUpperCase();
                    const levelBadge = getLevelBadgeClass(levelUp);
                    const ipStr = String(log.ip || '');
                    const badge = classifyLocalIp(ipStr) ? 'ID' : 'UN';
                    const cleanIp = extractIpOnly(ipStr);
                    let displayIp = cleanIp;
                    if (cleanIp.includes(':') && cleanIp.length > 20) {
                      displayIp = cleanIp.slice(0, 9) + '…' + cleanIp.slice(-5);
                    }

                    return (
                      <tr
                        key={log.id}
                        onClick={() => setSelectedLog(log)}
                        className={`group cursor-pointer border-b border-zinc-100/80 transition-colors hover:bg-zinc-50/80 dark:border-zinc-800/50 dark:hover:bg-zinc-800/40 ${
                          idx % 2 === 1 ? 'bg-zinc-50/30 dark:bg-zinc-900/20' : ''
                        }`}
                      >
                        {/* Time */}
                        <td className="pl-4 pr-2 py-2.5 font-mono text-[10px] text-zinc-400 dark:text-zinc-500 whitespace-nowrap align-top select-none">
                          {formatTime(log.timestamp)}
                        </td>

                        {/* Level badge */}
                        <td className="px-2.5 py-2.5 text-center whitespace-nowrap align-top">
                          <span className={`inline-block px-1.5 py-0.5 rounded border text-[10px] font-mono font-bold uppercase tracking-wide ${levelBadge}`}>
                            {levelUp}
                          </span>
                        </td>

                        {/* Source */}
                        <td className="px-3 py-2.5 align-top whitespace-nowrap">
                          <span className="inline-flex items-center gap-1.5 text-[11px] font-medium text-zinc-700 dark:text-zinc-300">
                            <span className={`w-1.5 h-1.5 rounded-full shrink-0 ${getSourceDot(log.source)}`} />
                            <span className="truncate">{formatSourceName(log.source)}</span>
                          </span>
                        </td>

                        {/* Message */}
                        <td className="px-3 py-2.5 align-top">
                          <div className="truncate font-mono text-[11px] text-zinc-700 dark:text-zinc-300 leading-snug">
                            {log.message}
                          </div>
                          {log.host && (
                            <div className="mt-0.5 font-mono text-[10px] text-zinc-400 dark:text-zinc-500 truncate">
                              host: {log.host}
                            </div>
                          )}
                        </td>

                        {/* Source IP */}
                        <td className="pl-2 pr-6 sm:pr-8 py-2.5 align-top text-right whitespace-nowrap">
                          {log.ip && log.ip !== '—' ? (
                            <div className="inline-flex items-center justify-end gap-1.5">
                              <CountryFlag
                                code={badge}
                                name={getCountryName(badge)}
                                width={18}
                                height={12}
                              />
                              <span className="font-mono text-[11px] text-zinc-700 dark:text-zinc-300" title={ipStr}>{displayIp}</span>
                            </div>
                          ) : (
                            <span className="font-mono text-[10px] text-zinc-400 dark:text-zinc-500">—</span>
                          )}
                        </td>
                      </tr>
                    );
                  })
                )}
              </tbody>
            </table>

            {userScrolledUp && (
              <button
                type="button"
                onClick={() => {
                  setUserScrolledUp(false);
                  if (scrollContainerRef.current) {
                    scrollContainerRef.current.scrollTo({
                      top: scrollContainerRef.current.scrollHeight,
                      behavior: 'smooth'
                    });
                  }
                }}
                className="sticky bottom-3 left-1/2 -translate-x-1/2 z-20 mx-auto inline-flex items-center gap-1.5 px-3 py-1.5 rounded-full text-xs font-medium bg-zinc-900/90 text-white dark:bg-zinc-100 dark:text-zinc-900 shadow-md border border-zinc-700/50 hover:opacity-95 transition cursor-pointer backdrop-blur-xs animate-in fade-in-0 duration-150"
              >
                <ChevronDown className="w-3.5 h-3.5" />
                <span>Scroll to bottom</span>
              </button>
            )}
          </div>

          {/* Footer — pagination and page size controls pinned to the bottom of the card */}
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
              {levelFilter !== 'ALL' || sourceFilter !== 'ALL' || searchTerm ? 'matching logs' : 'recorded logs'}
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
                  <option value={500}>500 per page</option>
                </select>
                <span className="absolute right-2 top-1/2 -translate-y-1/2 pointer-events-none text-zinc-400">
                  <ChevronDown className="w-3.5 h-3.5" />
                </span>
              </div>

              {/* Navigation buttons: Return and Next */}
              <div className="flex items-center gap-1.5">
                <button
                  type="button"
                  onClick={() => setCurrentPage(p => Math.max(1, p - 1))}
                  disabled={currentPage <= 1 || loading}
                  className="inline-flex h-8 shrink-0 items-center gap-1 rounded-lg border border-zinc-200/80 bg-white px-2.5 text-xs font-medium text-zinc-600 transition hover:border-zinc-300 hover:text-zinc-900 cursor-pointer disabled:pointer-events-none disabled:opacity-40 dark:border-zinc-700 dark:bg-zinc-900 dark:text-zinc-300 dark:hover:border-zinc-600 dark:hover:text-zinc-100"
                  title="Previous page (Return)"
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

        {/* Summary rail — plain numbers for the events currently loaded, identical to Live Traffic */}
        <aside className="grid content-start gap-5 sm:grid-cols-2 lg:grid-cols-1">
          {/* Log levels breakdown card */}
          <div className="rounded-2xl border border-zinc-200/80 bg-white p-4 shadow-2xs dark:border-zinc-800 dark:bg-[#0c0c0e]">
            <div className="text-[11px] font-medium uppercase tracking-wider text-zinc-400 dark:text-zinc-500">
              Log levels
            </div>
            <div className="mt-3 space-y-2.5">
              {levelRailRows.map(row => {
                const pct = levelRailMax > 0 ? Math.round((row.count / levelRailMax) * 100) : 0;
                return (
                  <div key={row.label}>
                    <div className="flex items-center justify-between gap-2">
                      <span className="flex min-w-0 items-center gap-1.5">
                        <span className={`h-1.5 w-1.5 shrink-0 rounded-full ${row.dot}`} />
                        <span className="truncate text-xs text-zinc-600 dark:text-zinc-300">{row.label}</span>
                      </span>
                      <span className="shrink-0 font-mono text-[10px] font-medium text-zinc-500 dark:text-zinc-400">{row.count.toLocaleString()}</span>
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

          {/* Busiest source IPs card */}
          <div className="rounded-2xl border border-zinc-200/80 bg-white p-4 shadow-2xs dark:border-zinc-800 dark:bg-[#0c0c0e]">
            <div className="text-[11px] font-medium uppercase tracking-wider text-zinc-400 dark:text-zinc-500">
              Busiest source IPs
            </div>
            <div className="mt-3 space-y-2.5">
              {topSourceIps.length === 0 ? (
                <div className="text-xs text-zinc-400 dark:text-zinc-500">No logs loaded yet.</div>
              ) : (
                topSourceIps.map(({ ip, count, sourceCountry, sourceCountryCode }) => {
                  const ipStr = String(ip);
                  const rawBadge = (sourceCountryCode as string | undefined) || (classifyLocalIp(ipStr) ? 'ID' : 'UN');
                  const badge = (rawBadge === 'LAN' || rawBadge === 'SYS') ? 'ID' : rawBadge;
                  const cleanIp = extractIpOnly(ipStr);
                  let displayIp: string = cleanIp;
                  if (cleanIp.includes(':') && cleanIp.length > 20) {
                    displayIp = cleanIp.slice(0, 9) + '…' + cleanIp.slice(-5);
                  }
                  const pct = topSourceIpMax > 0 ? Math.round((count / topSourceIpMax) * 100) : 0;
                  const barClass = badge === 'ID'
                    ? 'bg-emerald-500 dark:bg-emerald-400'
                    : 'bg-indigo-400 dark:bg-indigo-500';

                  return (
                    <div key={ip}>
                      <div className="flex items-center justify-between gap-2">
                        <div className="flex items-center gap-1.5 min-w-0">
                          <CountryFlag
                            code={badge}
                            name={sourceCountry}
                            width={18}
                            height={12}
                          />
                          <span className="truncate font-mono text-[11px] text-zinc-700 dark:text-zinc-200" title={ipStr}>{displayIp}</span>
                        </div>
                        <span className="shrink-0 font-mono text-[10px] font-medium text-zinc-500 dark:text-zinc-400">{Number(count).toLocaleString()}</span>
                      </div>
                      <div className="mt-1.5 h-1 overflow-hidden rounded-full bg-zinc-100 dark:bg-zinc-800/80">
                        <div className={`h-full rounded-full ${barClass}`} style={{ width: `${pct}%` }} />
                      </div>
                    </div>
                  );
                })
              )}
            </div>
          </div>

          {/* Top log sources card */}
          <div className="rounded-2xl border border-zinc-200/80 bg-white p-4 shadow-2xs dark:border-zinc-800 dark:bg-[#0c0c0e]">
            <div className="text-[11px] font-medium uppercase tracking-wider text-zinc-400 dark:text-zinc-500">
              Top log sources
            </div>
            <div className="mt-3 space-y-2.5">
              {topSources.length === 0 ? (
                <div className="text-xs text-zinc-400 dark:text-zinc-500">No logs loaded yet.</div>
              ) : (
                topSources.map(([sourceName, count]) => {
                  const pct = topSourceMax > 0 ? Math.round((count / topSourceMax) * 100) : 0;
                  return (
                    <div key={sourceName}>
                      <div className="flex items-center justify-between gap-2">
                        <span className="truncate text-[11px] font-medium text-zinc-700 dark:text-zinc-200 capitalize">
                          {formatSourceName(sourceName)}
                        </span>
                        <span className="shrink-0 font-mono text-[10px] font-medium text-zinc-500 dark:text-zinc-400">{Number(count).toLocaleString()}</span>
                      </div>
                      <div className="mt-1.5 h-1 overflow-hidden rounded-full bg-zinc-100 dark:bg-zinc-800/80">
                        <div className="h-full rounded-full bg-sky-400 dark:bg-sky-500" style={{ width: `${pct}%` }} />
                      </div>
                    </div>
                  );
                })
              )}
            </div>
          </div>

          <p className="px-1 text-[11px] text-zinc-400 dark:text-zinc-500 sm:col-span-2 lg:col-span-1">
            Aggregated from all logs in the database.
          </p>
        </aside>
      </div>

      {/* Log details drawer — slides in from the right like the engine inspector; closes on any click outside the panel */}
      {selectedLog && (
        <div className="fixed inset-0 z-50">
          {/* Dimmed backdrop — clicking anywhere outside the panel closes the drawer. */}
          <div
            className="absolute inset-0 bg-zinc-950/45 dark:bg-black/70 backdrop-blur-[2px] animate-in fade-in-0 duration-200 transition-opacity"
            style={{ opacity: swipeTranslateX > 0 ? Math.max(0.1, 1 - swipeTranslateX / 300) : undefined }}
            onClick={() => setSelectedLog(null)}
          />

          <aside
            role="dialog"
            aria-modal="true"
            aria-label="Log entry details"
            onTouchStart={handleLogTouchStart}
            onTouchMove={handleLogTouchMove}
            onTouchEnd={handleLogTouchEnd}
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
            {/* Drawer header */}
            <header className="shrink-0 border-b border-zinc-200/80 bg-white px-5 pb-4 pt-3.5 dark:border-zinc-800 dark:bg-[#0b0b0d] sm:px-6">
              <div className="flex min-w-0 items-center gap-1.5 font-mono text-[10px] uppercase tracking-[0.16em] text-zinc-400 dark:text-zinc-500">
                <span className="shrink-0">Centralized Logs</span>
                <span className="shrink-0 text-zinc-300 dark:text-zinc-700">/</span>
                <span className="truncate font-sans text-[11px] font-medium normal-case tracking-normal text-zinc-500 dark:text-zinc-400">
                  Log Details
                </span>
              </div>

              <div className="mt-3 flex items-start gap-3">
                <span className="flex h-11 w-11 shrink-0 items-center justify-center rounded-xl border border-zinc-200/80 bg-zinc-50 text-zinc-500 dark:border-zinc-800 dark:bg-zinc-900/60 dark:text-zinc-400">
                  <Terminal className="text-lg" />
                </span>
                <div className="min-w-0 flex-1">
                  <div className="flex flex-wrap items-center gap-2">
                    <h2 className="truncate text-base font-semibold tracking-tight text-zinc-900 dark:text-zinc-100">
                      Log Details
                    </h2>
                    <span className={`inline-block px-2 py-0.5 rounded border text-[10px] uppercase font-bold ${getLevelBadgeClass(selectedLog.level)}`}>
                      {selectedLog.level}
                    </span>
                  </div>
                  <p className="mt-0.5 truncate text-[11px] text-zinc-500 dark:text-zinc-400">
                    Full record of this log entry.
                  </p>
                </div>
              </div>

              <div className="mt-3 flex flex-wrap items-center gap-x-4 gap-y-1 font-mono text-[10px] uppercase tracking-wider text-zinc-400 dark:text-zinc-500">
                <span>Time · {formatTime(selectedLog.timestamp)}</span>
                <span className="truncate">Source · {formatSourceName(selectedLog.source)}</span>
              </div>
            </header>

            {/* Scrollable body */}
            <div className="flex-1 space-y-5 overflow-y-auto px-5 py-5 text-xs sm:px-6">
              {/* Log overview */}
              <section>
                <div className="mb-2 text-[10px] font-bold uppercase tracking-[0.14em] text-zinc-400 dark:text-zinc-500">
                  Log overview
                </div>
                <dl className="overflow-hidden rounded-xl border border-zinc-200/80 bg-white divide-y divide-zinc-100 dark:border-zinc-800 dark:bg-zinc-900/20 dark:divide-zinc-800/70">
                  <div className="grid grid-cols-[112px_1fr] gap-3 px-3.5 py-2.5 sm:grid-cols-[136px_1fr]">
                    <dt className="font-mono text-[10px] uppercase tracking-wider text-zinc-400 dark:text-zinc-500">Time</dt>
                    <dd className="font-mono text-[11px] text-zinc-700 dark:text-zinc-300">
                      {formatDateTime(selectedLog.timestamp)}
                    </dd>
                  </div>
                  <div className="grid grid-cols-[112px_1fr] gap-3 px-3.5 py-2.5 sm:grid-cols-[136px_1fr]">
                    <dt className="font-mono text-[10px] uppercase tracking-wider text-zinc-400 dark:text-zinc-500">Entry ID</dt>
                    <dd className="break-all font-mono text-[11px] text-zinc-700 dark:text-zinc-300">{selectedLog.id}</dd>
                  </div>
                  <div className="grid grid-cols-[112px_1fr] gap-3 px-3.5 py-2.5 sm:grid-cols-[136px_1fr]">
                    <dt className="font-mono text-[10px] uppercase tracking-wider text-zinc-400 dark:text-zinc-500">Level</dt>
                    <dd>
                      <span className={`inline-block px-2 py-0.5 rounded border text-[10px] uppercase font-bold ${getLevelBadgeClass(selectedLog.level)}`}>
                        {selectedLog.level}
                      </span>
                    </dd>
                  </div>
                  <div className="grid grid-cols-[112px_1fr] gap-3 px-3.5 py-2.5 sm:grid-cols-[136px_1fr]">
                    <dt className="font-mono text-[10px] uppercase tracking-wider text-zinc-400 dark:text-zinc-500">Source</dt>
                    <dd className="text-[11px] uppercase text-zinc-700 dark:text-zinc-300">{formatSourceName(selectedLog.source)}</dd>
                  </div>
                  {selectedLog.host && (
                    <div className="grid grid-cols-[112px_1fr] gap-3 px-3.5 py-2.5 sm:grid-cols-[136px_1fr]">
                      <dt className="font-mono text-[10px] uppercase tracking-wider text-zinc-400 dark:text-zinc-500">Host</dt>
                      <dd className="break-all font-mono text-[11px] text-zinc-700 dark:text-zinc-300">{selectedLog.host}</dd>
                    </div>
                  )}
                  {selectedLog.ip && (
                    <div className="grid grid-cols-[112px_1fr] gap-3 px-3.5 py-2.5 sm:grid-cols-[136px_1fr]">
                      <dt className="font-mono text-[10px] uppercase tracking-wider text-zinc-400 dark:text-zinc-500">Source IP</dt>
                      <dd className="font-mono text-[11px] text-zinc-700 dark:text-zinc-300">{selectedLog.ip}</dd>
                    </div>
                  )}
                  {selectedLog.correlationId && (
                    <div className="grid grid-cols-[112px_1fr] gap-3 px-3.5 py-2.5 sm:grid-cols-[136px_1fr]">
                      <dt className="font-mono text-[10px] uppercase tracking-wider text-zinc-400 dark:text-zinc-500">Correlation ID</dt>
                      <dd className="flex min-w-0 items-center gap-2">
                        <span className="min-w-0 break-all font-mono text-[11px] text-zinc-700 dark:text-zinc-300">{selectedLog.correlationId}</span>
                        <button
                          onClick={() => copyToClipboard(selectedLog.correlationId || '', selectedLog.id)}
                          className="shrink-0 text-zinc-400 transition hover:text-zinc-900 cursor-pointer dark:text-zinc-500 dark:hover:text-zinc-100"
                          title="Copy correlation ID"
                        >
                          {copiedId === selectedLog.id ? <CheckCircle2 className="w-3.5 h-3.5 text-emerald-500" /> : <Copy className="w-3.5 h-3.5" />}
                        </button>
                      </dd>
                    </div>
                  )}
                </dl>
              </section>

              {/* Log message */}
              <section>
                <div className="mb-2 text-[10px] font-bold uppercase tracking-[0.14em] text-zinc-400 dark:text-zinc-500">
                  Log message
                </div>
                <div className="whitespace-pre-wrap break-all rounded-xl border border-zinc-200/80 bg-zinc-50 p-3 font-mono text-[11px] leading-relaxed text-zinc-700 dark:border-zinc-800 dark:bg-zinc-900/40 dark:text-zinc-300">
                  {selectedLog.message}
                </div>
              </section>

              {/* Metadata */}
              {selectedLog.metadata && Object.keys(selectedLog.metadata).length > 0 && (
                <section>
                  <div className="mb-2 text-[10px] font-bold uppercase tracking-[0.14em] text-zinc-400 dark:text-zinc-500">
                    Metadata
                  </div>
                  <pre className="max-h-56 overflow-auto custom-scrollbar rounded-xl border border-zinc-200/80 bg-zinc-50 p-3 font-mono text-[11px] text-zinc-600 dark:border-zinc-800 dark:bg-zinc-900/40 dark:text-zinc-300">
                    {JSON.stringify(selectedLog.metadata, null, 2)}
                  </pre>
                </section>
              )}
            </div>

            {/* Drawer footer */}
            <footer className="shrink-0 border-t border-zinc-200/80 bg-zinc-50/60 px-5 py-3 dark:border-zinc-800 dark:bg-zinc-900/30 sm:px-6">
              <div className="flex flex-wrap items-center justify-between gap-2 font-mono text-[10px] uppercase tracking-wider text-zinc-400 dark:text-zinc-500">
                <span>Centralized Logs · log record</span>
                <span className="normal-case tracking-normal">Click anywhere outside to close</span>
              </div>
            </footer>
          </aside>
        </div>
      )}
    </div>
  );
};
