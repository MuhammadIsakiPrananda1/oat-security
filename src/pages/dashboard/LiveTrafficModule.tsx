import React, { useState, useEffect, useRef } from 'react';
import { Radio, RefreshCw, Search, ChevronDown, ChevronLeft, ChevronRight, Filter } from 'lucide-react';
import { FontAwesomeIcon } from '@fortawesome/react-fontawesome';
import { faTowerBroadcast } from '@fortawesome/free-solid-svg-icons';
import { ModulePageHeader } from '../../components/common/ModulePageHeader';
import { telemetryStreamManager, securityApi, normalizeRealtimeSecurityEvent } from '../../services/api';
import { SecurityEvent } from '../../types';
import { StatusBadge } from '../../components/common/StatusBadge';
import { BackendOfflineBanner } from '../../components/common/BackendOfflineBanner';
import { useAuth } from '../../context/AuthContext';
import { formatDateTime, formatTime } from '../../utils/dateTime';
import { classifyLocalIp, getCountryName, extractIpOnly } from '../../utils/ip';
import { CountryFlag } from '../../components/common/CountryFlag';
import { getLanguage } from '../../i18n/translator';

type ActionFilterValue = 'ALL' | 'BLOCKED' | 'ALLOWED' | 'CHALLENGED' | 'LOGGED';
type ActionGroup = 'BLOCKED' | 'ALLOWED' | 'CHALLENGED' | 'LOGGED' | 'OTHER';

// The database stores raw actions (BLOCK, DENY, ALLOW, LOG...) while the interface uses plain groups.
const actionGroupOf = (action?: string | null): ActionGroup => {
  const value = String(action || '').toUpperCase();
  if (['BLOCK', 'BLOCKED', 'DENY', 'DROP'].includes(value)) return 'BLOCKED';
  if (['ALLOW', 'ALLOWED', 'PASS'].includes(value)) return 'ALLOWED';
  if (['CHALLENGE', 'CHALLENGED', 'RATE_LIMIT'].includes(value)) return 'CHALLENGED';
  if (['LOG', 'LOGGED'].includes(value)) return 'LOGGED';
  return 'OTHER';
};

const ACTION_FILTER_OPTIONS: { value: ActionFilterValue; label: string; dot: string; activeBg: string; activeText: string; countColor: string }[] = [
  { value: 'ALL',       label: 'All',       dot: 'bg-zinc-400',   activeBg: '',                                activeText: 'text-zinc-900 dark:text-zinc-100',    countColor: 'text-zinc-400 dark:text-zinc-500' },
  { value: 'BLOCKED',   label: 'Blocked',   dot: 'bg-rose-500',   activeBg: 'bg-rose-50 dark:bg-rose-950/40',  activeText: 'text-rose-600 dark:text-rose-400',   countColor: 'text-rose-500' },
  { value: 'ALLOWED',   label: 'Allowed',   dot: 'bg-emerald-500',activeBg: 'bg-emerald-50 dark:bg-emerald-950/40', activeText: 'text-emerald-600 dark:text-emerald-400', countColor: 'text-emerald-500' },
  { value: 'CHALLENGED',label: 'Challenged',dot: 'bg-amber-400',  activeBg: 'bg-amber-50 dark:bg-amber-950/40', activeText: 'text-amber-600 dark:text-amber-400',  countColor: 'text-amber-500' },
  { value: 'LOGGED',    label: 'Logged',    dot: 'bg-zinc-400',   activeBg: 'bg-zinc-100 dark:bg-zinc-800',    activeText: 'text-zinc-700 dark:text-zinc-200',   countColor: 'text-zinc-500' },
];

type SeverityFilterValue = 'ALL' | 'Critical' | 'High' | 'Medium' | 'Low';

const SEVERITY_FILTER_OPTIONS: { value: SeverityFilterValue; label: string; dot: string; activeBg: string; activeText: string; countColor: string }[] = [
  { value: 'ALL',      label: 'All severities', dot: 'bg-zinc-400',   activeBg: '',                                           activeText: 'text-zinc-900 dark:text-zinc-100',   countColor: 'text-zinc-400 dark:text-zinc-500' },
  { value: 'Critical', label: 'Critical',       dot: 'bg-rose-500',   activeBg: 'bg-rose-50 dark:bg-rose-950/40',             activeText: 'text-rose-600 dark:text-rose-400',   countColor: 'text-rose-500' },
  { value: 'High',     label: 'High',           dot: 'bg-amber-400',  activeBg: 'bg-amber-50 dark:bg-amber-950/40',           activeText: 'text-amber-600 dark:text-amber-400', countColor: 'text-amber-500' },
  { value: 'Medium',   label: 'Medium',         dot: 'bg-yellow-400', activeBg: 'bg-yellow-50 dark:bg-yellow-950/40',         activeText: 'text-yellow-600 dark:text-yellow-300', countColor: 'text-yellow-500' },
  { value: 'Low',      label: 'Low',            dot: 'bg-sky-400',    activeBg: 'bg-sky-50 dark:bg-sky-950/40',               activeText: 'text-sky-600 dark:text-sky-300',     countColor: 'text-sky-500' },
];

export const LiveTrafficModule: React.FC = () => {
  const { isBackendOffline } = useAuth();
  const [events, setEvents] = useState<SecurityEvent[]>([]);
  const [loading, setLoading] = useState(true);
  const [filterAction, setFilterAction] = useState<ActionFilterValue>('ALL');
  const [showFilterDropdown, setShowFilterDropdown] = useState(false);
  const filterDropdownRef = useRef<HTMLDivElement>(null);
  const [filterSeverity, setFilterSeverity] = useState<SeverityFilterValue>('ALL');
  const [showSeverityDropdown, setShowSeverityDropdown] = useState(false);
  const severityDropdownRef = useRef<HTMLDivElement>(null);
  const [search, setSearch] = useState('');
  const [searchTerm, setSearchTerm] = useState('');
  const [selectedEvent, setSelectedEvent] = useState<SecurityEvent | null>(null);
  const [recordedTotal, setRecordedTotal] = useState(0);
  const [currentPage, setCurrentPage] = useState(1);
  const [pageSize, setPageSize] = useState(100); // Default page size

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
        setSwipeTranslateX(0);
        setIsSwiping(false);
      }, 150);
    } else {
      setIsSwiping(false);
      setSwipeTranslateX(0);
    }
    touchStartRef.current = null;
  };

  // Aggregated stats from the FULL database (not just the events on this page).
  const [topSourceIpsAgg, setTopSourceIpsAgg] = useState<Array<{
    ip: string;
    count: number;
    sourceCountry?: string;
    sourceCountryCode?: string;
  }>>([]);
  const [topApplicationsAgg, setTopApplicationsAgg] = useState<Array<{ application: string; count: number }>>([]);
  const [aggregateActions, setAggregateActions] = useState<{ blocked: number; allowed: number; challenged: number; logged: number; other: number; total: number } | null>(null);
  const [aggregateSeverities, setAggregateSeverities] = useState<{ critical: number; high: number; medium: number; low: number } | null>(null);

  // Wait until typing pauses before querying the database; every new search starts at page one.
  useEffect(() => {
    const timer = window.setTimeout(() => {
      setSearchTerm(search.trim());
      setCurrentPage(1);
    }, 300);
    return () => window.clearTimeout(timer);
  }, [search]);

  // Load telemetry events from the database for the active page, page size, and filters.
  useEffect(() => {
    let isMounted = true;
    async function loadEvents() {
      if (isBackendOffline) return;
      setLoading(true);
      try {
        const res = await securityApi.getSecurityEvents({
          limit: pageSize,
          page: currentPage,
          action: filterAction === 'ALL' ? undefined : filterAction,
          severity: filterSeverity === 'ALL' ? undefined : filterSeverity,
          search: searchTerm || undefined
        });
        if (isMounted) {
          if (res.events) {
            setEvents(prev => {
              // Merge preserving real-time items received before query finished
              const serverIds = new Set(res.events.map(e => e.id));
              const pendingLive = prev.filter(e => !serverIds.has(e.id));
              return [...pendingLive, ...res.events].slice(0, pageSize);
            });
          }
          if (typeof res.total === 'number') {
            setRecordedTotal(res.total);
          }
        }
      } catch (err) {
        console.error('[LiveTraffic] Events fetch failed:', err);
      } finally {
        if (isMounted) setLoading(false);
      }
    }
    loadEvents();
    return () => { isMounted = false; };
  }, [isBackendOffline, currentPage, pageSize, filterAction, filterSeverity, searchTerm]);

  // Periodic live sync every 2.5s for page 1 to ensure events stream in without user refresh
  useEffect(() => {
    if (isBackendOffline) return;
    const interval = window.setInterval(async () => {
      if (currentPage !== 1) return;
      try {
        const res = await securityApi.getSecurityEvents({
          limit: pageSize,
          page: 1,
          action: filterAction === 'ALL' ? undefined : filterAction,
          severity: filterSeverity === 'ALL' ? undefined : filterSeverity,
          search: searchTerm || undefined
        });
        if (res.events && res.events.length > 0) {
          setEvents(prev => {
            const serverIds = new Set(res.events.map(e => e.id));
            const pendingLive = prev.filter(e => !serverIds.has(e.id));
            const merged = [...pendingLive, ...res.events].slice(0, pageSize);
            if (prev.length === merged.length && prev.every((e, i) => e.id === merged[i]?.id)) {
              return prev;
            }
            return merged;
          });
          if (typeof res.total === 'number') {
            setRecordedTotal(res.total);
          }
        }
      } catch {}
    }, 2500);
    return () => window.clearInterval(interval);
  }, [isBackendOffline, currentPage, pageSize, filterAction, filterSeverity, searchTerm]);

  // Load aggregated stats from the FULL database — separate from the live feed.
  useEffect(() => {
    let isMounted = true;
    async function loadAggregates() {
      try {
        const res = await securityApi.getSecurityEventsAggregates({ limit: 10 });
        if (isMounted) {
          setTopSourceIpsAgg(res.topSourceIps || []);
          setTopApplicationsAgg(res.topApplications || []);
          setAggregateActions(res.actions || null);
          setAggregateSeverities(res.severities || null);
        }
      } catch (err) {
        console.error('[LiveTraffic] Aggregates fetch failed:', err);
      }
    }
    loadAggregates();
    const timer = window.setInterval(loadAggregates, 60000);
    return () => { isMounted = false; window.clearInterval(timer); };
  }, [isBackendOffline]);

  // Real-time WebSocket stream subscription
  useEffect(() => {
    if (isBackendOffline) {
      return;
    }

    const matchesActiveView = (evt: SecurityEvent) => {
      if (filterAction !== 'ALL' && actionGroupOf(evt.action) !== filterAction) return false;
      if (filterSeverity !== 'ALL' && String(evt.severity || '').toLowerCase() !== filterSeverity.toLowerCase()) return false;
      const term = searchTerm.trim().toLowerCase();
      if (!term) return true;
      return [evt.sourceIp, evt.application, evt.threat]
        .some(value => String(value || '').toLowerCase().includes(term));
    };

    const unsubscribe = telemetryStreamManager.subscribe((msg: any) => {
      const newEvent = normalizeRealtimeSecurityEvent(msg);
      if (!newEvent || !matchesActiveView(newEvent)) return;

      setRecordedTotal(prev => prev + 1);

      // Instantly update aggregated counts and top cards in real time (0ms delay)
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

      if (newEvent.application && newEvent.application !== 'failed') {
        setTopApplicationsAgg(prev => {
          const idx = prev.findIndex(item => item.application.toLowerCase() === newEvent.application.toLowerCase());
          if (idx >= 0) {
            const next = [...prev];
            next[idx] = { ...next[idx], count: next[idx].count + 1 };
            return next.sort((a, b) => b.count - a.count);
          }
          return [...prev, { application: newEvent.application, count: 1 }].sort((a, b) => b.count - a.count).slice(0, 10);
        });
      }

      // Prepend incoming events if user is looking at the latest (first) page
      if (currentPage === 1) {
        setEvents(prev => {
          if (prev.some(e => e.id === newEvent.id)) return prev;
          return [newEvent, ...prev.slice(0, pageSize - 1)];
        });
      }
    });

    return () => {
      unsubscribe();
    };
  }, [isBackendOffline, currentPage, pageSize, filterAction, filterSeverity, searchTerm]);

  if (isBackendOffline) {
    return <BackendOfflineBanner onRetry={() => window.location.reload()} />;
  }

  // The API already applies the action filter and search, so the loaded page is ready to render.
  const filteredEvents = events;

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

  // Side-rail summaries — use DB-wide aggregates so they reflect ALL history, not just the events on this page.
  const maxRailRows = 5;

  // Keep the GeoIP fields alongside each aggregate so the rail uses the same
  // server-side lookup as the table instead of guessing from IP prefixes.
  const topSourceIps = topSourceIpsAgg.slice(0, maxRailRows);
  const topApplications = (topApplicationsAgg.slice(0, maxRailRows)).map(r => [r.application, r.count] as [string, number]);
  const topSourceIpMax = topSourceIps.length > 0 ? topSourceIps[0].count : 0;
  const topApplicationMax = topApplications.length > 0 ? topApplications[0][1] : 0;

  // Ranked the same way as the other rail cards: most frequent action first, bars scaled to the top row.
  const actionRailRows = [
    { label: 'Blocked', count: actionFilterCounts.BLOCKED, dot: 'bg-rose-500', bar: 'bg-rose-500' },
    { label: 'Allowed', count: actionFilterCounts.ALLOWED, dot: 'bg-emerald-500', bar: 'bg-emerald-500' },
    { label: 'Challenged', count: actionFilterCounts.CHALLENGED, dot: 'bg-amber-400', bar: 'bg-amber-400' },
    { label: 'Logged', count: actionFilterCounts.LOGGED, dot: 'bg-zinc-400', bar: 'bg-zinc-400' }
  ].sort((a, b) => b.count - a.count);
  const actionRailMax = actionRailRows[0]?.count ?? 0;

  const totalPages = Math.max(1, Math.ceil(recordedTotal / pageSize));
  const startRecord = recordedTotal === 0 ? 0 : (currentPage - 1) * pageSize + 1;
  const endRecord = Math.min(currentPage * pageSize, recordedTotal);

  const extractReadableMessage = (raw?: string): string => {
    if (!raw) return '';
    const s = String(raw).trim();
    if (s.startsWith('{') || s.includes('"MESSAGE"') || s.includes('"SYSLOG_IDENTIFIER"')) {
      try {
        const jsonCandidate = s.startsWith('{') ? (s.endsWith('}') ? s : s + '}') : '{' + s + '}';
        const obj = JSON.parse(jsonCandidate);
        if (obj.threat || obj.threatName) return String(obj.threat || obj.threatName);
        if (obj.message || obj.MESSAGE) {
          const id = obj.SYSLOG_IDENTIFIER || obj.ident || obj.application || '';
          return id ? `${id}: ${obj.message || obj.MESSAGE}` : String(obj.message || obj.MESSAGE);
        }
        if (obj.rawLog) return String(obj.rawLog);
      } catch {
        // Fallback regex if truncated JSON
        const msgMatch = s.match(/"(?:MESSAGE|message)"\s*:\s*"([^"\\]*(?:\\.[^"\\]*)*)"/);
        const idMatch = s.match(/"(?:SYSLOG_IDENTIFIER|ident|application)"\s*:\s*"([^"\\]*(?:\\.[^"\\]*)*)"/);
        if (msgMatch && msgMatch[1]) {
          const cleanMsg = msgMatch[1].replace(/\\"/g, '"');
          return idMatch && idMatch[1] ? `${idMatch[1]}: ${cleanMsg}` : cleanMsg;
        }
      }
    }
    return s;
  };

  return (
    <div className="space-y-5">
      {/* Header — dashboard page header style. */}
      <ModulePageHeader
        icon={<FontAwesomeIcon icon={faTowerBroadcast} />}
        title="Live"
        titleTail="Traffic"
        subtitle="Every request and connection inspected as it happens. Click any row to see the full details of that event."
      />

      {/* Live feed on the left, summary rail on the right. */}
      <div className="grid items-start gap-5 lg:grid-cols-[minmax(0,1fr)_300px] xl:grid-cols-[minmax(0,1fr)_340px]">
        {/* Feed — toolbar and table share one card so it reads like a stream window. */}
        <div className="flex min-w-0 flex-col overflow-hidden rounded-2xl border border-zinc-200/80 bg-white shadow-2xs dark:border-zinc-800 dark:bg-[#0c0c0e]">
          <div className="shrink-0 flex flex-wrap items-center gap-2 border-b border-zinc-100 bg-zinc-50/60 px-3 py-2.5 dark:border-zinc-800/80 dark:bg-zinc-900/40">
            {/* Action filter — notification-style dropdown */}
            <div className="relative" ref={filterDropdownRef}>
              <button
                type="button"
                onClick={() => { setShowFilterDropdown(prev => !prev); setShowSeverityDropdown(false); }}
                className="h-8 px-3 rounded-lg border border-zinc-200/80 dark:border-zinc-800 bg-white dark:bg-zinc-900 hover:bg-zinc-50 dark:hover:bg-zinc-800 text-xs font-medium text-zinc-700 dark:text-zinc-200 inline-flex items-center gap-2 transition cursor-pointer shadow-2xs"
              >
                <Filter className="w-3 h-3 text-zinc-400" />
                <span>
                  {(() => {
                    const opt = ACTION_FILTER_OPTIONS.find(o => o.value === filterAction)!;
                    return `${opt.label} (${actionFilterCounts[filterAction].toLocaleString()})`;
                  })()}
                </span>
                <ChevronDown className={`w-3 h-3 text-zinc-400 transition-transform ${showFilterDropdown ? 'rotate-180' : ''}`} />
              </button>

              {showFilterDropdown && (
                <>
                  <div
                    className="fixed inset-0 z-20 cursor-default"
                    onClick={() => setShowFilterDropdown(false)}
                  />
                  <div className="absolute left-0 top-full mt-1.5 w-52 max-w-[calc(100vw-32px)] rounded-xl border border-zinc-200/80 dark:border-zinc-800 bg-white dark:bg-zinc-900 shadow-xl p-1 z-30">
                    {ACTION_FILTER_OPTIONS.map((opt) => {
                      const isActive = filterAction === opt.value;
                      return (
                        <button
                          key={opt.value}
                          type="button"
                          onClick={() => { setFilterAction(opt.value); setCurrentPage(1); setShowFilterDropdown(false); }}
                          className={`w-full px-2.5 py-1.5 rounded-lg text-xs text-left flex items-center justify-between transition cursor-pointer ${
                            isActive
                              ? `font-semibold ${opt.activeBg || 'bg-zinc-100 dark:bg-zinc-800'} ${opt.activeText}`
                              : 'text-zinc-600 dark:text-zinc-400 hover:bg-zinc-50 dark:hover:bg-zinc-800/60'
                          }`}
                        >
                          <span className="flex items-center gap-1.5">
                            {opt.value !== 'ALL' && (
                              <span className={`w-2 h-2 rounded-full shrink-0 ${opt.dot}`} />
                            )}
                            {opt.value === 'ALL' && (
                              <span className="w-2 h-2 rounded-full shrink-0 bg-zinc-400" />
                            )}
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

            {/* Severity filter — same dropdown language as the action filter */}
            <div className="relative" ref={severityDropdownRef}>
              <button
                type="button"
                onClick={() => { setShowSeverityDropdown(prev => !prev); setShowFilterDropdown(false); }}
                className="h-8 px-3 rounded-lg border border-zinc-200/80 dark:border-zinc-800 bg-white dark:bg-zinc-900 hover:bg-zinc-50 dark:hover:bg-zinc-800 text-xs font-medium text-zinc-700 dark:text-zinc-200 inline-flex items-center gap-2 transition cursor-pointer shadow-2xs"
              >
                <Filter className="w-3 h-3 text-zinc-400" />
                <span>
                  {(() => {
                    const opt = SEVERITY_FILTER_OPTIONS.find(o => o.value === filterSeverity)!;
                    return `${opt.label} (${severityFilterCounts[filterSeverity].toLocaleString()})`;
                  })()}
                </span>
                <ChevronDown className={`w-3 h-3 text-zinc-400 transition-transform ${showSeverityDropdown ? 'rotate-180' : ''}`} />
              </button>

              {showSeverityDropdown && (
                <>
                  <div
                    className="fixed inset-0 z-20 cursor-default"
                    onClick={() => setShowSeverityDropdown(false)}
                  />
                  <div className="absolute left-0 top-full mt-1.5 w-52 max-w-[calc(100vw-32px)] rounded-xl border border-zinc-200/80 dark:border-zinc-800 bg-white dark:bg-zinc-900 shadow-xl p-1 z-30">
                    {SEVERITY_FILTER_OPTIONS.map(opt => {
                      const isActive = filterSeverity === opt.value;
                      return (
                        <button
                          key={opt.value}
                          type="button"
                          onClick={() => { setFilterSeverity(opt.value); setCurrentPage(1); setShowSeverityDropdown(false); }}
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

          <div className="h-[580px] overflow-y-auto overflow-x-auto custom-scrollbar">
            <table className="min-w-[720px] w-full table-fixed border-separate border-spacing-0 text-left text-xs">
              <thead>
                <tr className="text-[11px] font-medium uppercase tracking-wider text-zinc-400 dark:text-zinc-500">
                  <th className="sticky top-0 z-20 w-[13%] min-w-[85px] border-b border-zinc-200/80 bg-zinc-50 pl-4 pr-2 py-2.5 font-medium dark:border-zinc-800 dark:bg-zinc-900">Time</th>
                  <th className="sticky top-0 z-20 w-[18%] min-w-[130px] border-b border-zinc-200/80 bg-zinc-50 px-3 py-2.5 font-medium dark:border-zinc-800 dark:bg-zinc-900">Source IP</th>
                  <th className="sticky top-0 z-20 w-[9%] min-w-[65px] border-b border-zinc-200/80 bg-zinc-50 px-2 py-2.5 font-medium text-center dark:border-zinc-800 dark:bg-zinc-900">Country</th>
                  <th className="sticky top-0 z-20 w-[15%] min-w-[110px] border-b border-zinc-200/80 bg-zinc-50 px-3 py-2.5 font-medium dark:border-zinc-800 dark:bg-zinc-900">Application</th>
                  <th className="sticky top-0 z-20 w-[22%] min-w-[160px] border-b border-zinc-200/80 bg-zinc-50 px-3 py-2.5 font-medium dark:border-zinc-800 dark:bg-zinc-900">Threat</th>
                  <th className="sticky top-0 z-20 w-[10%] min-w-[80px] border-b border-zinc-200/80 bg-zinc-50 px-2 py-2.5 font-medium text-center dark:border-zinc-800 dark:bg-zinc-900">Severity</th>
                  <th className="sticky top-0 z-20 w-[13%] min-w-[90px] border-b border-zinc-200/80 bg-zinc-50 pl-2 pr-6 sm:pr-8 py-2.5 font-medium text-right dark:border-zinc-800 dark:bg-zinc-900">Action</th>
                </tr>
              </thead>
              <tbody>
                {loading && events.length === 0 ? (
                  <tr>
                    <td colSpan={7} className="border-0 px-4 py-28 text-center">
                      <RefreshCw className="w-5 h-5 animate-spin mx-auto text-zinc-400 dark:text-zinc-500 mb-2" />
                      <div className="text-xs text-zinc-400 dark:text-zinc-500">Loading events...</div>
                    </td>
                  </tr>
                ) : filteredEvents.length === 0 ? (
                  <tr>
                    <td colSpan={7} className="border-0 px-4 py-28 text-center">
                      <div className="text-sm font-medium text-zinc-500 dark:text-zinc-400">
                        No traffic matches the current filter
                      </div>
                      <div className="mt-1 text-xs text-zinc-400 dark:text-zinc-500">
                        New events appear here automatically as they are inspected.
                      </div>
                    </td>
                  </tr>
                ) : (
                  filteredEvents.map(evt => {
                    const isInternal = evt.sourceIp === '0.0.0.0';
                    const appLabel = (!evt.application || evt.application === 'failed') ? 'Raw Traffic' : evt.application;

                    return (
                      <tr
                        key={evt.id}
                        onClick={() => setSelectedEvent(evt)}
                        className={`cursor-pointer transition hover:bg-zinc-50/70 dark:hover:bg-zinc-900/40 ${
                          selectedEvent?.id === evt.id ? 'bg-zinc-50 dark:bg-zinc-900/50' : ''
                        }`}
                      >
                        <td className="border-b border-zinc-100 pl-4 pr-2 py-2.5 font-mono text-[11px] text-zinc-400 whitespace-nowrap truncate dark:border-zinc-800/60 dark:text-zinc-500">
                          {formatTime(evt.timestamp)}
                        </td>
                        <td className="border-b border-zinc-100 px-3 py-2.5 font-mono text-[11px] truncate dark:border-zinc-800/60" title={evt.sourceIp}>
                          {isInternal ? (
                            <span className="text-zinc-400 dark:text-zinc-500 italic">0.0.0.0 (Internal)</span>
                          ) : (
                            <span className="font-medium text-zinc-700 dark:text-zinc-300">{extractIpOnly(evt.sourceIp)}</span>
                          )}
                        </td>
                        <td className="border-b border-zinc-100 px-2 py-2.5 text-center dark:border-zinc-800/60">
                          <CountryFlag
                            code={evt.sourceCountryCode}
                            name={evt.sourceCountry}
                            width={22}
                            height={15}
                            className="hover:scale-115 transition-transform"
                          />
                        </td>
                        <td className="border-b border-zinc-100 px-3 py-2.5 truncate dark:border-zinc-800/60" title={appLabel}>
                          <span className={`text-[11px] ${evt.application === 'failed' || !evt.application ? 'text-zinc-400 dark:text-zinc-500 italic' : 'font-medium text-zinc-700 dark:text-zinc-300'}`}>
                            {appLabel}
                          </span>
                        </td>
                        <td className="border-b border-zinc-100 px-3 py-2.5 truncate dark:border-zinc-800/60" title={evt.threat}>
                          <span className="text-[11px] font-medium text-zinc-800 dark:text-zinc-200 truncate block">
                            {evt.threat}
                          </span>
                        </td>
                        <td className="border-b border-zinc-100 px-2 py-2.5 text-center whitespace-nowrap dark:border-zinc-800/60">
                          <StatusBadge type="severity" value={evt.severity} size="sm" />
                        </td>
                        <td className="border-b border-zinc-100 pl-2 pr-6 sm:pr-8 py-2.5 text-right whitespace-nowrap dark:border-zinc-800/60">
                          <StatusBadge type="action" value={evt.action} size="sm" />
                        </td>
                      </tr>
                    );
                  })
                )}
              </tbody>
            </table>
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
              {filterAction !== 'ALL' || filterSeverity !== 'ALL' || searchTerm ? 'matching events' : 'recorded events'}
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

        {/* Summary rail — plain numbers for the events currently loaded. */}
        <aside className="grid content-start gap-5 sm:grid-cols-2 lg:grid-cols-1">
          <div className="rounded-2xl border border-zinc-200/80 bg-white p-4 shadow-2xs dark:border-zinc-800 dark:bg-[#0c0c0e]">
            <div className="text-[11px] font-medium uppercase tracking-wider text-zinc-400 dark:text-zinc-500">
              Actions taken
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

          <div className="rounded-2xl border border-zinc-200/80 bg-white p-4 shadow-2xs dark:border-zinc-800 dark:bg-[#0c0c0e]">
            <div className="text-[11px] font-medium uppercase tracking-wider text-zinc-400 dark:text-zinc-500">
              Busiest source IPs
            </div>
            <div className="mt-3 space-y-2.5">
              {topSourceIps.length === 0 ? (
                <div className="text-xs text-zinc-400 dark:text-zinc-500">No events loaded yet.</div>
              ) : (
                topSourceIps.map(({ ip, count, sourceCountry, sourceCountryCode }) => {
                  // Use the server-side GeoIP result; classify only local ranges
                  // here as a fallback for very old rows.
                  const ipStr = String(ip);
                  const rawBadge = sourceCountryCode || (classifyLocalIp(ipStr) ? 'ID' : 'UN');
                  const badge = (rawBadge === 'LAN' || rawBadge === 'SYS') ? 'ID' : rawBadge;
                  const cleanIp = extractIpOnly(ipStr);
                  let displayIp: string = cleanIp;
                  // Shorten IPv6 for display
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

          <div className="rounded-2xl border border-zinc-200/80 bg-white p-4 shadow-2xs dark:border-zinc-800 dark:bg-[#0c0c0e]">
            <div className="text-[11px] font-medium uppercase tracking-wider text-zinc-400 dark:text-zinc-500">
              Most targeted applications
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
                        <span className="shrink-0 font-mono text-[10px] font-medium text-zinc-500 dark:text-zinc-400">{Number(count).toLocaleString()}</span>
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
            Aggregated from all events in the database.
          </p>
        </aside>
      </div>

      {/* Event details drawer — slides in from the right like the engine inspector; closes on any click outside the panel */}
      {selectedEvent && (
        <div className="fixed inset-0 z-50">
          {/* Dimmed backdrop — clicking anywhere outside the panel closes the drawer. */}
          <div
            className="absolute inset-0 bg-zinc-950/45 dark:bg-black/70 backdrop-blur-[2px] animate-in fade-in-0 duration-200 transition-opacity"
            style={{ opacity: swipeTranslateX > 0 ? Math.max(0.1, 1 - swipeTranslateX / 300) : undefined }}
            onClick={() => setSelectedEvent(null)}
          />

          <aside
            role="dialog"
            aria-modal="true"
            aria-label="Traffic event details"
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
            {/* Drawer header */}
            <header className="shrink-0 border-b border-zinc-200/80 bg-white px-5 pb-4 pt-3.5 dark:border-zinc-800 dark:bg-[#0b0b0d] sm:px-6">
              <div className="flex min-w-0 items-center gap-1.5 font-mono text-[10px] uppercase tracking-[0.16em] text-zinc-400 dark:text-zinc-500">
                <span className="shrink-0">Live Traffic</span>
                <span className="shrink-0 text-zinc-300 dark:text-zinc-700">/</span>
                <span className="truncate font-sans text-[11px] font-medium normal-case tracking-normal text-zinc-500 dark:text-zinc-400">
                  Event Details
                </span>
              </div>

              <div className="mt-3 flex items-start gap-3">
                <span className="flex h-11 w-11 shrink-0 items-center justify-center rounded-xl border border-zinc-200/80 bg-zinc-50 text-zinc-500 dark:border-zinc-800 dark:bg-zinc-900/60 dark:text-zinc-400">
                  <Radio className="text-lg" />
                </span>
                <div className="min-w-0 flex-1">
                  <div className="flex flex-wrap items-center gap-2">
                    <h2 className="truncate text-base font-semibold tracking-tight text-zinc-900 dark:text-zinc-100">
                      Event Details
                    </h2>
                    <StatusBadge type="severity" value={selectedEvent.severity} />
                    <StatusBadge type="action" value={selectedEvent.action} />
                  </div>
                  <p className="mt-0.5 truncate text-[11px] text-zinc-500 dark:text-zinc-400">
                    Full inspection record for this traffic event.
                  </p>
                </div>
              </div>

              <div className="mt-3 flex flex-wrap items-center gap-x-4 gap-y-1 font-mono text-[10px] uppercase tracking-wider text-zinc-400 dark:text-zinc-500">
                <span>Time · {formatTime(selectedEvent.timestamp)}</span>
                <span className="truncate">Source · {selectedEvent.sourceIp}</span>
              </div>
            </header>

            {/* Scrollable body */}
            <div className="flex-1 space-y-5 overflow-y-auto px-5 py-5 text-xs sm:px-6">
              {/* Event overview */}
              <section>
                <div className="mb-2 text-[10px] font-bold uppercase tracking-[0.14em] text-zinc-400 dark:text-zinc-500">
                  Event overview
                </div>
                <div className="grid grid-cols-1 gap-2.5 sm:grid-cols-2">
                  <div className="rounded-xl border border-zinc-200/80 bg-zinc-50/60 p-3 dark:border-zinc-800 dark:bg-zinc-900/40">
                    <div className="font-mono text-[10px] uppercase tracking-wider text-zinc-400 dark:text-zinc-500">Time</div>
                    <div className="mt-1.5 font-mono text-[11px] text-zinc-700 dark:text-zinc-300">
                      {formatDateTime(selectedEvent.timestamp)}
                    </div>
                  </div>
                  <div className="rounded-xl border border-zinc-200/80 bg-zinc-50/60 p-3 dark:border-zinc-800 dark:bg-zinc-900/40">
                    <div className="font-mono text-[10px] uppercase tracking-wider text-zinc-400 dark:text-zinc-500">Event ID</div>
                    <div className="mt-1.5 break-all font-mono text-[11px] text-zinc-700 dark:text-zinc-300">
                      {selectedEvent.id}
                    </div>
                  </div>
                  <div className="rounded-xl border border-zinc-200/80 bg-zinc-50/60 p-3 dark:border-zinc-800 dark:bg-zinc-900/40">
                    <div className="font-mono text-[10px] uppercase tracking-wider text-zinc-400 dark:text-zinc-500">Source</div>
                    <div className="mt-1.5 flex flex-wrap items-center gap-2">
                      <span className="break-all font-mono text-[11px] text-zinc-700 dark:text-zinc-300">{selectedEvent.sourceIp}</span>
                      <span className="inline-flex items-center gap-1.5 rounded border border-zinc-200 bg-white px-2 py-0.5 font-mono text-[10px] text-zinc-700 dark:border-zinc-700 dark:bg-zinc-900 dark:text-zinc-300">
                        <CountryFlag code={selectedEvent.sourceCountryCode} name={selectedEvent.sourceCountry} width={18} height={12} />
                        <span className="font-medium">{getCountryName(selectedEvent.sourceCountryCode, selectedEvent.sourceCountry)}</span>
                      </span>
                    </div>
                  </div>
                  <div className="rounded-xl border border-zinc-200/80 bg-zinc-50/60 p-3 dark:border-zinc-800 dark:bg-zinc-900/40">
                    <div className="font-mono text-[10px] uppercase tracking-wider text-zinc-400 dark:text-zinc-500">Target</div>
                    <div className="mt-1.5 break-all text-[11px] text-zinc-700 dark:text-zinc-300">
                      {selectedEvent.application} ({selectedEvent.destination})
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

              {/* Inspection result */}
              <section>
                <div className="mb-2 text-[10px] font-bold uppercase tracking-[0.14em] text-zinc-400 dark:text-zinc-500">
                  Inspection result
                </div>
                <dl className="overflow-hidden rounded-xl border border-zinc-200/80 bg-white dark:border-zinc-800 dark:bg-zinc-900/20">
                  <div className="grid grid-cols-[112px_1fr] gap-3 border-b border-zinc-100 px-3.5 py-2.5 dark:border-zinc-800/70 sm:grid-cols-[136px_1fr]">
                    <dt className="font-mono text-[10px] uppercase tracking-wider text-zinc-400 dark:text-zinc-500">Threat</dt>
                    <dd className="min-w-0 break-all text-[11px] font-medium text-rose-600 dark:text-rose-400">
                      {extractReadableMessage(selectedEvent.threat) || selectedEvent.threat || 'Security Signature Match'}
                    </dd>
                  </div>
                  <div className="grid grid-cols-[112px_1fr] gap-3 px-3.5 py-2.5 sm:grid-cols-[136px_1fr]">
                    <dt className="font-mono text-[10px] uppercase tracking-wider text-zinc-400 dark:text-zinc-500">What happened</dt>
                    <dd className="text-[11px] leading-relaxed text-zinc-500 dark:text-zinc-400">
                      The request matched a known attack pattern during inspection. The perimeter policy recorded
                      this event and applied the action shown above.
                    </dd>
                  </div>
                </dl>
              </section>
            </div>

            {/* Drawer footer — the drawer closes on any click outside the panel */}
            <footer className="shrink-0 border-t border-zinc-200/80 bg-zinc-50/60 px-5 py-3 dark:border-zinc-800 dark:bg-zinc-900/30 sm:px-6">
              <div className="flex flex-wrap items-center justify-between gap-2 font-mono text-[10px] uppercase tracking-wider text-zinc-400 dark:text-zinc-500">
                <span>Live Traffic · inspection record</span>
                <span className="normal-case tracking-normal">
                  <span className="sm:hidden">Geser ke samping untuk keluar</span>
                  <span className="hidden sm:inline">Click anywhere outside to close</span>
                </span>
              </div>
            </footer>
          </aside>
        </div>
      )}
    </div>
  );
};