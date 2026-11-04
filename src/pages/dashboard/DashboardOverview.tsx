import React, { useEffect, useState, useMemo, useRef } from 'react';
import { FontAwesomeIcon } from '@fortawesome/react-fontawesome';
import {
  faShieldHalved,
  faShieldVirus,
  faFire,
  faServer,
  faNetworkWired,
  faBolt,
  faTriangleExclamation,
  faArrowTrendUp,
  faArrowUpRightFromSquare,
  faArrowRight,
  faFilter,
  faRotateRight,
  faMicrochip,
  faEye,
  faDatabase,
  faGlobe,
  faChevronDown
} from '@fortawesome/free-solid-svg-icons';
import { Radio, RefreshCw, Search, ChevronDown, ChevronLeft, ChevronRight, Filter, X, LineChart as ChartLineIcon, Table as TableIcon } from 'lucide-react';
import { securityApi, telemetryStreamManager, globalRealtimeClient, normalizeRealtimeSecurityEvent } from '../../services/api';
import { StatusBadge } from '../../components/common/StatusBadge';
import { BackendOfflineBanner } from '../../components/common/BackendOfflineBanner';
import { ModulePageHeader, ModulePageBadge } from '../../components/common/ModulePageHeader';
import { SecurityEvent } from '../../types';
import { useAuth } from '../../context/AuthContext';
import { DashboardView } from '../../components/layout/DashboardSidebar';
import { formatDateTime, formatTime } from '../../utils/dateTime';
import { useLiveConnectionState } from '../../hooks/useRealtimeStatus';
import { getCountryName } from '../../utils/ip';
import { CountryFlag } from '../../components/common/CountryFlag';
import { CloudflareGeoMap, CloudflareCountryList, CountryTrafficData } from '../../components/dashboard/CloudflareGeoMap';
import { CountUpNumber } from '../../components/common/CountUpNumber';

interface DashboardOverviewProps {
  onNavigate: (view: DashboardView) => void;
}

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

const ACTION_FILTER_OPTIONS: { value: ActionFilterValue; label: string; dot: string; activeBg: string; activeText: string; countColor: string }[] = [
  { value: 'ALL', label: 'All', dot: 'bg-zinc-400', activeBg: '', activeText: 'text-zinc-900 dark:text-zinc-100', countColor: 'text-zinc-400 dark:text-zinc-500' },
  { value: 'BLOCKED', label: 'Blocked', dot: 'bg-rose-500', activeBg: 'bg-rose-50 dark:bg-rose-950/40', activeText: 'text-rose-600 dark:text-rose-400', countColor: 'text-rose-500' },
  { value: 'ALLOWED', label: 'Allowed', dot: 'bg-emerald-500', activeBg: 'bg-emerald-50 dark:bg-emerald-950/40', activeText: 'text-emerald-600 dark:text-emerald-400', countColor: 'text-emerald-500' },
  { value: 'CHALLENGED', label: 'Challenged', dot: 'bg-amber-400', activeBg: 'bg-amber-50 dark:bg-amber-950/40', activeText: 'text-amber-600 dark:text-amber-400', countColor: 'text-amber-500' },
  { value: 'LOGGED', label: 'Logged', dot: 'bg-zinc-400', activeBg: 'bg-zinc-100 dark:bg-zinc-800', activeText: 'text-zinc-700 dark:text-zinc-200', countColor: 'text-zinc-500' },
];

type SeverityFilterValue = 'ALL' | 'Critical' | 'High' | 'Medium' | 'Low';

const SEVERITY_FILTER_OPTIONS: { value: SeverityFilterValue; label: string; dot: string; activeBg: string; activeText: string; countColor: string }[] = [
  { value: 'ALL', label: 'All severities', dot: 'bg-zinc-400', activeBg: '', activeText: 'text-zinc-900 dark:text-zinc-100', countColor: 'text-zinc-400 dark:text-zinc-500' },
  { value: 'Critical', label: 'Critical', dot: 'bg-rose-500', activeBg: 'bg-rose-50 dark:bg-rose-950/40', activeText: 'text-rose-600 dark:text-rose-400', countColor: 'text-rose-500' },
  { value: 'High', label: 'High', dot: 'bg-amber-500', activeBg: 'bg-amber-50 dark:bg-amber-950/40', activeText: 'text-amber-600 dark:text-amber-400', countColor: 'text-amber-500' },
  { value: 'Medium', label: 'Medium', dot: 'bg-blue-500', activeBg: 'bg-blue-50 dark:bg-blue-950/40', activeText: 'text-blue-600 dark:text-blue-400', countColor: 'text-blue-500' },
  { value: 'Low', label: 'Low & Info', dot: 'bg-zinc-400', activeBg: 'bg-zinc-100 dark:bg-zinc-800', activeText: 'text-zinc-700 dark:text-zinc-200', countColor: 'text-zinc-500' },
];



// Core defense engines expected to report to the health probe
const HEALTH_ROSTER = [
  'WAF Engine',
  'Next-Gen Firewall',
  'Endpoint Detection',
  'Database Vault',
  'API Gateway',
  'SIEM Monitor',
  'WebSocket Stream',
  'Threat Intel'
];

interface ServiceHealthRow {
  service_name: string;
  status: string;
  latency_ms: number | null;
  last_check: string;
  details?: string;
}

type HealthFilter = 'All' | 'Operational' | 'Degraded' | 'Offline';

const HEALTH_FILTER_OPTIONS: { value: HealthFilter; label: string; dot?: string }[] = [
  { value: 'All', label: 'All Engines' },
  { value: 'Operational', label: 'Operational', dot: 'bg-emerald-500' },
  { value: 'Degraded', label: 'Degraded', dot: 'bg-amber-500' },
  { value: 'Offline', label: 'Offline', dot: 'bg-rose-500' }
];

// ---------------------------------------------------------------------------
// Layout primitives
// ---------------------------------------------------------------------------
interface SectionShellProps {
  id?: string;
  title: string;
  action?: React.ReactNode;
  bodyClassName?: string;
  children: React.ReactNode;
}

const SectionShell: React.FC<SectionShellProps> = ({
  id,
  title,
  action,
  bodyClassName = 'p-4 sm:p-5',
  children
}) => (
  <section id={id} className="rounded-2xl border border-zinc-200/80 dark:border-zinc-800 bg-white dark:bg-[#0c0c0e] shadow-2xs overflow-hidden scroll-mt-24 transition-colors">
    <header className="px-5 py-3.5 border-b border-zinc-100 dark:border-zinc-800/80 bg-zinc-50/60 dark:bg-zinc-900/40 flex flex-wrap items-center justify-between gap-x-4 gap-y-2">
      <h2 className="text-sm font-bold text-zinc-900 dark:text-zinc-100 uppercase tracking-wide truncate">{title}</h2>
      {action && <div className="shrink-0">{action}</div>}
    </header>
    <div className={bodyClassName}>{children}</div>
  </section>
);

// Enhanced KPI Card with trend and better visual hierarchy
type AccentColor = 'emerald' | 'blue' | 'indigo' | 'rose' | 'amber' | 'red' | 'violet' | 'slate';

interface EnhancedKpiCardProps {
  label: string;
  icon: React.ReactNode;
  iconColor: AccentColor;
  value: React.ReactNode;
  trend?: { value: string; label: string; positive: boolean };
  meta: string;
  accent?: 'neutral' | 'danger';
  onClick?: () => void;
}

const iconColors: Record<AccentColor, string> = {
  emerald: 'text-emerald-600 dark:text-emerald-400',
  blue: 'text-blue-600 dark:text-blue-400',
  indigo: 'text-indigo-600 dark:text-indigo-400',
  rose: 'text-rose-600 dark:text-rose-400',
  amber: 'text-amber-600 dark:text-amber-400',
  red: 'text-red-600 dark:text-red-400',
  violet: 'text-violet-600 dark:text-violet-400',
  slate: 'text-slate-600 dark:text-slate-400',
};

const statusColors: Record<AccentColor, string> = {
  emerald: 'bg-emerald-100 dark:bg-emerald-950/50 text-emerald-700 dark:text-emerald-300 border-emerald-200 dark:border-emerald-900/40',
  blue: 'bg-blue-100 dark:bg-blue-950/50 text-blue-700 dark:text-blue-300 border-blue-200 dark:border-blue-900/40',
  indigo: 'bg-indigo-100 dark:bg-indigo-950/50 text-indigo-700 dark:text-indigo-300 border-indigo-200 dark:border-indigo-900/40',
  rose: 'bg-rose-100 dark:bg-rose-950/50 text-rose-700 dark:text-rose-300 border-rose-200 dark:border-rose-900/40',
  amber: 'bg-amber-100 dark:bg-amber-950/50 text-amber-700 dark:text-amber-300 border-amber-200 dark:border-amber-900/40',
  red: 'bg-red-100 dark:bg-red-950/50 text-red-700 dark:text-red-300 border-red-200 dark:border-red-900/40',
  violet: 'bg-violet-100 dark:bg-violet-950/50 text-violet-700 dark:text-violet-300 border-violet-200 dark:border-violet-900/40',
  slate: 'bg-slate-100 dark:bg-slate-950/50 text-slate-700 dark:text-slate-300 border-slate-200 dark:border-slate-700/40',
};

const EnhancedKpiCard: React.FC<EnhancedKpiCardProps> = ({
  label,
  icon,
  iconColor,
  value,
  trend,
  meta,
  accent = 'neutral',
  onClick
}) => {
  const isDanger = accent === 'danger';
  const baseClass = [
    'group text-left p-3.5 sm:p-4 rounded-xl border flex flex-col justify-between transition-all w-full select-none',
    isDanger
      ? 'border-rose-500/25 dark:border-rose-900/40 bg-rose-500/[0.03] dark:bg-rose-950/15'
      : 'border-zinc-200/80 dark:border-zinc-800/90 bg-white dark:bg-[#0c0c0e] hover:border-zinc-300 dark:hover:border-zinc-700/80',
    onClick ? 'cursor-pointer hover:shadow-sm' : ''
  ].join(' ');

  const content = (
    <div className="flex flex-col justify-between h-full min-h-[118px]">
      {/* Top row: Label + Status Dot/Icon */}
      <div className="flex items-center justify-between gap-2">
        <span className="text-[11px] font-mono uppercase tracking-wider text-zinc-500 dark:text-zinc-400 font-semibold truncate">
          {label}
        </span>
        <span className={`shrink-0 opacity-80 group-hover:opacity-100 transition-opacity ${iconColors[iconColor]}`}>
          {icon}
        </span>
      </div>

      {/* Middle row: Big Metric Value */}
      <div className="my-1.5 min-w-0">
        <div className={`text-2xl sm:text-[28px] font-bold font-mono tracking-tight leading-none ${isDanger ? 'text-rose-600 dark:text-rose-400' : 'text-zinc-900 dark:text-zinc-100'}`}>
          {value}
        </div>
      </div>

      {/* Bottom row: Trend badge + Meta info */}
      <div className="flex items-center justify-between gap-2 pt-2 border-t border-zinc-100 dark:border-zinc-800/70 text-[11px] font-mono">
        {trend ? (
          <div className="flex items-center gap-1.5 shrink-0">
            <span className={`font-semibold ${trend.positive ? 'text-emerald-500' : 'text-rose-500'}`}>
              {trend.value}
            </span>
            <span className="text-zinc-400 dark:text-zinc-500 text-[10px]">
              {trend.label}
            </span>
          </div>
        ) : (
          <span className="text-zinc-400 dark:text-zinc-500 text-[10px]">—</span>
        )}
        <span className="text-zinc-400 dark:text-zinc-500 text-[11px] truncate max-w-[50%] text-right font-sans">
          {meta}
        </span>
      </div>
    </div>
  );

  if (onClick) {
    return <button type="button" onClick={onClick} className={baseClass}>{content}</button>;
  }
  return <div className={baseClass}>{content}</div>;
};

// ---------------------------------------------------------------------------
// Core defense engine health — cards + inspector popup
// ---------------------------------------------------------------------------
interface EngineMeta {
  icon: any;
  descriptor: string;
  derivation: string;
  logs?: { kind: 'events'; source: string } | { kind: 'logs' };
}

const DEFAULT_ENGINE_META: EngineMeta = {
  icon: faMicrochip,
  descriptor: 'Custom engine',
  derivation: 'Status reported directly by the health probe.'
};

const ENGINE_META: Record<string, EngineMeta> = {
  'WAF Engine': {
    icon: faShieldHalved,
    descriptor: 'Layer 7 inspection',
    derivation: 'Derived from the freshness of the newest source = waf security event.',
    logs: { kind: 'events', source: 'waf' }
  },
  'Next-Gen Firewall': {
    icon: faShieldVirus,
    descriptor: 'L3/L4 packet filter',
    derivation: 'Derived from the freshness of the newest source = firewall security event.',
    logs: { kind: 'events', source: 'firewall' }
  },
  'Endpoint Detection': {
    icon: faEye,
    descriptor: 'Endpoint agent telemetry',
    derivation: 'Derived from enrolled endpoint agent heartbeats and agent security events.',
    logs: { kind: 'events', source: 'agent' }
  },
  'Database Vault': {
    icon: faDatabase,
    descriptor: 'Data access control',
    derivation: 'Derived from a live read probe against the MySQL 8 store.'
  },
  'API Gateway': {
    icon: faServer,
    descriptor: 'API edge service',
    derivation: 'Healthy by construction — the API answered the latest health probe.'
  },
  'SIEM Monitor': {
    icon: faMicrochip,
    descriptor: 'Centralized log pipeline',
    derivation: 'Derived from the freshness of the newest centralized log record.',
    logs: { kind: 'logs' }
  },
  'WebSocket Stream': {
    icon: faBolt,
    descriptor: 'Realtime event channel',
    derivation: 'Derived from the live realtime server state and connected consoles.'
  },
  'Threat Intel': {
    icon: faGlobe,
    descriptor: 'Reputation feed lookups',
    derivation: 'Derived from reputation provider configuration (THREAT_INTEL_API_KEY).'
  }
};

type EngineTone = 'emerald' | 'amber' | 'rose';

const statusTone = (status: string): EngineTone =>
  status === 'Operational' ? 'emerald' : status === 'Degraded' ? 'amber' : 'rose';

const toneAccentBar: Record<EngineTone, string> = {
  emerald: 'bg-emerald-500',
  amber: 'bg-amber-500',
  rose: 'bg-rose-500'
};

const toneValueText: Record<EngineTone, string> = {
  emerald: 'text-emerald-600 dark:text-emerald-400',
  amber: 'text-amber-600 dark:text-amber-400',
  rose: 'text-rose-600 dark:text-rose-400'
};

const toneDot: Record<EngineTone, string> = {
  emerald: 'bg-emerald-500',
  amber: 'bg-amber-500',
  rose: 'bg-rose-500'
};

/** Condense the server-provided health detail into a scannable card readout. */
function parseEngineReadout(row: ServiceHealthRow): { value: string; caption: string } {
  if (row.latency_ms !== null && row.latency_ms !== undefined) {
    return { value: `${row.latency_ms.toFixed(1)} ms`, caption: 'Latency' };
  }
  const details = row.details || '';
  const eventAge = details.match(/last event (\d+[smhd]) ago/);
  if (eventAge) return { value: eventAge[1], caption: 'Last event' };
  const consoles = details.match(/(\d+) console/);
  if (consoles) return { value: consoles[1], caption: 'Consoles' };
  if (/no consoles? connected/i.test(details)) return { value: '0', caption: 'Consoles' };
  // Signal readouts use normal-case words so an offline engine reads clearly
  // ("Offline"), not as a loud display string.
  if (row.status === 'Operational') return { value: 'Ready', caption: 'Signal' };
  if (row.status === 'Degraded') return { value: 'Stale', caption: 'Signal' };
  return { value: 'Offline', caption: 'Signal' };
}

const LOG_LEVEL_STYLES: Record<string, string> = {
  CRITICAL: 'bg-rose-100 dark:bg-rose-950/50 text-rose-700 dark:text-rose-300 border-rose-200 dark:border-rose-900/40',
  ERROR: 'bg-rose-100 dark:bg-rose-950/50 text-rose-700 dark:text-rose-300 border-rose-200 dark:border-rose-900/40',
  WARN: 'bg-amber-100 dark:bg-amber-950/50 text-amber-700 dark:text-amber-300 border-amber-200 dark:border-amber-900/40',
  INFO: 'bg-blue-100 dark:bg-blue-950/50 text-blue-700 dark:text-blue-300 border-blue-200 dark:border-blue-900/40',
  DEBUG: 'bg-zinc-100 dark:bg-zinc-800 text-zinc-600 dark:text-zinc-400 border-zinc-200 dark:border-zinc-700'
};

const engineStatusPill = (tone: EngineTone, status: string) => (
  <span className={`inline-flex items-center gap-1.5 px-2 py-0.5 rounded-full text-[10px] font-semibold border ${statusColors[tone]}`}>
    <span className={`w-1.5 h-1.5 rounded-full ${toneDot[tone]}`} />
    {status}
  </span>
);

interface EngineCardProps {
  row: ServiceHealthRow;
  onClick: () => void;
}

const EngineCard: React.FC<EngineCardProps> = ({ row, onClick }) => {
  const meta = ENGINE_META[row.service_name] || DEFAULT_ENGINE_META;
  const tone = statusTone(row.status);
  const readout = parseEngineReadout(row);

  return (
    <button
      type="button"
      onClick={onClick}
      title={`Inspect ${row.service_name} telemetry`}
      className="relative group text-left p-4 pl-5 rounded-xl border min-h-[144px] flex flex-col justify-between transition-all w-full shadow-2xs cursor-pointer border-zinc-200/80 dark:border-zinc-800 bg-white dark:bg-zinc-900/40 hover:bg-zinc-50/80 dark:hover:bg-zinc-800/60 hover:border-zinc-300 dark:hover:border-zinc-700 hover:shadow-xs"
    >
      <span className={`absolute left-0 top-3.5 bottom-3.5 w-1 rounded-r-full transition-colors ${toneAccentBar[tone]}`} />

      <div className="flex items-start justify-between gap-2 mb-2">
        <span className="text-[11px] font-semibold tracking-wider text-zinc-500 dark:text-zinc-400 uppercase leading-tight">
          {row.service_name}
        </span>
        <span className={`shrink-0 transition-colors ${iconColors[tone]}`}>
          <FontAwesomeIcon icon={meta.icon} className="text-base" />
        </span>
      </div>

      <div className="min-w-0 mb-2">
        {readout.caption === 'Signal' ? (
          // No metric signal — keep the word calm and normal-case; the tone
          // color plus the status pill below already carry the urgency.
          <div className={`text-base font-semibold tracking-tight ${toneValueText[tone]}`}>{readout.value}</div>
        ) : (
          <div className={`text-xl font-bold font-mono tracking-tight ${toneValueText[tone]}`}>{readout.value}</div>
        )}
        <div className="text-[10px] font-mono uppercase tracking-wider text-zinc-400 dark:text-zinc-500 mt-0.5">
          {readout.caption}
        </div>
      </div>

      <div className="flex items-center justify-between gap-2">
        {engineStatusPill(tone, row.status)}
        <span className="relative flex items-center justify-end text-[10px] font-mono min-w-0 max-w-[52%]">
          <span className="truncate text-zinc-400 dark:text-zinc-500 transition-opacity group-hover:opacity-0">
            {meta.descriptor}
          </span>
          <span className="absolute right-0 whitespace-nowrap font-semibold text-blue-600 dark:text-blue-400 opacity-0 group-hover:opacity-100 transition-opacity">
            Inspect logs →
          </span>
        </span>
      </div>
    </button>
  );
};

interface EngineInspectorDrawerProps {
  row: ServiceHealthRow;
  onClose: () => void;
}

const EngineInspectorDrawer: React.FC<EngineInspectorDrawerProps> = ({ row, onClose }) => {
  const meta = ENGINE_META[row.service_name] || DEFAULT_ENGINE_META;
  const tone = statusTone(row.status);
  const readout = parseEngineReadout(row);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [records, setRecords] = useState<any[]>([]);

  // Mobile-only swipe-to-dismiss
  const [swipeTranslateX, setSwipeTranslateX] = useState(0);
  const [isSwiping, setIsSwiping] = useState(false);
  const touchStartRef = React.useRef<{ x: number; y: number; time: number } | null>(null);

  const handleDrawerTouchStart = (e: React.TouchEvent) => {
    if (typeof window !== 'undefined' && window.innerWidth >= 640) return;
    const t = e.touches[0];
    touchStartRef.current = { x: t.clientX, y: t.clientY, time: Date.now() };
    setIsSwiping(false);
  };

  const handleDrawerTouchMove = (e: React.TouchEvent) => {
    if (!touchStartRef.current || (typeof window !== 'undefined' && window.innerWidth >= 640)) return;
    const t = e.touches[0];
    const dx = t.clientX - touchStartRef.current.x;
    const dy = t.clientY - touchStartRef.current.y;
    if (dx > 8 && dx > Math.abs(dy) * 1.1) {
      setIsSwiping(true);
      setSwipeTranslateX(Math.max(0, dx));
    } else if (dx <= 0 && isSwiping) {
      setSwipeTranslateX(0);
    }
  };

  const handleDrawerTouchEnd = () => {
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
        onClose();
        setSwipeTranslateX(0);
        setIsSwiping(false);
      }, 150);
    } else {
      setIsSwiping(false);
      setSwipeTranslateX(0);
    }
    touchStartRef.current = null;
  };

  useEffect(() => {
    let cancelled = false;
    setLoading(true);
    setError(null);
    setRecords([]);

    const load = async () => {
      if (!meta.logs) {
        if (!cancelled) setLoading(false);
        return;
      }
      try {
        if (meta.logs.kind === 'events') {
          const res: any = await securityApi.getSecurityEvents({ source: meta.logs.source, limit: 15, page: 1 });
          if (!cancelled) setRecords(res.events || []);
        } else {
          const res: any = await securityApi.getLogs({ limit: 15, page: 1 });
          if (!cancelled) setRecords(res.logs || []);
        }
      } catch (err: any) {
        if (!cancelled) setError(err?.message || 'Failed to load telemetry');
      } finally {
        if (!cancelled) setLoading(false);
      }
    };

    load();
    return () => {
      cancelled = true;
    };
  }, [row.service_name]);

  // Close on ESC — the inspector has no dedicated close control.
  useEffect(() => {
    const handleKeyDown = (e: KeyboardEvent) => {
      if (e.key === 'Escape') {
        e.preventDefault();
        onClose();
      }
    };
    window.addEventListener('keydown', handleKeyDown);
    return () => window.removeEventListener('keydown', handleKeyDown);
  }, [onClose]);

  const logTitle = meta.logs?.kind === 'events'
    ? `Recent telemetry · ${meta.logs.source} events`
    : meta.logs?.kind === 'logs'
      ? 'Recent telemetry · centralized log records'
      : 'Telemetry stream';

  const signalLabel = meta.logs
    ? meta.logs.kind === 'events'
      ? `security_events · ${meta.logs.source}`
      : 'logs · pipeline'
    : 'live probe';

  return (
    <div className="fixed inset-0 z-50">
      {/* Dimmed backdrop — clicking anywhere outside the panel closes the inspector. */}
      <div
        className="absolute inset-0 bg-zinc-950/45 dark:bg-black/70 backdrop-blur-[2px] animate-in fade-in-0 duration-200 transition-opacity"
        style={{ opacity: swipeTranslateX > 0 ? Math.max(0.1, 1 - swipeTranslateX / 300) : undefined }}
        onClick={onClose}
      />

      <aside
        role="dialog"
        aria-modal="true"
        aria-label={`${row.service_name} engine inspector`}
        onTouchStart={handleDrawerTouchStart}
        onTouchMove={handleDrawerTouchMove}
        onTouchEnd={handleDrawerTouchEnd}
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
        <div className={`h-0.5 w-full shrink-0 ${toneAccentBar[tone]}`} />

        {/* Drawer header */}
        <header className="shrink-0 border-b border-zinc-200/80 bg-white px-5 pb-4 pt-3.5 dark:border-zinc-800 dark:bg-[#0b0b0d] sm:px-6">
          <div className="flex min-w-0 items-center gap-1.5 font-mono text-[10px] uppercase tracking-[0.16em] text-zinc-400 dark:text-zinc-500">
            <span className="shrink-0">Core Defense Engine</span>
            <span className="shrink-0 text-zinc-300 dark:text-zinc-700">/</span>
            <span className="truncate font-sans text-[11px] font-medium normal-case tracking-normal text-zinc-500 dark:text-zinc-400">
              {row.service_name}
            </span>
          </div>

          <div className="mt-3 flex items-start gap-3">
            <span className={`flex h-11 w-11 shrink-0 items-center justify-center rounded-xl border border-zinc-200/80 bg-zinc-50 dark:border-zinc-800 dark:bg-zinc-900/60 ${iconColors[tone]}`}>
              <FontAwesomeIcon icon={meta.icon} className="text-lg" />
            </span>
            <div className="min-w-0 flex-1">
              <div className="flex flex-wrap items-center gap-2">
                <h2 className="truncate text-base font-semibold tracking-tight text-zinc-900 dark:text-zinc-100">
                  {row.service_name}
                </h2>
                {engineStatusPill(tone, row.status)}
              </div>
              <p className="mt-0.5 truncate text-[11px] text-zinc-500 dark:text-zinc-400">{meta.descriptor}</p>
            </div>
          </div>

          <div className="mt-3 flex flex-wrap items-center gap-x-4 gap-y-1 font-mono text-[10px] uppercase tracking-wider text-zinc-400 dark:text-zinc-500">
            <span>Probe · 30s interval</span>
            <span>Last check · {row.last_check ? formatDateTime(row.last_check) : '—'}</span>
            <span>Signal · {signalLabel}</span>
          </div>
        </header>

        {/* Scrollable body */}
        <div className="flex-1 space-y-5 overflow-y-auto px-5 py-5 text-xs sm:px-6">
          {/* Snapshot */}
          <section>
            <div className="mb-2 text-[10px] font-bold uppercase tracking-[0.14em] text-zinc-400 dark:text-zinc-500">Snapshot</div>
            <div className="grid grid-cols-2 gap-2.5 sm:grid-cols-4">
              <div className="rounded-xl border border-zinc-200/80 bg-zinc-50/60 p-3 dark:border-zinc-800 dark:bg-zinc-900/40">
                <div className="font-mono text-[10px] uppercase tracking-wider text-zinc-400 dark:text-zinc-500">Status</div>
                <div className="mt-1.5">{engineStatusPill(tone, row.status)}</div>
              </div>
              <div className="rounded-xl border border-zinc-200/80 bg-zinc-50/60 p-3 dark:border-zinc-800 dark:bg-zinc-900/40">
                <div className="font-mono text-[10px] uppercase tracking-wider text-zinc-400 dark:text-zinc-500">{readout.caption}</div>
                <div className="mt-1.5 font-mono font-semibold text-zinc-800 dark:text-zinc-200">{readout.value}</div>
              </div>
              <div className="rounded-xl border border-zinc-200/80 bg-zinc-50/60 p-3 dark:border-zinc-800 dark:bg-zinc-900/40">
                <div className="font-mono text-[10px] uppercase tracking-wider text-zinc-400 dark:text-zinc-500">Last Check</div>
                <div className="mt-1.5 font-mono text-zinc-700 dark:text-zinc-300">{row.last_check ? formatDateTime(row.last_check) : '—'}</div>
              </div>
              <div className="rounded-xl border border-zinc-200/80 bg-zinc-50/60 p-3 dark:border-zinc-800 dark:bg-zinc-900/40">
                <div className="font-mono text-[10px] uppercase tracking-wider text-zinc-400 dark:text-zinc-500">Signal</div>
                <div className="mt-1.5 truncate font-mono text-zinc-700 dark:text-zinc-300">{signalLabel}</div>
              </div>
            </div>
          </section>

          {/* Health derivation */}
          <section>
            <div className="mb-2 text-[10px] font-bold uppercase tracking-[0.14em] text-zinc-400 dark:text-zinc-500">Health derivation</div>
            <dl className="overflow-hidden rounded-xl border border-zinc-200/80 bg-white dark:border-zinc-800 dark:bg-zinc-900/20">
              <div className="grid grid-cols-[112px_1fr] gap-3 border-b border-zinc-100 px-3.5 py-2.5 dark:border-zinc-800/70 sm:grid-cols-[136px_1fr]">
                <dt className="font-mono text-[10px] uppercase tracking-wider text-zinc-400 dark:text-zinc-500">Reported detail</dt>
                <dd className="break-words font-mono text-[11px] text-zinc-700 dark:text-zinc-300">{row.details || 'No detail reported'}</dd>
              </div>
              <div className="grid grid-cols-[112px_1fr] gap-3 px-3.5 py-2.5 sm:grid-cols-[136px_1fr]">
                <dt className="font-mono text-[10px] uppercase tracking-wider text-zinc-400 dark:text-zinc-500">Derivation</dt>
                <dd className="text-[11px] leading-relaxed text-zinc-500 dark:text-zinc-400">{meta.derivation}</dd>
              </div>
            </dl>
          </section>

          {/* Telemetry inspector */}
          <section>
            <div className="mb-2 flex items-center justify-between gap-3">
              <div className="text-[10px] font-bold uppercase tracking-[0.14em] text-zinc-400 dark:text-zinc-500">{logTitle}</div>
              {!loading && !error && meta.logs && (
                <span className="rounded-full border border-zinc-200 bg-zinc-50 px-2 py-0.5 font-mono text-[10px] text-zinc-500 dark:border-zinc-800 dark:bg-zinc-900 dark:text-zinc-400">{records.length} records</span>
              )}
            </div>

            {!meta.logs ? (
              <div className="p-4 rounded-xl border border-dashed border-zinc-200 dark:border-zinc-800 text-[11px] font-mono text-zinc-400 dark:text-zinc-500 text-center">
                No dedicated log stream — this engine reports health through live probes only.
              </div>
            ) : loading ? (
              <div className="p-6 flex flex-col items-center justify-center text-center">
                <FontAwesomeIcon icon={faRotateRight} className="text-sm text-zinc-400 animate-spin mb-2" />
                <div className="text-[11px] font-mono text-zinc-400">Fetching latest telemetry…</div>
              </div>
            ) : error ? (
              <div className="p-4 rounded-xl border border-rose-200 dark:border-rose-900/40 bg-rose-50/40 dark:bg-rose-950/20 text-[11px] font-mono text-rose-600 dark:text-rose-400 text-center">
                {error}
              </div>
            ) : records.length === 0 ? (
              <div className="p-4 rounded-xl border border-dashed border-zinc-200 dark:border-zinc-800 text-[11px] font-mono text-zinc-400 dark:text-zinc-500 text-center">
                No telemetry recorded for this engine in the current window.
              </div>
            ) : (
              <div className="rounded-xl border border-zinc-200/80 dark:border-zinc-800 overflow-hidden bg-white dark:bg-zinc-900/20">
                <div className="max-h-[340px] overflow-y-auto divide-y divide-zinc-100 dark:divide-zinc-800/60">
                  {meta.logs.kind === 'events'
                    ? records.map((record: any) => (
                        <div
                          key={record.id}
                          className="px-3 py-2 flex items-center gap-2.5 text-[11px] hover:bg-zinc-50/80 dark:hover:bg-zinc-800/40 transition"
                        >
                          <span className="font-mono text-zinc-400 dark:text-zinc-500 shrink-0">{formatTime(record.timestamp)}</span>
                          <span className="font-medium text-zinc-700 dark:text-zinc-200 truncate flex-1 min-w-0">
                            {record.threat || record.threatName || 'Security event'}
                          </span>
                          <StatusBadge type="severity" value={record.severity} />
                          <StatusBadge type="action" value={record.action} />
                          <span className="font-mono text-zinc-400 dark:text-zinc-500 shrink-0 hidden md:block">{record.sourceIp}</span>
                        </div>
                      ))
                    : records.map((record: any) => (
                        <div
                          key={record.id}
                          className="px-3 py-2 flex items-center gap-2.5 text-[11px] hover:bg-zinc-50/80 dark:hover:bg-zinc-800/40 transition"
                        >
                          <span className="font-mono text-zinc-400 dark:text-zinc-500 shrink-0">{formatTime(record.timestamp)}</span>
                          <span
                            className={`inline-flex items-center px-1.5 py-0.5 rounded border text-[10px] font-mono font-semibold shrink-0 ${
                              LOG_LEVEL_STYLES[(record.level || 'INFO').toUpperCase()] || LOG_LEVEL_STYLES.DEBUG
                            }`}
                          >
                            {(record.level || 'INFO').toUpperCase()}
                          </span>
                          <span className="text-zinc-700 dark:text-zinc-200 truncate flex-1 min-w-0">{record.message}</span>
                          <span className="font-mono text-zinc-400 dark:text-zinc-500 shrink-0 hidden md:block">{record.source}</span>
                        </div>
                      ))}
                </div>
              </div>
            )}
          </section>
        </div>

        {/* Drawer footer */}
        <footer className="shrink-0 border-t border-zinc-200/80 bg-zinc-50/60 px-5 py-3 dark:border-zinc-800 dark:bg-zinc-900/30 sm:px-6">
          <div className="flex flex-wrap items-center justify-between gap-2 font-mono text-[10px] uppercase tracking-wider text-zinc-400 dark:text-zinc-500">
            <span>Snapshot at open</span>
            <span className="normal-case tracking-normal">Core Defense · {row.service_name}</span>
          </div>
        </footer>
      </aside>
    </div>
  );
};

export const DashboardOverview: React.FC<DashboardOverviewProps> = ({ onNavigate }) => {
  const { currentOrg, organizations, isBackendOffline } = useAuth();
  const liveState = useLiveConnectionState();
  const [error, setError] = useState<string | null>(null);
  const [data, setData] = useState<any>(null);
  const [healthServices, setHealthServices] = useState<ServiceHealthRow[]>([]);
  const [healthLoaded, setHealthLoaded] = useState(false);
  const [healthFilter, setHealthFilter] = useState<HealthFilter>('All');
  const [healthMenuOpen, setHealthMenuOpen] = useState(false);
  const [selectedEngine, setSelectedEngine] = useState<ServiceHealthRow | null>(null);

  // Live Activity Log stream state
  const [activityEvents, setActivityEvents] = useState<SecurityEvent[]>([]);
  const [activityLoading, setActivityLoading] = useState(false);
  const [activityTotal, setActivityTotal] = useState(0);
  const [activityPage, setActivityPage] = useState(1);
  const [activityPageSize, setActivityPageSize] = useState(10);
  const [activitySearch, setActivitySearch] = useState('');
  const [activitySearchTerm, setActivitySearchTerm] = useState('');
  const [activityFilterAction, setActivityFilterAction] = useState<ActionFilterValue>('ALL');
  const [activityFilterSeverity, setActivityFilterSeverity] = useState<SeverityFilterValue>('ALL');
  const [showActionDropdown, setShowActionDropdown] = useState(false);
  const [showSeverityDropdown, setShowSeverityDropdown] = useState(false);
  const [selectedEvent, setSelectedEvent] = useState<SecurityEvent | null>(null);

  // Ingress Traffic Recap series toggles — clicking a legend chip includes /
  // excludes that series from the recap table (excluded series reads "—").
  type TrafficDisplayMode = 'chart' | 'table';
  const [trafficDisplayMode, setTrafficDisplayMode] = useState<TrafficDisplayMode>('chart');
  const [trafficModeDropdownOpen, setTrafficModeDropdownOpen] = useState(false);
  const [hoveredPointIndex, setHoveredPointIndex] = useState<number | null>(null);
  const trafficModeRef = useRef<HTMLDivElement>(null);

  useEffect(() => {
    const handleOutside = (e: MouseEvent) => {
      if (trafficModeRef.current && !trafficModeRef.current.contains(e.target as Node)) {
        setTrafficModeDropdownOpen(false);
      }
    };
    document.addEventListener('mousedown', handleOutside);
    return () => document.removeEventListener('mousedown', handleOutside);
  }, []);

  type TrafficSeriesKey = 'allowed' | 'blocked' | 'suspicious';
  const [hiddenSeries, setHiddenSeries] = useState<Record<TrafficSeriesKey, boolean>>({
    allowed: false,
    blocked: false,
    suspicious: false
  });
  const toggleTrafficSeries = (key: TrafficSeriesKey) =>
    setHiddenSeries(prev => ({ ...prev, [key]: !prev[key] }));

  // Aggregated action/severity counts for filter dropdowns
  const [activityAggregateActions, setActivityAggregateActions] = useState<{ blocked: number; allowed: number; challenged: number; logged: number; other: number; total: number } | null>(null);
  const [activityAggregateSeverities, setActivityAggregateSeverities] = useState<{ critical: number; high: number; medium: number; low: number } | null>(null);
  const [countryTrafficData, setCountryTrafficData] = useState<CountryTrafficData[]>([]);

  // Mobile swipe gesture for Event Details drawer
  const eventTouchStartRef = useRef<{ x: number; y: number; time: number } | null>(null);
  const [eventSwipeX, setEventSwipeX] = useState<number>(0);
  const [isEventSwiping, setIsEventSwiping] = useState<boolean>(false);

  const handleEventTouchStart = (e: React.TouchEvent) => {
    if (typeof window !== 'undefined' && window.innerWidth >= 640) return;
    eventTouchStartRef.current = {
      x: e.touches[0].clientX,
      y: e.touches[0].clientY,
      time: Date.now()
    };
    setIsEventSwiping(false);
  };

  const handleEventTouchMove = (e: React.TouchEvent) => {
    if (!eventTouchStartRef.current || (typeof window !== 'undefined' && window.innerWidth >= 640)) return;
    const touch = e.touches[0];
    const deltaX = touch.clientX - eventTouchStartRef.current.x;
    const deltaY = touch.clientY - eventTouchStartRef.current.y;

    if (deltaX > 8 && deltaX > Math.abs(deltaY) * 1.1) {
      setIsEventSwiping(true);
      setEventSwipeX(Math.max(0, deltaX));
    } else if (deltaX <= 0 && isEventSwiping) {
      setEventSwipeX(0);
    }
  };

  const handleEventTouchEnd = () => {
    if (!eventTouchStartRef.current || (typeof window !== 'undefined' && window.innerWidth >= 640)) {
      eventTouchStartRef.current = null;
      setIsEventSwiping(false);
      setEventSwipeX(0);
      return;
    }

    const elapsed = Date.now() - eventTouchStartRef.current.time;
    const shouldDismiss = eventSwipeX > 80 || (eventSwipeX > 40 && elapsed < 250);

    if (shouldDismiss) {
      setEventSwipeX(window.innerWidth || 400);
      setTimeout(() => {
        setSelectedEvent(null);
        setEventSwipeX(0);
        setIsEventSwiping(false);
      }, 150);
    } else {
      setIsEventSwiping(false);
      setEventSwipeX(0);
    }
    eventTouchStartRef.current = null;
  };

  // Wait until typing pauses before querying events
  useEffect(() => {
    const timer = window.setTimeout(() => {
      setActivitySearchTerm(activitySearch.trim());
      setActivityPage(1);
    }, 300);
    return () => window.clearTimeout(timer);
  }, [activitySearch]);

  // Load events from database for the active page, filters, and page size
  useEffect(() => {
    let isMounted = true;
    async function loadEvents() {
      if (isBackendOffline) return;
      try {
        const res = await securityApi.getSecurityEvents({
          limit: activityPageSize,
          page: activityPage,
          action: activityFilterAction === 'ALL' ? undefined : activityFilterAction,
          severity: activityFilterSeverity === 'ALL' ? undefined : activityFilterSeverity,
          search: activitySearchTerm || undefined
        });
        if (isMounted) {
          if (res.events) {
            setActivityEvents(res.events);
          }
          if (typeof res.total === 'number') {
            setActivityTotal(res.total);
          }
        }
      } catch (err) {
        console.error('[DashboardOverview] Events fetch failed:', err);
      } finally {
        if (isMounted) setActivityLoading(false);
      }
    }
    setActivityLoading(true);
    loadEvents();
    // Auto-sync polling every 5s so fresh traffic updates even if stream briefly reconects
    const timer = window.setInterval(loadEvents, 5000);
    return () => { isMounted = false; window.clearInterval(timer); };
  }, [isBackendOffline, activityPage, activityPageSize, activityFilterAction, activityFilterSeverity, activitySearchTerm]);

  // Load aggregate counts for the filter dropdowns
  useEffect(() => {
    let isMounted = true;
    async function loadAggregates() {
      if (isBackendOffline) return;
      try {
        const res = await securityApi.getSecurityEventsAggregates({ limit: 10 });
        if (isMounted) {
          setActivityAggregateActions(res.actions || null);
          setActivityAggregateSeverities(res.severities || null);
          setCountryTrafficData(res.topCountries || []);
        }
      } catch (err) {
        console.error('[DashboardOverview] Aggregates fetch failed:', err);
      }
    }
    loadAggregates();
    const timer = window.setInterval(loadAggregates, 60000);
    return () => { isMounted = false; window.clearInterval(timer); };
  }, [isBackendOffline]);

  const fetchData = async (isBackground = false) => {
    setError(null);
    try {
      const res = await securityApi.getDashboard();
      setData(res);
      if (!isBackground && res?.recentEvents && activityEvents.length === 0) {
        setActivityEvents(res.recentEvents.slice(0, activityPageSize));
        setActivityTotal(res.recentEvents.length);
      }
    } catch (err: any) {
      setError(err?.message || 'Failed to load security telemetry');
    }
  };

  useEffect(() => {
    fetchData();
    if (isBackendOffline) return;
    // Auto sync dashboard data in background so full computed stats remain fresh
    const timer = setInterval(() => {
      fetchData(true);
    }, 5000);
    return () => clearInterval(timer);
  }, [currentOrg?.id, isBackendOffline]);

  // Load aggregate counts for the filter dropdowns and country traffic
  useEffect(() => {
    let isMounted = true;
    async function loadAggregates() {
      if (isBackendOffline) return;
      try {
        const res = await securityApi.getSecurityEventsAggregates({ limit: 10 });
        if (isMounted) {
          setActivityAggregateActions(res.actions || null);
          setActivityAggregateSeverities(res.severities || null);
          setCountryTrafficData(res.topCountries || []);
        }
      } catch (err) {
        console.error('[DashboardOverview] Aggregates fetch failed:', err);
      }
    }
    loadAggregates();
    const timer = window.setInterval(loadAggregates, 5000);
    return () => { isMounted = false; window.clearInterval(timer); };
  }, [isBackendOffline]);

  // Real-time telemetry WebSocket stream subscription
  useEffect(() => {
    if (isBackendOffline) return;
    const unsub = telemetryStreamManager.subscribe(
      (msg: any) => {
        // Direct handling for alert / threat messages that update KPI counts
        if (msg?.type === 'threat.created' || msg?.type === 'incident.created') {
          setData((prev: any) => {
            if (!prev) return prev;
            return {
              ...prev,
              metrics: {
                ...prev.metrics,
                activeThreats: (prev.metrics?.activeThreats ?? 0) + 1,
                criticalAlerts: (prev.metrics?.criticalAlerts ?? 0) + (msg?.data?.severity === 'Critical' || msg?.data?.severity === 'critical' ? 1 : 0)
              }
            };
          });
        }

        const evt = normalizeRealtimeSecurityEvent(msg);
        if (!evt) return;

        // Auto-increment activity log total count live
        setActivityTotal(prev => prev + 1);

        // Real-time feed injection for activity log
        const matchesAction = activityFilterAction === 'ALL' || actionGroupOf(evt.action) === activityFilterAction;
        const matchesSev = activityFilterSeverity === 'ALL' || String(evt.severity || '').toLowerCase() === activityFilterSeverity.toLowerCase();
        const term = activitySearchTerm.toLowerCase();
        const matchesSearch = !term || [evt.sourceIp, evt.application, evt.threat].some(val => String(val || '').toLowerCase().includes(term));

        if (matchesAction && matchesSev && matchesSearch) {
          if (activityPage === 1) {
            setActivityEvents(prev => {
              if (prev.some(e => e.id === evt.id)) return prev;
              return [evt, ...prev.slice(0, activityPageSize - 1)];
            });
          }
        }

        const actionUpper = (evt.action || '').toUpperCase();
        const isBlocked = ['BLOCK', 'BLOCKED', 'DENY', 'DROP', 'CHALLENGE'].includes(actionUpper);
        const isAllowedAction = ['ALLOW', 'ALLOWED', 'LOG'].includes(actionUpper);
        const isBlockedAction = ['BLOCK', 'BLOCKED', 'DENY', 'DROP'].includes(actionUpper);
        const isSuspiciousAction = ['CHALLENGE', 'RATE_LIMIT'].includes(actionUpper);

        // Update real-time aggregate actions for filters and status
        setActivityAggregateActions(prev => {
          if (!prev) return prev;
          return {
            total: (prev.total || 0) + 1,
            allowed: (prev.allowed || 0) + (isAllowedAction ? 1 : 0),
            blocked: (prev.blocked || 0) + (isBlockedAction ? 1 : 0),
            challenged: (prev.challenged || 0) + (isSuspiciousAction ? 1 : 0),
            logged: (prev.logged || 0) + (actionUpper === 'LOG' ? 1 : 0),
            other: (prev.other || 0) + (!isAllowedAction && !isBlockedAction && !isSuspiciousAction ? 1 : 0)
          };
        });

        // Update real-time aggregate severities
        if (evt.severity) {
          const sevKey = String(evt.severity).toLowerCase();
          setActivityAggregateSeverities(prev => {
            if (!prev) return prev;
            return {
              critical: (prev.critical || 0) + (sevKey === 'critical' ? 1 : 0),
              high: (prev.high || 0) + (sevKey === 'high' ? 1 : 0),
              medium: (prev.medium || 0) + (sevKey === 'medium' ? 1 : 0),
              low: (prev.low || 0) + (sevKey === 'low' ? 1 : 0)
            };
          });
        }

        // Update live country traffic data
        const countryCode = (evt.sourceCountryCode || '').toUpperCase().trim();
        const countryName = evt.sourceCountry || (countryCode === 'ID' || countryCode === 'SYS' || countryCode === 'LAN' ? 'Indonesia' : countryCode);
        if (countryCode && countryCode !== 'UN') {
          const resolvedCode = (countryCode === 'SYS' || countryCode === 'LAN') ? 'ID' : countryCode;
          setCountryTrafficData(prev => {
            const list = Array.isArray(prev) ? [...prev] : [];
            const idx = list.findIndex(c => (c.code || '').toUpperCase() === resolvedCode);
            if (idx >= 0) {
              list[idx] = {
                ...list[idx],
                count: (list[idx].count || 0) + 1,
                lastAttackIp: evt.sourceIp || list[idx].lastAttackIp,
                lastAttackType: evt.threat || evt.threatName || evt.eventType || list[idx].lastAttackType,
                lastAttackTime: Date.now()
              };
            } else {
              list.push({
                code: resolvedCode,
                country: countryName,
                count: 1,
                lastAttackIp: evt.sourceIp,
                lastAttackType: evt.threat || evt.threatName || evt.eventType,
                lastAttackTime: Date.now()
              });
            }
            return list.sort((a, b) => b.count - a.count);
          });
        }

        setData((prev: any) => {
          if (!prev) return prev;
          const newEvents = [evt, ...(prev.recentEvents || []).slice(0, 19)];

          // Mirror the recap query in real time: bump the current minute bucket so
          // the top row of the per-minute recap ticks as packets stream in.
          const parsedTime = evt.timestamp ? new Date(evt.timestamp) : new Date();
          const eventTime = Number.isNaN(parsedTime.getTime()) ? new Date() : parsedTime;
          const minuteLabel = `${String(eventTime.getHours()).padStart(2, '0')}:${String(eventTime.getMinutes()).padStart(2, '0')}`;
          
          // If we were displaying a paused historical snapshot, start a fresh live sequence
          let history: any[] = Array.isArray(prev.trafficHistory) ? prev.trafficHistory : [];
          if (!prev.isLiveTraffic) {
            history = [];
          }

          let minuteFound = false;
          const nextHistory = history.map((row: any) => {
            if ((row.hour ?? row.time) !== minuteLabel) return row;
            minuteFound = true;
            return {
              ...row,
              allowed: (row.allowed || 0) + (isAllowedAction ? 1 : 0),
              blocked: (row.blocked || 0) + (isBlockedAction ? 1 : 0),
              suspicious: (row.suspicious || 0) + (isSuspiciousAction ? 1 : 0)
            };
          });
          if (!minuteFound) {
            nextHistory.push({
              hour: minuteLabel,
              allowed: isAllowedAction ? 1 : 0,
              blocked: isBlockedAction ? 1 : 0,
              suspicious: isSuspiciousAction ? 1 : 0
            });
          }

          const isCriticalSev = String(evt.severity || '').toLowerCase() === 'critical';
          const isThreatEvent = evt.eventType === 'threat' || isCriticalSev || (evt.threat && !evt.threat.includes('Security Event'));

          return {
            ...prev,
            isLiveTraffic: true,
            trafficHistory: nextHistory,
            metrics: {
              ...prev.metrics,
              requestsToday: (prev.metrics?.requestsToday ?? 0) + 1,
              blockedRequests: (prev.metrics?.blockedRequests ?? 0) + (isBlocked ? 1 : 0),
              securityEventsCount: (prev.metrics?.securityEventsCount ?? 0) + 1,
              activeThreats: (prev.metrics?.activeThreats ?? 0) + (isThreatEvent ? 1 : 0),
              criticalAlerts: (prev.metrics?.criticalAlerts ?? 0) + (isCriticalSev ? 1 : 0)
            },
            recentEvents: newEvents
          };
        });
      },
      () => { }
    );
    return () => unsub();
  }, [isBackendOffline, activityFilterAction, activityFilterSeverity, activitySearchTerm, activityPage, activityPageSize]);

  // Core defense engine health — realtime over the /ws stream. The server
  // broadcasts a fresh snapshot every second and immediately after any
  // security/log/agent activity; REST polling remains only as a fallback.
  useEffect(() => {
    if (isBackendOffline) return;
    let cancelled = false;

    const applySnapshot = (services: unknown) => {
      if (cancelled || !Array.isArray(services)) return;
      setHealthServices(services as ServiceHealthRow[]);
      setHealthLoaded(true);
    };

    const loadHealth = async () => {
      try {
        const res = await securityApi.getSystemHealthDetailed();
        if (cancelled) return;
        applySnapshot(res.services || []);
      } catch {
        // Keep last known snapshot
      } finally {
        if (!cancelled) setHealthLoaded(true);
      }
    };

    loadHealth();

    // Instant path: health snapshots arrive via the realtime stream the
    // moment the server computes them — cards update without waiting for
    // any polling interval.
    const unsub = globalRealtimeClient.subscribe((msg: any) => {
      const type = msg?.type || '';
      if (type === 'system.health' || type === 'system.health_changed') {
        applySnapshot(msg?.data?.services ?? msg?.services);
      }
    });

    const timer = setInterval(loadHealth, 30000);
    return () => {
      cancelled = true;
      clearInterval(timer);
      unsub();
    };
  }, [isBackendOffline]);

  const metrics = data?.metrics || {
    protectedAppsCount: 0,
    protectedNetworksCount: 0,
    requestsToday: 0,
    blockedRequests: 0,
    activeThreats: 0,
    criticalAlerts: 0,
    securityEventsCount: 0,
    securityScore: null
  };

  const healthRows = useMemo<ServiceHealthRow[]>(() => {
    const byName = new Map(healthServices.map(s => [s.service_name, s]));
    const roster = HEALTH_ROSTER.map(
      name =>
        byName.get(name) || {
          service_name: name,
          status: 'Offline',
          latency_ms: null,
          last_check: '',
          details: 'Not reporting to the health probe'
        }
    );
    const extras = healthServices.filter(s => !HEALTH_ROSTER.includes(s.service_name));
    return [...roster, ...extras];
  }, [healthServices]);

  const healthSummary = useMemo(
    () => ({
      operational: healthRows.filter(r => r.status === 'Operational').length,
      degraded: healthRows.filter(r => r.status === 'Degraded').length,
      offline: healthRows.filter(r => r.status === 'Offline').length
    }),
    [healthRows]
  );

  const visibleHealthRows = useMemo(
    () => (healthFilter === 'All' ? healthRows : healthRows.filter(r => r.status === healthFilter)),
    [healthRows, healthFilter]
  );

  const healthFilterCounts: Record<HealthFilter, number> = {
    All: healthRows.length,
    Operational: healthSummary.operational,
    Degraded: healthSummary.degraded,
    Offline: healthSummary.offline
  };

  const selectedHealthOption =
    HEALTH_FILTER_OPTIONS.find(option => option.value === healthFilter) || HEALTH_FILTER_OPTIONS[0];

  const threatBreakdown = data?.threatOverview || { critical: 0, high: 0, medium: 0, low: 0 };
  const totalThreats = threatBreakdown.critical + threatBreakdown.high + threatBreakdown.medium + threatBreakdown.low;
  const recentEvents: SecurityEvent[] = data?.recentEvents || [];
  const trafficHistory = data?.trafficHistory || [];

  const actionFilterCounts: Record<ActionFilterValue, number> = {
    ALL: activityAggregateActions?.total ?? (activityTotal || recentEvents.length),
    BLOCKED: activityAggregateActions?.blocked ?? 0,
    ALLOWED: activityAggregateActions?.allowed ?? 0,
    CHALLENGED: activityAggregateActions?.challenged ?? 0,
    LOGGED: activityAggregateActions?.logged ?? 0
  };

  const severityFilterCounts: Record<SeverityFilterValue, number> = {
    ALL: activityAggregateActions?.total ?? (activityTotal || recentEvents.length),
    Critical: activityAggregateSeverities?.critical ?? 0,
    High: activityAggregateSeverities?.high ?? 0,
    Medium: activityAggregateSeverities?.medium ?? 0,
    Low: activityAggregateSeverities?.low ?? 0
  };

  const displayActivityEvents = useMemo(() => {
    let list = activityEvents;
    if (!list || list.length === 0) {
      list = recentEvents;
    }
    if (activityFilterAction !== 'ALL') {
      list = list.filter(e => actionGroupOf(e.action) === activityFilterAction);
    }
    if (activityFilterSeverity !== 'ALL') {
      list = list.filter(e => String(e.severity || '').toLowerCase() === activityFilterSeverity.toLowerCase());
    }
    if (activitySearchTerm) {
      const term = activitySearchTerm.toLowerCase();
      list = list.filter(e => [e.sourceIp, e.application, e.threat].some(val => String(val || '').toLowerCase().includes(term)));
    }

    return list;
  }, [activityEvents, recentEvents, activityFilterAction, activityFilterSeverity, activitySearchTerm]);

  const rawTotal = activityTotal || activityAggregateActions?.total || recentEvents.length;
  const displayTotal = Math.max(displayActivityEvents.length, rawTotal);
  const activityTotalPages = Math.max(1, Math.ceil(displayTotal / activityPageSize));
  const activityStartRecord = displayTotal === 0 ? 0 : (activityPage - 1) * activityPageSize + 1;
  const activityEndRecord = Math.min(activityPage * activityPageSize, displayTotal);

  const trafficSummary = useMemo(() => {
    const totalAllowed = trafficHistory.reduce((s: number, h: any) => s + (h.allowed || 0), 0);
    const totalBlocked = trafficHistory.reduce((s: number, h: any) => s + (h.blocked || 0), 0);
    const totalSuspicious = trafficHistory.reduce((s: number, h: any) => s + (h.suspicious || 0), 0);
    const totalTraffic = totalAllowed + totalBlocked + totalSuspicious;
    const blockedRate = totalTraffic > 0 ? ((totalBlocked / totalTraffic) * 100).toFixed(1) : '0.0';

    return { totalAllowed, totalBlocked, totalSuspicious, totalTraffic, blockedRate };
  }, [trafficHistory]);

  // Continuous 60-minute axis (newest first). If live streaming, anchors to now.
  // If telemetry is paused (historical snapshot), anchors to the latest telemetry timestamp
  // or the latest minute in trafficHistory so the recorded activity is prominently shown!
  const trafficRows = useMemo(() => {
    if (!trafficHistory || trafficHistory.length === 0) return [];

    const byMinute = new Map<string, any>();
    trafficHistory.forEach((row: any) => {
      const label = String(row.hour ?? row.time ?? '');
      if (label) byMinute.set(label, row);
    });

    const isLive = Boolean(data?.isLiveTraffic);
    let anchorTime = new Date();

    if (!isLive && data?.latestTelemetryTimestamp) {
      const parsed = new Date(data.latestTelemetryTimestamp);
      if (!Number.isNaN(parsed.getTime())) {
        anchorTime = parsed;
      }
    } else if (!isLive && trafficHistory.length > 0) {
      const lastRow = trafficHistory[trafficHistory.length - 1];
      const lastLabel = String(lastRow?.hour ?? '');
      if (lastLabel && lastLabel.includes(':')) {
        const [h, m] = lastLabel.split(':').map(Number);
        if (!Number.isNaN(h) && !Number.isNaN(m)) {
          const d = new Date();
          d.setHours(h, m, 0, 0);
          anchorTime = d;
        }
      }
    }

    const rows: { hour: string; allowed: number; blocked: number; suspicious: number }[] = [];
    for (let i = 0; i < 60; i++) {
      const moment = new Date(anchorTime.getTime() - i * 60_000);
      const label = `${String(moment.getHours()).padStart(2, '0')}:${String(moment.getMinutes()).padStart(2, '0')}`;
      const found = byMinute.get(label);
      if (found) {
        rows.push({
          hour: label,
          allowed: found.allowed ?? 0,
          blocked: found.blocked ?? 0,
          suspicious: found.suspicious ?? 0
        });
      } else if (isLive) {
        rows.push({
          hour: label,
          allowed: 0,
          blocked: 0,
          suspicious: 0
        });
      }
    }

    // Safety fallback: if rows is empty or missed all active entries, use reverse of trafficHistory
    if (rows.length === 0 || rows.every(r => (r.allowed + r.blocked + r.suspicious) === 0)) {
      return [...trafficHistory].reverse();
    }

    return rows;
  }, [trafficHistory, data?.isLiveTraffic, data?.latestTelemetryTimestamp]);

  const blockRateToday = (metrics.requestsToday ?? 0) > 0
    ? ((((metrics.blockedRequests ?? 0)) / (metrics.requestsToday ?? 1)) * 100).toFixed(2)
    : '0.00';

  if (isBackendOffline || error === 'BACKEND OFFLINE') {
    return (
      <div className="space-y-6">
        <BackendOfflineBanner onRetry={() => fetchData(false)} />
        <div className="p-12 text-center border border-zinc-200/80 dark:border-zinc-800 rounded-2xl bg-white dark:bg-[#0c0c0e] shadow-2xs">
          <FontAwesomeIcon icon={faTriangleExclamation} className="text-3xl text-rose-500 mx-auto mb-3" />
          <h3 className="text-base font-bold text-zinc-900 dark:text-zinc-100 uppercase tracking-wide">
            TELEMETRY SERVICE OFFLINE
          </h3>
          <p className="text-sm text-zinc-500 dark:text-zinc-400 max-w-md mx-auto mt-1 leading-relaxed">
            The perimeter telemetry collection link is down. Ensure the backend service is running to resume continuous monitoring.
          </p>
          <button
            onClick={() => fetchData(false)}
            className="mt-5 px-4 py-2 rounded-lg bg-zinc-900 hover:bg-zinc-800 text-white dark:bg-white dark:hover:bg-zinc-200 dark:text-zinc-900 text-sm font-semibold transition cursor-pointer shadow-xs"
          >
            Reconnect Telemetry Stream
          </button>
        </div>
      </div>
    );
  }

  return (
    <div className="space-y-5 pb-12">
      {/* Page Header — dashboard identity (shared with every module page) */}
      <ModulePageHeader
        icon={<FontAwesomeIcon icon={faShieldHalved} />}
        title="Security Operations"
        titleTail="Overview"
        badge={
          <ModulePageBadge isDimmed={organizations.length === 0 || !currentOrg?.name}>
            {organizations.length > 0 && currentOrg?.name ? currentOrg.name : 'No Endpoints Enrolled'}
          </ModulePageBadge>
        }
        subtitle="Real-time perimeter monitoring, threat analytics, and active defense telemetry."
      />

      {/* 01 — Security metrics */}
      <SectionShell
        id="section-kpi"
        title="Security Metrics Overview"
      >
        <div className="grid grid-cols-2 md:grid-cols-4 gap-3.5">
          <EnhancedKpiCard
            label="Protected Applications"
            icon={<FontAwesomeIcon icon={faServer} className="text-base" />}
            iconColor="emerald"
            value={<CountUpNumber value={metrics.protectedAppsCount ?? 0} />}
            trend={{ value: "+2", label: "this week", positive: true }}
            meta="WAF policies enforced"
            onClick={() => onNavigate("applications")}
          />
          <EnhancedKpiCard
            label="Protected Networks"
            icon={<FontAwesomeIcon icon={faNetworkWired} className="text-base" />}
            iconColor="blue"
            value={<CountUpNumber value={metrics.protectedNetworksCount ?? 0} />}
            trend={{ value: "0", label: "no change", positive: true }}
            meta="L3/L4 segmentation"
            onClick={() => onNavigate("networks")}
          />
          <EnhancedKpiCard
            label="Requests Today"
            icon={<FontAwesomeIcon icon={faArrowTrendUp} className="text-base" />}
            iconColor="indigo"
            value={<CountUpNumber value={metrics.requestsToday ?? 0} />}
            trend={{ value: "+12.5%", label: "vs yesterday", positive: true }}
            meta="Ingress traffic recorded"
          />
          <EnhancedKpiCard
            label="Blocked Requests"
            icon={<FontAwesomeIcon icon={faShieldVirus} className="text-base" />}
            iconColor="rose"
            value={<CountUpNumber value={metrics.blockedRequests ?? 0} />}
            trend={{ value: `${blockRateToday}%`, label: "block rate", positive: Number(blockRateToday) < 5 }}
            meta="Active mitigation"
            accent="danger"
            onClick={() => onNavigate("waf")}
          />
          <EnhancedKpiCard
            label="Active Threats"
            icon={<FontAwesomeIcon icon={faTriangleExclamation} className="text-base" />}
            iconColor="amber"
            value={<CountUpNumber value={metrics.activeThreats ?? 0} />}
            trend={{ value: "-3", label: "vs last hour", positive: true }}
            meta="Heuristic threat clusters"
            onClick={() => onNavigate("threats")}
          />
          <EnhancedKpiCard
            label="Critical Alerts"
            icon={<FontAwesomeIcon icon={faFire} className="text-base" />}
            iconColor="red"
            value={<CountUpNumber value={metrics.criticalAlerts ?? 0} />}
            trend={{ value: "0", label: "new today", positive: true }}
            meta="SOC attention needed"
            accent="danger"
            onClick={() => onNavigate("incidents")}
          />
          <EnhancedKpiCard
            label="Security Events"
            icon={<FontAwesomeIcon icon={faBolt} className="text-base" />}
            iconColor="violet"
            value={<CountUpNumber value={metrics.securityEventsCount ?? 0} />}
            trend={{ value: "+156", label: "last 24h", positive: true }}
            meta="Full audit trail"
            onClick={() => onNavigate("security-events")}
          />
          <EnhancedKpiCard
            label="Security Score"
            icon={<FontAwesomeIcon icon={faShieldHalved} className="text-base" />}
            iconColor={metrics.securityScore >= 80 ? "emerald" : metrics.securityScore >= 60 ? "amber" : "rose"}
            value={
              metrics.securityScore !== null && metrics.securityScore !== undefined ? (
                <span className="flex items-baseline gap-1.5">
                  <span className={`font-bold ${metrics.securityScore >= 80 ? "text-emerald-600 dark:text-emerald-400" : metrics.securityScore >= 60 ? "text-amber-600 dark:text-amber-400" : "text-rose-600 dark:text-rose-400"}`}>
                    <CountUpNumber value={metrics.securityScore} />
                  </span>
                  <span className="text-xs font-mono text-zinc-400">/ 100</span>
                </span>
              ) : (
                <span className="text-sm font-semibold text-zinc-400">Calculating...</span>
              )
            }
            trend={{ value: metrics.securityScore >= 80 ? "Excellent" : metrics.securityScore >= 60 ? "Good" : "Needs Work", label: "posture grade", positive: metrics.securityScore >= 70 }}
            meta="Weighted risk model"
          />
        </div>
      </SectionShell>

      {/* 02 — Traffic & threat analytics */}
      <SectionShell
        id="section-analytics"
        title="Traffic & Threat Analytics"
      >
        <div className="grid grid-cols-1 lg:grid-cols-3 gap-4">
          {/* Traffic Overview - Cloudflare Style Timeseries Graph & Recap */}
          <div className="lg:col-span-2 rounded-xl border border-zinc-200/80 dark:border-zinc-800 bg-zinc-50/40 dark:bg-zinc-900/40 p-4 flex flex-col shadow-2xs">
            <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 pb-4 border-b border-zinc-200/80 dark:border-zinc-800">
              <div>
                <h3 className="text-sm font-semibold text-zinc-900 dark:text-zinc-100 flex items-center gap-2 flex-wrap">
                  <span>Ingress Traffic Recap (Per Minute)</span>
                  <span className="text-xs text-zinc-500 font-normal">
                    • {trafficSummary.totalTraffic.toLocaleString()} total
                  </span>
                </h3>
                <p className="text-xs text-zinc-500 dark:text-zinc-400 mt-0.5">
                  {data?.isLiveTraffic
                    ? "Minute-by-minute breakdown across allowed, blocked, and suspicious connections over the last 60 minutes."
                    : "Showing the latest stored telemetry. Live updates resume automatically when a monitored endpoint agent reconnects."}
                </p>
              </div>

              <div className="flex items-center gap-3 flex-wrap sm:justify-end">
                {/* View Mode Dropdown: Chart / Table */}
                <div className="relative" ref={trafficModeRef}>
                  <button
                    type="button"
                    onClick={() => setTrafficModeDropdownOpen(prev => !prev)}
                    className="inline-flex items-center gap-2 rounded-lg border border-zinc-200/80 dark:border-zinc-800 bg-white dark:bg-zinc-900 px-3 py-1.5 text-xs font-semibold text-zinc-800 dark:text-zinc-200 shadow-2xs hover:bg-zinc-50 dark:hover:bg-zinc-800/80 transition-colors cursor-pointer"
                  >
                    {trafficDisplayMode === 'chart' ? (
                      <>
                        <ChartLineIcon className="w-3.5 h-3.5 text-blue-500" />
                        <span>Chart</span>
                      </>
                    ) : (
                      <>
                        <TableIcon className="w-3.5 h-3.5 text-emerald-500" />
                        <span>Table</span>
                      </>
                    )}
                    <ChevronDown className={`w-3.5 h-3.5 text-zinc-400 transition-transform ${trafficModeDropdownOpen ? 'rotate-180' : ''}`} />
                  </button>

                  {trafficModeDropdownOpen && (
                    <div className="absolute right-0 mt-1.5 w-36 rounded-xl border border-zinc-200/80 dark:border-zinc-800 bg-white dark:bg-[#0c0c0e] shadow-xl p-1 z-30 space-y-0.5">
                      <button
                        type="button"
                        onClick={() => {
                          setTrafficDisplayMode('chart');
                          setTrafficModeDropdownOpen(false);
                        }}
                        className={`w-full flex items-center justify-between gap-2 px-2.5 py-1.5 rounded-lg text-xs font-medium transition cursor-pointer ${
                          trafficDisplayMode === 'chart'
                            ? 'bg-zinc-100 dark:bg-zinc-800 text-zinc-900 dark:text-zinc-100 font-semibold'
                            : 'text-zinc-600 dark:text-zinc-400 hover:bg-zinc-50 dark:hover:bg-zinc-800/60 hover:text-zinc-900 dark:hover:text-zinc-100'
                        }`}
                      >
                        <span className="flex items-center gap-2">
                          <ChartLineIcon className="w-3.5 h-3.5 text-blue-500" />
                          <span>Chart</span>
                        </span>
                        {trafficDisplayMode === 'chart' && <span className="w-1.5 h-1.5 rounded-full bg-blue-500" />}
                      </button>

                      <button
                        type="button"
                        onClick={() => {
                          setTrafficDisplayMode('table');
                          setTrafficModeDropdownOpen(false);
                        }}
                        className={`w-full flex items-center justify-between gap-2 px-2.5 py-1.5 rounded-lg text-xs font-medium transition cursor-pointer ${
                          trafficDisplayMode === 'table'
                            ? 'bg-zinc-100 dark:bg-zinc-800 text-zinc-900 dark:text-zinc-100 font-semibold'
                            : 'text-zinc-600 dark:text-zinc-400 hover:bg-zinc-50 dark:hover:bg-zinc-800/60 hover:text-zinc-900 dark:hover:text-zinc-100'
                        }`}
                      >
                        <span className="flex items-center gap-2">
                          <TableIcon className="w-3.5 h-3.5 text-emerald-500" />
                          <span>Table</span>
                        </span>
                        {trafficDisplayMode === 'table' && <span className="w-1.5 h-1.5 rounded-full bg-emerald-500" />}
                      </button>
                    </div>
                  )}
                </div>

                {/* Legends — clickable toggles: click a chip to strike it out and toggle series */}
                <div className="flex items-center gap-3 text-xs font-mono flex-wrap">
                  <button
                    type="button"
                    onClick={() => toggleTrafficSeries('allowed')}
                    aria-pressed={!hiddenSeries.allowed}
                    title={hiddenSeries.allowed ? 'Show Allowed' : 'Hide Allowed'}
                    className={`flex items-center gap-1.5 transition-opacity cursor-pointer select-none ${
                      hiddenSeries.allowed
                        ? 'opacity-40 text-zinc-400 dark:text-zinc-500'
                        : 'text-zinc-700 dark:text-zinc-300 hover:text-blue-600 dark:hover:text-blue-400'
                    }`}
                  >
                    <span className="w-2 h-2 rounded-full shrink-0 bg-blue-500" />
                    <span className={hiddenSeries.allowed ? 'line-through' : ''}>
                      Allowed {trafficSummary.totalAllowed.toLocaleString()}
                    </span>
                  </button>
                  <button
                    type="button"
                    onClick={() => toggleTrafficSeries('blocked')}
                    aria-pressed={!hiddenSeries.blocked}
                    title={hiddenSeries.blocked ? 'Show Blocked' : 'Hide Blocked'}
                    className={`flex items-center gap-1.5 transition-opacity cursor-pointer select-none ${
                      hiddenSeries.blocked
                        ? 'opacity-40 text-zinc-400 dark:text-zinc-500'
                        : 'text-rose-600 dark:text-rose-400 hover:text-rose-500'
                    }`}
                  >
                    <span className="w-2 h-2 rounded-full shrink-0 bg-rose-500" />
                    <span className={hiddenSeries.blocked ? 'line-through' : ''}>
                      Blocked {trafficSummary.totalBlocked.toLocaleString()} ({trafficSummary.blockedRate}%)
                    </span>
                  </button>
                  <button
                    type="button"
                    onClick={() => toggleTrafficSeries('suspicious')}
                    aria-pressed={!hiddenSeries.suspicious}
                    title={hiddenSeries.suspicious ? 'Show Suspicious' : 'Hide Suspicious'}
                    className={`flex items-center gap-1.5 transition-opacity cursor-pointer select-none ${
                      hiddenSeries.suspicious
                        ? 'opacity-40 text-zinc-400 dark:text-zinc-500'
                        : 'text-zinc-500 dark:text-zinc-400 hover:text-amber-500 dark:hover:text-amber-400'
                    }`}
                  >
                    <span className="w-2 h-2 rounded-full shrink-0 bg-amber-400" />
                    <span className={hiddenSeries.suspicious ? 'line-through' : ''}>
                      Suspicious {trafficSummary.totalSuspicious.toLocaleString()}
                    </span>
                  </button>
                </div>
              </div>
            </div>

            <div className="pt-3 flex-1 min-h-0">
              {trafficHistory.length === 0 && trafficRows.length === 0 ? (
                <div className="h-48 flex items-center justify-center text-center p-6 border border-dashed border-zinc-200/80 dark:border-zinc-800 rounded-lg">
                  <span className="text-xs font-medium text-zinc-400 dark:text-zinc-500 font-mono">
                    No Data
                  </span>
                </div>
              ) : trafficDisplayMode === 'chart' ? (
                /* Cloudflare Inspired Crisp SVG Timeseries Chart */
                (() => {
                  // Timeline points in chronological order (oldest to newest, left to right)
                  const rawChronological = trafficRows.length > 0
                    ? [...trafficRows].reverse()
                    : Array.from({ length: 60 }).map((_, i) => {
                        const d = new Date(Date.now() - (59 - i) * 60_000);
                        return {
                          hour: `${String(d.getHours()).padStart(2, '0')}:${String(d.getMinutes()).padStart(2, '0')}`,
                          allowed: 0,
                          blocked: 0,
                          suspicious: 0
                        };
                      });
                  const chronological = rawChronological;
                  const totalPoints = chronological.length;

                  // Compute max value for vertical scaling
                  const maxVal = Math.max(
                    1,
                    ...chronological.map(item => {
                      const a = !hiddenSeries.allowed ? (item.allowed || 0) : 0;
                      const b = !hiddenSeries.blocked ? (item.blocked || 0) : 0;
                      const s = !hiddenSeries.suspicious ? (item.suspicious || 0) : 0;
                      return Math.max(a, b, s);
                    })
                  );

                  const chartW = 800;
                  const chartH = 220;
                  const padLeft = 45;
                  const padRight = 20;
                  const padTop = 20;
                  const padBottom = 35;
                  const innerW = chartW - padLeft - padRight;
                  const innerH = chartH - padTop - padBottom;

                  const getX = (idx: number) => {
                    if (totalPoints <= 1) return padLeft + innerW / 2;
                    return padLeft + (idx / (totalPoints - 1)) * innerW;
                  };

                  const getY = (val: number) => {
                    const normalized = Math.min(1, Math.max(0, val / maxVal));
                    return padTop + innerH - (normalized * innerH);
                  };

                  // Build smooth area and line SVG paths
                  const buildPath = (key: 'allowed' | 'blocked' | 'suspicious') => {
                    if (totalPoints === 0) return '';
                    return chronological.map((pt, i) => `${i === 0 ? 'M' : 'L'} ${getX(i).toFixed(1)} ${getY(pt[key] || 0).toFixed(1)}`).join(' ');
                  };

                  const buildAreaPath = (key: 'allowed' | 'blocked' | 'suspicious') => {
                    if (totalPoints === 0) return '';
                    const line = buildPath(key);
                    const lastX = getX(totalPoints - 1).toFixed(1);
                    const firstX = getX(0).toFixed(1);
                    const bottomY = (padTop + innerH).toFixed(1);
                    return `${line} L ${lastX} ${bottomY} L ${firstX} ${bottomY} Z`;
                  };

                  const allowedLine = buildPath('allowed');
                  const allowedArea = buildAreaPath('allowed');
                  const blockedLine = buildPath('blocked');
                  const blockedArea = buildAreaPath('blocked');
                  const suspiciousLine = buildPath('suspicious');
                  const suspiciousArea = buildAreaPath('suspicious');

                  // Hovered data details
                  const activeItem = hoveredPointIndex !== null && chronological[hoveredPointIndex] ? chronological[hoveredPointIndex] : null;

                  return (
                    <div className="relative rounded-xl border border-zinc-200/80 dark:border-zinc-800 bg-white/60 dark:bg-zinc-950/40 p-3 select-none">
                      {/* Floating Tooltip like Cloudflare Analytics */}
                      {activeItem && hoveredPointIndex !== null && (
                        <div
                          className="absolute z-30 pointer-events-none rounded-lg border border-zinc-200 dark:border-zinc-700 bg-white/95 dark:bg-zinc-900/95 backdrop-blur-md p-2.5 shadow-xl text-xs font-mono transition-all duration-75"
                          style={{
                            left: `${Math.min(chartW - 170, Math.max(20, (getX(hoveredPointIndex) / chartW) * 100))}%`,
                            top: '16px'
                          }}
                        >
                          <div className="font-semibold text-zinc-900 dark:text-zinc-100 pb-1 mb-1 border-b border-zinc-100 dark:border-zinc-800 flex items-center justify-between gap-4">
                            <span>Time</span>
                            <span className="text-zinc-500 font-normal">{activeItem.hour ?? activeItem.time}</span>
                          </div>
                          <div className="space-y-0.5 text-[11px]">
                            {!hiddenSeries.allowed && (
                              <div className="flex items-center justify-between gap-3 text-blue-600 dark:text-blue-400">
                                <span className="flex items-center gap-1.5">
                                  <span className="w-1.5 h-1.5 rounded-full bg-blue-500" />
                                  Allowed
                                </span>
                                <span className="font-semibold">{(activeItem.allowed || 0).toLocaleString()}</span>
                              </div>
                            )}
                            {!hiddenSeries.blocked && (
                              <div className="flex items-center justify-between gap-3 text-rose-600 dark:text-rose-400">
                                <span className="flex items-center gap-1.5">
                                  <span className="w-1.5 h-1.5 rounded-full bg-rose-500" />
                                  Blocked
                                </span>
                                <span className="font-semibold">{(activeItem.blocked || 0).toLocaleString()}</span>
                              </div>
                            )}
                            {!hiddenSeries.suspicious && (
                              <div className="flex items-center justify-between gap-3 text-amber-600 dark:text-amber-400">
                                <span className="flex items-center gap-1.5">
                                  <span className="w-1.5 h-1.5 rounded-full bg-amber-400" />
                                  Suspicious
                                </span>
                                <span className="font-semibold">{(activeItem.suspicious || 0).toLocaleString()}</span>
                              </div>
                            )}
                          </div>
                        </div>
                      )}

                      <svg
                        viewBox={`0 0 ${chartW} ${chartH}`}
                        className="w-full h-52 sm:h-64 overflow-visible"
                        onMouseLeave={() => setHoveredPointIndex(null)}
                      >
                        <defs>
                          <linearGradient id="cfAllowedGrad" x1="0" y1="0" x2="0" y2="1">
                            <stop offset="0%" stopColor="#3b82f6" stopOpacity="0.28" />
                            <stop offset="100%" stopColor="#3b82f6" stopOpacity="0.0" />
                          </linearGradient>
                          <linearGradient id="cfBlockedGrad" x1="0" y1="0" x2="0" y2="1">
                            <stop offset="0%" stopColor="#f43f5e" stopOpacity="0.35" />
                            <stop offset="100%" stopColor="#f43f5e" stopOpacity="0.0" />
                          </linearGradient>
                          <linearGradient id="cfSuspiciousGrad" x1="0" y1="0" x2="0" y2="1">
                            <stop offset="0%" stopColor="#fbbf24" stopOpacity="0.25" />
                            <stop offset="100%" stopColor="#fbbf24" stopOpacity="0.0" />
                          </linearGradient>
                        </defs>

                        {/* Horizontal Grid lines */}
                        {[0, 0.25, 0.5, 0.75, 1].map((ratio, idx) => {
                          const y = padTop + innerH - ratio * innerH;
                          const val = Math.round(ratio * maxVal);
                          return (
                            <g key={idx}>
                              <line
                                x1={padLeft}
                                y1={y}
                                x2={chartW - padRight}
                                y2={y}
                                stroke="currentColor"
                                className="text-zinc-200 dark:text-zinc-800/80"
                                strokeDasharray="3 3"
                                strokeWidth="1"
                              />
                              <text
                                x={padLeft - 8}
                                y={y + 3}
                                textAnchor="end"
                                className="fill-zinc-400 text-[10px] font-mono select-none"
                              >
                                {val}
                              </text>
                            </g>
                          );
                        })}

                        {/* X-axis tick labels */}
                        {chronological.map((item, idx) => {
                          // Show roughly 5 to 7 labels evenly distributed
                          const step = Math.max(1, Math.floor(totalPoints / 6));
                          if (idx % step !== 0 && idx !== totalPoints - 1) return null;
                          const x = getX(idx);
                          return (
                            <text
                              key={idx}
                              x={x}
                              y={chartH - 12}
                              textAnchor="middle"
                              className="fill-zinc-400 text-[10px] font-mono select-none"
                            >
                              {item.hour ?? item.time}
                            </text>
                          );
                        })}

                        {/* Areas */}
                        {!hiddenSeries.allowed && (
                          <path d={allowedArea} fill="url(#cfAllowedGrad)" />
                        )}
                        {!hiddenSeries.suspicious && (
                          <path d={suspiciousArea} fill="url(#cfSuspiciousGrad)" />
                        )}
                        {!hiddenSeries.blocked && (
                          <path d={blockedArea} fill="url(#cfBlockedGrad)" />
                        )}

                        {/* Lines */}
                        {!hiddenSeries.allowed && (
                          <path
                            d={allowedLine}
                            fill="none"
                            stroke="#3b82f6"
                            strokeWidth="2"
                            strokeLinecap="round"
                            strokeLinejoin="round"
                          />
                        )}
                        {!hiddenSeries.suspicious && (
                          <path
                            d={suspiciousLine}
                            fill="none"
                            stroke="#fbbf24"
                            strokeWidth="1.5"
                            strokeLinecap="round"
                            strokeLinejoin="round"
                            strokeDasharray="4 2"
                          />
                        )}
                        {!hiddenSeries.blocked && (
                          <path
                            d={blockedLine}
                            fill="none"
                            stroke="#f43f5e"
                            strokeWidth="2.5"
                            strokeLinecap="round"
                            strokeLinejoin="round"
                          />
                        )}

                        {/* Interactive vertical hover guide & hit points */}
                        {hoveredPointIndex !== null && (
                          <line
                            x1={getX(hoveredPointIndex)}
                            y1={padTop}
                            x2={getX(hoveredPointIndex)}
                            y2={padTop + innerH}
                            stroke="currentColor"
                            className="text-zinc-400 dark:text-zinc-500"
                            strokeDasharray="2 2"
                            strokeWidth="1"
                          />
                        )}

                        {/* Invisible hover overlay slices */}
                        {chronological.map((_, idx) => {
                          const x = getX(idx);
                          const sliceWidth = innerW / Math.max(1, totalPoints);
                          return (
                            <rect
                              key={idx}
                              x={x - sliceWidth / 2}
                              y={padTop}
                              width={sliceWidth}
                              height={innerH}
                              fill="transparent"
                              className="cursor-crosshair"
                              onMouseEnter={() => setHoveredPointIndex(idx)}
                            />
                          );
                        })}
                      </svg>
                    </div>
                  );
                })()
              ) : (
                /* Fallback Tabular View */
                <div className="max-h-[300px] overflow-y-auto custom-scrollbar rounded-lg border border-zinc-200/80 dark:border-zinc-800 bg-white dark:bg-zinc-900">
                  <table className="w-full min-w-[560px] border-separate border-spacing-0 text-left">
                    <thead>
                      <tr className="text-zinc-500 font-mono text-[11px]">
                        <th className="sticky top-0 z-20 border-b border-zinc-200/80 bg-zinc-50 py-2.5 px-3 font-semibold dark:border-zinc-800 dark:bg-zinc-900">MINUTE</th>
                        <th className={`sticky top-0 z-20 border-b border-zinc-200/80 bg-zinc-50 py-2.5 px-3 font-semibold text-right dark:border-zinc-800 dark:bg-zinc-900 ${hiddenSeries.allowed ? 'opacity-40 line-through' : ''}`}>ALLOWED</th>
                        <th className={`sticky top-0 z-20 border-b border-zinc-200/80 bg-zinc-50 py-2.5 px-3 font-semibold text-right dark:border-zinc-800 dark:bg-zinc-900 ${hiddenSeries.blocked ? 'opacity-40 line-through' : ''}`}>BLOCKED</th>
                        <th className={`sticky top-0 z-20 border-b border-zinc-200/80 bg-zinc-50 py-2.5 px-3 font-semibold text-right dark:border-zinc-800 dark:bg-zinc-900 ${hiddenSeries.suspicious ? 'opacity-40 line-through' : ''}`}>SUSPICIOUS</th>
                        <th className="sticky top-0 z-20 border-b border-zinc-200/80 bg-zinc-50 py-2.5 px-3 font-semibold text-right dark:border-zinc-800 dark:bg-zinc-900">TOTAL</th>
                        <th className="sticky top-0 z-20 border-b border-zinc-200/80 bg-zinc-50 py-2.5 px-3 font-semibold dark:border-zinc-800 dark:bg-zinc-900">BLOCK RATIO</th>
                      </tr>
                    </thead>
                    <tbody className="font-mono text-[11px]">
                      {trafficRows.map((item: any, idx: number) => {
                        const allowed = item.allowed ?? 0;
                        const blocked = item.blocked ?? 0;
                        const suspicious = item.suspicious ?? 0;
                        const showAllowed = !hiddenSeries.allowed;
                        const showBlocked = !hiddenSeries.blocked;
                        const showSuspicious = !hiddenSeries.suspicious;
                        const total = (showAllowed ? allowed : 0) + (showBlocked ? blocked : 0) + (showSuspicious ? suspicious : 0);
                        const blockRate = showBlocked && total > 0 ? (blocked / total) * 100 : 0;
                        const hasBlocked = showBlocked && blocked > 0;
                        const dimmedCell = 'text-zinc-300 dark:text-zinc-600';

                        return (
                          <tr
                            key={`${item.hour ?? item.time}-${idx}`}
                            className={`transition ${hasBlocked
                              ? 'bg-rose-50/40 dark:bg-rose-950/20 hover:bg-rose-50/80 dark:hover:bg-rose-950/40'
                              : 'hover:bg-zinc-50/80 dark:hover:bg-zinc-800/40'
                              }`}
                          >
                            <td className="border-b border-zinc-100 py-2.5 px-3 text-zinc-900 dark:border-zinc-800/60 dark:text-zinc-100 font-semibold whitespace-nowrap">
                              {item.hour ?? item.time}
                            </td>
                            <td className={`border-b border-zinc-100 py-2.5 px-3 text-right dark:border-zinc-800/60 ${showAllowed ? 'text-zinc-700 dark:text-zinc-300' : dimmedCell}`}>
                              {showAllowed ? allowed.toLocaleString() : '—'}
                            </td>
                            <td className={`border-b border-zinc-100 py-2.5 px-3 text-right font-semibold dark:border-zinc-800/60 ${showBlocked ? (hasBlocked ? 'text-rose-600 dark:text-rose-400' : 'text-zinc-400') : dimmedCell}`}>
                              {showBlocked ? blocked.toLocaleString() : '—'}
                            </td>
                            <td className={`border-b border-zinc-100 py-2.5 px-3 text-right dark:border-zinc-800/60 ${showSuspicious ? 'text-zinc-600 dark:text-zinc-400' : dimmedCell}`}>
                              {showSuspicious ? suspicious.toLocaleString() : '—'}
                            </td>
                            <td className="border-b border-zinc-100 py-2.5 px-3 text-right text-zinc-900 dark:border-zinc-800/60 dark:text-zinc-100 font-semibold">
                              {total.toLocaleString()}
                            </td>
                            <td className="border-b border-zinc-100 py-2.5 px-3 dark:border-zinc-800/60">
                              <div className="flex items-center gap-2 min-w-[100px]">
                                <div className="flex-1 h-1.5 rounded-full bg-zinc-200 dark:bg-zinc-800 overflow-hidden">
                                  <div
                                    className={`h-full rounded-full ${showBlocked ? 'bg-rose-500' : 'bg-transparent'}`}
                                    style={{ width: `${Math.min(100, blockRate)}%` }}
                                  />
                                </div>
                                <span className={`w-10 text-right ${showBlocked ? (hasBlocked ? 'text-rose-600 dark:text-rose-400' : 'text-zinc-400') : dimmedCell}`}>
                                  {showBlocked ? `${blockRate.toFixed(1)}%` : '—'}
                                </span>
                              </div>
                            </td>
                          </tr>
                        );
                      })}
                    </tbody>
                  </table>
                </div>
              )}
            </div>

            <div className="pt-3 flex flex-wrap items-center justify-between text-[11px] text-zinc-400 border-t border-zinc-200/80 dark:border-zinc-800 mt-3">
              <span>Hover over graph for minute inspection. Click legend to show/hide series. Recap refreshes automatically.</span>
              <button
                onClick={() => onNavigate('analytics')}
                className="text-blue-600 dark:text-blue-400 hover:underline font-medium inline-flex items-center gap-1 cursor-pointer"
              >
                <span>View Full Analytics</span>
                <FontAwesomeIcon icon={faArrowUpRightFromSquare} className="text-[10px]" />
              </button>
            </div>

            {/* Requests by country — Cloudflare Geolocation Map (Tepat di bawah Ingress Traffic Recap) */}
            <div className="mt-4 pt-4 border-t border-zinc-200/80 dark:border-zinc-800">
              <CloudflareGeoMap
                data={countryTrafficData}
                totalTraffic={trafficSummary.totalTraffic}
              />
            </div>
          </div>

          {/* Right Column: 2 Separate Boxes (Threat Breakdown on top, Requests by country below) */}
          <div className="flex flex-col gap-4">
            {/* Box 1: Threat Severity Distribution */}
            <div className="rounded-xl border border-zinc-200/80 dark:border-zinc-800 bg-zinc-50/40 dark:bg-zinc-900/40 p-4 flex flex-col justify-between shadow-2xs">
              <div>
                <div className="flex items-center justify-between gap-2 pb-4 border-b border-zinc-200/80 dark:border-zinc-800">
                  <div>
                    <h3 className="text-sm font-semibold text-zinc-900 dark:text-zinc-100">
                      Threat Breakdown
                    </h3>
                    <p className="text-xs text-zinc-500 mt-0.5">
                      {totalThreats} total perimeter incidents
                    </p>
                  </div>
                  <button
                    onClick={() => onNavigate('threats')}
                    className="text-xs text-blue-600 dark:text-blue-400 hover:underline font-medium cursor-pointer"
                  >
                    View All →
                  </button>
                </div>

                {/* Distribution bar */}
                <div className="py-4">
                  <div className="h-2.5 w-full rounded-full bg-zinc-200 dark:bg-zinc-800 overflow-hidden flex">
                    {totalThreats > 0 ? (
                      <>
                        <div
                          style={{ width: `${(threatBreakdown.critical / totalThreats) * 100}%` }}
                          className="bg-rose-500"
                          title={`Critical: ${threatBreakdown.critical}`}
                        />
                        <div
                          style={{ width: `${(threatBreakdown.high / totalThreats) * 100}%` }}
                          className="bg-amber-400"
                          title={`High: ${threatBreakdown.high}`}
                        />
                        <div
                          style={{ width: `${(threatBreakdown.medium / totalThreats) * 100}%` }}
                          className="bg-blue-500"
                          title={`Medium: ${threatBreakdown.medium}`}
                        />
                        <div
                          style={{ width: `${(threatBreakdown.low / totalThreats) * 100}%` }}
                          className="bg-zinc-400"
                          title={`Low: ${threatBreakdown.low}`}
                        />
                      </>
                    ) : (
                      <div className="w-full bg-zinc-200 dark:bg-zinc-800" />
                    )}
                  </div>
                </div>

                {/* Severity Cards List */}
                <div className="space-y-2">
                  {[
                    {
                      label: 'Critical',
                      count: threatBreakdown.critical,
                      border: 'border-rose-200 dark:border-rose-900/40 bg-rose-50/50 dark:bg-rose-950/20',
                      dot: 'bg-rose-500',
                      textColor: 'text-rose-600 dark:text-rose-400'
                    },
                    {
                      label: 'High',
                      count: threatBreakdown.high,
                      border: 'border-amber-200 dark:border-amber-900/40 bg-amber-50/50 dark:bg-amber-950/20',
                      dot: 'bg-amber-400',
                      textColor: 'text-amber-600 dark:text-amber-400'
                    },
                    {
                      label: 'Medium',
                      count: threatBreakdown.medium,
                      border: 'border-zinc-200/80 dark:border-zinc-800 bg-white dark:bg-zinc-900',
                      dot: 'bg-blue-500',
                      textColor: 'text-blue-600 dark:text-blue-400'
                    },
                    {
                      label: 'Low & Info',
                      count: threatBreakdown.low,
                      border: 'border-zinc-200/80 dark:border-zinc-800 bg-white dark:bg-zinc-900',
                      dot: 'bg-zinc-400',
                      textColor: 'text-zinc-600 dark:text-zinc-400'
                    }
                  ].map(item => (
                    <div
                      key={item.label}
                      onClick={() => onNavigate('threats')}
                      className={`p-2.5 rounded-lg border ${item.border} flex items-center justify-between cursor-pointer hover:shadow-2xs transition shadow-2xs`}
                    >
                      <div className="flex items-center gap-2">
                        <span className={`w-2 h-2 rounded-full ${item.dot}`} />
                        <span className="text-xs font-medium text-zinc-700 dark:text-zinc-200">{item.label}</span>
                      </div>
                      <span className={`text-xs font-bold font-mono ${item.textColor}`}>
                        {item.count}
                      </span>
                    </div>
                  ))}
                </div>
              </div>

              <button
                onClick={() => onNavigate('threats')}
                className="w-full mt-4 py-2 text-xs font-semibold text-zinc-900 dark:text-zinc-100 bg-zinc-100 dark:bg-zinc-800 hover:bg-zinc-200 dark:hover:bg-zinc-700 rounded-lg transition flex items-center justify-center gap-2 cursor-pointer shadow-2xs"
              >
                <span>Explore Threat Repository</span>
                <FontAwesomeIcon icon={faArrowRight} className="text-[10px]" />
              </button>
            </div>

            {/* Box 2: Requests by country List Panel — Terpisah Mandiri di bawah Box Threat Breakdown */}
            <CloudflareCountryList
              data={countryTrafficData}
              totalTraffic={trafficSummary.totalTraffic}
            />
          </div>
        </div>
      </SectionShell>

      {/* 04 — Core defense engine health */}
      <SectionShell
        id="section-health"
        title="Core Defense Engine Health"
        action={
          <div className="relative">
            <button
              type="button"
              onClick={() => setHealthMenuOpen(prev => !prev)}
              className="h-8 px-3 rounded-lg border border-zinc-200/80 dark:border-zinc-800 bg-white dark:bg-zinc-900 hover:bg-zinc-50 dark:hover:bg-zinc-800 text-xs font-medium text-zinc-700 dark:text-zinc-200 flex items-center gap-2 transition cursor-pointer shadow-2xs"
            >
              <FontAwesomeIcon icon={faFilter} className="text-[10px] text-zinc-400" />
              <span>
                {selectedHealthOption.label} ({healthFilterCounts[healthFilter]})
              </span>
              <FontAwesomeIcon
                icon={faChevronDown}
                className={`text-[9px] text-zinc-400 ml-0.5 transition-transform ${healthMenuOpen ? 'rotate-180' : ''}`}
              />
            </button>

            {healthMenuOpen && (
              <>
                <div className="fixed inset-0 z-20 cursor-default" onClick={() => setHealthMenuOpen(false)} />
                <div className="absolute right-0 mt-1.5 w-52 rounded-xl border border-zinc-200/80 dark:border-zinc-800 bg-white dark:bg-zinc-900 shadow-xl p-1 z-30">
                  {HEALTH_FILTER_OPTIONS.map(option => (
                    <button
                      key={option.value}
                      type="button"
                      onClick={() => {
                        setHealthFilter(option.value);
                        setHealthMenuOpen(false);
                      }}
                      className={`w-full px-2.5 py-1.5 rounded-lg text-xs text-left flex items-center justify-between transition cursor-pointer ${healthFilter === option.value
                        ? 'bg-zinc-100 dark:bg-zinc-800 font-semibold text-zinc-900 dark:text-zinc-100'
                        : 'text-zinc-600 dark:text-zinc-400 hover:bg-zinc-50 dark:hover:bg-zinc-800/60'
                        }`}
                    >
                      <span className="flex items-center gap-2">
                        {option.dot && <span className={`w-2 h-2 rounded-full ${option.dot}`} />}
                        <span>{option.label}</span>
                      </span>
                      <span className="text-[10px] text-zinc-400 tabular-nums">({healthFilterCounts[option.value]})</span>
                    </button>
                  ))}
                </div>
              </>
            )}
          </div>
        }
        bodyClassName=""
      >
        <div className="p-4 sm:p-5">
          {!healthLoaded ? (
            <div className="p-8 flex flex-col items-center justify-center text-center">
              <FontAwesomeIcon icon={faRotateRight} className="text-sm text-zinc-400 animate-spin mb-2" />
              <div className="text-xs font-mono text-zinc-400">Probing engine health…</div>
            </div>
          ) : visibleHealthRows.length === 0 ? (
            <div className="p-8 text-center">
              <FontAwesomeIcon icon={faFilter} className="text-xl text-zinc-300 dark:text-zinc-600 mx-auto mb-2" />
              <div className="text-xs font-semibold text-zinc-700 dark:text-zinc-300 uppercase tracking-wider">
                NO ENGINES IN THIS STATE
              </div>
              <button
                type="button"
                onClick={() => setHealthFilter('All')}
                className="mt-3 px-3 py-1.5 rounded-lg border border-zinc-200 dark:border-zinc-700 bg-white dark:bg-zinc-800 text-xs font-medium text-zinc-700 dark:text-zinc-300 hover:bg-zinc-50 dark:hover:bg-zinc-700 transition cursor-pointer shadow-2xs"
              >
                Show All Engines
              </button>
            </div>
          ) : (
            <div className="grid grid-cols-2 md:grid-cols-4 gap-3.5">
              {visibleHealthRows.map(row => (
                <EngineCard
                  key={row.service_name}
                  row={row}
                  onClick={() => setSelectedEngine(row)}
                />
              ))}
            </div>
          )}
        </div>
      </SectionShell>

      {selectedEngine && (
        <EngineInspectorDrawer
          row={selectedEngine}
          onClose={() => setSelectedEngine(null)}
        />
      )}

      {selectedEvent && (
        <div className="fixed inset-0 z-50">
          {/* Dimmed backdrop — clicking anywhere outside the panel closes the drawer */}
          <div
            className="absolute inset-0 bg-zinc-950/45 dark:bg-black/70 backdrop-blur-[2px] animate-in fade-in-0 duration-200 transition-opacity"
            style={{ opacity: eventSwipeX > 0 ? Math.max(0.1, 1 - eventSwipeX / 300) : undefined }}
            onClick={() => setSelectedEvent(null)}
          />

          <aside
            role="dialog"
            aria-modal="true"
            aria-label="Traffic event details"
            onTouchStart={handleEventTouchStart}
            onTouchMove={handleEventTouchMove}
            onTouchEnd={handleEventTouchEnd}
            style={{
              transform: eventSwipeX > 0 ? `translateX(${eventSwipeX}px)` : undefined,
              transition: isEventSwiping ? 'none' : 'transform 0.2s ease-out'
            }}
            className="absolute inset-y-0 right-0 flex w-full flex-col border-l border-zinc-200/80 bg-white text-zinc-900 shadow-2xl animate-in slide-in-from-right duration-300 ease-out dark:border-zinc-800 dark:bg-[#0b0b0d] dark:text-zinc-100 sm:max-w-[560px] lg:max-w-[640px]"
          >
            {/* Mobile swipe grab handle */}
            <div className="sm:hidden pt-2.5 pb-0.5 flex justify-center">
              <div className="h-1 w-10 rounded-full bg-zinc-300 dark:bg-zinc-700" />
            </div>

            {/* Drawer header */}
            <header className="shrink-0 border-b border-zinc-200/80 bg-white px-5 pb-4 pt-3.5 dark:border-zinc-800 dark:bg-[#0b0b0d] sm:px-6">
              <div className="flex min-w-0 items-center justify-between">
                <div className="flex min-w-0 items-center gap-1.5 font-mono text-[10px] uppercase tracking-[0.16em] text-zinc-400 dark:text-zinc-500">
                  <span className="shrink-0">Live Traffic</span>
                  <span className="shrink-0 text-zinc-300 dark:text-zinc-700">/</span>
                  <span className="truncate font-sans text-[11px] font-medium normal-case tracking-normal text-zinc-500 dark:text-zinc-400">
                    Event Details
                  </span>
                </div>
                <button
                  type="button"
                  onClick={() => setSelectedEvent(null)}
                  className="rounded-lg p-1.5 text-zinc-400 hover:bg-zinc-100 hover:text-zinc-600 dark:hover:bg-zinc-800 dark:hover:text-zinc-200 transition cursor-pointer"
                  title="Close (Esc)"
                >
                  <X className="w-4 h-4" />
                </button>
              </div>

              <div className="mt-3 flex items-start gap-3">
                <span className="flex h-11 w-11 shrink-0 items-center justify-center rounded-xl border border-zinc-200/80 bg-zinc-50 text-zinc-500 dark:border-zinc-800 dark:bg-zinc-900/60 dark:text-zinc-400">
                  <Radio className="w-5 h-5 text-blue-500" />
                </span>
                <div className="min-w-0 flex-1">
                  <div className="flex flex-wrap items-center gap-2">
                    <h2 className="truncate text-base font-semibold tracking-tight text-zinc-900 dark:text-zinc-100">
                      Event Details
                    </h2>
                    <StatusBadge type="severity" value={selectedEvent.severity || 'Medium'} />
                    <StatusBadge type="action" value={selectedEvent.action || 'LOG'} />
                  </div>
                  <p className="mt-0.5 truncate text-[11px] text-zinc-500 dark:text-zinc-400">
                    Full inspection record for this traffic event.
                  </p>
                </div>
              </div>

              <div className="mt-3 flex flex-wrap items-center gap-x-4 gap-y-1 font-mono text-[10px] uppercase tracking-wider text-zinc-400 dark:text-zinc-500">
                <span>Time · {selectedEvent.timestamp ? formatTime(selectedEvent.timestamp) : 'Just now'}</span>
                <span className="truncate">Source · {selectedEvent.sourceIp || '0.0.0.0'}</span>
              </div>
            </header>

            {/* Scrollable body */}
            <div className="flex-1 space-y-5 overflow-y-auto px-5 py-5 text-xs sm:px-6 custom-scrollbar">
              {/* Event overview */}
              <section>
                <div className="mb-2 text-[10px] font-bold uppercase tracking-[0.14em] text-zinc-400 dark:text-zinc-500">
                  Event overview
                </div>
                <div className="grid grid-cols-1 gap-2.5 sm:grid-cols-2">
                  <div className="rounded-xl border border-zinc-200/80 bg-zinc-50/60 p-3 dark:border-zinc-800 dark:bg-zinc-900/40">
                    <div className="font-mono text-[10px] uppercase tracking-wider text-zinc-400 dark:text-zinc-500">Time</div>
                    <div className="mt-1.5 font-mono text-[11px] text-zinc-700 dark:text-zinc-300">
                      {selectedEvent.timestamp ? formatDateTime(selectedEvent.timestamp) : 'Recent'}
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
                      <span className="break-all font-mono text-[11px] text-zinc-700 dark:text-zinc-300">{selectedEvent.sourceIp || '0.0.0.0'}</span>
                      {(selectedEvent.sourceCountryCode || (selectedEvent as any).source_country_code) && (
                        <span className="inline-flex items-center gap-1.5 rounded border border-zinc-200 bg-white px-2 py-0.5 font-mono text-[10px] text-zinc-700 dark:border-zinc-700 dark:bg-zinc-900 dark:text-zinc-300">
                          <CountryFlag
                            code={selectedEvent.sourceCountryCode || (selectedEvent as any).source_country_code}
                            name={selectedEvent.sourceCountry || (selectedEvent as any).source_country}
                            width={18}
                            height={12}
                          />
                          <span className="font-medium">
                            {getCountryName(
                              selectedEvent.sourceCountryCode || (selectedEvent as any).source_country_code,
                              selectedEvent.sourceCountry || (selectedEvent as any).source_country
                            )}
                          </span>
                        </span>
                      )}
                    </div>
                  </div>
                  <div className="rounded-xl border border-zinc-200/80 bg-zinc-50/60 p-3 dark:border-zinc-800 dark:bg-zinc-900/40">
                    <div className="font-mono text-[10px] uppercase tracking-wider text-zinc-400 dark:text-zinc-500">Target</div>
                    <div className="mt-1.5 break-all text-[11px] text-zinc-700 dark:text-zinc-300">
                      {selectedEvent.application || 'Edge Gateway'} ({selectedEvent.destination || 'Perimeter Gateway'})
                    </div>
                  </div>
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
                    <dd className="break-words text-[11px] font-medium text-rose-600 dark:text-rose-400">{selectedEvent.threat || 'Security Signature Match'}</dd>
                  </div>
                  <div className="grid grid-cols-[112px_1fr] gap-3 px-3.5 py-2.5 sm:grid-cols-[136px_1fr]">
                    <dt className="font-mono text-[10px] uppercase tracking-wider text-zinc-400 dark:text-zinc-500">What happened</dt>
                    <dd className="text-[11px] leading-relaxed text-zinc-500 dark:text-zinc-400">
                      The request matched a perimeter inspection rule or traffic policy. The security gateway recorded
                      this telemetry snapshot and applied the action ({selectedEvent.action || 'LOG'}).
                    </dd>
                  </div>
                </dl>
              </section>
            </div>

            {/* Drawer footer */}
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







