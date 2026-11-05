import React, { useCallback, useEffect, useRef, useState } from 'react';
import {
  ShieldAlert,
  RefreshCw,
  Layers,
  Activity,
  Ban,
  Radio,
  Users,
  Gauge,
  Clock3
} from 'lucide-react';
import { securityApi, globalRealtimeClient } from '../../services/api';
import { BackendOfflineBanner } from '../../components/common/BackendOfflineBanner';
import { FontAwesomeIcon } from '@fortawesome/react-fontawesome';
import { faChartColumn } from '@fortawesome/free-solid-svg-icons';
import { ModulePageHeader } from '../../components/common/ModulePageHeader';
import { useAuth } from '../../context/AuthContext';

interface TelemetryMetrics {
  totalRequests: number;
  blocked: number;
  allowed: number;
  challenged: number;
  rateLimited: number;
  logged: number;
  uniqueSources: number;
  blockRate: string;
}

interface TelemetryAnalytics {
  generatedAt: string;
  windowHours: number;
  metrics: TelemetryMetrics;
  topAttackingIps: Array<{ ip: string; country: string; countryCode?: string; asn: string; count: number; threat: string }>;
  topTargetedApps: Array<{ name: string; requests: number; blocked: number; pctBlocked: string }>;
  responseCodes: Array<{ code: string; count: number; pct: string; color: string }>;
  actions: Array<{ action: string; count: number; pct: string; color: string }>;
  timeline: Array<{ hour: string; total: number; blocked: number }>;
}

function buildSmoothPath(points: Array<{ x: number; y: number }>): string {
  if (points.length === 0) return '';
  if (points.length === 1) return `M ${points[0].x} ${points[0].y}`;
  let path = `M ${points[0].x} ${points[0].y}`;
  for (let i = 0; i < points.length - 1; i++) {
    const p0 = points[Math.max(i - 1, 0)];
    const p1 = points[i];
    const p2 = points[i + 1];
    const p3 = points[Math.min(i + 2, points.length - 1)];

    const cp1x = p1.x + (p2.x - p0.x) / 6;
    const cp1y = p1.y + (p2.y - p0.y) / 6;
    const cp2x = p2.x - (p3.x - p1.x) / 6;
    const cp2y = p2.y - (p3.y - p1.y) / 6;

    path += ` C ${cp1x.toFixed(1)} ${cp1y.toFixed(1)}, ${cp2x.toFixed(1)} ${cp2y.toFixed(1)}, ${p2.x.toFixed(1)} ${p2.y.toFixed(1)}`;
  }
  return path;
}

function formatHour(hour: string): string {
  const date = new Date(hour.replace(' ', 'T'));
  if (Number.isNaN(date.getTime())) return hour;
  return `${String(date.getHours()).padStart(2, '0')}:00`;
}

function MetricCard({
  label,
  value,
  hint,
  icon: Icon,
  tone = 'zinc'
}: {
  label: string;
  value: string | number;
  hint?: string;
  icon: React.ComponentType<{ className?: string }>;
  tone?: 'zinc' | 'rose' | 'emerald' | 'sky' | 'amber';
}) {
  const tones: Record<string, string> = {
    zinc: 'bg-zinc-100 text-zinc-600 dark:bg-zinc-800 dark:text-zinc-300',
    rose: 'bg-rose-50 text-rose-600 dark:bg-rose-500/10 dark:text-rose-300',
    emerald: 'bg-emerald-50 text-emerald-600 dark:bg-emerald-500/10 dark:text-emerald-300',
    sky: 'bg-sky-50 text-sky-600 dark:bg-sky-500/10 dark:text-sky-300',
    amber: 'bg-amber-50 text-amber-600 dark:bg-amber-500/10 dark:text-amber-300'
  };
  return (
    <div className="rounded-xl border border-zinc-200 bg-white p-4 dark:border-zinc-800 dark:bg-[#0c0c0e]">
      <div className="flex items-center justify-between gap-2">
        <span className="text-[10px] font-semibold uppercase tracking-wider text-zinc-400 dark:text-zinc-500">{label}</span>
        <span className={`flex h-7 w-7 items-center justify-center rounded-lg ${tones[tone]}`}>
          <Icon className="h-3.5 w-3.5" />
        </span>
      </div>
      <div className="mt-2 text-2xl font-extrabold tabular-nums tracking-tight text-zinc-900 dark:text-white">
        {typeof value === 'number' ? value.toLocaleString() : value}
      </div>
      {hint && <div className="mt-0.5 text-[11px] text-zinc-500 dark:text-zinc-400">{hint}</div>}
    </div>
  );
}

export const AnalyticsModule: React.FC = () => {
  const { isBackendOffline } = useAuth();
  const [loading, setLoading] = useState(true);
  const [data, setData] = useState<TelemetryAnalytics | null>(null);
  const [live, setLive] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [activePoint, setActivePoint] = useState<{ hour: string; total: number; blocked: number; x: number; yTotal: number; yBlocked: number } | null>(null);
  const inFlight = useRef(false);

  const fetchAnalytics = useCallback(async (quiet = false) => {
    if (inFlight.current) return;
    inFlight.current = true;
    if (!quiet) setLoading(true);
    try {
      const res = await securityApi.getAnalytics();
      setData(res as TelemetryAnalytics);
      setError(null);
    } catch (err: any) {
      if (!quiet) setError(err?.message || 'Could not load telemetry analytics.');
    } finally {
      inFlight.current = false;
      if (!quiet) setLoading(false);
    }
  }, []);

  useEffect(() => {
    void fetchAnalytics();
  }, [fetchAnalytics, isBackendOffline]);

  // Live channel: the server pushes an authoritative analytics snapshot after
  // every ingested event, so the dashboard updates without polling.
  useEffect(() => {
    const unsubStatus = globalRealtimeClient.onStatusChange(status => {
      setLive(status === 'CONNECTED');
    });

    let debounce: number | null = null;
    const scheduleRefresh = (fast = false) => {
      if (debounce) window.clearTimeout(debounce);
      debounce = window.setTimeout(() => {
        debounce = null;
        void fetchAnalytics(true);
      }, fast ? 300 : 1200);
    };

    const unsubscribe = globalRealtimeClient.subscribe((msg: any) => {
      if (!msg?.type) return;
      if (msg.type === 'analytics.snapshot' && msg.data) {
        setData(msg.data as TelemetryAnalytics);
        setError(null);
        setLoading(false);
        return;
      }
      if (
        msg.type === 'security_event' ||
        msg.type === 'security_event.created' ||
        msg.type === 'threat.created' ||
        msg.type === 'threat.updated' ||
        msg.type === 'malware.detected' ||
        msg.type === 'agent.ingested' ||
        msg.type === 'incident.created' ||
        msg.type === 'incident.updated'
      ) {
        scheduleRefresh(true);
      }
    });

    // Auto-sync safety net every 10 seconds for real-time telemetry
    const timer = window.setInterval(() => void fetchAnalytics(true), 10000);

    return () => {
      unsubStatus();
      unsubscribe();
      window.clearInterval(timer);
      if (debounce) window.clearTimeout(debounce);
    };
  }, [fetchAnalytics]);

  if (isBackendOffline) {
    return <BackendOfflineBanner onRetry={() => void fetchAnalytics()} />;
  }

  const metrics: TelemetryMetrics = data?.metrics || {
    totalRequests: 0,
    blocked: 0,
    allowed: 0,
    challenged: 0,
    rateLimited: 0,
    logged: 0,
    uniqueSources: 0,
    blockRate: '0.00%'
  };
  const topAttackingIps = data?.topAttackingIps || [];
  const topTargetedApps = data?.topTargetedApps || [];
  const responseCodes = data?.responseCodes || [];
  const actions = data?.actions || [];
  const timeline = data?.timeline || [];
  const peak = Math.max(1, ...timeline.map(point => point.total));

  return (
    <div className="space-y-6">
      <ModulePageHeader
        icon={<FontAwesomeIcon icon={faChartColumn} />}
        title="Security Telemetry"
        titleTail="Analytics"
        badge={
          <span
            className={`inline-flex items-center gap-1.5 rounded-md border px-2 py-0.5 text-[10px] font-semibold ${
              live
                ? 'border-emerald-200 bg-emerald-50 text-emerald-700 dark:border-emerald-500/30 dark:bg-emerald-500/10 dark:text-emerald-300'
                : 'border-amber-200 bg-amber-50 text-amber-700 dark:border-amber-500/30 dark:bg-amber-500/10 dark:text-amber-300'
            }`}
          >
            <span className={`h-1.5 w-1.5 rounded-full ${live ? 'animate-pulse bg-emerald-500' : 'bg-amber-500'}`} />
            {live ? 'Live stream' : 'Reconnecting'}
          </span>
        }
        subtitle="Every request, block and status code is aggregated from live WAF, firewall and endpoint telemetry — window: last 24 hours."
        actions={
          <span className="hidden items-center gap-1.5 text-[10px] font-mono text-zinc-400 dark:text-zinc-500 sm:inline-flex">
            <Clock3 className="h-3 w-3" />
            {data?.generatedAt ? new Date(data.generatedAt).toLocaleTimeString() : '—'}
          </span>
        }
      />

      {error && (
        <div className="rounded-lg border border-rose-200 bg-rose-50 px-3 py-2 text-xs text-rose-700 dark:border-rose-500/30 dark:bg-rose-500/10 dark:text-rose-300">
          {error}
        </div>
      )}

      {/* Headline metrics */}
      <div className="grid grid-cols-2 gap-3 md:grid-cols-3 xl:grid-cols-6">
        <MetricCard label="Requests" value={metrics.totalRequests} hint="Last 24h" icon={Activity} tone="sky" />
        <MetricCard label="Blocked" value={metrics.blocked} hint={`${metrics.blockRate} of traffic`} icon={Ban} tone="rose" />
        <MetricCard label="Allowed" value={metrics.allowed} hint="Passed to origin" icon={ShieldAlert} tone="emerald" />
        <MetricCard label="Unique sources" value={metrics.uniqueSources} hint="Distinct source IPs" icon={Users} tone="zinc" />
        <MetricCard label="Rate limited" value={metrics.rateLimited} hint="Throttled requests" icon={Gauge} tone="amber" />
        <MetricCard label="Challenged" value={metrics.challenged} hint="Bot / CAPTCHA checks" icon={Radio} tone="sky" />
      </div>

      {/* Timeline with Modern Interactive Line Chart */}
      <div className="rounded-xl border border-zinc-200 bg-white p-5 dark:border-zinc-800 dark:bg-[#0c0c0e]">
        <div className="flex flex-wrap items-center justify-between gap-2">
          <div className="flex items-center gap-2">
            <h2 className="text-sm font-semibold text-zinc-900 dark:text-white">Ingress Volume &amp; Real-Time Attack Trend</h2>
            <span className="flex items-center gap-1 rounded-full bg-emerald-50 px-2 py-0.5 text-[10px] font-semibold text-emerald-700 dark:bg-emerald-500/10 dark:text-emerald-300">
              <span className="h-1.5 w-1.5 animate-pulse rounded-full bg-emerald-500" />
              Live Feed
            </span>
          </div>
          <div className="flex items-center gap-4 text-[10px] font-medium text-zinc-500 dark:text-zinc-400">
            <span className="inline-flex items-center gap-1.5">
              <span className="h-2 w-3 rounded-full bg-sky-500" /> Total Ingress
            </span>
            <span className="inline-flex items-center gap-1.5">
              <span className="h-2 w-3 rounded-full bg-rose-500" /> Blocked Attacks
            </span>
          </div>
        </div>

        {timeline.length === 0 || timeline.every(point => point.total === 0) ? (
          <div className="py-12 text-center text-xs text-zinc-400 dark:text-zinc-500">
            No HTTP telemetry in the last 24 hours.
            <p className="mt-1 text-[11px]">Line charts populate automatically in real time as the WAF, agent, and perimeter engines log events.</p>
          </div>
        ) : (() => {
          const w = 1000;
          const h = 220;
          const padX = 20;
          const padY = 25;
          const innerW = w - padX * 2;
          const innerH = h - padY * 2;

          const pointsTotal = timeline.map((pt, idx) => {
            const x = padX + (idx / Math.max(timeline.length - 1, 1)) * innerW;
            const y = padY + innerH - (pt.total / peak) * innerH;
            return { x, y, hour: pt.hour, total: pt.total, blocked: pt.blocked };
          });

          const pointsBlocked = timeline.map((pt, idx) => {
            const x = padX + (idx / Math.max(timeline.length - 1, 1)) * innerW;
            const y = padY + innerH - (pt.blocked / peak) * innerH;
            return { x, y, hour: pt.hour, total: pt.total, blocked: pt.blocked };
          });

          const pathTotal = buildSmoothPath(pointsTotal);
          const pathBlocked = buildSmoothPath(pointsBlocked);

          const firstX = pointsTotal[0].x;
          const lastX = pointsTotal[pointsTotal.length - 1].x;
          const bottomY = padY + innerH;
          const areaTotal = `${pathTotal} L ${lastX} ${bottomY} L ${firstX} ${bottomY} Z`;
          const areaBlocked = `${pathBlocked} L ${lastX} ${bottomY} L ${firstX} ${bottomY} Z`;

          return (
            <div className="relative mt-4 select-none">
              <svg
                viewBox={`0 0 ${w} ${h}`}
                className="w-full h-48 sm:h-56 overflow-visible"
                onMouseLeave={() => setActivePoint(null)}
              >
                <defs>
                  <linearGradient id="skyGrad" x1="0" y1="0" x2="0" y2="1">
                    <stop offset="0%" stopColor="#0ea5e9" stopOpacity="0.25" />
                    <stop offset="100%" stopColor="#0ea5e9" stopOpacity="0.0" />
                  </linearGradient>
                  <linearGradient id="roseGrad" x1="0" y1="0" x2="0" y2="1">
                    <stop offset="0%" stopColor="#f43f5e" stopOpacity="0.30" />
                    <stop offset="100%" stopColor="#f43f5e" stopOpacity="0.0" />
                  </linearGradient>
                </defs>

                {/* Subtle horizontal grid lines */}
                {[0, 0.25, 0.5, 0.75, 1].map((ratio, idx) => {
                  const yVal = padY + innerH * (1 - ratio);
                  return (
                    <g key={idx}>
                      <line
                        x1={padX}
                        y1={yVal}
                        x2={w - padX}
                        y2={yVal}
                        stroke="currentColor"
                        strokeDasharray="3 3"
                        className="text-zinc-100 dark:text-zinc-800/70"
                        strokeWidth="1"
                      />
                      <text
                        x={padX}
                        y={yVal - 4}
                        className="fill-zinc-400 dark:fill-zinc-600 font-mono text-[9px]"
                      >
                        {Math.round(peak * ratio).toLocaleString()}
                      </text>
                    </g>
                  );
                })}

                {/* Area fills */}
                <path d={areaTotal} fill="url(#skyGrad)" />
                <path d={areaBlocked} fill="url(#roseGrad)" />

                {/* Smooth lines */}
                <path
                  d={pathTotal}
                  fill="none"
                  stroke="#0ea5e9"
                  strokeWidth="2.5"
                  strokeLinecap="round"
                  strokeLinejoin="round"
                />
                <path
                  d={pathBlocked}
                  fill="none"
                  stroke="#f43f5e"
                  strokeWidth="2.5"
                  strokeLinecap="round"
                  strokeLinejoin="round"
                />

                {/* Hover trigger zones */}
                {pointsTotal.map((pt, idx) => {
                  const bPt = pointsBlocked[idx];
                  const colW = innerW / Math.max(pointsTotal.length - 1, 1);
                  return (
                    <g key={pt.hour}>
                      <rect
                        x={pt.x - colW / 2}
                        y={padY}
                        width={colW}
                        height={innerH}
                        fill="transparent"
                        className="cursor-pointer"
                        onMouseEnter={() =>
                          setActivePoint({
                            hour: pt.hour,
                            total: pt.total,
                            blocked: pt.blocked,
                            x: (pt.x / w) * 100,
                            yTotal: pt.y,
                            yBlocked: bPt.y
                          })
                        }
                      />
                      {/* Active points circle indicator */}
                      {activePoint?.hour === pt.hour && (
                        <>
                          <line
                            x1={pt.x}
                            y1={padY}
                            x2={pt.x}
                            y2={padY + innerH}
                            stroke="currentColor"
                            strokeWidth="1.5"
                            strokeDasharray="2 2"
                            className="text-zinc-400 dark:text-zinc-500"
                          />
                          <circle cx={pt.x} cy={pt.y} r="4.5" fill="#0ea5e9" stroke="#fff" strokeWidth="2" />
                          <circle cx={bPt.x} cy={bPt.y} r="4.5" fill="#f43f5e" stroke="#fff" strokeWidth="2" />
                        </>
                      )}
                    </g>
                  );
                })}
              </svg>

              {/* Floating Tooltip */}
              {activePoint && (
                <div
                  className="pointer-events-none absolute -top-2 z-20 -translate-x-1/2 -translate-y-full rounded-xl border border-zinc-200/90 bg-white/95 px-3 py-2 text-xs shadow-xl backdrop-blur-xs transition-all dark:border-zinc-800 dark:bg-zinc-950/95"
                  style={{ left: `${activePoint.x}%` }}
                >
                  <div className="font-mono text-[10px] font-semibold text-zinc-500 dark:text-zinc-400">
                    {formatHour(activePoint.hour)}
                  </div>
                  <div className="mt-1 flex items-center gap-2">
                    <span className="h-2 w-2 rounded-full bg-sky-500" />
                    <span className="text-[11px] text-zinc-700 dark:text-zinc-300">Total:</span>
                    <span className="font-mono font-bold text-zinc-900 dark:text-white">
                      {activePoint.total.toLocaleString()}
                    </span>
                  </div>
                  <div className="flex items-center gap-2">
                    <span className="h-2 w-2 rounded-full bg-rose-500" />
                    <span className="text-[11px] text-zinc-700 dark:text-zinc-300">Blocked:</span>
                    <span className="font-mono font-bold text-rose-600 dark:text-rose-400">
                      {activePoint.blocked.toLocaleString()}
                    </span>
                  </div>
                </div>
              )}

              {/* Bottom X-Axis hour timestamps */}
              <div className="mt-2 flex justify-between font-mono text-[9px] text-zinc-400 dark:text-zinc-500">
                <span>{formatHour(timeline[0].hour)}</span>
                <span>{formatHour(timeline[Math.floor(timeline.length * 0.25)]?.hour || timeline[0].hour)}</span>
                <span>{formatHour(timeline[Math.floor(timeline.length * 0.5)]?.hour || timeline[0].hour)}</span>
                <span>{formatHour(timeline[Math.floor(timeline.length * 0.75)]?.hour || timeline[0].hour)}</span>
                <span>{formatHour(timeline[timeline.length - 1].hour)} (Now)</span>
              </div>
            </div>
          );
        })()}
      </div>

      {/* Top attacking IPs & targeted apps */}
      <div className="grid grid-cols-1 gap-6 lg:grid-cols-2">
        <div className="space-y-4 rounded-xl border border-zinc-200 bg-white p-5 dark:border-zinc-800 dark:bg-[#0c0c0e]">
          <div className="flex flex-wrap items-center justify-between gap-2">
            <h2 className="flex items-center gap-2 text-sm font-semibold text-zinc-900 dark:text-white">
              <ShieldAlert className="h-4 w-4 text-rose-600 dark:text-rose-400" />
              <span>Top Malicious Ingress Sources (24h)</span>
            </h2>
            <span className="text-[11px] font-mono text-zinc-500 dark:text-slate-400">Total Block Drops</span>
          </div>

          <div className="divide-y divide-zinc-100 font-mono text-xs dark:divide-zinc-800/60">
            {topAttackingIps.length === 0 ? (
              <div className="py-8 text-center text-zinc-400 dark:text-slate-500">
                NO SECURITY EVENTS DETECTED
                <p className="mt-1 font-sans text-[11px] text-zinc-400 dark:text-slate-500">No malicious ingress IP clusters recorded in database telemetry.</p>
              </div>
            ) : (
              topAttackingIps.map(item => (
                <div key={item.ip} className="flex items-center justify-between py-2.5">
                  <div>
                    <div className="flex items-center gap-2 font-bold text-zinc-800 dark:text-zinc-200">
                      <span className="text-zinc-700 dark:text-zinc-300">{item.ip}</span>
                      <span className="text-[10px] font-normal text-zinc-500 dark:text-slate-400">
                        ({item.country}{item.asn ? ` • ${item.asn}` : ''})
                      </span>
                    </div>
                    <div className="mt-0.5 text-[11px] text-rose-600/90 dark:text-rose-400/90">{item.threat}</div>
                  </div>
                  <div className="text-right">
                    <div className="font-bold text-rose-600 dark:text-rose-400">{item.count.toLocaleString()}</div>
                    <div className="text-[10px] text-zinc-400 dark:text-slate-500">events blocked</div>
                  </div>
                </div>
              ))
            )}
          </div>
        </div>

        <div className="space-y-4 rounded-xl border border-zinc-200 bg-white p-5 dark:border-zinc-800 dark:bg-[#0c0c0e]">
          <div className="flex flex-wrap items-center justify-between gap-2">
            <h2 className="flex items-center gap-2 text-sm font-semibold text-zinc-900 dark:text-white">
              <Layers className="h-4 w-4 text-zinc-700 dark:text-zinc-300" />
              <span>Top Targeted Applications &amp; APIs</span>
            </h2>
            <span className="text-[11px] font-mono text-zinc-500 dark:text-slate-400">Threat Ingress Load</span>
          </div>

          <div className="divide-y divide-zinc-100 text-xs dark:divide-zinc-800/60">
            {topTargetedApps.length === 0 ? (
              <div className="py-8 text-center font-mono text-zinc-400 dark:text-slate-500">
                NO TARGETED APPS RECORDED
                <p className="mt-1 font-sans text-[11px] text-zinc-400 dark:text-slate-500">Applications configured in inventory have zero ingress events in this window.</p>
              </div>
            ) : (
              topTargetedApps.map(app => (
                <div key={app.name} className="flex items-center justify-between py-2.5 font-mono">
                  <div>
                    <div className="font-sans font-medium text-zinc-800 dark:text-zinc-200">{app.name}</div>
                    <div className="mt-0.5 text-[10px] text-zinc-500 dark:text-slate-400">
                      {app.requests.toLocaleString()} total ingress requests
                    </div>
                  </div>
                  <div className="text-right">
                    <div className="font-bold text-rose-600 dark:text-rose-400">{app.blocked.toLocaleString()}</div>
                    <div className="text-[10px] text-zinc-400 dark:text-slate-500">{app.pctBlocked} filtered</div>
                  </div>
                </div>
              ))
            )}
          </div>
        </div>
      </div>

      {/* Actions + response codes */}
      <div className="grid grid-cols-1 gap-6 lg:grid-cols-5">
        <div className="space-y-3 rounded-xl border border-zinc-200 bg-white p-5 dark:border-zinc-800 dark:bg-[#0c0c0e] lg:col-span-2">
          <h2 className="text-sm font-semibold text-zinc-900 dark:text-white">Enforcement actions</h2>
          {actions.length === 0 ? (
            <div className="py-8 text-center text-xs text-zinc-400 dark:text-zinc-500">No enforcement actions logged.</div>
          ) : (
            <div className="space-y-2.5">
              {actions.map(action => (
                <div key={action.action}>
                  <div className="flex items-center justify-between text-[11px]">
                    <span className="font-mono font-semibold text-zinc-700 dark:text-zinc-300">{action.action}</span>
                    <span className="tabular-nums text-zinc-500 dark:text-zinc-400">{action.count.toLocaleString()} · {action.pct}</span>
                  </div>
                  <div className="mt-1 h-1.5 overflow-hidden rounded-full bg-zinc-100 dark:bg-zinc-800">
                    <div className={`h-full ${action.color}`} style={{ width: action.pct }} />
                  </div>
                </div>
              ))}
            </div>
          )}
        </div>

        <div className="space-y-4 rounded-xl border border-zinc-200 bg-white p-5 dark:border-zinc-800 dark:bg-[#0c0c0e] lg:col-span-3">
          <h2 className="text-sm font-semibold text-zinc-900 dark:text-white">Edge HTTP Status Code Breakdown (24h)</h2>
          <p className="text-xs text-zinc-500 dark:text-slate-400">
            Proves perimeter efficacy: illegitimate traffic is rejected before reaching origin compute.
          </p>

          {responseCodes.length === 0 ? (
            <div className="rounded-lg border border-zinc-200 bg-zinc-50 p-6 text-center font-mono text-zinc-400 dark:border-zinc-800 dark:bg-zinc-900/40 dark:text-slate-500">
              NO PROTOCOL RESPONSE CODES LOGGED
              <p className="mt-1 font-sans text-[11px] text-zinc-400 dark:text-slate-500">Status codes will be tabulated once HTTP ingress requests traverse the perimeter.</p>
            </div>
          ) : (
            <>
              <div className="flex h-6 w-full overflow-hidden rounded-full border border-zinc-200 bg-zinc-50 dark:border-zinc-800 dark:bg-zinc-900/40">
                {responseCodes.map((rc, idx) => (
                  <div
                    key={idx}
                    style={{ width: rc.pct }}
                    className={`${rc.color} h-full`}
                    title={`${rc.code}: ${rc.count.toLocaleString()} (${rc.pct})`}
                  />
                ))}
              </div>

              <div className="grid grid-cols-2 gap-4 pt-2 font-mono text-xs sm:grid-cols-4">
                {responseCodes.map((rc, idx) => (
                  <div key={idx} className="rounded-lg border border-zinc-200 bg-zinc-50 p-3 dark:border-zinc-800 dark:bg-zinc-900/40">
                    <div className="mb-1 flex items-center gap-2">
                      <span className={`h-2.5 w-2.5 rounded-full ${rc.color}`} />
                      <span className="font-semibold text-zinc-800 dark:text-zinc-200">{rc.code}</span>
                    </div>
                    <div className="text-base font-bold text-zinc-900 dark:text-white">{rc.count.toLocaleString()}</div>
                    <div className="text-[11px] text-zinc-500 dark:text-slate-400">{rc.pct} of all ingress</div>
                  </div>
                ))}
              </div>
            </>
          )}
        </div>
      </div>
    </div>
  );
};
