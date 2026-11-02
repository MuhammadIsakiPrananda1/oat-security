import React, { useEffect, useState } from 'react';
import { ArrowRight } from 'lucide-react';
import { FontAwesomeIcon } from '@fortawesome/react-fontawesome';
import { faShield } from '@fortawesome/free-solid-svg-icons';
import { ModulePageHeader } from '../../components/common/ModulePageHeader';
import { DashboardView } from '../../components/layout/DashboardSidebar';
import { securityApi, globalRealtimeClient } from '../../services/api';
import { useAuth } from '../../context/AuthContext';
import { CountUpNumber } from '../../components/common/CountUpNumber';

interface SecurityOverviewModuleProps {
  onNavigate: (view: DashboardView) => void;
}

interface DefenseLayer {
  layer: string;
  desc: string;
  engine: string;
  targetView: DashboardView;
  measured: (metrics: any) => string;
}

interface EngineHealth {
  service_name: string;
  status: string;
}

// The five concentric rings are fixed architecture, but their live state is read
// from the server health probe and live ingestion counters — nothing on this
// page is hard-coded, so a ring whose engine stops reporting shows as Offline.
const DEFENSE_LAYERS: DefenseLayer[] = [
  {
    layer: 'Global Anycast Perimeter',
    desc: 'Stops large-scale attacks at the edge of the network, before they reach your services.',
    engine: 'Next-Gen Firewall',
    targetView: 'firewall' as DashboardView,
    measured: m => `${(m?.protectedAppsCount ?? 0).toLocaleString()} protected applications behind the edge`
  },
  {
    layer: 'Web Application Firewall (WAF)',
    desc: 'Checks every web request and blocks common attacks such as SQL injection and cross-site scripting.',
    engine: 'WAF Engine',
    targetView: 'waf' as DashboardView,
    measured: m =>
      `${(m?.blockedRequests ?? 0).toLocaleString()} blocked of ${(m?.requestsToday ?? 0).toLocaleString()} requests today`
  },
  {
    layer: 'Endpoint Threat Detection',
    desc: 'Inspects host telemetry and web requests on monitored servers for attacks, policy violations, and suspicious behavior.',
    engine: 'Endpoint Detection',
    targetView: 'threats' as DashboardView,
    measured: m => `${(m?.activeThreats ?? 0).toLocaleString()} correlated threat clusters`
  },
  {
    layer: 'Network Segmentation',
    desc: 'Separates internal systems into zones, so an attack on one zone cannot reach the core data.',
    engine: 'Database Vault',
    targetView: 'networks' as DashboardView,
    measured: m => `${(m?.protectedNetworksCount ?? 0).toLocaleString()} segmented network zones`
  },
  {
    layer: 'Security Monitoring & Logging',
    desc: 'Collects security events from every layer, keeps a full audit trail, and raises alerts for the SOC team.',
    engine: 'SIEM Monitor',
    targetView: 'security-events' as DashboardView,
    measured: m => `${(m?.securityEventsCount ?? 0).toLocaleString()} security events ingested`
  }
];

const statusDot = (status: string) => {
  if (status === 'Operational') return 'bg-emerald-500';
  if (status === 'Degraded') return 'bg-amber-500';
  return 'bg-rose-500';
};

interface SummaryStatProps {
  label: string;
  value: React.ReactNode;
  note?: string;
  dot?: string;
}

const SummaryStat: React.FC<SummaryStatProps> = ({ label, value, note, dot }) => (
  <div className="relative group rounded-xl border border-zinc-200/80 dark:border-zinc-800 bg-white dark:bg-zinc-900/40 p-4 pl-5 min-h-[144px] flex flex-col justify-between shadow-2xs transition-colors">
    {/* Left accent bar — same treatment as dashboard KPI cards */}
    <span className="absolute left-0 top-3.5 bottom-3.5 w-1 rounded-r-full bg-zinc-200 dark:bg-zinc-700 transition-colors group-hover:bg-blue-600 dark:group-hover:bg-blue-400" />
    <div className="text-[11px] font-semibold uppercase tracking-wider text-zinc-500 dark:text-zinc-400 leading-tight">
      {label}
    </div>
    <div className="min-w-0">
      <div className="text-2xl sm:text-3xl font-bold font-mono tracking-tight text-zinc-900 dark:text-zinc-100">
        {value}
      </div>
      {note && (
        <div className="mt-2 flex items-center gap-1.5 text-[12px] font-bold text-zinc-500 dark:text-zinc-400">
          {dot && <span className={`h-1.5 w-1.5 shrink-0 rounded-full ${dot}`} />}
          <span className="truncate">{note}</span>
        </div>
      )}
    </div>
  </div>
);

export const SecurityOverviewModule: React.FC<SecurityOverviewModuleProps> = ({ onNavigate }) => {
  const { currentOrg, isBackendOffline } = useAuth();
  const [loading, setLoading] = useState(true);
  const [metrics, setMetrics] = useState<any>(null);
  const [engines, setEngines] = useState<EngineHealth[]>([]);
  const [threatOverview, setThreatOverview] = useState<{ critical: number; high: number; medium: number; low: number } | null>(null);
  const [trafficHistory, setTrafficHistory] = useState<any[]>([]);

  const loadData = async () => {
    try {
      const [dash, health] = await Promise.all([
        securityApi.getDashboard().catch(() => null),
        securityApi.getSystemHealthDetailed().catch(() => null)
      ]);
      setMetrics(dash?.metrics ?? null);
      if (Array.isArray(health?.services)) {
        setEngines(health.services);
      }
      setThreatOverview(dash?.threatOverview ?? null);
      setTrafficHistory(Array.isArray(dash?.trafficHistory) ? dash.trafficHistory : []);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    if (isBackendOffline) {
      setLoading(false);
      return;
    }

    loadData();

    // Fast polling fallback (every 3 seconds) for real-time guarantee
    const timer = setInterval(loadData, 3000);

    // Live Real-Time WebSocket stream listener
    const unsub = globalRealtimeClient.subscribe((msg: any) => {
      if (!msg) return;
      const type = msg.type || '';
      const data = msg.data || msg;

      if (type === 'system.health' || type === 'system.health_changed') {
        if (Array.isArray(data?.services)) {
          setEngines(data.services);
        }
      } else if (
        type === 'security_event' ||
        type === 'waf.blocked' ||
        type === 'waf.synced' ||
        type === 'log.created' ||
        type === 'rule.updated'
      ) {
        loadData();
      }
    });

    return () => {
      clearInterval(timer);
      unsub();
    };
  }, [currentOrg?.id, isBackendOffline]);

  const engineStatus = (name: string) =>
    engines.find(e => e.service_name === name)?.status || 'Offline';

  const operational = DEFENSE_LAYERS.filter(l => engineStatus(l.engine) === 'Operational').length;
  const needsAttention = DEFENSE_LAYERS.length - operational;

  const num = (value: any) => (metrics ? (value ?? 0).toLocaleString() : '—');

  // Last-hour totals from the per-minute traffic history returned by the dashboard endpoint.
  const hourTotals = trafficHistory.reduce(
    (acc, bucket: any) => ({
      allowed: acc.allowed + (Number(bucket.allowed) || 0),
      suspicious: acc.suspicious + (Number(bucket.suspicious) || 0),
      blocked: acc.blocked + (Number(bucket.blocked) || 0)
    }),
    { allowed: 0, suspicious: 0, blocked: 0 }
  );
  const inspectedLastHour = hourTotals.allowed + hourTotals.suspicious + hourTotals.blocked;
  const share = (value: number) => (inspectedLastHour > 0 ? (value / inspectedLastHour) * 100 : 0);

  const threatSeverityTiles: { label: string; dot: string; value?: number }[] = [
    { label: 'Critical', dot: 'bg-rose-500', value: threatOverview?.critical },
    { label: 'High', dot: 'bg-amber-400', value: threatOverview?.high },
    { label: 'Medium', dot: 'bg-yellow-400', value: threatOverview?.medium },
    { label: 'Low', dot: 'bg-sky-400', value: threatOverview?.low }
  ];

  return (
    <div className="space-y-5 pb-12">
      {/* Page header — dashboard identity: solid FontAwesome glyph so the mark
          reads exactly as heavy as the Overview page, one-line subtitle. */}
      <ModulePageHeader
        icon={<FontAwesomeIcon icon={faShield} />}
        title="Defense in Depth"
        titleTail="Security Architecture"
        subtitle="Five defensive layers monitored in real time, from the network edge to the core data vault."
      />

      {/* Plain summary — four numbers, nothing more. */}
      <div className="grid grid-cols-2 gap-3.5 lg:grid-cols-4">
        <SummaryStat
          label="Active Layers"
          value={`${operational} / ${DEFENSE_LAYERS.length}`}
          note={needsAttention > 0 ? `${needsAttention} ${needsAttention === 1 ? 'needs' : 'need'} attention` : 'All layers operating'}
          dot={operational === DEFENSE_LAYERS.length ? 'bg-emerald-500' : operational > 0 ? 'bg-amber-500' : 'bg-rose-500'}
        />
        <SummaryStat
          label="Protected Applications"
          value={<CountUpNumber value={metrics?.protectedAppsCount ?? 0} />}
          note="Behind the perimeter edge"
        />
        <SummaryStat
          label="Requests Today"
          value={<CountUpNumber value={metrics?.requestsToday ?? 0} />}
          note="Inspected at the network edge"
        />
        <SummaryStat
          label="Blocked Requests"
          value={<CountUpNumber value={metrics?.blockedRequests ?? 0} />}
          note="Blocked by active mitigation"
        />
      </div>

      {/* Layers of defense — one simple row per layer, ordered edge → core. */}
      <section className="rounded-2xl border border-zinc-200/80 dark:border-zinc-800 bg-white dark:bg-[#0c0c0e] overflow-hidden shadow-2xs">
        <header className="px-4 sm:px-5 py-3.5 border-b border-zinc-100 dark:border-zinc-800/80 bg-zinc-50/60 dark:bg-zinc-900/40">
          <h2 className="text-sm font-bold text-zinc-900 dark:text-zinc-100 uppercase tracking-wide truncate">
            Layers of Defense
          </h2>
        </header>

        <div className="divide-y divide-zinc-100 dark:divide-zinc-800/60">
          {DEFENSE_LAYERS.map((d, idx) => {
            const status = engineStatus(d.engine);
            return (
              <div
                key={d.layer}
                className="px-4 sm:px-5 py-4 flex flex-col gap-3 transition md:flex-row md:items-center md:justify-between hover:bg-zinc-50/60 dark:hover:bg-zinc-900/30"
              >
                <div className="flex min-w-0 items-start gap-3.5">
                  <span className="mt-0.5 flex h-8 w-8 shrink-0 items-center justify-center rounded-full border border-zinc-200 text-xs font-semibold text-zinc-500 dark:border-zinc-700 dark:text-zinc-400">
                    {idx + 1}
                  </span>
                  <div className="min-w-0">
                    <div className="flex flex-wrap items-center gap-2">
                      <h3 className="text-base font-semibold text-zinc-900 dark:text-zinc-100">{d.layer}</h3>
                      <span className="inline-flex items-center gap-1.5 text-xs text-zinc-500 dark:text-zinc-400">
                        <span className={`h-1.5 w-1.5 rounded-full ${statusDot(status)}`} />
                        {status}
                      </span>
                    </div>
                    <p className="mt-1 text-[13px] text-zinc-500 dark:text-zinc-400 leading-relaxed">{d.desc}</p>
                    <p className="mt-1.5 text-xs font-mono text-zinc-400 dark:text-zinc-500">
                      {metrics ? d.measured(metrics) : loading ? 'Loading measurement…' : 'No telemetry available'}
                    </p>
                  </div>
                </div>

                <button
                  type="button"
                  onClick={() => onNavigate(d.targetView)}
                  className="shrink-0 self-start inline-flex items-center gap-1.5 rounded-lg border border-zinc-200 bg-white px-3 py-1.5 text-[13px] font-medium text-zinc-600 transition hover:border-zinc-300 hover:text-zinc-900 cursor-pointer dark:border-zinc-700 dark:bg-zinc-900 dark:text-zinc-300 dark:hover:border-zinc-600 dark:hover:text-zinc-100 md:self-auto"
                >
                  Open Module
                  <ArrowRight className="w-3.5 h-3.5" />
                </button>
              </div>
            );
          })}
        </div>
      </section>

      {/* Last-hour activity — traffic split and threats by severity side by side. */}
      <div className="grid gap-3.5 xl:grid-cols-2">
        {/* Traffic in the last hour */}
        <section className="rounded-2xl border border-zinc-200/80 dark:border-zinc-800 bg-white dark:bg-[#0c0c0e] overflow-hidden shadow-2xs">
          <header className="flex items-center justify-between gap-3 px-4 sm:px-5 py-3.5 border-b border-zinc-100 dark:border-zinc-800/80 bg-zinc-50/60 dark:bg-zinc-900/40">
            <h2 className="text-sm font-bold text-zinc-900 dark:text-zinc-100 uppercase tracking-wide truncate">
              Traffic in the Last Hour
            </h2>
            <button
              type="button"
              onClick={() => onNavigate('live-traffic')}
              className="inline-flex h-8 shrink-0 items-center gap-1.5 rounded-lg border border-zinc-200 bg-white px-2.5 text-[13px] font-medium text-zinc-600 transition hover:border-zinc-300 hover:text-zinc-900 cursor-pointer dark:border-zinc-700 dark:bg-zinc-900 dark:text-zinc-300 dark:hover:border-zinc-600 dark:hover:text-zinc-100"
            >
              Open Live Traffic
              <ArrowRight className="w-3.5 h-3.5" />
            </button>
          </header>

          <div className="p-4 sm:p-5">
            <div className="flex items-baseline justify-between">
              <div>
                <div className="text-2xl font-bold tracking-tight text-zinc-900 dark:text-zinc-100 font-mono">
                  {inspectedLastHour.toLocaleString()}
                </div>
                <div className="mt-0.5 text-[13px] text-zinc-400 dark:text-zinc-500">Total requests inspected</div>
              </div>
            </div>

            <div className="mt-4 flex h-3 w-full overflow-hidden rounded-full bg-zinc-100 dark:bg-zinc-800">
              <div
                style={{ width: `${share(hourTotals.allowed)}%` }}
                className="bg-emerald-500 transition-all duration-500"
                title={`Allowed: ${hourTotals.allowed.toLocaleString()}`}
              />
              <div
                style={{ width: `${share(hourTotals.suspicious)}%` }}
                className="bg-amber-400 transition-all duration-500"
                title={`Challenged / Suspicious: ${hourTotals.suspicious.toLocaleString()}`}
              />
              <div
                style={{ width: `${share(hourTotals.blocked)}%` }}
                className="bg-rose-500 transition-all duration-500"
                title={`Blocked: ${hourTotals.blocked.toLocaleString()}`}
              />
            </div>

            <div className="mt-4 grid grid-cols-3 gap-2 pt-2 border-t border-zinc-100 dark:border-zinc-800 text-xs">
              <div>
                <div className="flex items-center gap-1.5 text-[13px] text-zinc-500 dark:text-zinc-400">
                  <span className="h-2 w-2 rounded-full bg-emerald-500" />
                  Allowed
                </div>
                <div className="mt-1 text-base font-semibold text-zinc-900 dark:text-zinc-100 font-mono">
                  {hourTotals.allowed.toLocaleString()}
                </div>
                <div className="text-xs text-zinc-400">{share(hourTotals.allowed).toFixed(1)}%</div>
              </div>
              <div>
                <div className="flex items-center gap-1.5 text-[13px] text-zinc-500 dark:text-zinc-400">
                  <span className="h-2 w-2 rounded-full bg-amber-400" />
                  Challenged
                </div>
                <div className="mt-1 text-base font-semibold text-zinc-900 dark:text-zinc-100 font-mono">
                  {hourTotals.suspicious.toLocaleString()}
                </div>
                <div className="text-xs text-zinc-400">{share(hourTotals.suspicious).toFixed(1)}%</div>
              </div>
              <div>
                <div className="flex items-center gap-1.5 text-[13px] text-zinc-500 dark:text-zinc-400">
                  <span className="h-2 w-2 rounded-full bg-rose-500" />
                  Blocked
                </div>
                <div className="mt-1 text-base font-semibold text-zinc-900 dark:text-zinc-100 font-mono">
                  {hourTotals.blocked.toLocaleString()}
                </div>
                <div className="text-xs text-zinc-400">{share(hourTotals.blocked).toFixed(1)}%</div>
              </div>
            </div>
          </div>
        </section>

        {/* Threats by severity */}
        <section className="rounded-2xl border border-zinc-200/80 dark:border-zinc-800 bg-white dark:bg-[#0c0c0e] overflow-hidden shadow-2xs">
          <header className="flex items-center justify-between gap-3 px-4 sm:px-5 py-3.5 border-b border-zinc-100 dark:border-zinc-800/80 bg-zinc-50/60 dark:bg-zinc-900/40">
            <h2 className="text-sm font-bold text-zinc-900 dark:text-zinc-100 uppercase tracking-wide truncate">
              Threats by Severity
            </h2>
            <button
              type="button"
              onClick={() => onNavigate('threats')}
              className="inline-flex h-8 shrink-0 items-center gap-1.5 rounded-lg border border-zinc-200 bg-white px-2.5 text-[13px] font-medium text-zinc-600 transition hover:border-zinc-300 hover:text-zinc-900 cursor-pointer dark:border-zinc-700 dark:bg-zinc-900 dark:text-zinc-300 dark:hover:border-zinc-600 dark:hover:text-zinc-100"
            >
              Open Threat Monitor
              <ArrowRight className="w-3.5 h-3.5" />
            </button>
          </header>

          <div className="p-4 sm:p-5">
            <div className="grid grid-cols-2 gap-3 sm:grid-cols-4">
              {threatSeverityTiles.map(t => (
                <div
                  key={t.label}
                  className="rounded-xl border border-zinc-200/80 dark:border-zinc-800 bg-zinc-50/50 dark:bg-zinc-900/50 p-3"
                >
                  <div className="flex items-center gap-1.5 text-[13px] text-zinc-500 dark:text-zinc-400">
                    <span className={`h-2 w-2 rounded-full ${t.dot}`} />
                    {t.label}
                  </div>
                  <div className="mt-1.5 text-2xl font-bold tracking-tight text-zinc-900 dark:text-zinc-100 font-mono">
                    {t.value !== undefined ? t.value.toLocaleString() : '—'}
                  </div>
                </div>
              ))}
            </div>

            <div className="mt-4 pt-3 border-t border-zinc-100 dark:border-zinc-800 text-[13px] text-zinc-400 dark:text-zinc-500 flex items-center justify-between">
              <span>Telemetry correlated across DVWA & endpoint agents</span>
              <span className="font-mono text-xs text-zinc-500">Endpoint Agent + WAF Layer</span>
            </div>
          </div>
        </section>
      </div>
    </div>
  );
};
