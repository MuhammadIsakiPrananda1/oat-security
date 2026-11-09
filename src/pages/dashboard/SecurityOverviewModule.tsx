import React, { useEffect, useState } from 'react';
import { ArrowRight, Activity, Server, Cpu, ShieldCheck, CheckCircle2, AlertTriangle, XCircle, Clock, ShieldAlert } from 'lucide-react';
import { FontAwesomeIcon } from '@fortawesome/react-fontawesome';
import { faShield, faShieldHalved } from '@fortawesome/free-solid-svg-icons';
import { ModulePageHeader } from '../../components/common/ModulePageHeader';
import { DashboardView } from '../../components/layout/DashboardSidebar';
import { securityApi, globalRealtimeClient } from '../../services/api';
import { useAuth } from '../../context/AuthContext';
import { CountUpNumber } from '../../components/common/CountUpNumber';
import { getLanguage } from '../../i18n/translator';
import { useEndpointConnection } from '../../context/EndpointConnectionContext';
import { getSlaInfo } from '../../components/incidents/utils';
import { Incident } from '../../types';

interface SecurityOverviewModuleProps {
  onNavigate: (view: DashboardView) => void;
}

interface EngineMetadata {
  service_name: string;
  category: string;
  desc: string;
  targetView: DashboardView;
}

const ENGINE_ROSTER: EngineMetadata[] = [
  {
    service_name: 'WAF Engine',
    category: 'Application Security',
    desc: 'Real-time HTTP payload inspection and rule matching for Web Application Attacks.',
    targetView: 'waf' as DashboardView
  },
  {
    service_name: 'Next-Gen Firewall',
    category: 'Perimeter Defense',
    desc: 'Network traffic filtering, DDoS mitigation, and edge IP rate limiting.',
    targetView: 'firewall' as DashboardView
  },
  {
    service_name: 'Endpoint Detection',
    category: 'Host Security',
    desc: 'Fleet telemetry ingestion, host behavioral analysis, and threat hunting.',
    targetView: 'agents' as DashboardView
  },
  {
    service_name: 'Database Vault',
    category: 'Data Protection',
    desc: 'Database connection encryption, access auditing, and query inspection.',
    targetView: 'networks' as DashboardView
  },
  {
    service_name: 'API Gateway',
    category: 'Edge Infrastructure',
    desc: 'Authentication gateway, schema validation, and secure service routing.',
    targetView: 'applications' as DashboardView
  },
  {
    service_name: 'SIEM Monitor',
    category: 'Telemetry & Logs',
    desc: 'Unified security event pipeline, correlation engine, and alert dispatches.',
    targetView: 'security-events' as DashboardView
  },
  {
    service_name: 'WebSocket Stream',
    category: 'Real-time Transport',
    desc: 'Low-latency telemetry broadcast channel to active console clients.',
    targetView: 'live-traffic' as DashboardView
  },
  {
    service_name: 'Threat Intel',
    category: 'Threat Intelligence',
    desc: 'Global threat feed correlation, known malicious IP/domain intelligence.',
    targetView: 'threat-intel' as DashboardView
  }
];

interface EngineHealthRecord {
  service_name: string;
  status: string;
  latency_ms: number | null;
  last_check?: string;
  details?: string;
}

const statusDot = (status: string) => {
  if (status === 'Operational') return 'bg-emerald-500';
  if (status === 'Degraded') return 'bg-amber-500';
  return 'bg-rose-500';
};

const statusBadge = (status: string) => {
  if (status === 'Operational') {
    return 'bg-emerald-500/10 text-emerald-600 dark:text-emerald-400 border-emerald-500/20';
  }
  if (status === 'Degraded') {
    return 'bg-amber-500/10 text-amber-600 dark:text-amber-400 border-amber-500/20';
  }
  return 'bg-rose-500/10 text-rose-600 dark:text-rose-400 border-rose-500/20';
};

interface SummaryStatProps {
  label: string;
  value: React.ReactNode;
  note?: string;
  dot?: string;
}

const SummaryStat: React.FC<SummaryStatProps> = ({ label, value, note, dot }) => (
  <div className="relative group rounded-xl border border-zinc-200/80 dark:border-zinc-800 bg-white dark:bg-zinc-900/40 p-4 pl-5 min-h-[144px] flex flex-col justify-between shadow-2xs transition-colors">
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
  const { hasConnectedEndpoints } = useEndpointConnection();
  const [loading, setLoading] = useState(true);
  const [metrics, setMetrics] = useState<any>(null);
  const [engines, setEngines] = useState<EngineHealthRecord[]>([]);
  const [threatOverview, setThreatOverview] = useState<{ critical: number; high: number; medium: number; low: number } | null>(null);
  const [trafficHistory, setTrafficHistory] = useState<any[]>([]);
  const [incidents, setIncidents] = useState<Incident[]>([]);

  const [securityScoreData, setSecurityScoreData] = useState<any>(null);

  const loadData = async () => {
    try {
      const [dash, health, score, incRes] = await Promise.all([
        securityApi.getDashboard().catch(() => null),
        securityApi.getSystemHealthDetailed().catch(() => null),
        securityApi.getSecurityScore().catch(() => null),
        securityApi.getIncidents().catch(() => null)
      ]);
      setMetrics(dash?.metrics ?? null);
      if (Array.isArray(health?.services)) {
        setEngines(health.services);
      }
      setSecurityScoreData(score ?? null);
      if (Array.isArray(incRes?.incidents)) {
        setIncidents(incRes.incidents);
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
        type === 'rule.updated' ||
        type === 'incident.created' ||
        type === 'incident.updated' ||
        type === 'incident.deleted' ||
        type === 'incident.snapshot'
      ) {
        loadData();
      }
    });

    return () => {
      clearInterval(timer);
      unsub();
    };
  }, [currentOrg?.id, isBackendOffline]);

  const engineMap = new Map<string, EngineHealthRecord>(engines.map(e => [e.service_name, e]));
  const operationalCount = ENGINE_ROSTER.filter(
    e => (engineMap.get(e.service_name)?.status || 'Offline') === 'Operational'
  ).length;
  const attentionCount = ENGINE_ROSTER.length - operationalCount;

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

  // SLA Calculation from real incidents
  const totalIncidents = incidents.length;
  const closedIncidents = incidents.filter(i => ['MITIGATED', 'CLOSED', 'RESOLVED'].includes((i.status || '').toUpperCase()));
  const activeIncidents = incidents.filter(i => !['MITIGATED', 'CLOSED', 'RESOLVED'].includes((i.status || '').toUpperCase()));

  const breachedIncidents = activeIncidents.filter(i => {
    const sla = getSlaInfo(i.severity, i.created, i.status, (i.tier as any) || 'L1');
    return sla.isBreached;
  });

  // Server-authoritative real-time SLA metrics with client fallback
  const slaCompliancePct = metrics?.slaCompliancePct !== undefined
    ? metrics.slaCompliancePct
    : totalIncidents > 0
    ? Math.round(((totalIncidents - breachedIncidents.length) / totalIncidents) * 100)
    : 100;

  const breachedIncidentsCount = metrics?.breachedIncidentsCount !== undefined
    ? metrics.breachedIncidentsCount
    : breachedIncidents.length;

  return (
    <div className="space-y-5 pb-12">
      <ModulePageHeader
        icon={<FontAwesomeIcon icon={faShield} />}
        title="Security Infrastructure"
        titleTail="Engine Telemetry"
        subtitle="Real-time operational health and telemetry across core security engines and transport pipelines."
      />

      {/* Summary KPI Cards */}
      <div className="grid grid-cols-2 gap-3.5 lg:grid-cols-4">
        <SummaryStat
          label="SOC SLA Compliance"
          value={`${slaCompliancePct}%`}
          note={
            breachedIncidentsCount > 0
              ? `${breachedIncidentsCount} incident SLA breached`
              : '100% SLA target achieved'
          }
          dot={
            slaCompliancePct >= 95
              ? 'bg-emerald-500'
              : slaCompliancePct >= 80
              ? 'bg-amber-500'
              : 'bg-rose-500'
          }
        />
        <SummaryStat
          label="Protected Applications"
          value={<CountUpNumber value={metrics?.protectedAppsCount ?? 0} />}
          note="Active web applications secured"
        />
        <SummaryStat
          label="All Requests"
          value={<CountUpNumber value={metrics?.requestsToday ?? 0} />}
          note="Inspected at the edge pipeline"
        />
        <SummaryStat
          label="Blocked Requests"
          value={<CountUpNumber value={metrics?.blockedRequests ?? 0} />}
          note="Mitigated threats & anomalies"
        />
      </div>

      {/* Comprehensive Security Posture & Compliance Factors */}
      <section className="rounded-2xl border border-zinc-200/80 dark:border-zinc-800 bg-white dark:bg-[#0c0c0e] overflow-hidden shadow-2xs">
        <header className="px-4 sm:px-5 py-3.5 border-b border-zinc-100 dark:border-zinc-800/80 bg-zinc-50/60 dark:bg-zinc-900/40 flex items-center justify-between">
          <div className="flex items-center gap-2">
            <ShieldCheck className="w-4 h-4 text-emerald-500 dark:text-emerald-400" />
            <h2 className="text-sm font-bold text-zinc-900 dark:text-zinc-100 uppercase tracking-wide truncate">
              Security Posture & Compliance Breakdown
            </h2>
          </div>
          <div className="flex items-center gap-2">
            {securityScoreData?.grade ? (
              <span className="text-xs font-mono font-bold px-2 py-0.5 rounded bg-zinc-100 dark:bg-zinc-800 text-zinc-700 dark:text-zinc-300">
                Grade: {securityScoreData.grade}
              </span>
            ) : null}
            <span className="text-xs font-mono text-zinc-500 dark:text-zinc-400">
              {loading ? 'Evaluating…' : 'Continuous Audit'}
            </span>
          </div>
        </header>

        <div className="p-4 sm:p-5">
          {/* Posture Score & Core Domains */}
          <div className="grid grid-cols-2 sm:grid-cols-3 lg:grid-cols-6 gap-3 pb-5 border-b border-zinc-100 dark:border-zinc-800/80">
            {[
              { label: 'WAF Coverage', val: securityScoreData?.breakdown?.wafCoverage ?? 100, target: 'waf' },
              { label: 'Firewall ACL', val: securityScoreData?.breakdown?.firewallCoverage ?? 100, target: 'firewall' },
              { label: 'Threat Defense', val: securityScoreData?.breakdown?.threatPosture ?? 100, target: 'threats' },
              { label: 'Incident SLA', val: securityScoreData?.breakdown?.incidentResolution ?? 100, target: 'incidents' },
              { label: 'Subsystem Health', val: securityScoreData?.breakdown?.engineHealth ?? 100, target: 'dashboard' },
              { label: 'Auth & MFA', val: securityScoreData?.breakdown?.authSecurity ?? 100, target: 'users-roles' }
            ].map(item => (
                  <div
                    key={item.label}
                    onClick={() => onNavigate(item.target as DashboardView)}
                    className="group p-3 rounded-xl border border-zinc-200/70 dark:border-zinc-800 bg-zinc-50/50 dark:bg-zinc-900/40 hover:border-zinc-300 dark:hover:border-zinc-700 transition cursor-pointer"
                  >
                    <div className="text-[11px] font-medium text-zinc-500 dark:text-zinc-400 truncate flex items-center justify-between">
                      <span>{item.label}</span>
                      <ArrowRight className="w-3 h-3 text-zinc-400 opacity-0 group-hover:opacity-100 transition-opacity" />
                    </div>
                    <div className="mt-1.5 flex items-baseline gap-1">
                      <span className="text-xl font-bold font-mono tracking-tight text-zinc-900 dark:text-zinc-100">
                        {item.val}
                      </span>
                      <span className="text-xs text-zinc-400 font-mono">/100</span>
                    </div>
                    <div className="mt-2 h-1.5 w-full bg-zinc-200 dark:bg-zinc-800 rounded-full overflow-hidden">
                      <div
                        className={`h-full rounded-full transition-all duration-500 ${
                          item.val >= 80 ? 'bg-emerald-500' : item.val >= 50 ? 'bg-amber-500' : 'bg-rose-500'
                        }`}
                        style={{ width: `${Math.min(100, Math.max(0, item.val))}%` }}
                      />
                    </div>
                  </div>
                ))}
              </div>

              {/* Audit Factors Matrix */}
              <div className="mt-4">
                <div className="text-xs font-semibold text-zinc-400 uppercase tracking-wider mb-3">
                  Evaluated Policy & Audit Factors
                </div>
                <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
                  {(securityScoreData?.factors && securityScoreData.factors.length > 0
                    ? securityScoreData.factors
                    : [
                        {
                          name: 'WAF Engine & Policy Coverage',
                          weight: 20,
                          score: securityScoreData?.breakdown?.wafCoverage ?? 100,
                          status: 'Pass',
                          details: 'Active web mitigation rules inspecting all ingress payloads.'
                        },
                        {
                          name: 'Firewall Policy Enforcement',
                          weight: 20,
                          score: securityScoreData?.breakdown?.firewallCoverage ?? 100,
                          status: 'Pass',
                          details: 'Active firewall ACL rules blocking malicious IPs and unauthorised ports.'
                        },
                        {
                          name: 'Active Critical Threats',
                          weight: 25,
                          score: securityScoreData?.breakdown?.threatPosture ?? 100,
                          status: 'Pass',
                          details: 'Zero unmitigated critical threats endangering the web perimeter.'
                        },
                        {
                          name: 'Authentication Security & Account Access',
                          weight: 10,
                          score: securityScoreData?.breakdown?.authSecurity ?? 100,
                          status: 'Pass',
                          details: 'Brute-force protection and account access policies operating optimally.'
                        }
                      ]
                  ).map((f: any, idx: number) => {
                    const isPass = f.status === 'Pass' || f.score >= 80;
                    const isWarn = f.status === 'Warning' || (f.score >= 50 && f.score < 80);
                    return (
                      <div
                        key={idx}
                        className="p-3.5 rounded-xl border border-zinc-200/70 dark:border-zinc-800 bg-white dark:bg-zinc-950/40 flex items-start gap-3"
                      >
                        <div className="mt-0.5 shrink-0">
                          {isPass ? (
                            <CheckCircle2 className="w-4 h-4 text-emerald-500" />
                          ) : isWarn ? (
                            <AlertTriangle className="w-4 h-4 text-amber-500" />
                          ) : (
                            <XCircle className="w-4 h-4 text-rose-500" />
                          )}
                        </div>
                        <div className="min-w-0 flex-1">
                          <div className="flex items-center justify-between gap-2">
                            <span className="text-xs font-semibold text-zinc-900 dark:text-zinc-100 truncate">
                              {f.name}
                            </span>
                            <span
                              className={`text-[10px] font-mono font-semibold px-1.5 py-0.5 rounded border ${
                                isPass
                                  ? 'bg-emerald-500/10 text-emerald-600 dark:text-emerald-400 border-emerald-500/20'
                                  : isWarn
                                  ? 'bg-amber-500/10 text-amber-600 dark:text-amber-400 border-amber-500/20'
                                  : 'bg-rose-500/10 text-rose-600 dark:text-rose-400 border-rose-500/20'
                              }`}
                            >
                              {f.score} / 100
                            </span>
                          </div>
                          <p className="mt-1 text-xs text-zinc-500 dark:text-zinc-400 leading-relaxed">
                            {f.details}
                          </p>
                        </div>
                      </div>
                    );
                  })}
                </div>
              </div>
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
                    {(t.value ?? 0).toLocaleString()}
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
