import React, { useEffect, useMemo, useState } from 'react';
import { RefreshCw, ShieldCheck } from 'lucide-react';
import { securityApi, globalRealtimeClient } from '../../services/api';
import { StatusBadge } from '../../components/common/StatusBadge';
import { FontAwesomeIcon } from '@fortawesome/react-fontawesome';
import { faClipboardCheck } from '@fortawesome/free-solid-svg-icons';
import { ModulePageHeader } from '../../components/common/ModulePageHeader';
import { useAuth } from '../../context/AuthContext';

interface ControlCheck {
  id: string;
  name: string;
  requirement: string;
  measured: string;
  signal: 'operational' | 'degraded' | 'offline' | 'empty';
}

// Every check below is measured from live perimeter telemetry. Nothing on this
// page is a pre-baked certification claim: when an engine stops reporting or no
// telemetry has been ingested yet, the check is reported as such.
export const ComplianceModule: React.FC = () => {
  const { currentOrg, isBackendOffline } = useAuth();
  const [loading, setLoading] = useState(true);
  const [metrics, setMetrics] = useState<any>(null);
  const [health, setHealth] = useState<Array<{ service_name: string; status: string }>>([]);
  const [error, setError] = useState<string | null>(null);

  const load = async () => {
    setLoading(true);
    setError(null);
    try {
      const [dash, sys] = await Promise.all([
        securityApi.getDashboard().catch(() => null),
        securityApi.getSystemHealthDetailed().catch(() => null)
      ]);
      setMetrics(dash?.metrics ?? null);
      setHealth(Array.isArray(sys?.services) ? sys.services : []);
    } catch (err: any) {
      setError(err?.message || 'Failed to load control signals');
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    if (isBackendOffline) return;
    load();
  }, [currentOrg?.id, isBackendOffline]);

  // Real-time WebSocket listener for continuous control signal verification
  useEffect(() => {
    const unsubscribe = globalRealtimeClient.subscribe((msg: any) => {
      const type = msg?.type || '';
      if (
        type.startsWith('security') ||
        type.startsWith('threat') ||
        type.startsWith('incident') ||
        type.startsWith('rule') ||
        type.startsWith('agent') ||
        type.startsWith('system') ||
        type === 'waf.blocked' ||
        type === 'metric.tick'
      ) {
        void load();
      }
    });

    return () => {
      unsubscribe();
    };
  }, []);

  const checks = useMemo<ControlCheck[]>(() => {
    const engineStatus = (name: string): 'operational' | 'degraded' | 'offline' =>
      health.find(s => s.service_name === name)?.status === 'Operational'
        ? 'operational'
        : health.find(s => s.service_name === name)?.status === 'Degraded'
          ? 'degraded'
          : 'offline';

    const m = metrics || {};
    const num = (v: any) => (typeof v === 'number' ? v : 0);
    const events = num(m.securityEventsCount);
    const blocks = num(m.blockedRequests);
    const requests = num(m.requestsToday);

    return [
      {
        id: 'CC-01',
        name: 'Web application firewall enforcement',
        requirement: 'Public-facing applications are shielded against known web attack classes.',
        measured: `${blocks.toLocaleString()} blocked of ${requests.toLocaleString()} requests today`,
        signal: engineStatus('WAF Engine')
      },
      {
        id: 'CC-02',
        name: 'Perimeter firewall & traffic control',
        requirement: 'Inbound and outbound traffic is restricted at the network edge.',
        measured: `${num(m.protectedNetworksCount).toLocaleString()} protected network zones`,
        signal: engineStatus('Next-Gen Firewall')
      },
      {
        id: 'CC-03',
        name: 'Endpoint threat detection & prevention',
        requirement: 'Automated detection of host-level intrusion and web attack attempts is active.',
        measured: `${num(m.activeThreats).toLocaleString()} correlated threat clusters`,
        signal: engineStatus('Endpoint Detection')
      },
      {
        id: 'CC-04',
        name: 'Zero Trust network zoning',
        requirement: 'Workloads are separated into zones with least-privilege reachability.',
        measured: `${num(m.protectedNetworksCount).toLocaleString()} segmented zones · ${num(m.protectedAppsCount).toLocaleString()} protected applications`,
        signal: engineStatus('Database Vault')
      },
      {
        id: 'CC-05',
        name: 'Application & API gateway controls',
        requirement: 'Request routing through the gateway is inspected and rate controlled.',
        measured: `${requests.toLocaleString()} ingress requests recorded`,
        signal: engineStatus('API Gateway')
      },
      {
        id: 'CC-06',
        name: 'Audit logging & SIEM retention',
        requirement: 'Administrative and security events are recorded for audit review.',
        measured: `${events.toLocaleString()} security events ingested`,
        signal: engineStatus('SIEM Monitor')
      }
    ];
  }, [health, metrics]);

  const passed = checks.filter(c => c.signal === 'operational').length;
  const attention = checks.filter(c => c.signal === 'degraded').length;
  const noSignal = checks.filter(c => c.signal === 'offline').length;

  const badgeValue = (signal: ControlCheck['signal']) =>
    signal === 'operational' ? 'Passed' : signal === 'degraded' ? 'Under review' : 'No signal';

  return (
    <div className="space-y-5 pb-12">
      <ModulePageHeader
        icon={<FontAwesomeIcon icon={faClipboardCheck} />}
        title="Regulatory Compliance"
        titleTail="Control Verification"
        subtitle={`Technical control signals measured continuously from live perimeter telemetry${currentOrg?.name ? ` for ${currentOrg.name}` : ''}. Formal certification requires an external audit attestation — this page reports the measured state only.`}
        actions={
          <span className="inline-flex items-center gap-1.5 text-[10px] font-mono px-2 py-1 rounded-lg bg-emerald-500/10 text-emerald-600 dark:text-emerald-400 border border-emerald-500/20 font-semibold">
            <span className="w-1.5 h-1.5 rounded-full bg-emerald-500 animate-pulse" />
            LIVE TELEMETRY SIGNALS
          </span>
        }
      />

      {/* Summary */}
      <div className="grid grid-cols-2 gap-3.5 sm:grid-cols-3">
        {[
          { label: 'Controls Verifying', value: passed, tone: 'text-emerald-600 dark:text-emerald-400' },
          { label: 'Needs Attention', value: attention, tone: 'text-zinc-900 dark:text-white' },
          { label: 'No Signal', value: noSignal, tone: 'text-rose-600 dark:text-rose-400' }
        ].map(card => (
          <div key={card.label} className="p-4 rounded-xl border border-zinc-200/80 dark:border-zinc-800 bg-white dark:bg-zinc-900/40">
            <div className="text-[11px] font-semibold tracking-wider text-zinc-500 dark:text-slate-400 uppercase">{card.label}</div>
            <div className={`text-2xl font-bold font-mono mt-1.5 ${card.tone}`}>{card.value}</div>
            <div className="text-[11px] text-zinc-400 dark:text-slate-500 mt-0.5">of {checks.length} monitored controls</div>
          </div>
        ))}
      </div>

      {error && (
        <div className="p-3 rounded-xl border border-rose-500/25 bg-rose-500/10 text-rose-600 dark:text-rose-400 text-xs">
          {error}
        </div>
      )}

      {/* Control verification list */}
      <section className="rounded-2xl border border-zinc-200/80 dark:border-zinc-800 bg-white dark:bg-[#0c0c0e] overflow-hidden transition-colors">
        <header className="px-4 sm:px-5 py-3 border-b border-zinc-100 dark:border-zinc-800/80 bg-zinc-50/60 dark:bg-zinc-900/40 flex flex-wrap items-center justify-between gap-x-4 gap-y-2">
          <div className="flex items-center gap-2.5 min-w-0">
            <span className="text-[11px] font-mono font-semibold text-zinc-500 dark:text-zinc-400 border border-zinc-200 dark:border-zinc-700 rounded px-1.5 py-0.5 bg-white dark:bg-zinc-800 shadow-2xs shrink-0">
              01
            </span>
            <h2 className="text-sm font-semibold text-zinc-900 dark:text-zinc-100 uppercase tracking-wide truncate">
              Continuous Control Verification
            </h2>
          </div>
          <span className="text-[11px] text-zinc-400 dark:text-zinc-500 shrink-0">
            Measured {loading ? '…' : 'just now'} · refreshes on open
          </span>
        </header>

        <div className="divide-y divide-zinc-100 dark:divide-zinc-800/60">
          {checks.map(check => (
            <div
              key={check.id}
              className="px-4 sm:px-5 py-4 flex flex-col md:flex-row md:items-center justify-between gap-4 hover:bg-zinc-50 dark:hover:bg-zinc-800/40 transition"
            >
              <div className="min-w-0 space-y-1.5">
                <div className="flex items-center gap-2 flex-wrap">
                  <span className="text-[11px] font-mono font-semibold text-zinc-500 dark:text-zinc-400 border border-zinc-200 dark:border-zinc-700 rounded px-1.5 py-0.5 bg-white dark:bg-zinc-800 shrink-0">
                    {check.id}
                  </span>
                  <span className="text-sm font-semibold text-zinc-900 dark:text-zinc-100">{check.name}</span>
                </div>
                <p className="text-xs text-zinc-500 dark:text-slate-400">{check.requirement}</p>
                <p className="text-[11px] font-mono text-zinc-400 dark:text-slate-500">Measured: {check.measured}</p>
              </div>

              <div className="shrink-0">
                <StatusBadge type="status" value={badgeValue(check.signal)} />
              </div>
            </div>
          ))}
        </div>

        <footer className="px-4 sm:px-5 py-3 border-t border-zinc-100 dark:border-zinc-800/80 bg-zinc-50/60 dark:bg-zinc-900/40 flex items-center gap-2 text-[11px] text-zinc-400 dark:text-slate-500">
          <ShieldCheck className="w-3.5 h-3.5 text-zinc-500 dark:text-slate-400" />
          <span>
            Signals are derived from the live health probe and ingestion counters — no static
            certification data is stored on this page.
          </span>
        </footer>
      </section>
    </div>
  );
};
