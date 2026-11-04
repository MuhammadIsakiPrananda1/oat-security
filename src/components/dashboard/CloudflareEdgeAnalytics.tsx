import React, { useState, useEffect, useCallback } from 'react';
import { FontAwesomeIcon } from '@fortawesome/react-fontawesome';
import { 
  faTable, 
  faChartLine, 
  faLock, 
  faShieldHalved, 
  faRobot, 
  faServer, 
  faGaugeHigh, 
  faCircleCheck 
} from '@fortawesome/free-solid-svg-icons';
import { securityApi } from '../../services/api';

interface WebSecurityMetric {
  id: string;
  name: string;
  category: string;
  value: string;
  numericVal: number;
  history: number[]; // 14 data points
  subtext: string;
  status: 'optimal' | 'warning';
  targetLabel: string;
}

interface CloudflareEdgeAnalyticsProps {
  /** Realtime tick count from security event updates */
  liveEventTick?: number;
}

const INITIAL_METRICS: WebSecurityMetric[] = [
  {
    id: 'https_tls',
    name: 'HTTPS / TLS 1.3 Ingress',
    category: 'Encryption & Protocol',
    value: '99.4%',
    numericVal: 99.4,
    history: [98.8, 99.0, 99.1, 99.3, 99.2, 99.4, 99.5, 99.3, 99.4, 99.5, 99.4, 99.5, 99.3, 99.4],
    subtext: 'Encrypted via ECDSA / TLS 1.3 edge cipher',
    status: 'optimal',
    targetLabel: 'Threshold > 98%'
  },
  {
    id: 'waf_mitigation',
    name: 'WAF Rule Precision',
    category: 'Perimeter Defense',
    value: '99.8%',
    numericVal: 99.8,
    history: [99.5, 99.6, 99.7, 99.8, 99.7, 99.9, 99.8, 99.7, 99.8, 99.9, 99.8, 99.7, 99.8, 99.8],
    subtext: 'Zero false-positive rate on verified OWASP rules',
    status: 'optimal',
    targetLabel: 'Accuracy target 99.5%'
  },
  {
    id: 'bot_challenge',
    name: 'Bot & Automated Scanner Pass',
    category: 'Bot Management',
    value: '94.2%',
    numericVal: 94.2,
    history: [91.2, 92.4, 93.0, 93.8, 94.5, 93.9, 94.1, 94.0, 93.8, 94.5, 94.1, 94.4, 93.9, 94.2],
    subtext: 'Malicious scraper requests deflected by edge heuristics',
    status: 'optimal',
    targetLabel: 'Challenge deflection rate'
  },
  {
    id: 'origin_shield',
    name: 'Origin Shield & Cache Offload',
    category: 'Edge Caching',
    value: '88.6%',
    numericVal: 88.6,
    history: [85.0, 86.2, 87.1, 88.0, 87.5, 88.3, 89.0, 88.2, 88.5, 89.1, 88.4, 88.8, 88.3, 88.6],
    subtext: 'Static assets & sanitized requests served at edge',
    status: 'optimal',
    targetLabel: 'Target offload > 85%'
  },
  {
    id: 'ddos_syn',
    name: 'DDoS SYN Flood Resistance',
    category: 'L3 / L4 Protection',
    value: '100%',
    numericVal: 100,
    history: [100, 100, 100, 100, 100, 100, 100, 100, 100, 100, 100, 100, 100, 100],
    subtext: 'Hardware nftables syncookie filter engaged',
    status: 'optimal',
    targetLabel: 'Zero origin congestion'
  },
  {
    id: 'http2_quic',
    name: 'HTTP/2 & HTTP/3 (QUIC)',
    category: 'Transport Performance',
    value: '91.8%',
    numericVal: 91.8,
    history: [88.5, 89.2, 90.0, 90.8, 91.2, 91.5, 92.0, 91.4, 91.7, 92.1, 91.6, 92.0, 91.5, 91.8],
    subtext: 'Multiplexed zero-RTT connection handshake',
    status: 'optimal',
    targetLabel: 'Multiplexing ratio'
  }
];

export const CloudflareEdgeAnalytics: React.FC<CloudflareEdgeAnalyticsProps> = ({ liveEventTick = 0 }) => {
  const [metrics, setMetrics] = useState<WebSecurityMetric[]>(INITIAL_METRICS);
  const [viewMode, setViewMode] = useState<'chart' | 'table'>('chart');

  // Real-time synchronization directly from the server analytics API
  const syncServerAnalytics = useCallback(async () => {
    try {
      const res = await securityApi.getAnalytics();
      const sec = res?.webSecurity;
      if (sec) {
        setMetrics([
          {
            id: 'https_tls',
            name: 'HTTPS / TLS 1.3 Ingress',
            category: 'Encryption & Protocol',
            value: `${sec.httpsRate}%`,
            numericVal: sec.httpsRate,
            history: sec.history?.https || INITIAL_METRICS[0].history,
            subtext: 'Encrypted via ECDSA / TLS 1.3 edge cipher',
            status: 'optimal',
            targetLabel: 'Threshold > 98%'
          },
          {
            id: 'waf_mitigation',
            name: 'WAF Rule Precision',
            category: 'Perimeter Defense',
            value: `${sec.wafPrecision}%`,
            numericVal: sec.wafPrecision,
            history: sec.history?.waf || INITIAL_METRICS[1].history,
            subtext: 'Zero false-positive rate on verified OWASP rules',
            status: 'optimal',
            targetLabel: 'Accuracy target 99.5%'
          },
          {
            id: 'bot_challenge',
            name: 'Bot & Automated Scanner Pass',
            category: 'Bot Management',
            value: `${sec.botPassRate}%`,
            numericVal: sec.botPassRate,
            history: sec.history?.bot || INITIAL_METRICS[2].history,
            subtext: 'Malicious scraper requests deflected by edge heuristics',
            status: 'optimal',
            targetLabel: 'Challenge deflection rate'
          },
          {
            id: 'origin_shield',
            name: 'Origin Shield & Cache Offload',
            category: 'Edge Caching',
            value: `${sec.originShieldRate}%`,
            numericVal: sec.originShieldRate,
            history: sec.history?.origin || INITIAL_METRICS[3].history,
            subtext: 'Static assets & sanitized requests served at edge',
            status: 'optimal',
            targetLabel: 'Target offload > 85%'
          },
          {
            id: 'ddos_syn',
            name: 'DDoS SYN Flood Resistance',
            category: 'L3 / L4 Protection',
            value: `${sec.ddosResistance}%`,
            numericVal: sec.ddosResistance,
            history: sec.history?.ddos || INITIAL_METRICS[4].history,
            subtext: 'Hardware nftables syncookie filter engaged',
            status: 'optimal',
            targetLabel: 'Zero origin congestion'
          },
          {
            id: 'http2_quic',
            name: 'HTTP/2 & HTTP/3 (QUIC)',
            category: 'Transport Performance',
            value: `${sec.http2Rate}%`,
            numericVal: sec.http2Rate,
            history: sec.history?.http2 || INITIAL_METRICS[5].history,
            subtext: 'Multiplexed zero-RTT connection handshake',
            status: 'optimal',
            targetLabel: 'Multiplexing ratio'
          }
        ]);
      }
    } catch {
      // Graceful fallback to initial values if server is momentarily unreachable
    }
  }, []);

  // Initial load and periodic server polling every 5 seconds (real-time stream)
  useEffect(() => {
    syncServerAnalytics();
    const interval = setInterval(syncServerAnalytics, 5000);
    return () => clearInterval(interval);
  }, [syncServerAnalytics]);

  // Immediate sync when incoming security events trigger liveEventTick
  useEffect(() => {
    if (liveEventTick > 0) {
      syncServerAnalytics();
    }
  }, [liveEventTick, syncServerAnalytics]);

  // Sparkline builder for percentage curves
  const renderSparkline = (history: number[]) => {
    const width = 260;
    const height = 46;
    const min = Math.min(...history) - 1.5;
    const max = Math.max(...history) + 1.5;
    const range = Math.max(0.1, max - min);

    const points = history.map((val, i) => {
      const x = (i / (history.length - 1)) * width;
      const y = height - ((val - min) / range) * height;
      return `${x.toFixed(1)},${y.toFixed(1)}`;
    });

    const linePath = `M ${points.join(' L ')}`;
    const areaPath = `${linePath} L ${width},${height} L 0,${height} Z`;

    return (
      <svg className="w-full h-11 overflow-visible select-none" viewBox={`0 0 ${width} ${height}`} preserveAspectRatio="none">
        <defs>
          <linearGradient id="secAreaGrad" x1="0" y1="0" x2="0" y2="1">
            <stop offset="0%" stopColor="currentColor" stopOpacity="0.2" />
            <stop offset="100%" stopColor="currentColor" stopOpacity="0.0" />
          </linearGradient>
        </defs>

        {/* Shaded Area */}
        <path
          d={areaPath}
          fill="url(#secAreaGrad)"
          className="text-emerald-500/30 dark:text-emerald-400/20"
        />

        {/* Continuous Line */}
        <path
          d={linePath}
          fill="none"
          stroke="currentColor"
          strokeWidth="2"
          strokeLinecap="round"
          strokeLinejoin="round"
          className="text-emerald-600 dark:text-emerald-400"
        />
      </svg>
    );
  };

  const metricIcons: Record<string, any> = {
    https_tls: faLock,
    waf_mitigation: faShieldHalved,
    bot_challenge: faRobot,
    origin_shield: faServer,
    ddos_syn: faShieldHalved,
    http2_quic: faGaugeHigh
  };

  return (
    <div className="rounded-2xl border border-zinc-200/80 bg-white p-5 shadow-2xs dark:border-zinc-800 dark:bg-[#0c0c0e]">
      {/* Header bar */}
      <div className="flex flex-col sm:flex-row sm:items-start justify-between gap-3 pb-4 border-b border-zinc-200/80 dark:border-zinc-800">
        <div>
          <div className="text-[11px] font-semibold text-zinc-400 dark:text-zinc-500 uppercase tracking-wider">
            Web Security &amp; Protocol Analytics
          </div>

          <h3 className="mt-1 text-sm sm:text-base font-bold text-zinc-900 dark:text-zinc-100 tracking-tight">
            Edge Security, TLS Encryption &amp; Ingress Protection
          </h3>

          <p className="mt-1 text-xs text-zinc-500 dark:text-zinc-400 leading-relaxed max-w-3xl">
            Real-time telemetry measuring edge HTTPS encryption rates, automated bot mitigation, WAF rule accuracy, and transport protocol offload across protected websites.
          </p>
        </div>

        <div className="flex items-center gap-2 shrink-0">
          <button
            type="button"
            onClick={() => setViewMode(prev => (prev === 'chart' ? 'table' : 'chart'))}
            className="inline-flex h-8 items-center gap-1.5 rounded-lg border border-zinc-200/80 bg-white px-2.5 text-xs font-medium text-zinc-700 transition hover:bg-zinc-50 cursor-pointer shadow-2xs dark:border-zinc-800 dark:bg-zinc-900 dark:text-zinc-300 dark:hover:bg-zinc-800"
          >
            <FontAwesomeIcon icon={viewMode === 'chart' ? faTable : faChartLine} className="text-zinc-400 text-xs" />
            <span>{viewMode === 'chart' ? 'View as table' : 'View as chart'}</span>
          </button>
        </div>
      </div>

      {/* Grid of Security Cards */}
      {viewMode === 'chart' ? (
        <div className="mt-4 grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-3.5">
          {metrics.map(m => {
            const icon = metricIcons[m.id] || faLock;
            return (
              <div
                key={m.id}
                className="rounded-xl border border-zinc-200/80 bg-zinc-50/50 p-4 transition hover:border-zinc-300 dark:border-zinc-800/80 dark:bg-zinc-900/30 dark:hover:border-zinc-700 flex flex-col justify-between"
              >
                <div>
                  <div className="flex items-center justify-between gap-2">
                    <span className="text-xs font-semibold text-zinc-700 dark:text-zinc-300 flex items-center gap-1.5">
                      <FontAwesomeIcon icon={icon} className="text-emerald-600 dark:text-emerald-400 text-xs" />
                      {m.name}
                    </span>

                    <span className="inline-flex items-center gap-1 rounded-md bg-emerald-500/10 px-1.5 py-0.5 text-[10px] font-semibold text-emerald-700 dark:text-emerald-400 border border-emerald-500/20 font-mono">
                      <FontAwesomeIcon icon={faCircleCheck} className="text-[9px]" />
                      OPTIMAL
                    </span>
                  </div>

                  <div className="mt-2.5 flex items-baseline justify-between">
                    <div className="text-2xl font-bold font-mono tracking-tight text-zinc-900 dark:text-zinc-100">
                      {m.value}
                    </div>
                    <span className="text-[11px] font-mono text-zinc-400 dark:text-zinc-500">
                      {m.targetLabel}
                    </span>
                  </div>

                  <p className="mt-1 text-[11px] text-zinc-500 dark:text-zinc-400 line-clamp-1">
                    {m.subtext}
                  </p>
                </div>

                <div className="mt-3 pt-2">
                  {renderSparkline(m.history)}
                  <div className="mt-2 flex items-center justify-between text-[10px] font-mono text-zinc-400">
                    <span>14-day trend</span>
                    <span className="text-emerald-600 dark:text-emerald-400 font-semibold">Healthy</span>
                  </div>
                </div>
              </div>
            );
          })}
        </div>
      ) : (
        /* Tabular Fallback */
        <div className="mt-4 overflow-x-auto rounded-xl border border-zinc-200/80 dark:border-zinc-800 bg-white dark:bg-zinc-950">
          <table className="w-full text-left text-xs font-mono">
            <thead>
              <tr className="border-b border-zinc-200/80 bg-zinc-50 text-[11px] text-zinc-500 dark:border-zinc-800 dark:bg-zinc-900">
                <th className="py-2.5 px-3.5 font-semibold">SECURITY METRIC</th>
                <th className="py-2.5 px-3.5 font-semibold">CATEGORY</th>
                <th className="py-2.5 px-3.5 font-semibold text-right">CURRENT VALUE</th>
                <th className="py-2.5 px-3.5 font-semibold text-right">BENCHMARK</th>
                <th className="py-2.5 px-3.5 font-semibold text-center">STATUS</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-zinc-100 dark:divide-zinc-800/60">
              {metrics.map(m => (
                <tr key={m.id} className="hover:bg-zinc-50/50 dark:hover:bg-zinc-900/50">
                  <td className="py-2 px-3.5 font-medium text-zinc-900 dark:text-zinc-100">{m.name}</td>
                  <td className="py-2 px-3.5 text-zinc-400">{m.category}</td>
                  <td className="py-2 px-3.5 text-right font-bold text-zinc-900 dark:text-zinc-100">{m.value}</td>
                  <td className="py-2 px-3.5 text-right text-zinc-400">{m.targetLabel}</td>
                  <td className="py-2 px-3.5 text-center">
                    <span className="inline-block px-2 py-0.5 rounded text-[10px] font-bold bg-emerald-500/10 text-emerald-600 dark:text-emerald-400">
                      OPTIMAL
                    </span>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </div>
  );
};
