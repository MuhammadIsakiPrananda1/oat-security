import React, { useState, useEffect, useCallback, useMemo } from 'react';
import { FontAwesomeIcon } from '@fortawesome/react-fontawesome';
import { 
  faTable, 
  faChartLine, 
  faCircleExclamation
} from '@fortawesome/free-solid-svg-icons';
import { securityApi } from '../../services/api';
import { getLanguage } from '../../i18n/translator';

interface WebSecurityMetricItem {
  id: string;
  name: string;
  code: string;
  currentVal: number;
  unit: string;
  target: number;
  targetDirection: 'min' | 'max'; // 'min' = higher is better, 'max' = lower is better
  history: number[]; // 14 data points
  description: string;
}

interface CloudflareEdgeAnalyticsProps {
  /** Realtime tick count from security event updates */
  liveEventTick?: number;
}

const METRIC_TEXTS = {
  https_tls: {
    en: { name: 'HTTPS / TLS Ingress Rate', desc: 'Real ratio of HTTPS/TLS packets (port 443 / TLS ingress).' },
    id: { name: 'HTTPS / TLS Ingress Rate', desc: 'Rasio riil paket HTTPS/TLS (port 443 / TLS ingress).' },
  },
  waf_precision: {
    en: { name: 'WAF Rule Precision', desc: 'WAF mitigation accuracy rate against verified threats.' },
    id: { name: 'Presisi Aturan WAF', desc: 'Tingkat akurasi mitigasi WAF terhadap ancaman terverifikasi.' },
  },
  bot_pass: {
    en: { name: 'Bot & Scanner Filter Rate', desc: 'Interception ratio of automated crawlers and bot scanners.' },
    id: { name: 'Filter Bot & Scanner', desc: 'Rasio penangkapan crawler liar / bot scanner.' },
  },
  origin_shield: {
    en: { name: 'Origin Shield & Cache Rate', desc: 'Ratio of protected requests and origin cache offload.' },
    id: { name: 'Origin Shield & Rasio Cache', desc: 'Rasio permintaan terproteksi & cache offload.' },
  },
  ddos_res: {
    en: { name: 'DDoS Resistance Level', desc: 'L3/L4 hardware DDoS filter defense status.' },
    id: { name: 'Tingkat Ketahanan DDoS', desc: 'Status pertahanan filter hardware DDoS L3/L4.' },
  },
  http2_quic: {
    en: { name: 'HTTP/2 & QUIC Transport Rate', desc: 'Transport connection multiplexing ratio.' },
    id: { name: 'Rasio Transport HTTP/2 & QUIC', desc: 'Rasio multiplexing koneksi transport.' },
  },
};

const DEFAULT_METRICS: WebSecurityMetricItem[] = [
  {
    id: 'https_tls',
    name: 'HTTPS / TLS Ingress Rate',
    code: 'httpsRate',
    currentVal: 99.4,
    unit: '%',
    target: 95.0,
    targetDirection: 'min',
    history: [98.8, 99.0, 99.1, 99.3, 99.2, 99.4, 99.5, 99.3, 99.4, 99.5, 99.4, 99.5, 99.3, 99.4],
    description: 'HTTPS / TLS ingress packet verification ratio.'
  },
  {
    id: 'waf_precision',
    name: 'WAF Rule Precision',
    code: 'wafPrecision',
    currentVal: 99.8,
    unit: '%',
    target: 98.0,
    targetDirection: 'min',
    history: [99.5, 99.6, 99.7, 99.8, 99.7, 99.9, 99.8, 99.7, 99.8, 99.9, 99.8, 99.7, 99.8, 99.8],
    description: 'WAF mitigation accuracy rate against verified threats.'
  },
  {
    id: 'bot_pass',
    name: 'Bot & Scanner Filter Rate',
    code: 'botPassRate',
    currentVal: 94.2,
    unit: '%',
    target: 90.0,
    targetDirection: 'min',
    history: [91.2, 92.4, 93.0, 93.8, 94.5, 93.9, 94.1, 94.0, 93.8, 94.5, 94.1, 94.4, 93.9, 94.2],
    description: 'Interception ratio of automated crawlers and bot scanners.'
  },
  {
    id: 'origin_shield',
    name: 'Origin Shield & Cache Rate',
    code: 'originShieldRate',
    currentVal: 88.6,
    unit: '%',
    target: 80.0,
    targetDirection: 'min',
    history: [85.0, 86.2, 87.1, 88.0, 87.5, 88.3, 89.0, 88.2, 88.5, 89.1, 88.4, 88.8, 88.3, 88.6],
    description: 'Ratio of protected requests and origin cache offload.'
  },
  {
    id: 'ddos_res',
    name: 'DDoS Resistance Level',
    code: 'ddosResistance',
    currentVal: 100.0,
    unit: '%',
    target: 99.0,
    targetDirection: 'min',
    history: [100, 100, 100, 100, 100, 100, 100, 100, 100, 100, 100, 100, 100, 100],
    description: 'L3/L4 hardware DDoS filter defense status.'
  },
  {
    id: 'http2_quic',
    name: 'HTTP/2 & QUIC Transport Rate',
    code: 'http2Rate',
    currentVal: 91.8,
    unit: '%',
    target: 85.0,
    targetDirection: 'min',
    history: [88.5, 89.2, 90.0, 90.8, 91.2, 91.5, 92.0, 91.4, 91.7, 92.1, 91.6, 92.0, 91.5, 91.8],
    description: 'Transport connection multiplexing ratio.'
  }
];

export const CloudflareEdgeAnalytics: React.FC<CloudflareEdgeAnalyticsProps> = ({ liveEventTick = 0 }) => {
  const isId = getLanguage() === 'id';
  const [metrics, setMetrics] = useState<WebSecurityMetricItem[]>(DEFAULT_METRICS);
  const [viewMode, setViewMode] = useState<'chart' | 'table'>('chart');
  const [hoverIndex, setHoverIndex] = useState<number | null>(null);

  // Sync directly from server analytics real-time
  const syncServerAnalytics = useCallback(async () => {
    try {
      const res = await securityApi.getAnalytics();
      const sec = res?.webSecurity;
      if (sec) {
        setMetrics([
          {
            id: 'https_tls',
            name: 'HTTPS / TLS Ingress Rate',
            code: 'httpsRate',
            currentVal: sec.httpsRate,
            unit: '%',
            target: 95.0,
            targetDirection: 'min',
            history: sec.history?.https || DEFAULT_METRICS[0].history,
            description: 'HTTPS / TLS ingress packet verification ratio.'
          },
          {
            id: 'waf_precision',
            name: 'WAF Rule Precision',
            code: 'wafPrecision',
            currentVal: sec.wafPrecision,
            unit: '%',
            target: 98.0,
            targetDirection: 'min',
            history: sec.history?.waf || DEFAULT_METRICS[1].history,
            description: 'WAF mitigation accuracy rate against verified threats.'
          },
          {
            id: 'bot_pass',
            name: 'Bot & Scanner Filter Rate',
            code: 'botPassRate',
            currentVal: sec.botPassRate,
            unit: '%',
            target: 90.0,
            targetDirection: 'min',
            history: sec.history?.bot || DEFAULT_METRICS[2].history,
            description: 'Interception ratio of automated crawlers and bot scanners.'
          },
          {
            id: 'origin_shield',
            name: 'Origin Shield & Cache Rate',
            code: 'originShieldRate',
            currentVal: sec.originShieldRate,
            unit: '%',
            target: 80.0,
            targetDirection: 'min',
            history: sec.history?.origin || DEFAULT_METRICS[3].history,
            description: 'Ratio of protected requests and origin cache offload.'
          },
          {
            id: 'ddos_res',
            name: 'DDoS Resistance Level',
            code: 'ddosResistance',
            currentVal: sec.ddosResistance,
            unit: '%',
            target: 99.0,
            targetDirection: 'min',
            history: sec.history?.ddos || DEFAULT_METRICS[4].history,
            description: 'L3/L4 hardware DDoS filter defense status.'
          },
          {
            id: 'http2_quic',
            name: 'HTTP/2 & QUIC Transport Rate',
            code: 'http2Rate',
            currentVal: sec.http2Rate,
            unit: '%',
            target: 85.0,
            targetDirection: 'min',
            history: sec.history?.http2 || DEFAULT_METRICS[5].history,
            description: 'Transport connection multiplexing ratio.'
          }
        ]);
      }
    } catch {}
  }, []);

  useEffect(() => {
    syncServerAnalytics();
    const interval = setInterval(syncServerAnalytics, 5000);
    return () => clearInterval(interval);
  }, [syncServerAnalytics]);

  useEffect(() => {
    if (liveEventTick > 0) syncServerAnalytics();
  }, [liveEventTick, syncServerAnalytics]);

  // Compute 14 day date labels
  const dateLabels = useMemo(() => {
    const dates: string[] = [];
    const now = new Date();
    for (let i = 13; i >= 0; i--) {
      const d = new Date(now.getTime() - i * 86400000);
      dates.push(d.toLocaleDateString('en-US', { month: 'short', day: 'numeric' }));
    }
    return dates;
  }, []);

  const totalPoints = 14;
  const svgWidth = 260;
  const svgHeight = 48;
  const maxScale = 100;
  const minScale = 50;

  const getX = (idx: number) => (idx / (totalPoints - 1)) * svgWidth;
  const getY = (val: number) => {
    const clamped = Math.max(minScale, Math.min(maxScale, val));
    return svgHeight - ((clamped - minScale) / (maxScale - minScale)) * svgHeight;
  };

  const activeIndex = hoverIndex !== null ? hoverIndex : totalPoints - 1;
  const activeDateLabel = dateLabels[activeIndex] || dateLabels[dateLabels.length - 1];

  // Identify any metric failing the target
  const alertMetric = metrics.find(m => m.currentVal < m.target);

  return (
    <div className="rounded-2xl border border-zinc-200/80 bg-white p-5 shadow-2xs dark:border-zinc-800 dark:bg-[#0c0c0e]">
      {/* Header bar */}
      <div className="flex flex-col sm:flex-row sm:items-start justify-between gap-3 pb-4 border-b border-zinc-200/80 dark:border-zinc-800">
        <div>
          <div className="text-[11px] font-semibold text-zinc-400 dark:text-zinc-500 uppercase tracking-wider">
            {isId ? 'KEAMANAN WEB & PERFORMA PROTOKOL, 14 HARI TERAKHIR' : 'WEB SECURITY & PROTOCOL PERFORMANCE, LAST 14 DAYS'}
          </div>

          <h3 className="mt-1 text-sm sm:text-base font-bold text-zinc-900 dark:text-zinc-100 tracking-tight">
            {alertMetric ? (
              <span>
                <strong className="text-zinc-900 dark:text-white font-extrabold">
                  {METRIC_TEXTS[alertMetric.id as keyof typeof METRIC_TEXTS]?.[isId ? 'id' : 'en']?.name || alertMetric.name}
                </strong>{' '}
                {isId ? 'saat ini berada di bawah ambang batas target' : 'is currently below target threshold'}
              </span>
            ) : (
              <span>
                {isId
                  ? 'Semua metrik keamanan web & protokol beroperasi di atas standar optimal'
                  : 'All web security & protocol metrics are operating above optimal benchmarks'}
              </span>
            )}
          </h3>

          <p className="mt-1 text-xs text-zinc-500 dark:text-zinc-400 leading-relaxed max-w-3xl">
            {isId
              ? 'Telemetri real-time yang mengukur tingkat enkripsi HTTPS edge, mitigasi bot otomatis, akurasi aturan WAF, dan offload protokol transport di seluruh situs terlindungi.'
              : 'Real-time telemetry measuring edge HTTPS encryption rates, automated bot mitigation, WAF rule accuracy, and transport protocol offload across protected websites.'}
          </p>

          <div className="mt-2.5 flex flex-wrap items-center gap-x-4 gap-y-1 text-[11px] text-zinc-400 dark:text-zinc-500 font-mono">
            <span className="flex items-center gap-1.5 text-zinc-700 dark:text-zinc-300">
              <span className="h-0.5 w-3 bg-zinc-800 dark:bg-zinc-200 inline-block" />
              {isId ? 'rasio saat ini' : 'current rate'}
            </span>
            <span className="flex items-center gap-1.5">
              <span className="h-0.5 w-3 border-t border-dashed border-zinc-400 inline-block" />
              {isId ? 'garis dasar benchmark' : 'benchmark baseline'}
            </span>
            <span>
              {isId ? 'Riwayat kurva 14 data point tren telemetri' : '14-point telemetry trend curve history'}
            </span>
          </div>
        </div>

        <div className="flex items-center gap-2 shrink-0">
          <button
            type="button"
            onClick={() => setViewMode(prev => (prev === 'chart' ? 'table' : 'chart'))}
            className="inline-flex h-9 shrink-0 cursor-pointer items-center justify-center gap-2 rounded-lg border border-neutral-200 bg-white px-3.5 text-xs font-medium whitespace-nowrap text-neutral-950 shadow-xs transition-colors duration-150 hover:bg-neutral-50 focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-zinc-950 active:bg-neutral-100 dark:border-neutral-700 dark:bg-neutral-900 dark:text-neutral-50 dark:hover:bg-neutral-800 dark:focus-visible:outline-zinc-50 dark:active:bg-neutral-700"
          >
            <FontAwesomeIcon icon={viewMode === 'chart' ? faTable : faChartLine} className="text-neutral-500 dark:text-neutral-400 text-xs" />
            <span>
              {viewMode === 'chart'
                ? isId ? 'Lihat sebagai tabel' : 'View as table'
                : isId ? 'Lihat sebagai grafik' : 'View as chart'}
            </span>
          </button>
        </div>
      </div>

      {/* Grid of 6 Interactive Scrubbable Security Metric Cards */}
      {viewMode === 'chart' ? (
        <div className="mt-4 grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-3.5">
          {metrics.map(m => {
            const currentScrubbedVal = m.history[activeIndex] ?? m.currentVal;
            const isFailing = currentScrubbedVal < m.target;
            const scrubbedX = getX(activeIndex);
            const scrubbedY = getY(currentScrubbedVal);
            const targetY = getY(m.target);

            const itemText = METRIC_TEXTS[m.id as keyof typeof METRIC_TEXTS]?.[isId ? 'id' : 'en'];
            const metricDisplayName = itemText?.name || m.name;
            const metricDisplayDesc = itemText?.desc || m.description;

            const points = m.history.map((val, i) => `${getX(i).toFixed(1)},${getY(val).toFixed(1)}`);
            const linePath = `M ${points.join(' L ')}`;
            const areaPath = `${linePath} L ${svgWidth},${svgHeight} L 0,${svgHeight} Z`;

            return (
              <div
                key={m.id}
                onMouseLeave={() => setHoverIndex(null)}
                className="rounded-xl border border-zinc-200/80 bg-white p-4 transition hover:border-zinc-300 dark:border-zinc-800/80 dark:bg-[#0c0c0e] dark:hover:border-zinc-700 flex flex-col justify-between select-none"
              >
                <div>
                  <div className="flex items-center justify-between gap-2">
                    <span className="text-xs font-semibold text-zinc-700 dark:text-zinc-300">
                      {metricDisplayName} <span className="text-zinc-400 font-mono text-[11px] font-normal">({m.code})</span>
                    </span>

                    {isFailing ? (
                      <span className="inline-flex items-center gap-1 rounded-md bg-amber-500/10 px-1.5 py-0.5 text-[10px] font-semibold text-amber-700 dark:text-amber-400 border border-amber-500/25">
                        <FontAwesomeIcon icon={faCircleExclamation} className="text-[9px]" />
                        {isId ? 'Di bawah target' : 'Below target'}
                      </span>
                    ) : (
                      <span className="inline-flex items-center gap-1 rounded-md bg-emerald-500/10 px-1.5 py-0.5 text-[10px] font-semibold text-emerald-700 dark:text-emerald-400 border border-emerald-500/20 font-mono">
                        OPTIMAL
                      </span>
                    )}
                  </div>

                  <div className="mt-2 flex items-baseline justify-between">
                    <div className="text-2xl font-bold font-mono tracking-tight text-zinc-900 dark:text-zinc-100">
                      {currentScrubbedVal} <span className="text-xs font-normal text-zinc-400">{m.unit}</span>
                    </div>
                    <span className="text-[11px] font-mono text-zinc-500 dark:text-zinc-400">
                      {activeDateLabel}
                    </span>
                  </div>

                  <p className="mt-1 text-[11px] text-zinc-500 dark:text-zinc-400 leading-snug line-clamp-1">
                    {metricDisplayDesc}
                  </p>
                </div>

                <div className="mt-3 pt-2 relative">
                  <svg
                    className="w-full h-12 overflow-visible cursor-crosshair"
                    viewBox={`0 0 ${svgWidth} ${svgHeight}`}
                    preserveAspectRatio="none"
                  >
                    {/* Benchmark target line */}
                    <line
                      x1={0}
                      y1={targetY}
                      x2={svgWidth}
                      y2={targetY}
                      stroke="currentColor"
                      strokeDasharray="3 3"
                      strokeWidth="1"
                      className="text-zinc-400 dark:text-zinc-600"
                    />

                    {/* Shaded Area */}
                    <path
                      d={areaPath}
                      fill="currentColor"
                      className="text-zinc-100 dark:text-zinc-900/60"
                    />

                    {/* Continuous Trend Line */}
                    <path
                      d={linePath}
                      fill="none"
                      stroke="currentColor"
                      strokeWidth="1.8"
                      strokeLinecap="round"
                      strokeLinejoin="round"
                      className="text-zinc-900 dark:text-zinc-100"
                    />

                    {/* Interactive Vertical Scrubber Line & Point (Seperti di chart Ingress Traffic Recap) */}
                    {hoverIndex !== null && (
                      <>
                        <line
                          x1={scrubbedX}
                          y1={0}
                          x2={scrubbedX}
                          y2={svgHeight}
                          stroke="currentColor"
                          strokeWidth="1"
                          className="text-zinc-400 dark:text-zinc-500"
                        />
                        <circle
                          cx={scrubbedX}
                          cy={scrubbedY}
                          r="3"
                          className="fill-zinc-950 dark:fill-zinc-50 stroke-white dark:stroke-zinc-900 stroke-1"
                        />
                      </>
                    )}

                    {/* Invisible scrubber slices */}
                    {m.history.map((_, i) => {
                      const sliceWidth = svgWidth / totalPoints;
                      const sliceX = Math.max(0, getX(i) - sliceWidth / 2);
                      return (
                        <rect
                          key={i}
                          x={sliceX}
                          y={0}
                          width={sliceWidth}
                          height={svgHeight}
                          fill="transparent"
                          onMouseEnter={() => setHoverIndex(i)}
                          onTouchMove={() => setHoverIndex(i)}
                        />
                      );
                    })}
                  </svg>

                  <div className="mt-2 flex items-center justify-between text-[10px] font-mono text-zinc-400">
                    <span>{dateLabels[0]}</span>
                    <span>{dateLabels[dateLabels.length - 1]}</span>
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
                <th className="py-2.5 px-3.5 font-semibold">{isId ? 'METRIK KEAMANAN' : 'SECURITY METRIC'}</th>
                <th className="py-2.5 px-3.5 font-semibold">{isId ? 'KODE' : 'CODE'}</th>
                <th className="py-2.5 px-3.5 font-semibold text-right">{isId ? 'NILAI' : 'VALUE'}</th>
                <th className="py-2.5 px-3.5 font-semibold text-right">{isId ? 'GARIS DASAR' : 'BASELINE'}</th>
                <th className="py-2.5 px-3.5 font-semibold">{isId ? 'DESKRIPSI' : 'DESCRIPTION'}</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-zinc-100 dark:divide-zinc-800/60">
              {metrics.map(m => {
                const itemText = METRIC_TEXTS[m.id as keyof typeof METRIC_TEXTS]?.[isId ? 'id' : 'en'];
                const metricDisplayName = itemText?.name || m.name;
                const metricDisplayDesc = itemText?.desc || m.description;
                return (
                  <tr key={m.id} className="hover:bg-zinc-50/50 dark:hover:bg-zinc-900/50">
                    <td className="py-2 px-3.5 font-medium text-zinc-900 dark:text-zinc-100">{metricDisplayName}</td>
                    <td className="py-2 px-3.5 text-zinc-400">{m.code}</td>
                    <td className="py-2 px-3.5 text-right font-bold text-zinc-900 dark:text-zinc-100">{m.currentVal} {m.unit}</td>
                    <td className="py-2 px-3.5 text-right text-zinc-400">{m.target} {m.unit}</td>
                    <td className="py-2 px-3.5 text-zinc-500">{metricDisplayDesc}</td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        </div>
      )}
    </div>
  );
};
