import React, { useState, useEffect } from 'react';
import { FontAwesomeIcon } from '@fortawesome/react-fontawesome';
import { faBolt, faTable, faChartLine, faCircleExclamation } from '@fortawesome/free-solid-svg-icons';

interface RegionMetric {
  id: string;
  name: string;
  code: string;
  p95: number;
  history: number[]; // 14 days values
  status: 'normal' | 'above';
  target: number;
}

interface CloudflareEdgeAnalyticsProps {
  /** Optional live request counter or events to trigger real-time micro-fluctuations */
  liveEventTick?: number;
}

const REGIONS_INITIAL: RegionMetric[] = [
  {
    id: 'fra1',
    name: 'Frankfurt',
    code: 'fra1',
    p95: 145,
    history: [142, 144, 146, 145, 143, 144, 145, 146, 144, 143, 145, 146, 144, 145],
    status: 'normal',
    target: 250
  },
  {
    id: 'iad1',
    name: 'Virginia',
    code: 'iad1',
    p95: 134,
    history: [136, 135, 134, 133, 135, 134, 138, 136, 135, 133, 134, 135, 133, 134],
    status: 'normal',
    target: 250
  },
  {
    id: 'pdx1',
    name: 'Oregon',
    code: 'pdx1',
    p95: 151,
    history: [148, 150, 153, 151, 149, 152, 150, 151, 153, 149, 150, 152, 150, 151],
    status: 'normal',
    target: 250
  },
  {
    id: 'gru1',
    name: 'São Paulo',
    code: 'gru1',
    p95: 238,
    history: [228, 230, 232, 235, 231, 234, 239, 237, 236, 238, 235, 239, 237, 238],
    status: 'normal',
    target: 250
  },
  {
    id: 'sin1',
    name: 'Singapore',
    code: 'sin1',
    p95: 279,
    history: [242, 246, 252, 258, 263, 268, 271, 274, 276, 275, 277, 278, 276, 279],
    status: 'above',
    target: 250
  },
  {
    id: 'syd1',
    name: 'Sydney',
    code: 'syd1',
    p95: 187,
    history: [184, 186, 185, 183, 185, 186, 188, 187, 185, 186, 188, 187, 186, 187],
    status: 'normal',
    target: 250
  }
];

export const CloudflareEdgeAnalytics: React.FC<CloudflareEdgeAnalyticsProps> = ({ liveEventTick = 0 }) => {
  const [regions, setRegions] = useState<RegionMetric[]>(REGIONS_INITIAL);
  const [viewMode, setViewMode] = useState<'chart' | 'table'>('chart');
  const [lastSyncTime, setLastSyncTime] = useState<string>('Just now');

  // Real-time auto-sync simulation: smoothly updates edge metrics every 5 seconds
  // without needing any user page reload
  useEffect(() => {
    const updateMetrics = () => {
      setRegions(prev =>
        prev.map(r => {
          // Micro variation around genuine p95 (+/- 2ms)
          const delta = (Math.random() - 0.48) * 3;
          const nextVal = Math.max(80, Math.min(300, Math.round(r.p95 + delta)));
          const nextHistory = [...r.history.slice(1), nextVal];
          return {
            ...r,
            p95: nextVal,
            history: nextHistory,
            status: nextVal > r.target ? 'above' : 'normal'
          };
        })
      );
      setLastSyncTime(new Date().toLocaleTimeString('id-ID', { hour: '2-digit', minute: '2-digit', second: '2-digit' }));
    };

    const timer = setInterval(updateMetrics, 4000);
    return () => clearInterval(timer);
  }, []);

  // Also react to liveEventTick when incoming realtime telemetry events arrive
  useEffect(() => {
    if (liveEventTick > 0) {
      setRegions(prev =>
        prev.map(r => {
          const shift = (Math.random() - 0.5) * 2;
          const nextVal = Math.round(Math.max(80, Math.min(300, r.p95 + shift)));
          return {
            ...r,
            p95: nextVal,
            status: nextVal > r.target ? 'above' : 'normal'
          };
        })
      );
    }
  }, [liveEventTick]);

  // Sparkline builder for 0 to 300ms chart
  const renderSparkline = (history: number[], isAbove: boolean) => {
    const width = 260;
    const height = 48;
    const max = 300;
    const targetY = height - (250 / max) * height;

    const points = history.map((val, i) => {
      const x = (i / (history.length - 1)) * width;
      const y = height - (Math.min(max, val) / max) * height;
      return `${x.toFixed(1)},${y.toFixed(1)}`;
    });

    const linePath = `M ${points.join(' L ')}`;
    const areaPath = `${linePath} L ${width},${height} L 0,${height} Z`;

    return (
      <svg className="w-full h-12 overflow-visible select-none" viewBox={`0 0 ${width} ${height}`} preserveAspectRatio="none">
        {/* Target 250ms threshold dashed line */}
        <line
          x1={0}
          y1={targetY}
          x2={width}
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
          className={isAbove ? 'text-amber-500/10 dark:text-amber-400/10' : 'text-zinc-200/70 dark:text-zinc-800/60'}
        />

        {/* Continuous Line */}
        <path
          d={linePath}
          fill="none"
          stroke="currentColor"
          strokeWidth="1.8"
          strokeLinecap="round"
          strokeLinejoin="round"
          className={isAbove ? 'text-amber-600 dark:text-amber-400' : 'text-zinc-800 dark:text-zinc-200'}
        />
      </svg>
    );
  };

  const aboveRegion = regions.find(r => r.status === 'above');

  return (
    <div className="rounded-2xl border border-zinc-200/80 bg-white p-5 shadow-2xs dark:border-zinc-800 dark:bg-[#0c0c0e]">
      {/* Header bar */}
      <div className="flex flex-col sm:flex-row sm:items-start justify-between gap-3 pb-4 border-b border-zinc-200/80 dark:border-zinc-800">
        <div>
          <div className="text-[11px] font-medium text-zinc-400 dark:text-zinc-500 uppercase tracking-wider flex items-center gap-2">
            <span>API latency by region, p95, last 14 days</span>
            <span className="inline-flex items-center gap-1 text-[10px] text-emerald-600 dark:text-emerald-400 font-semibold lowercase">
              <span className="w-1.5 h-1.5 rounded-full bg-emerald-500 animate-pulse" />
              live sync
            </span>
          </div>

          <h3 className="mt-1 text-sm sm:text-base font-bold text-zinc-900 dark:text-zinc-100 tracking-tight">
            {aboveRegion ? (
              <span>
                <strong className="text-zinc-900 dark:text-white font-extrabold">{aboveRegion.name}</strong> is currently above the latency target
              </span>
            ) : (
              <span>All global edge regions are within optimal latency targets</span>
            )}
          </h3>

          <p className="mt-1 text-xs text-zinc-500 dark:text-zinc-400 leading-relaxed max-w-3xl">
            {aboveRegion ? (
              <>
                Its p95 has exceeded 250 ms across recent ingestion windows, currently peaking at{' '}
                <strong className="text-zinc-800 dark:text-zinc-200 font-semibold">{aboveRegion.p95} ms</strong>. Other edge points remain fully compliant under the perimeter SLA.
              </>
            ) : (
              'Global edge routing, DNS resolution, and WAF inspection times are healthy across all regional ingress clusters.'
            )}
          </p>

          <div className="mt-2.5 flex flex-wrap items-center gap-x-4 gap-y-1 text-[11px] text-zinc-400 dark:text-zinc-500 font-mono">
            <span className="flex items-center gap-1.5 text-zinc-700 dark:text-zinc-300">
              <span className="h-0.5 w-3 bg-zinc-800 dark:bg-zinc-200 inline-block" />
              p95 latency
            </span>
            <span className="flex items-center gap-1.5">
              <span className="h-0.5 w-3 border-t border-dashed border-zinc-400 inline-block" />
              250 ms target
            </span>
            <span>Every chart runs from 0 to 300 ms</span>
          </div>
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

      {/* Grid of Regional Cards */}
      {viewMode === 'chart' ? (
        <div className="mt-4 grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-3.5">
          {regions.map(r => {
            const isAbove = r.status === 'above';
            return (
              <div
                key={r.id}
                className="rounded-xl border border-zinc-200/80 bg-zinc-50/50 p-4 transition hover:border-zinc-300 dark:border-zinc-800/80 dark:bg-zinc-900/30 dark:hover:border-zinc-700 flex flex-col justify-between"
              >
                <div>
                  <div className="flex items-center justify-between gap-2">
                    <span className="text-xs font-medium text-zinc-700 dark:text-zinc-300">
                      {r.name} <span className="text-zinc-400 font-mono text-[11px]">{r.code}</span>
                    </span>

                    {isAbove && (
                      <span className="inline-flex items-center gap-1 rounded-md bg-amber-500/10 px-1.5 py-0.5 text-[10px] font-semibold text-amber-700 dark:text-amber-400 border border-amber-500/25">
                        <FontAwesomeIcon icon={faCircleExclamation} className="text-[9px]" />
                        Above target
                      </span>
                    )}
                  </div>

                  <div className="mt-2 flex items-baseline justify-between">
                    <div className="text-2xl font-bold font-mono tracking-tight text-zinc-900 dark:text-zinc-100">
                      {r.p95} <span className="text-xs font-normal text-zinc-400">ms</span>
                    </div>
                    <span className="text-[11px] font-mono text-zinc-400">Live</span>
                  </div>
                </div>

                <div className="mt-3 pt-2">
                  {renderSparkline(r.history, isAbove)}
                  <div className="mt-2 flex items-center justify-between text-[10px] font-mono text-zinc-400">
                    <span>14d ago</span>
                    <span>Today</span>
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
                <th className="py-2.5 px-3.5 font-semibold">REGION</th>
                <th className="py-2.5 px-3.5 font-semibold">POP CODE</th>
                <th className="py-2.5 px-3.5 font-semibold text-right">P95 LATENCY</th>
                <th className="py-2.5 px-3.5 font-semibold text-right">TARGET</th>
                <th className="py-2.5 px-3.5 font-semibold text-center">STATUS</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-zinc-100 dark:divide-zinc-800/60">
              {regions.map(r => (
                <tr key={r.id} className="hover:bg-zinc-50/50 dark:hover:bg-zinc-900/50">
                  <td className="py-2 px-3.5 font-medium text-zinc-900 dark:text-zinc-100">{r.name}</td>
                  <td className="py-2 px-3.5 text-zinc-400">{r.code}</td>
                  <td className="py-2 px-3.5 text-right font-bold text-zinc-900 dark:text-zinc-100">{r.p95} ms</td>
                  <td className="py-2 px-3.5 text-right text-zinc-400">{r.target} ms</td>
                  <td className="py-2 px-3.5 text-center">
                    <span
                      className={`inline-block px-2 py-0.5 rounded text-[10px] font-bold ${
                        r.status === 'above'
                          ? 'bg-amber-500/10 text-amber-600 dark:text-amber-400'
                          : 'bg-emerald-500/10 text-emerald-600 dark:text-emerald-400'
                      }`}
                    >
                      {r.status === 'above' ? 'ABOVE TARGET' : 'OPTIMAL'}
                    </span>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}

      {/* Footer info bar */}
      <div className="mt-4 pt-3 flex flex-wrap items-center justify-between gap-2 text-[11px] text-zinc-400 dark:text-zinc-500 border-t border-zinc-200/80 dark:border-zinc-800 font-mono">
        <span className="flex items-center gap-1.5">
          <FontAwesomeIcon icon={faBolt} className="text-amber-500 text-xs" />
          OAT Cloud Edge · p95 API response times at the edge, real-time sync stream (UTC)
        </span>
        <span>Last synced: {lastSyncTime}</span>
      </div>
    </div>
  );
};

