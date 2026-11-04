import React, { useMemo, useRef, useState, useEffect } from 'react';
import * as d3 from 'd3';
import am5geodata_worldHigh from '@amcharts/amcharts5-geodata/worldHigh';

export interface CountryTrafficData {
  country: string;
  code: string;
  count: number;
  lastAttackIp?: string;
  lastAttackType?: string;
  lastAttackTime?: number;
}

interface CloudflareGeoMapProps {
  data: CountryTrafficData[];
  totalTraffic?: number;
}

interface CountryListPanelProps {
  data: CountryTrafficData[];
  totalTraffic?: number;
}

const formatCount = (num: number): string => {
  if (num >= 1000000) return (num / 1000000).toFixed(1) + 'M';
  if (num >= 1000) return Math.round(num / 1000) + 'k';
  return String(num);
};

interface TooltipState {
  visible: boolean;
  x: number;
  y: number;
  countryName: string;
  count: number;
  lastAttackIp?: string;
  lastAttackType?: string;
  lastAttackTime?: number;
}

const WIDTH = 960;
const HEIGHT = 460;

/**
 * Natural Earth Admin 0 World Map powered by D3.js
 * Crisp vector SVG, instant native hit-testing, zoom & pan, with direct hover over all countries and micro-states.
 */
export const CloudflareGeoMap: React.FC<CloudflareGeoMapProps> = ({ data }) => {
  const svgRef = useRef<SVGSVGElement | null>(null);

  const [hoveredCode, setHoveredCode] = useState<string | null>(null);
  const [tooltip, setTooltip] = useState<TooltipState>({
    visible: false,
    x: 0,
    y: 0,
    countryName: '',
    count: 0
  });

  const activeList = useMemo(() => data ?? [], [data]);

  // Lookup map: ISO2 code -> CountryTrafficData
  const countryMap = useMemo(() => {
    const map = new Map<string, CountryTrafficData>();
    activeList.forEach(item => {
      map.set(item.code.toUpperCase(), item);
    });
    return map;
  }, [activeList]);

  const maxVal = useMemo(() => Math.max(1, ...activeList.map(c => c.count)), [activeList]);

  // Filter features (exclude Antarctica)
  const features = useMemo(() => {
    const raw = (am5geodata_worldHigh as any).features || (am5geodata_worldHigh as any).default?.features || [];
    return raw.filter((f: any) => f.id !== 'AQ');
  }, []);

  // Compute projection and path generator
  const { featureData } = useMemo(() => {
    const projection = d3
      .geoMercator()
      .fitSize([WIDTH, HEIGHT], { type: 'FeatureCollection', features });

    const path = d3.geoPath(projection);

    const fData = features.map((f: any) => {
      const code = String(f.id || '').toUpperCase();
      const rawName = f.properties?.name || code;
      const match = countryMap.get(code);
      const d = path(f) || '';

      return {
        id: code,
        name: match ? match.country : rawName,
        d,
        count: match ? match.count : 0,
        lastAttackIp: match?.lastAttackIp,
        lastAttackType: match?.lastAttackType,
        lastAttackTime: match?.lastAttackTime
      };
    });

    return { featureData: fData };
  }, [features, countryMap]);

  const handlePointerMove = (e: React.PointerEvent, item: { id: string; name: string; count: number; lastAttackIp?: string; lastAttackType?: string; lastAttackTime?: number }) => {
    const rect = svgRef.current?.getBoundingClientRect();
    if (!rect) return;
    setHoveredCode(item.id);
    setTooltip({
      visible: true,
      x: e.clientX - rect.left,
      y: e.clientY - rect.top,
      countryName: item.name,
      count: item.count,
      lastAttackIp: item.lastAttackIp,
      lastAttackType: item.lastAttackType,
      lastAttackTime: item.lastAttackTime
    });
  };

  const handlePointerLeave = () => {
    setHoveredCode(null);
    setTooltip(prev => ({ ...prev, visible: false }));
  };

  return (
    <div className="relative rounded-xl border border-zinc-200/80 dark:border-zinc-800 bg-[#0c0c0e] text-zinc-100 p-4 sm:p-5 shadow-2xs select-none">
      <div className="pb-3 border-b border-zinc-800/80 flex items-center justify-between gap-2">
        <h3 className="text-sm font-semibold tracking-tight text-zinc-200">
          Global Traffic Map
        </h3>
        <div className="flex items-center gap-1.5">
          <span className="w-2 h-2 rounded-full bg-emerald-500 animate-pulse" />
          <span className="text-[10px] font-mono text-emerald-400 tracking-widest">LIVE</span>
        </div>
      </div>

      <div className="relative mt-2 w-full h-[320px] sm:h-[400px] lg:h-[440px] overflow-hidden rounded-lg">
        <svg
          ref={svgRef}
          viewBox={`0 0 ${WIDTH} ${HEIGHT}`}
          className="w-full h-full block"
          onPointerLeave={handlePointerLeave}
        >
          <g>
            {/* Country Polygons */}
            {featureData.map(item => {
              const isHovered = hoveredCode === item.id;
              const hasTraffic = item.count > 0;
              const isTop = item.count === maxVal && hasTraffic;

              let fill = '#27272a'; // zinc-800 default
              let stroke = '#18181b'; // zinc-900 border
              let strokeWidth = 0.5;

              if (hasTraffic) {
                fill = isTop ? '#3b82f6' : '#2563eb';
                stroke = '#60a5fa';
                strokeWidth = 0.8;
              }

              if (isHovered) {
                fill = '#3b82f6';
                stroke = '#93c5fd';
                strokeWidth = 1.2;
              }

              return (
                <path
                  key={item.id}
                  d={item.d}
                  fill={fill}
                  stroke={stroke}
                  strokeWidth={strokeWidth}
                  className="transition-colors duration-150 ease-out cursor-pointer"
                  style={{ vectorEffect: 'non-scaling-stroke' }}
                  onPointerEnter={e => handlePointerMove(e, item)}
                  onPointerMove={e => handlePointerMove(e, item)}
                />
              );
            })}
          </g>
        </svg>

        {/* Custom React Floating Tooltip (Clean: Country Name & Requests) */}
        {tooltip.visible && (
          <div
            className="pointer-events-none absolute z-30 transition-all duration-75"
            style={{
              left: `${tooltip.x}px`,
              top: `${tooltip.y - 12}px`,
              transform: 'translate(-50%, -100%)'
            }}
          >
            <div className="px-3 py-2 rounded-xl bg-zinc-950/95 border border-zinc-700/80 shadow-2xl backdrop-blur-md min-w-[140px] space-y-1">
              <div className="flex items-center justify-between gap-2 border-b border-zinc-800/80 pb-1">
                <span className="font-bold text-white text-xs leading-tight">
                  {tooltip.countryName}
                </span>
                <span className="text-[10px] font-mono px-1.5 py-0.5 rounded bg-zinc-800 text-zinc-300">
                  {hoveredCode}
                </span>
              </div>
              <div className="text-[11px] font-mono">
                {tooltip.count > 0 ? (
                  <div className="flex items-center justify-between text-blue-400 font-medium">
                    <span>Requests</span>
                    <span>{tooltip.count.toLocaleString()}</span>
                  </div>
                ) : (
                  <span className="text-zinc-500">0 requests</span>
                )}
              </div>
            </div>
          </div>
        )}
      </div>
    </div>
  );
};

/**
 * Requests by country List Panel — Displayed cleanly in its own Box under Threat Breakdown
 */
export const CloudflareCountryList: React.FC<CountryListPanelProps> = ({ data }) => {
  const activeList: CountryTrafficData[] = data || [];
  const maxCount = Math.max(1, ...activeList.map(c => c.count));

  return (
    <div className="rounded-xl border border-zinc-200/80 dark:border-zinc-800 bg-zinc-50/40 dark:bg-zinc-900/40 text-zinc-900 dark:text-zinc-100 p-4 shadow-2xs">
      <div className="pb-3 border-b border-zinc-200/80 dark:border-zinc-800 flex items-center justify-between">
        <h3 className="text-sm font-semibold tracking-tight text-zinc-900 dark:text-zinc-200">
          Requests by country
        </h3>
        <span className="text-[10px] font-mono text-zinc-500 dark:text-zinc-400">
          Top Sources
        </span>
      </div>

      <div className="mt-3.5 space-y-2.5 font-sans text-xs">
        {activeList.length === 0 ? (
          <div className="py-6 text-center text-xs text-zinc-400 dark:text-zinc-500">
            No country traffic recorded yet
          </div>
        ) : (
          activeList.slice(0, 8).map(item => {
            const ratio = (item.count / maxCount) * 100;
            const isTop = item.count === maxCount;

            return (
              <div key={item.code} className="flex items-center justify-between gap-3 group">
                <span className="w-24 sm:w-28 truncate text-zinc-700 dark:text-zinc-300 group-hover:text-zinc-900 dark:group-hover:text-white transition">
                  {item.country}
                </span>

                <div className="flex-1 flex items-center gap-3">
                  <div className="flex-1 h-1.5 rounded-full bg-zinc-200 dark:bg-zinc-800/90 overflow-hidden">
                    <div
                      className={`h-full rounded-full transition-all duration-500 ${
                        isTop ? 'bg-[#3b82f6]' : 'bg-[#2563eb]/70'
                      }`}
                      style={{ width: `${Math.max(3, ratio)}%` }}
                    />
                  </div>
                  <span className="w-10 text-right font-mono text-zinc-500 dark:text-zinc-400 text-[11px] group-hover:text-zinc-900 dark:group-hover:text-zinc-200 transition">
                    {formatCount(item.count)}
                  </span>
                </div>
              </div>
            );
          })
        )}
      </div>
    </div>
  );
};
