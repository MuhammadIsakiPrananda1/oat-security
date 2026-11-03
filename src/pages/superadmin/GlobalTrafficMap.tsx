import React, { useEffect, useRef, useState, useMemo } from 'react';

// ─── Types ───────────────────────────────────────────────────────────────────

interface TrafficDot {
  id: number;
  x: number;       // SVG x (0–1000)
  y: number;       // SVG y (0–500)
  cx: number;      // screen x (%)
  cy: number;      // screen y (%)
  country: string;
  ip: string;
  type: 'attack' | 'block' | 'normal';
  age: number;     // ms since spawn
  maxAge: number;
}

interface LiveEvent {
  id: number;
  time: string;
  ip: string;
  country: string;
  type: 'attack' | 'block' | 'normal';
  threat: string;
}

// ─── Geo hotspots (approximate SVG coords on equirectangular map 1000×500) ───

const GEO_NODES: { label: string; x: number; y: number; region: string }[] = [
  { label: 'US-East',     x: 250,  y: 195, region: 'North America' },
  { label: 'US-West',     x: 140,  y: 200, region: 'North America' },
  { label: 'Brazil',      x: 300,  y: 330, region: 'South America' },
  { label: 'UK',          x: 480,  y: 155, region: 'Europe' },
  { label: 'Germany',     x: 510,  y: 155, region: 'Europe' },
  { label: 'Russia',      x: 580,  y: 135, region: 'Europe' },
  { label: 'India',       x: 660,  y: 245, region: 'Asia' },
  { label: 'China',       x: 730,  y: 195, region: 'Asia' },
  { label: 'Japan',       x: 795,  y: 190, region: 'Asia' },
  { label: 'Singapore',   x: 745,  y: 285, region: 'Asia' },
  { label: 'Australia',   x: 800,  y: 370, region: 'Oceania' },
  { label: 'Nigeria',     x: 508,  y: 280, region: 'Africa' },
  { label: 'S.Africa',    x: 540,  y: 360, region: 'Africa' },
  { label: 'Korea',       x: 775,  y: 190, region: 'Asia' },
  { label: 'Indonesia',   x: 757,  y: 305, region: 'Asia' },
  { label: 'Egypt',       x: 563,  y: 225, region: 'Africa' },
];

const THREATS = ['SQL Injection', 'XSS Payload', 'DDoS Flood', 'Brute Force', 'RCE Attempt', 'Path Traversal', 'CSRF Token', 'Bot Crawl', 'Port Scan'];

let _dotId = 0;
let _evtId = 0;

function randGeo() {
  return GEO_NODES[Math.floor(Math.random() * GEO_NODES.length)];
}

function randIp() {
  return `${Math.floor(Math.random() * 255)}.${Math.floor(Math.random() * 255)}.${Math.floor(Math.random() * 255)}.${Math.floor(Math.random() * 255)}`;
}

function randType(): TrafficDot['type'] {
  const r = Math.random();
  return r < 0.35 ? 'attack' : r < 0.55 ? 'block' : 'normal';
}

function spawnDot(): TrafficDot {
  const geo = randGeo();
  // scatter around node ±30px
  const jx = (Math.random() - 0.5) * 60;
  const jy = (Math.random() - 0.5) * 40;
  return {
    id: ++_dotId,
    x: geo.x + jx,
    y: geo.y + jy,
    cx: ((geo.x + jx) / 1000) * 100,
    cy: ((geo.y + jy) / 500) * 100,
    country: geo.label,
    ip: randIp(),
    type: randType(),
    age: 0,
    maxAge: 2400 + Math.random() * 1600,
  };
}

function spawnEvent(dot: TrafficDot): LiveEvent {
  return {
    id: ++_evtId,
    time: new Date().toLocaleTimeString('en-US', { hour12: false }),
    ip: dot.ip,
    country: dot.country,
    type: dot.type,
    threat: THREATS[Math.floor(Math.random() * THREATS.length)],
  };
}

const TYPE_COLOR: Record<TrafficDot['type'], { dot: string; ring: string; badge: string }> = {
  attack: { dot: '#ef4444', ring: '#ef444466', badge: 'bg-rose-500/15 text-rose-400 border-rose-500/30' },
  block:  { dot: '#f59e0b', ring: '#f59e0b55', badge: 'bg-amber-500/15 text-amber-400 border-amber-500/30' },
  normal: { dot: '#10b981', ring: '#10b98155', badge: 'bg-emerald-500/15 text-emerald-400 border-emerald-500/30' },
};

// ─── Component ───────────────────────────────────────────────────────────────

export const GlobalTrafficMap: React.FC = () => {
  const [dots, setDots] = useState<TrafficDot[]>([]);
  const [events, setEvents] = useState<LiveEvent[]>([]);
  const [tick, setTick] = useState(0);
  const [stats, setStats] = useState({ attacks: 0, blocked: 0, normal: 0 });
  const animRef = useRef<number | null>(null);
  const lastRef = useRef<number>(0);
  const spawnAccRef = useRef<number>(0);
  const statsRef = useRef({ attacks: 0, blocked: 0, normal: 0 });

  useEffect(() => {
    let frame: number;
    function loop(ts: number) {
      const dt = lastRef.current ? Math.min(ts - lastRef.current, 100) : 16;
      lastRef.current = ts;
      spawnAccRef.current += dt;

      setDots(prev => {
        let next = prev
          .map(d => ({ ...d, age: d.age + dt }))
          .filter(d => d.age < d.maxAge);

        // Spawn 1–2 dots every ~350ms
        const spawnInterval = 350;
        while (spawnAccRef.current >= spawnInterval) {
          spawnAccRef.current -= spawnInterval;
          const count = Math.random() < 0.4 ? 2 : 1;
          for (let i = 0; i < count; i++) {
            const nd = spawnDot();
            next = [...next, nd];

            // Emit live event only for attacks/blocks
            if (nd.type !== 'normal') {
              const ev = spawnEvent(nd);
              if (nd.type === 'attack') statsRef.current.attacks++;
              else statsRef.current.blocked++;
              setEvents(evs => [ev, ...evs].slice(0, 30));
            } else {
              statsRef.current.normal++;
            }
          }
        }

        return next.slice(-80); // cap at 80 dots
      });

      setTick(t => t + 1);
      frame = requestAnimationFrame(loop);
    }

    frame = requestAnimationFrame(loop);
    animRef.current = frame;

    // Sync stats every 500ms
    const statsTimer = setInterval(() => {
      setStats({ ...statsRef.current });
    }, 500);

    return () => {
      cancelAnimationFrame(frame);
      clearInterval(statsTimer);
    };
  }, []);

  // Suppress unused tick warning — used to force re-render
  void tick;

  return (
    <div className="rounded-2xl border border-zinc-200/80 dark:border-zinc-800 bg-white dark:bg-[#0c0c0e] overflow-hidden shadow-xs">
      {/* Header */}
      <div className="px-4 sm:px-5 py-3.5 border-b border-zinc-100 dark:border-zinc-800/80 flex flex-col sm:flex-row sm:items-center justify-between gap-2">
        <div className="flex items-center gap-2.5">
          <span className="relative flex h-2 w-2">
            <span className="animate-ping absolute inline-flex h-full w-full rounded-full bg-emerald-400 opacity-75" />
            <span className="relative inline-flex rounded-full h-2 w-2 bg-emerald-500" />
          </span>
          <h2 className="text-xs font-bold text-zinc-900 dark:text-white uppercase tracking-wider">
            Global Traffic Map
          </h2>
          <span className="text-[10px] font-mono text-zinc-400 dark:text-zinc-500">LIVE</span>
        </div>
        {/* Mini stats */}
        <div className="flex items-center gap-2 text-[10px] font-mono">
          <span className="px-2 py-0.5 rounded-full border bg-rose-500/10 text-rose-400 border-rose-500/25">
            ↑ {stats.attacks.toLocaleString()} attacks
          </span>
          <span className="px-2 py-0.5 rounded-full border bg-amber-500/10 text-amber-400 border-amber-500/25">
            ⊗ {stats.blocked.toLocaleString()} blocked
          </span>
          <span className="px-2 py-0.5 rounded-full border bg-emerald-500/10 text-emerald-400 border-emerald-500/25">
            ✓ {stats.normal.toLocaleString()} clean
          </span>
        </div>
      </div>

      <div className="flex flex-col lg:flex-row">
        {/* ── Map Canvas ── */}
        <div className="relative flex-1 min-h-0 overflow-hidden bg-zinc-950 dark:bg-[#050507]" style={{ minHeight: 260 }}>
          {/* World map SVG background */}
          <svg
            viewBox="0 0 1000 500"
            className="w-full h-full opacity-25"
            aria-hidden
          >
            {/* Simplified world landmasses as paths */}
            {/* North America */}
            <path d="M80,120 L200,100 L280,130 L310,180 L280,240 L240,270 L190,290 L150,260 L100,240 L70,200 Z" fill="#52525b" />
            {/* South America */}
            <path d="M220,290 L310,285 L340,320 L330,390 L290,430 L250,420 L210,370 L200,320 Z" fill="#52525b" />
            {/* Europe */}
            <path d="M460,110 L560,100 L590,130 L570,170 L510,175 L470,155 Z" fill="#52525b" />
            {/* Africa */}
            <path d="M470,195 L570,195 L590,230 L570,310 L530,370 L490,375 L460,320 L450,260 Z" fill="#52525b" />
            {/* Asia */}
            <path d="M580,90 L820,80 L860,150 L820,220 L750,260 L680,260 L630,230 L590,180 L570,140 Z" fill="#52525b" />
            {/* India */}
            <path d="M635,230 L695,230 L700,290 L665,310 L635,275 Z" fill="#52525b" />
            {/* SE Asia */}
            <path d="M720,255 L790,255 L790,310 L750,330 L720,300 Z" fill="#52525b" />
            {/* Australia */}
            <path d="M750,330 L880,325 L890,400 L820,430 L750,400 L730,370 Z" fill="#52525b" />
            {/* Scandinavia */}
            <path d="M500,80 L540,75 L545,105 L510,115 Z" fill="#52525b" />
            {/* UK */}
            <path d="M463,125 L480,120 L480,145 L462,148 Z" fill="#52525b" />
          </svg>

          {/* Grid lines */}
          <svg
            viewBox="0 0 1000 500"
            className="absolute inset-0 w-full h-full opacity-[0.04]"
            aria-hidden
          >
            {/* Latitude lines */}
            {[100,200,300,400].map(y => (
              <line key={`h${y}`} x1={0} y1={y} x2={1000} y2={y} stroke="#6366f1" strokeWidth="1" />
            ))}
            {/* Longitude lines */}
            {[100,200,300,400,500,600,700,800,900].map(x => (
              <line key={`v${x}`} x1={x} y1={0} x2={x} y2={500} stroke="#6366f1" strokeWidth="1" />
            ))}
          </svg>

          {/* Static city nodes */}
          <svg viewBox="0 0 1000 500" className="absolute inset-0 w-full h-full" aria-hidden>
            {GEO_NODES.map(n => (
              <g key={n.label}>
                <circle cx={n.x} cy={n.y} r={2.5} fill="#6366f1" opacity={0.6} />
                <circle cx={n.x} cy={n.y} r={5} fill="none" stroke="#6366f1" strokeWidth={0.5} opacity={0.3} />
              </g>
            ))}
          </svg>

          {/* Live traffic dots */}
          <svg viewBox="0 0 1000 500" className="absolute inset-0 w-full h-full" aria-hidden>
            {dots.map(dot => {
              const progress = dot.age / dot.maxAge;
              const opacity = progress < 0.15
                ? progress / 0.15
                : progress > 0.75
                ? 1 - (progress - 0.75) / 0.25
                : 1;
              const c = TYPE_COLOR[dot.type];
              const pulseR = 4 + (1 - Math.cos(dot.age / 200)) * 3;

              return (
                <g key={dot.id} opacity={opacity}>
                  {/* Outer pulse ring */}
                  <circle
                    cx={dot.x} cy={dot.y}
                    r={pulseR * 2}
                    fill={c.ring}
                    opacity={0.4 * (1 - progress)}
                  />
                  {/* Core dot */}
                  <circle
                    cx={dot.x} cy={dot.y}
                    r={3.5}
                    fill={c.dot}
                  />
                </g>
              );
            })}
          </svg>

          {/* Legend */}
          <div className="absolute bottom-2 left-3 flex items-center gap-3 text-[9px] font-mono">
            <span className="flex items-center gap-1"><span className="w-1.5 h-1.5 rounded-full bg-rose-500 inline-block" /> Attack</span>
            <span className="flex items-center gap-1"><span className="w-1.5 h-1.5 rounded-full bg-amber-500 inline-block" /> Blocked</span>
            <span className="flex items-center gap-1"><span className="w-1.5 h-1.5 rounded-full bg-emerald-500 inline-block" /> Clean</span>
          </div>

          {/* Dot count badge */}
          <div className="absolute top-2 right-3 text-[9px] font-mono text-zinc-500 dark:text-zinc-600">
            {dots.length} active traces
          </div>
        </div>

        {/* ── Live Event Feed ── */}
        <div className="w-full lg:w-64 xl:w-72 border-t lg:border-t-0 lg:border-l border-zinc-100 dark:border-zinc-800/80 flex flex-col">
          <div className="px-3 py-2 border-b border-zinc-100 dark:border-zinc-800/80 flex items-center justify-between">
            <span className="text-[10px] font-bold uppercase tracking-wider text-zinc-500 dark:text-zinc-400">
              Live Threat Feed
            </span>
            <span className="text-[9px] font-mono text-zinc-400">{events.length} events</span>
          </div>
          <div className="flex-1 overflow-y-auto custom-scrollbar max-h-64 lg:max-h-none divide-y divide-zinc-100/60 dark:divide-zinc-800/40">
            {events.length === 0 ? (
              <div className="py-8 text-center text-[10px] text-zinc-400">Waiting for events...</div>
            ) : (
              events.map(ev => {
                const c = TYPE_COLOR[ev.type];
                return (
                  <div key={ev.id} className="px-3 py-2 hover:bg-zinc-50 dark:hover:bg-zinc-900/30 transition">
                    <div className="flex items-center justify-between gap-1 mb-0.5">
                      <span className={`text-[9px] font-semibold px-1.5 py-0.5 rounded border ${c.badge}`}>
                        {ev.type.toUpperCase()}
                      </span>
                      <span className="text-[9px] font-mono text-zinc-400">{ev.time}</span>
                    </div>
                    <div className="text-[10px] font-semibold text-zinc-800 dark:text-zinc-200 truncate">{ev.threat}</div>
                    <div className="text-[9px] font-mono text-zinc-400 mt-0.5 flex gap-1.5">
                      <span>{ev.ip}</span>
                      <span>·</span>
                      <span>{ev.country}</span>
                    </div>
                  </div>
                );
              })
            )}
          </div>
        </div>
      </div>
    </div>
  );
};

