import React from 'react';
import { Database, ShieldAlert, Ban, Activity } from 'lucide-react';
import { ThreatIntelStats } from './types';

interface ThreatIntelMetricsProps {
  stats: ThreatIntelStats;
  lastSyncTime?: string;
}

export const ThreatIntelMetrics: React.FC<ThreatIntelMetricsProps> = ({
  stats,
  lastSyncTime
}) => {
  const cards = [
    {
      label: 'Total Threat IOCs',
      value: stats.totalIocs.toLocaleString(),
      sub: 'Multi-feed deduplicated',
      icon: Database,
      tone: 'text-indigo-500 bg-indigo-500/10 border-indigo-500/20'
    },
    {
      label: 'Actively Blocked',
      value: stats.blockedIocs.toLocaleString(),
      sub: 'Enforced at perimeter firewall',
      icon: Ban,
      tone: 'text-rose-500 bg-rose-500/10 border-rose-500/20'
    },
    {
      label: 'Active Feed Sources',
      value: `${stats.activeFeeds} Feeds`,
      sub: 'FS-ISAC, CERTs, AbuseIPDB',
      icon: Activity,
      tone: 'text-sky-500 bg-sky-500/10 border-sky-500/20'
    },
    {
      label: 'Critical CVEs Mitigated',
      value: `${stats.criticalCves} Vulnerabilities`,
      sub: 'Zero-day WAF virtual patches',
      icon: ShieldAlert,
      tone: 'text-amber-500 bg-amber-500/10 border-amber-500/20'
    }
  ];

  return (
    <div className="space-y-3">
      {/* Ingestion context — the live channel chip lives in the page header. */}
      <div className="flex flex-col gap-1 px-1 sm:flex-row sm:items-center sm:justify-between">
        <span className="text-[11px] text-zinc-400 dark:text-zinc-500">
          Indicators are enriched automatically from endpoint-agent telemetry and global feeds.
        </span>
        {lastSyncTime && (
          <span className="text-[11px] font-mono text-zinc-400 dark:text-zinc-500">
            Last feed synchronization: <strong className="font-sans text-zinc-700 dark:text-zinc-300">{lastSyncTime}</strong>
          </span>
        )}
      </div>

      {/* Metrics Cards Grid */}
      <div className="grid grid-cols-2 lg:grid-cols-4 gap-2.5 sm:gap-3.5">
        {cards.map(card => (
          <div
            key={card.label}
            className="p-3.5 sm:p-4 rounded-2xl border border-zinc-200 dark:border-zinc-800 bg-white dark:bg-[#0c0c0e] shadow-xs hover:border-zinc-300 dark:hover:border-zinc-700 transition"
          >
            <div className="flex items-center justify-between mb-2">
              <span className="text-[10px] sm:text-xs font-mono uppercase tracking-wider text-zinc-400 truncate">
                {card.label}
              </span>
              <div className={`w-7 h-7 rounded-lg border flex items-center justify-center shrink-0 ${card.tone}`}>
                <card.icon className="w-3.5 h-3.5" />
              </div>
            </div>
            <div className="text-lg sm:text-2xl font-bold text-zinc-900 dark:text-white tabular-nums tracking-tight">
              {card.value}
            </div>
            <p className="text-[11px] text-zinc-500 dark:text-zinc-400 truncate mt-1">
              {card.sub}
            </p>
          </div>
        ))}
      </div>
    </div>
  );
};
