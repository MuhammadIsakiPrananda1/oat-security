import React from 'react';
import { FileText, ShieldAlert, Users, TrendingUp, Search, X, Download, ChevronRight, BookOpen } from 'lucide-react';
import { StatusBadge } from '../common/StatusBadge';
import { IncidentAuditRow, SocTier } from './types';
import { SOC_TIER_META } from './constants';
import { formatAuditTime, formatDeclaredDate, statusChip } from './utils';

interface IncidentAuditTrailProps {
  auditRows: IncidentAuditRow[];
  auditStats: {
    total: number;
    incidentsCovered: number;
    analysts: number;
    escalations: number;
  };
  auditSearch: string;
  onAuditSearchChange: (value: string) => void;
  auditTier: 'ALL' | SocTier;
  onAuditTierChange: (tier: 'ALL' | SocTier) => void;
  onExportCsv: () => void;
  onSelectIncident: (id: string) => void;
}

export const IncidentAuditTrail: React.FC<IncidentAuditTrailProps> = ({
  auditRows,
  auditStats,
  auditSearch,
  onAuditSearchChange,
  auditTier,
  onAuditTierChange,
  onExportCsv,
  onSelectIncident
}) => {
  return (
    <div className="space-y-4 animate-fadeIn">
      {/* Ringkasan audit */}
      <div className="grid grid-cols-2 lg:grid-cols-4 gap-2.5 sm:gap-3">
        {[
          { label: 'Audit Events', value: auditStats.total, icon: FileText, tone: 'text-zinc-500' },
          { label: 'Incidents Covered', value: auditStats.incidentsCovered, icon: ShieldAlert, tone: 'text-indigo-500' },
          { label: 'Analysts Involved', value: auditStats.analysts, icon: Users, tone: 'text-sky-500' },
          { label: 'Escalations Logged', value: auditStats.escalations, icon: TrendingUp, tone: 'text-amber-500' }
        ].map(card => (
          <div
            key={card.label}
            className="p-3 sm:p-4 rounded-xl sm:rounded-2xl border border-zinc-200 dark:border-zinc-800 bg-white dark:bg-[#0c0c0e] shadow-xs"
          >
            <div className="flex items-center gap-1.5 text-[10px] font-mono uppercase tracking-wider text-zinc-400">
              <card.icon className={`w-3.5 h-3.5 ${card.tone}`} />
              <span className="truncate">{card.label}</span>
            </div>
            <div className="text-lg sm:text-xl font-bold text-zinc-900 dark:text-white mt-1 tabular-nums">{card.value}</div>
          </div>
        ))}
      </div>

      {/* Filter & ekspor */}
      <div className="flex flex-col sm:flex-row items-stretch sm:items-center justify-between gap-2.5 sm:gap-3 p-2.5 sm:p-3 rounded-xl border border-zinc-200 dark:border-zinc-800 bg-white dark:bg-[#0c0c0e]">
        <div className="relative flex-1 max-w-md">
          <Search className="w-3.5 h-3.5 absolute left-3 top-1/2 -translate-y-1/2 text-zinc-400" />
          <input
            type="text"
            value={auditSearch}
            onChange={e => onAuditSearchChange(e.target.value)}
            placeholder="Search incident, actor, or audit note..."
            className="w-full pl-9 pr-8 py-1.5 bg-zinc-50 dark:bg-zinc-900/60 border border-zinc-200 dark:border-zinc-800 rounded-lg text-xs text-zinc-900 dark:text-white placeholder-zinc-400 focus:outline-none"
          />
          {auditSearch && (
            <button onClick={() => onAuditSearchChange('')} className="absolute right-2.5 top-1/2 -translate-y-1/2 text-zinc-400 hover:text-zinc-600 cursor-pointer">
              <X className="w-3.5 h-3.5" />
            </button>
          )}
        </div>

        <div className="flex flex-col sm:flex-row items-stretch sm:items-center gap-2">
          <div className="grid grid-cols-4 sm:flex items-center bg-zinc-100 dark:bg-zinc-900 p-0.5 rounded-lg border border-zinc-200 dark:border-zinc-800 text-xs w-full sm:w-auto text-center">
            {(['ALL', 'L1', 'L2', 'L3'] as const).map(tier => (
              <button
                key={tier}
                onClick={() => onAuditTierChange(tier)}
                className={`px-2.5 py-1 rounded-md transition cursor-pointer text-xs ${
                  auditTier === tier
                    ? 'bg-white dark:bg-zinc-800 text-zinc-900 dark:text-white font-bold shadow-xs'
                    : 'text-zinc-500'
                }`}
              >
                {tier === 'ALL' ? 'All Tiers' : tier}
              </button>
            ))}
          </div>

          <button
            onClick={onExportCsv}
            disabled={auditRows.length === 0}
            className="inline-flex items-center justify-center gap-1.5 px-3 py-1.5 rounded-lg border border-zinc-200 dark:border-zinc-800 bg-white dark:bg-zinc-900 text-xs font-medium text-zinc-700 dark:text-zinc-300 hover:bg-zinc-50 dark:hover:bg-zinc-800 disabled:opacity-50 cursor-pointer shadow-xs w-full sm:w-auto"
          >
            <Download className="w-3.5 h-3.5 text-zinc-500" />
            <span>Export CSV</span>
          </button>
        </div>
      </div>

      {/* Tabel jejak audit dengan Mobile Card View */}
      <div className="rounded-2xl border border-zinc-200 dark:border-zinc-800 bg-white dark:bg-[#0c0c0e] overflow-hidden shadow-xs">
        {/* Mobile Card List (< md) */}
        <div className="md:hidden divide-y divide-zinc-100 dark:divide-zinc-800/70">
          {auditRows.length === 0 ? (
            <div className="p-8 text-center text-xs text-zinc-400">
              No audit entries match the current filters.
            </div>
          ) : (
            auditRows.map((row, idx) => {
              const tierMeta = SOC_TIER_META[row.tier];
              return (
                <div
                  key={`${row.incidentId}-${idx}`}
                  onClick={() => onSelectIncident(row.incidentId)}
                  className="p-3.5 space-y-2 hover:bg-zinc-50 dark:hover:bg-zinc-900/40 cursor-pointer active:bg-zinc-100 dark:active:bg-zinc-800/60 transition-colors"
                >
                  <div className="flex items-center justify-between gap-1 flex-wrap text-[11px] font-mono text-zinc-400">
                    <span>{formatAuditTime(row.time)}</span>
                    <div className="flex items-center gap-1.5">
                      <span className={`inline-flex px-1.5 py-0.2 rounded border text-[10px] font-mono font-bold ${tierMeta.badgeStyle}`}>
                        {row.tier}
                      </span>
                      <StatusBadge type="severity" value={row.severity} size="sm" />
                      <span className={`inline-flex px-1.5 py-0.2 rounded border text-[10px] font-mono ${statusChip(row.status)}`}>
                        {row.status}
                      </span>
                    </div>
                  </div>

                  <div>
                    <span className="font-mono text-[10px] text-zinc-400 block">{row.incidentId}</span>
                    <h4 className="text-xs font-semibold text-zinc-800 dark:text-zinc-200 leading-snug">
                      {row.title}
                    </h4>
                  </div>

                  <div className="text-xs text-zinc-700 dark:text-zinc-300 bg-zinc-50 dark:bg-zinc-900/60 p-2.5 rounded-lg border border-zinc-100 dark:border-zinc-800/60 leading-relaxed break-words">
                    {row.note}
                  </div>

                  <div className="text-[10px] font-mono text-zinc-400 flex items-center justify-between pt-0.5">
                    <span className="truncate max-w-[200px]">Actor: <strong className="text-zinc-600 dark:text-zinc-300 font-sans">{row.author}</strong></span>
                    <span className="text-indigo-600 dark:text-indigo-400 font-semibold flex items-center gap-0.5 shrink-0">
                      Timeline <ChevronRight className="w-3 h-3" />
                    </span>
                  </div>
                </div>
              );
            })
          )}
        </div>

        {/* Desktop Table View (>= md) */}
        <div className="hidden md:block overflow-x-auto custom-scrollbar">
          <table className="w-full min-w-[920px] text-left text-xs">
            <thead className="bg-zinc-50 dark:bg-zinc-900/60 border-b border-zinc-200 dark:border-zinc-800">
              <tr className="text-[10px] font-mono uppercase tracking-wider text-zinc-400">
                <th className="px-4 py-2.5 font-semibold whitespace-nowrap">Timestamp</th>
                <th className="px-4 py-2.5 font-semibold">Incident</th>
                <th className="px-4 py-2.5 font-semibold">Tier</th>
                <th className="px-4 py-2.5 font-semibold">Severity</th>
                <th className="px-4 py-2.5 font-semibold">Status</th>
                <th className="px-4 py-2.5 font-semibold">Actor</th>
                <th className="px-4 py-2.5 font-semibold">Audit Note</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-zinc-100 dark:divide-zinc-800/70">
              {auditRows.length === 0 ? (
                <tr>
                  <td colSpan={7} className="px-4 py-10 text-center text-zinc-400">
                    No audit entries match the current filters.
                  </td>
                </tr>
              ) : (
                auditRows.map((row, idx) => {
                  const tierMeta = SOC_TIER_META[row.tier];
                  return (
                    <tr
                      key={`${row.incidentId}-${idx}`}
                      onClick={() => onSelectIncident(row.incidentId)}
                      className="hover:bg-zinc-50 dark:hover:bg-zinc-900/40 cursor-pointer align-top transition-colors"
                    >
                      <td className="px-4 py-2.5 whitespace-nowrap font-mono text-[11px] text-zinc-500 dark:text-zinc-400">
                        {formatAuditTime(row.time)}
                      </td>
                      <td className="px-4 py-2.5">
                        <div className="font-mono text-[10px] text-zinc-400">{row.incidentId}</div>
                        <div className="font-semibold text-zinc-800 dark:text-zinc-200 max-w-[240px] truncate" title={row.title}>
                          {row.title}
                        </div>
                        <div className="text-[10px] text-zinc-400 mt-0.5">Declared {formatDeclaredDate(row.declaredAt)}</div>
                      </td>
                      <td className="px-4 py-2.5">
                        <span className={`inline-flex px-1.5 py-0.5 rounded border text-[10px] font-mono font-bold ${tierMeta.badgeStyle}`}>
                          {row.tier}
                        </span>
                      </td>
                      <td className="px-4 py-2.5">
                        <StatusBadge type="severity" value={row.severity} size="sm" />
                      </td>
                      <td className="px-4 py-2.5">
                        <span className={`inline-flex px-1.5 py-0.5 rounded border text-[10px] font-mono ${statusChip(row.status)}`}>
                          {row.status}
                        </span>
                      </td>
                      <td className="px-4 py-2.5 font-mono text-[11px] text-zinc-500 dark:text-zinc-400 max-w-[180px] truncate" title={row.author}>
                        {row.author}
                      </td>
                      <td className="px-4 py-2.5 text-zinc-700 dark:text-zinc-300 max-w-[360px] break-words">
                        {row.note}
                      </td>
                    </tr>
                  );
                })
              )}
            </tbody>
          </table>
        </div>
      </div>

      <p className="text-[11px] text-zinc-400 dark:text-zinc-500 flex items-center gap-1.5">
        <BookOpen className="w-3.5 h-3.5 shrink-0" />
        Every status change, escalation, containment action and analyst note is recorded automatically. Click a row to open the incident timeline.
      </p>
    </div>
  );
};
