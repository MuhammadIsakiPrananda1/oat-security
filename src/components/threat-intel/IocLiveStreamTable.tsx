import React from 'react';
import { Search, X, Plus, Ban, ExternalLink, ChevronDown } from 'lucide-react';
import { CountryFlag } from '../common/CountryFlag';
import { ThreatIntelligenceFeed } from './types';
import { formatDateTime } from '../../utils/dateTime';

interface IocLiveStreamTableProps {
  indicators: ThreatIntelligenceFeed[];
  search: string;
  onSearchChange: (value: string) => void;
  typeFilter: string;
  onTypeFilterChange: (type: string) => void;
  statusFilter: string;
  onStatusFilterChange: (status: string) => void;
  onOpenAddModal: () => void;
  onBlockIndicator: (indicator: string) => void;
  onUpdateStatus: (id: string, newStatus: 'Active' | 'Blocked' | 'Monitored') => void;
  onInvestigate: (indicator: string, type: 'ip' | 'domain' | 'url') => void;
  busy: boolean;
}

export const IocLiveStreamTable: React.FC<IocLiveStreamTableProps> = ({
  indicators,
  search,
  onSearchChange,
  typeFilter,
  onTypeFilterChange,
  statusFilter,
  onStatusFilterChange,
  onOpenAddModal,
  onBlockIndicator,
  onUpdateStatus,
  onInvestigate,
  busy
}) => {
  const typeOptions = [
    'ALL',
    'Malicious IP',
    'C2 Server',
    'Phishing Domain',
    'Botnet Node',
    'Cryptominer',
    'Exploit Payload',
    'Malware Hash'
  ];

  return (
    <div className="space-y-4">
      {/* Controls Bar: Search, Dropdowns, Add Button */}
      <div className="flex flex-col md:flex-row items-stretch md:items-center justify-between gap-2.5 p-3 rounded-2xl border border-zinc-200 dark:border-zinc-800 bg-white dark:bg-[#0c0c0e]">
        <div className="relative flex-1">
          <Search className="w-4 h-4 absolute left-3.5 top-1/2 -translate-y-1/2 text-zinc-400 dark:text-zinc-500 pointer-events-none" />
          <input
            type="text"
            value={search}
            onChange={e => onSearchChange(e.target.value)}
            placeholder="Search indicator, tag, country, or feed source..."
            className="w-full pl-10 pr-9 py-2 bg-zinc-50/80 dark:bg-zinc-900/50 border border-zinc-200/90 dark:border-zinc-800 rounded-xl text-xs text-zinc-900 dark:text-zinc-100 placeholder-zinc-400 dark:placeholder-zinc-500 focus:outline-none focus:ring-1 focus:ring-zinc-400 dark:focus:ring-zinc-600 transition shadow-2xs"
          />
          {search && (
            <button
              type="button"
              onClick={() => onSearchChange('')}
              className="absolute right-3 top-1/2 -translate-y-1/2 text-zinc-400 hover:text-zinc-600 dark:hover:text-zinc-200 cursor-pointer p-0.5"
            >
              <X className="w-3.5 h-3.5" />
            </button>
          )}
        </div>

        <div className="flex items-center gap-2 flex-wrap sm:flex-nowrap shrink-0">
          {/* Type Dropdown */}
          <div className="relative flex-1 sm:flex-none">
            <select
              value={typeFilter}
              onChange={e => onTypeFilterChange(e.target.value)}
              className="w-full sm:w-auto appearance-none pl-3.5 pr-8 py-2 bg-zinc-50/80 dark:bg-zinc-900/50 border border-zinc-200/90 dark:border-zinc-800 rounded-xl text-xs font-medium text-zinc-800 dark:text-zinc-200 focus:outline-none focus:ring-1 focus:ring-zinc-400 dark:focus:ring-zinc-600 cursor-pointer shadow-2xs transition"
            >
              {typeOptions.map(t => (
                <option key={t} value={t}>{t === 'ALL' ? 'Type: All' : t}</option>
              ))}
            </select>
            <ChevronDown className="w-3.5 h-3.5 text-zinc-400 absolute right-2.5 top-1/2 -translate-y-1/2 pointer-events-none" />
          </div>

          {/* Status Dropdown */}
          <div className="relative flex-1 sm:flex-none">
            <select
              value={statusFilter}
              onChange={e => onStatusFilterChange(e.target.value)}
              className="w-full sm:w-auto appearance-none pl-3.5 pr-8 py-2 bg-zinc-50/80 dark:bg-zinc-900/50 border border-zinc-200/90 dark:border-zinc-800 rounded-xl text-xs font-medium text-zinc-800 dark:text-zinc-200 focus:outline-none focus:ring-1 focus:ring-zinc-400 dark:focus:ring-zinc-600 cursor-pointer shadow-2xs transition"
            >
              <option value="ALL">Status: All</option>
              <option value="Active">Active</option>
              <option value="Blocked">Blocked</option>
              <option value="Monitored">Monitored</option>
            </select>
            <ChevronDown className="w-3.5 h-3.5 text-zinc-400 absolute right-2.5 top-1/2 -translate-y-1/2 pointer-events-none" />
          </div>

          {/* Add Custom IOC Button — ReadymadeUI primary style */}
          <button
            type="button"
            onClick={onOpenAddModal}
            className="inline-flex h-9 shrink-0 cursor-pointer items-center justify-center gap-2 rounded-lg bg-zinc-950 px-3.5 text-xs font-medium whitespace-nowrap text-white shadow-md transition-colors duration-150 hover:bg-zinc-800 focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-zinc-950 active:bg-zinc-700 disabled:cursor-not-allowed disabled:opacity-50 motion-safe:active:translate-y-px motion-reduce:transition-none dark:bg-zinc-50 dark:text-zinc-950 dark:hover:bg-zinc-200 dark:focus-visible:outline-zinc-50 dark:active:bg-zinc-300 w-full sm:w-auto"
          >
            <Plus className="size-3.5 shrink-0" />
            <span>Add IOC</span>
          </button>
        </div>
      </div>

      {/* Main IOC Container */}
      <div className="rounded-2xl border border-zinc-200/80 dark:border-zinc-800 bg-white dark:bg-[#0c0c0e] overflow-hidden shadow-xs">
        {/* Mobile View: Cards (< md) */}
        <div className="md:hidden divide-y divide-zinc-100 dark:divide-zinc-800/70">
          {indicators.length === 0 ? (
            <div className="p-8 text-center text-xs text-zinc-400">
              No threat indicators match your filter criteria.
            </div>
          ) : (
            indicators.map(ioc => (
              <div key={ioc.id} className="p-4 space-y-2.5">
                <div className="flex items-center justify-between gap-1 flex-wrap">
                  <div className="flex items-center gap-2">
                    {ioc.country && <CountryFlag countryCode={ioc.country} />}
                    <span className="font-mono text-xs font-bold text-zinc-900 dark:text-white select-all">
                      {ioc.indicator}
                    </span>
                  </div>
                  <span className={`px-2 py-0.5 rounded-full text-[10px] font-mono font-bold border ${
                    ioc.status === 'Blocked'
                      ? 'bg-rose-500/10 text-rose-600 dark:text-rose-400 border-rose-500/25'
                      : ioc.status === 'Active'
                      ? 'bg-amber-500/10 text-amber-600 dark:text-amber-400 border-amber-500/25'
                      : 'bg-zinc-100 dark:bg-zinc-800 text-zinc-600 dark:text-zinc-400 border-zinc-200 dark:border-zinc-700'
                  }`}>
                    {ioc.status}
                  </span>
                </div>

                <div className="flex items-center justify-between text-xs text-zinc-500 font-mono">
                  <span>{ioc.type}</span>
                  <div className="flex items-center gap-1.5">
                    <span className="text-[10px] text-zinc-400">Threat Score:</span>
                    <strong className={ioc.threatScore >= 90 ? 'text-rose-600 dark:text-rose-400' : 'text-amber-600'}>
                      {ioc.threatScore}/100
                    </strong>
                  </div>
                </div>

                <div className="flex flex-wrap gap-1">
                  {(ioc.tags || []).map(tag => (
                    <span key={tag} className="px-1.5 py-0.2 rounded bg-zinc-100 dark:bg-zinc-800 text-zinc-600 dark:text-zinc-300 text-[10px] font-mono">
                      #{tag}
                    </span>
                  ))}
                </div>

                <div className="flex items-center justify-between pt-1 text-[11px] font-mono text-zinc-400 border-t border-zinc-100 dark:border-zinc-800/60">
                  <span className="truncate max-w-[180px]" title={ioc.reportedBy}>
                    {ioc.reportedBy}
                  </span>
                  <div className="flex items-center gap-2">
                    <button
                      onClick={() => onInvestigate(
                        ioc.indicator,
                        ioc.type.includes('Domain') ? 'domain' : ioc.type.includes('URL') ? 'url' : 'ip'
                      )}
                      className="text-indigo-600 dark:text-indigo-400 font-medium hover:underline flex items-center gap-0.5"
                    >
                      Investigate <ExternalLink className="w-3 h-3" />
                    </button>
                    {ioc.status !== 'Blocked' && (
                      <button
                        onClick={() => onBlockIndicator(ioc.indicator)}
                        disabled={busy}
                        className="px-2 py-0.5 rounded bg-rose-600 text-white text-[10px] font-semibold"
                      >
                        Block
                      </button>
                    )}
                  </div>
                </div>
              </div>
            ))
          )}
        </div>

        {/* Desktop View: Full Table (>= md) */}
        <div className="hidden md:block overflow-x-auto custom-scrollbar">
          <table className="w-full min-w-[960px] text-left text-xs font-mono">
            <thead className="border-b border-zinc-200 dark:border-zinc-800 bg-zinc-50 dark:bg-zinc-900/40 text-zinc-400 uppercase text-[10px] tracking-wider">
              <tr>
                <th className="p-3">INDICATOR / ENTITY</th>
                <th className="p-3">CLASSIFICATION</th>
                <th className="p-3">THREAT SCORE</th>
                <th className="p-3">CONFIDENCE</th>
                <th className="p-3">TAGS / SECTOR</th>
                <th className="p-3">REPORTED BY</th>
                <th className="p-3">STATUS</th>
                <th className="p-3 text-right">MITIGATION ACTION</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-zinc-100 dark:divide-zinc-800/60">
              {indicators.length === 0 ? (
                <tr>
                  <td colSpan={8} className="p-8 text-center text-zinc-400 font-sans">
                    No threat indicators match the current filters.
                  </td>
                </tr>
              ) : (
                indicators.map(ioc => (
                  <tr key={ioc.id} className="hover:bg-zinc-50 dark:hover:bg-zinc-900/40 transition">
                    <td className="p-3">
                      <div className="flex items-center gap-2 font-bold text-zinc-900 dark:text-zinc-100 select-all">
                        {ioc.country && <CountryFlag countryCode={ioc.country} />}
                        <span className="font-mono">{ioc.indicator}</span>
                      </div>
                      <div className="text-[10px] text-zinc-400 mt-0.5">
                        Last observed: {/^\d{4}-\d{2}-\d{2}/.test(ioc.lastSeen) ? formatDateTime(ioc.lastSeen) : ioc.lastSeen}
                      </div>
                    </td>
                    <td className="p-3">
                      <span className="font-semibold text-zinc-700 dark:text-zinc-300">{ioc.type}</span>
                      {ioc.targetSector && (
                        <div className="text-[10px] text-zinc-400 truncate max-w-[160px]">{ioc.targetSector}</div>
                      )}
                    </td>
                    <td className="p-3 font-bold">
                      <div className="flex items-center gap-1.5">
                        <div className="w-12 h-1.5 rounded-full bg-zinc-200 dark:bg-zinc-800 overflow-hidden">
                          <div
                            className={`h-full ${
                              ioc.threatScore >= 90 ? 'bg-rose-500' : ioc.threatScore >= 75 ? 'bg-amber-500' : 'bg-sky-500'
                            }`}
                            style={{ width: `${ioc.threatScore}%` }}
                          />
                        </div>
                        <span className={ioc.threatScore >= 90 ? 'text-rose-600 dark:text-rose-400' : 'text-amber-600'}>
                          {ioc.threatScore}
                        </span>
                      </div>
                    </td>
                    <td className="p-3">
                      <span className="text-zinc-600 dark:text-zinc-300 font-bold">{ioc.confidence}%</span>
                    </td>
                    <td className="p-3">
                      <div className="flex flex-wrap gap-1 max-w-[200px]">
                        {(ioc.tags || []).slice(0, 3).map(tag => (
                          <span key={tag} className="px-1.5 py-0.2 rounded bg-zinc-100 dark:bg-zinc-800 text-zinc-600 dark:text-zinc-300 text-[10px]">
                            #{tag}
                          </span>
                        ))}
                      </div>
                    </td>
                    <td className="p-3 text-zinc-600 dark:text-zinc-400 max-w-[180px] truncate" title={ioc.reportedBy}>
                      {ioc.reportedBy}
                    </td>
                    <td className="p-3">
                      <span className={`inline-flex px-2 py-0.5 rounded-full text-[10px] font-mono font-bold border ${
                        ioc.status === 'Blocked'
                          ? 'bg-rose-500/10 text-rose-600 dark:text-rose-400 border-rose-500/25'
                          : ioc.status === 'Active'
                          ? 'bg-amber-500/10 text-amber-600 dark:text-amber-400 border-amber-500/25'
                          : 'bg-zinc-100 dark:bg-zinc-800 text-zinc-600 dark:text-zinc-400 border-zinc-200 dark:border-zinc-700'
                      }`}>
                        {ioc.status}
                      </span>
                    </td>
                    <td className="p-3 text-right">
                      <div className="inline-flex items-center gap-1.5">
                        <button
                          onClick={() => onInvestigate(
                            ioc.indicator,
                            ioc.type.includes('Domain') ? 'domain' : ioc.type.includes('URL') ? 'url' : 'ip'
                          )}
                          className="px-2.5 py-1 rounded-md text-[11px] font-medium border border-zinc-200 dark:border-zinc-700 bg-white dark:bg-zinc-800 hover:bg-zinc-50 dark:hover:bg-zinc-700 text-zinc-700 dark:text-zinc-300 cursor-pointer shadow-2xs"
                        >
                          Lookup
                        </button>
                        {ioc.status !== 'Blocked' ? (
                          <button
                            onClick={() => onBlockIndicator(ioc.indicator)}
                            disabled={busy}
                            className="inline-flex items-center gap-1 px-2.5 py-1 rounded-md text-[11px] font-semibold bg-rose-600 hover:bg-rose-500 text-white cursor-pointer shadow-2xs transition"
                            title="Block indicator IP at Perimeter Firewall"
                          >
                            <Ban className="w-3 h-3" />
                            <span>Block IP</span>
                          </button>
                        ) : (
                          <button
                            onClick={() => onUpdateStatus(ioc.id, 'Monitored')}
                            disabled={busy}
                            className="px-2.5 py-1 rounded-md text-[11px] text-zinc-500 hover:text-zinc-700 dark:hover:text-zinc-300 cursor-pointer"
                            title="Unblock indicator"
                          >
                            Unblock
                          </button>
                        )}
                      </div>
                    </td>
                  </tr>
                ))
              )}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  );
};
