import React, { useState } from 'react';
import { Search, X, ShieldCheck, Server, Clock, ChevronRight, ChevronDown, Check } from 'lucide-react';
import { StatusBadge } from '../common/StatusBadge';
import { Incident, IncidentSection, AssetOption } from './types';
import { SOC_TIER_META } from './constants';

import { getIncidentTier, getSlaInfo, statusChip, severityBorder } from './utils';

interface IncidentQueueListProps {
  incidents: Incident[];
  activeSection: IncidentSection;
  search: string;
  onSearchChange: (value: string) => void;
  filterStatus: 'ALL' | 'ACTIVE' | 'RESOLVED';
  onFilterStatusChange: (status: 'ALL' | 'ACTIVE' | 'RESOLVED') => void;
  onSelectIncident: (id: string) => void;
  totalSectionCount: number;
  assets?: AssetOption[];
}

export const IncidentQueueList: React.FC<IncidentQueueListProps> = ({
  incidents,
  activeSection,
  search,
  onSearchChange,
  filterStatus,
  onFilterStatusChange,
  onSelectIncident,
  totalSectionCount,
  assets = []
}) => {
  const [showStatusDropdown, setShowStatusDropdown] = useState(false);

  const statusOptions: { id: 'ALL' | 'ACTIVE' | 'RESOLVED'; label: string }[] = [
    { id: 'ALL', label: `Status: All (${totalSectionCount})` },
    { id: 'ACTIVE', label: 'Status: Active Only' },
    { id: 'RESOLVED', label: 'Status: Resolved' },
  ];

  const activeLabel = statusOptions.find(o => o.id === filterStatus)?.label || `Status: All (${totalSectionCount})`;
  return (
    <div className="space-y-4 animate-fadeIn">
      {/* Banner Deskripsi Bagian Khusus jika di tab L1, L2, atau L3 */}
      {activeSection !== 'ALL' && activeSection !== 'GUIDE' && activeSection !== 'AUDIT' && (
        <div className={`p-3.5 sm:p-4 rounded-2xl border ${SOC_TIER_META[activeSection].badgeStyle} flex flex-col sm:flex-row items-start sm:items-center justify-between gap-2.5 sm:gap-3`}>
          <div className="space-y-0.5">
            <div className="text-xs font-bold font-mono uppercase tracking-wider flex items-center gap-1.5">
              {React.createElement(SOC_TIER_META[activeSection].icon, { className: 'w-4 h-4' })}
              <span>Dedicated Workspace — {SOC_TIER_META[activeSection].name} ({SOC_TIER_META[activeSection].roleTitle})</span>
            </div>
            <div className="text-xs text-zinc-600 dark:text-zinc-300">
              {SOC_TIER_META[activeSection].summary}
            </div>
          </div>
          <div className="text-xs font-mono font-bold shrink-0">
            Target SLA: {SOC_TIER_META[activeSection].targetSla}
          </div>
        </div>
      )}

      {/* Bar Filter Sederhana & Bersih dengan Dropdown Standar */}
      <div className="flex flex-col sm:flex-row items-stretch sm:items-center justify-between gap-2.5 sm:gap-3 p-2.5 sm:p-3 rounded-xl border border-zinc-200 dark:border-zinc-800 bg-white dark:bg-[#0c0c0e]">
        <div className="relative flex-1">
          <Search className="w-3.5 h-3.5 absolute left-3 top-1/2 -translate-y-1/2 text-zinc-400 pointer-events-none" />
          <input
            type="text"
            value={search}
            onChange={e => onSearchChange(e.target.value)}
            placeholder="Search incident ID, title, or target asset..."
            className="w-full pl-9 pr-8 py-1.5 bg-zinc-50 dark:bg-zinc-900/60 border border-zinc-200 dark:border-zinc-800 rounded-lg text-xs text-zinc-900 dark:text-white placeholder-zinc-400 focus:outline-none"
          />
          {search && (
            <button onClick={() => onSearchChange('')} className="absolute right-2.5 top-1/2 -translate-y-1/2 text-zinc-400 hover:text-zinc-600 cursor-pointer">
              <X className="w-3.5 h-3.5" />
            </button>
          )}
        </div>

        <div className="relative shrink-0">
          <button
            type="button"
            onClick={() => setShowStatusDropdown(prev => !prev)}
            className="w-full sm:w-auto h-8 px-3 rounded-lg border border-zinc-200/80 bg-white dark:border-zinc-800 dark:bg-zinc-900 text-xs font-medium text-zinc-700 dark:text-zinc-200 hover:bg-zinc-50 dark:hover:bg-zinc-800/60 inline-flex items-center justify-between gap-2 cursor-pointer shadow-xs transition"
          >
            <span>{activeLabel}</span>
            <ChevronDown className={`w-3.5 h-3.5 text-zinc-400 transition-transform ${showStatusDropdown ? 'rotate-180 text-zinc-600 dark:text-zinc-200' : ''}`} />
          </button>

          {showStatusDropdown && (
            <>
              <div className="fixed inset-0 z-20 cursor-default" onClick={() => setShowStatusDropdown(false)} />
              <div className="absolute right-0 top-full mt-1.5 w-48 rounded-xl border border-zinc-200/80 dark:border-zinc-800 bg-white dark:bg-zinc-900 shadow-xl p-1.5 z-30 space-y-0.5">
                {statusOptions.map(item => {
                  const active = filterStatus === item.id;
                  return (
                    <button
                      key={item.id}
                      type="button"
                      onClick={() => {
                        onFilterStatusChange(item.id);
                        setShowStatusDropdown(false);
                      }}
                      className={`w-full px-3 py-2 rounded-lg text-xs text-left flex items-center justify-between transition cursor-pointer ${
                        active
                          ? 'font-semibold bg-zinc-100 dark:bg-zinc-800 text-zinc-900 dark:text-zinc-100'
                          : 'text-zinc-600 dark:text-zinc-400 hover:bg-zinc-50 dark:hover:bg-zinc-800/60'
                      }`}
                    >
                      <span>{item.label}</span>
                      {active && <Check className="w-3.5 h-3.5 text-emerald-500 shrink-0" />}
                    </button>
                  );
                })}
              </div>
            </>
          )}
        </div>
      </div>

      {/* Daftar Kartu Insiden Bersih & Rapi */}
      {incidents.length === 0 ? (
        <div className="p-8 sm:p-12 rounded-2xl border border-dashed border-zinc-200 dark:border-zinc-800 bg-white dark:bg-[#0c0c0e] text-center space-y-3">
          <ShieldCheck className="w-10 h-10 text-emerald-500 mx-auto" />
          <h4 className="text-sm font-semibold text-zinc-800 dark:text-zinc-200">
            No incidents in this list
          </h4>
          <p className="text-xs text-zinc-500 max-w-sm mx-auto">
            {activeSection !== 'ALL' && activeSection !== 'GUIDE' && activeSection !== 'AUDIT'
              ? `The ${SOC_TIER_META[activeSection].name} queue is clear or every incident has been mitigated.`
              : 'The entire incident queue has been resolved.'}
          </p>
        </div>
      ) : (
        <div className="grid grid-cols-1 md:grid-cols-2 gap-3 sm:gap-3.5">
          {incidents.map(inc => {
            const tier = getIncidentTier(inc);
            const tierMeta = SOC_TIER_META[tier];
            const sla = getSlaInfo(inc.severity, inc.created, inc.status, tier);

            return (
              <div
                key={inc.id}
                onClick={() => onSelectIncident(inc.id)}
                className={`p-3.5 sm:p-4 rounded-2xl border bg-white dark:bg-[#0c0c0e] hover:border-zinc-300 dark:hover:border-zinc-700 transition cursor-pointer shadow-xs space-y-2.5 sm:space-y-3 ${severityBorder(inc.severity)}`}
              >
                <div className="flex items-start justify-between gap-2">
                  <div className="flex items-center gap-1.5 sm:gap-2 flex-wrap">
                    <span className="font-mono text-xs font-bold text-zinc-600 dark:text-zinc-400">{inc.id}</span>
                    <span className={`px-2 py-0.5 rounded text-[10px] font-mono font-bold border ${tierMeta.badgeStyle}`}>
                      {tierMeta.badgeLabel}
                    </span>
                    <span className={`px-2 py-0.5 rounded text-[10px] font-mono border ${statusChip(inc.status)}`}>
                      {inc.status}
                    </span>
                  </div>
                  <StatusBadge type="severity" value={inc.severity} size="sm" />
                </div>

                <h3 className="text-xs sm:text-sm font-semibold text-zinc-900 dark:text-zinc-100 leading-snug line-clamp-2">
                  {inc.title}
                </h3>

                <div className="flex flex-wrap items-center justify-between gap-1 text-[11px] text-zinc-500 dark:text-zinc-400 font-mono pt-2 border-t border-zinc-100 dark:border-zinc-800/80">
                  <div className="flex items-center gap-1.5 truncate max-w-[200px]">
                    <Server className="w-3.5 h-3.5 text-zinc-400 shrink-0" />
                    <span className="truncate">{inc.affectedAsset || 'Enterprise Perimeter'}</span>
                    {assets.some(a => (a.hostname && a.hostname.toLowerCase() === (inc.affectedAsset || '').toLowerCase()) || (a.name && a.name.toLowerCase() === (inc.affectedAsset || '').toLowerCase())) && (
                      <span className="w-1.5 h-1.5 rounded-full bg-emerald-500 shrink-0" title="Active Fleet Asset" />
                    )}
                  </div>

                  <div className="flex items-center gap-1.5">
                    <Clock className={`w-3 h-3 ${sla.isBreached ? 'text-rose-500' : 'text-zinc-400'}`} />
                    <span className={sla.isBreached ? 'text-rose-500 font-bold' : ''}>{sla.label}</span>
                  </div>
                </div>

                <div className="flex items-center justify-between pt-1 gap-2">
                  <div className="text-[11px] text-zinc-400 font-mono truncate max-w-[180px]">
                    Owner: <strong className="text-zinc-700 dark:text-zinc-300 font-sans">{inc.assignedAnalyst || 'Unassigned'}</strong>
                  </div>

                  <button
                    type="button"
                    className="inline-flex items-center gap-1 text-xs font-semibold text-indigo-600 dark:text-indigo-400 hover:underline cursor-pointer shrink-0"
                  >
                    <span>Open Workspace</span>
                    <ChevronRight className="w-3.5 h-3.5" />
                  </button>
                </div>
              </div>
            );
          })}
        </div>
      )}
    </div>
  );
};
