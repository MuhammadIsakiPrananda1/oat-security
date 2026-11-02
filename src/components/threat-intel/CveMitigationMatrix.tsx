import React from 'react';
import { Bug } from 'lucide-react';
import { StatusBadge } from '../common/StatusBadge';
import { CveMitigationItem } from './types';

interface CveMitigationMatrixProps {
  cves: CveMitigationItem[];
}

export const CveMitigationMatrix: React.FC<CveMitigationMatrixProps> = ({ cves }) => {
  return (
    <div className="rounded-2xl border border-zinc-200/80 dark:border-zinc-800 bg-white dark:bg-[#0c0c0e] overflow-hidden shadow-xs">
      <div className="p-4 sm:p-5 border-b border-zinc-200 dark:border-zinc-800 flex flex-col sm:flex-row sm:items-center justify-between gap-2">
        <div>
          <h3 className="text-sm sm:text-base font-bold text-zinc-900 dark:text-white flex items-center gap-2">
            <Bug className="w-4 h-4 text-rose-500" />
            <span>Critical CVE Threat Signatures in Active Mitigation</span>
          </h3>
          <p className="text-xs text-zinc-500 mt-0.5">
            Zero-day and high-impact N-day exploit vectors blocked in real-time by OAT WAF rule configurations.
          </p>
        </div>
        <span className="text-xs font-mono text-zinc-500 dark:text-zinc-400 bg-zinc-100 dark:bg-zinc-800 px-2.5 py-1 rounded-md self-start sm:self-auto border border-zinc-200 dark:border-zinc-700">
          {cves.length} signatures protected
        </span>
      </div>

      {/* Mobile Card List (< md) */}
      <div className="md:hidden divide-y divide-zinc-100 dark:divide-zinc-800/70">
        {cves.length === 0 ? (
          <div className="p-8 text-center text-xs text-zinc-400">
            No CVE signatures currently reported.
          </div>
        ) : (
          cves.map(c => (
            <div key={c.cve} className="p-4 space-y-2">
              <div className="flex items-center justify-between">
                <span className="font-mono text-xs font-bold text-zinc-900 dark:text-white">{c.cve}</span>
                <span className="px-2 py-0.5 rounded-full text-[10px] font-mono font-bold bg-rose-500/10 text-rose-600 dark:text-rose-400 border border-rose-500/20">
                  CVSS {c.score}
                </span>
              </div>
              <p className="text-xs text-zinc-700 dark:text-zinc-300 leading-relaxed font-sans">{c.desc}</p>
              {c.affectedSoftware && (
                <div className="text-[11px] font-mono text-zinc-400">
                  Target: <strong className="text-zinc-600 dark:text-zinc-300 font-sans">{c.affectedSoftware}</strong>
                </div>
              )}
              <div className="flex items-center justify-between pt-1 border-t border-zinc-100 dark:border-zinc-800/60">
                <StatusBadge type="severity" value={c.severity} size="sm" />
                <span className="px-2 py-0.5 rounded text-[10px] font-mono font-semibold bg-emerald-500/10 text-emerald-600 dark:text-emerald-400 border border-emerald-500/20">
                  {c.status}
                </span>
              </div>
            </div>
          ))
        )}
      </div>

      {/* Desktop Table (>= md) */}
      <div className="hidden md:block overflow-x-auto custom-scrollbar">
        <table className="w-full min-w-[760px] text-left text-xs font-mono">
          <thead className="border-b border-zinc-200 dark:border-zinc-800 bg-zinc-50 dark:bg-zinc-900/40 text-zinc-400 uppercase text-[10px] tracking-wider">
            <tr>
              <th className="p-3.5">CVE IDENTIFIER</th>
              <th className="p-3.5">CVSS</th>
              <th className="p-3.5">SEVERITY</th>
              <th className="p-3.5">AFFECTED TECHNOLOGY</th>
              <th className="p-3.5">VULNERABILITY DESCRIPTION</th>
              <th className="p-3.5 text-right">OAT DEFENSE STATUS</th>
            </tr>
          </thead>
          <tbody className="divide-y divide-zinc-100 dark:divide-zinc-800/60">
            {cves.length === 0 ? (
              <tr>
                <td colSpan={6} className="p-8 text-center text-zinc-400 font-sans">
                  No CVE signatures currently active.
                </td>
              </tr>
            ) : (
              cves.map(c => (
                <tr key={c.cve} className="hover:bg-zinc-50 dark:hover:bg-zinc-900/40 transition">
                  <td className="p-3.5 font-bold text-zinc-900 dark:text-white select-all">{c.cve}</td>
                  <td className="p-3.5">
                    <span className="font-bold text-rose-600 dark:text-rose-400">{c.score}</span>
                  </td>
                  <td className="p-3.5">
                    <StatusBadge type="severity" value={c.severity} size="sm" />
                  </td>
                  <td className="p-3.5 text-zinc-600 dark:text-zinc-300 font-sans max-w-[180px] truncate" title={c.affectedSoftware}>
                    {c.affectedSoftware || '—'}
                  </td>
                  <td className="p-3.5 font-sans text-zinc-700 dark:text-zinc-300 text-xs max-w-[340px] leading-relaxed">
                    {c.desc}
                  </td>
                  <td className="p-3.5 text-right">
                    <span className="inline-flex px-2.5 py-1 rounded bg-emerald-500/10 text-emerald-600 dark:text-emerald-400 border border-emerald-500/20 text-[11px] font-semibold">
                      {c.status}
                    </span>
                  </td>
                </tr>
              ))
            )}
          </tbody>
        </table>
      </div>
    </div>
  );
};
