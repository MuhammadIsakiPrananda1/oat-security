import React from 'react';
import { Database, RefreshCw } from 'lucide-react';
import { StatusBadge } from '../common/StatusBadge';
import { ThreatFeedSource } from './types';
import { formatDateTime } from '../../utils/dateTime';

interface ThreatFeedsOverviewProps {
  feeds: ThreatFeedSource[];
  serverStatus: string;
  onSync: () => void;
  syncing: boolean;
}

export const ThreatFeedsOverview: React.FC<ThreatFeedsOverviewProps> = ({
  feeds,
  serverStatus,
  onSync,
  syncing
}) => {
  return (
    <div className="p-4 sm:p-5 rounded-2xl border border-zinc-200/80 dark:border-zinc-800 bg-white dark:bg-[#0c0c0e] space-y-4 shadow-xs">
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 pb-2 border-b border-zinc-100 dark:border-zinc-800/80">
        <div>
          <h2 className="text-sm sm:text-base font-bold text-zinc-900 dark:text-white flex items-center gap-2">
            <Database className="w-4 h-4 text-indigo-500 shrink-0" />
            <span>Synchronized Threat Feeds &amp; ISAC Sources</span>
          </h2>
          <p className="text-xs text-zinc-500 mt-0.5">
            Continuous threat feed ingestion from global CERTs, banking ISACs, and distributed edge deception nodes.
          </p>
        </div>

        <div className="flex items-center gap-2 shrink-0">
          <span className="text-[11px] font-mono text-zinc-500 dark:text-zinc-400 bg-zinc-100 dark:bg-zinc-800 px-2.5 py-1 rounded-md border border-zinc-200 dark:border-zinc-700">
            {serverStatus}
          </span>
        </div>
      </div>

      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-3">
        {feeds.map((feed) => (
          <div
            key={feed.id}
            className="p-3.5 rounded-xl bg-zinc-50 dark:bg-zinc-900/40 border border-zinc-200 dark:border-zinc-800 hover:border-zinc-300 dark:hover:border-zinc-700 transition space-y-2.5"
          >
            <div className="flex items-start justify-between gap-2">
              <div className="min-w-0">
                <span className="text-xs font-bold text-zinc-900 dark:text-white block truncate" title={feed.name}>
                  {feed.name}
                </span>
                <span className="text-[11px] text-zinc-500 dark:text-zinc-400 truncate block">
                  {feed.provider}
                </span>
              </div>
              <StatusBadge type="health" value={feed.status} size="sm" />
            </div>

            <div className="flex items-center justify-between text-xs font-mono pt-1 border-t border-zinc-100 dark:border-zinc-800/60">
              <div>
                <span className="text-[10px] text-zinc-400 block uppercase">Indicators</span>
                <span className="text-zinc-800 dark:text-zinc-200 font-bold">{feed.entries}</span>
              </div>
              <div className="text-right">
                <span className="text-[10px] text-zinc-400 block uppercase">Confidence</span>
                <span className="text-emerald-600 dark:text-emerald-400 font-bold">{feed.confidenceAvg}% Avg</span>
              </div>
            </div>

            <div className="text-[10px] font-mono text-zinc-400 dark:text-zinc-500 pt-0.5">
              Synced: {/^\d{4}-\d{2}-\d{2}/.test(feed.lastSync) ? formatDateTime(feed.lastSync) : feed.lastSync}
            </div>
          </div>
        ))}
      </div>
    </div>
  );
};
