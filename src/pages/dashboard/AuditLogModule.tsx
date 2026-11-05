import React, { useState, useEffect, useCallback } from 'react';
import { 
  Search, 
  Download, 
  RefreshCw,
  ShieldCheck
} from 'lucide-react';
import { securityApi, globalRealtimeClient } from '../../services/api';
import { AuditLogItem } from '../../types';
import { BackendOfflineBanner } from '../../components/common/BackendOfflineBanner';
import { FontAwesomeIcon } from '@fortawesome/react-fontawesome';
import { faScroll } from '@fortawesome/free-solid-svg-icons';
import { ModulePageHeader } from '../../components/common/ModulePageHeader';
import { useAuth } from '../../context/AuthContext';
import { formatDateTime } from '../../utils/dateTime';

export const AuditLogModule: React.FC = () => {
  const { isBackendOffline } = useAuth();
  const [auditLogs, setAuditLogs] = useState<AuditLogItem[]>([]);
  const [loading, setLoading] = useState(true);
  const [search, setSearch] = useState('');
  const [lastLiveEventTime, setLastLiveEventTime] = useState<string | null>(null);

  const fetchAuditLogs = useCallback(async () => {
    setLoading(true);
    try {
      const res = await securityApi.getAuditLogs();
      setAuditLogs(res.logs || []);
    } catch (e) {
      console.error('[AuditLogs] Fetch error:', e);
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    fetchAuditLogs();
  }, [fetchAuditLogs, isBackendOffline]);

  // Real-time WebSocket subscription for live audit log stream
  useEffect(() => {
    const unsubscribe = globalRealtimeClient.subscribe((msg: any) => {
      if (msg?.type === 'audit.created' && msg?.data) {
        const newLog = msg.data as AuditLogItem;
        setAuditLogs(prev => [newLog, ...prev.filter(l => l.id !== newLog.id)]);
        setLastLiveEventTime(new Date().toLocaleTimeString());
      }
    });

    return () => {
      unsubscribe();
    };
  }, []);

  if (isBackendOffline) {
    return <BackendOfflineBanner onRetry={fetchAuditLogs} />;
  }

  const term = (search || '').trim().toLowerCase();
  const filtered = auditLogs.filter(l => 
    String(l.user || '').toLowerCase().includes(term) ||
    String(l.action || '').toLowerCase().includes(term) ||
    String(l.resource || '').toLowerCase().includes(term) ||
    String(l.ip || '').includes(term)
  );

  return (
    <div className="space-y-6" id="audit-log-module-container">
      {/* Header */}
      <ModulePageHeader
        icon={<FontAwesomeIcon icon={faScroll} />}
        title="Administrative"
        titleTail="Audit Trail"
        subtitle="Immutable tamper-evident record of all operator actions, policy alterations, and authentication events stored in MySQL."
        actions={
          <button
            onClick={() => {
                const dataStr = "data:text/json;charset=utf-8," + encodeURIComponent(JSON.stringify(auditLogs, null, 2));
                const downloadAnchor = document.createElement('a');
                downloadAnchor.setAttribute("href", dataStr);
                downloadAnchor.setAttribute("download", `audit_trail_${new Date().toISOString().slice(0, 10)}.json`);
                document.body.appendChild(downloadAnchor);
                downloadAnchor.click();
                downloadAnchor.remove();
              }}
              className="inline-flex h-8 items-center gap-1.5 rounded-lg border border-zinc-200/80 bg-white px-2.5 text-xs font-medium text-zinc-600 transition hover:border-zinc-300 hover:text-zinc-900 cursor-pointer dark:border-zinc-800 dark:bg-zinc-900 dark:text-zinc-300 dark:hover:border-zinc-600 dark:hover:text-zinc-100"
            >
              <Download className="w-3.5 h-3.5" />
              <span>Export Audit Trail (JSON)</span>
            </button>
        }
      />

      {/* Search Bar */}
      <div className="p-4 rounded-xl border border-zinc-200/80 dark:border-zinc-800 bg-white dark:bg-[#0c0c0e] flex flex-wrap items-center justify-between gap-3 transition-colors">
        <div className="relative flex-1 min-w-[240px] max-w-md">
          <Search className="w-4 h-4 text-zinc-400 dark:text-slate-500 absolute left-3 top-1/2 -translate-y-1/2" />
          <input
            type="text"
            value={search}
            onChange={e => setSearch(e.target.value)}
            placeholder="Search by operator email, action type, or target resource..."
            className="w-full pl-9 pr-3 py-1.5 bg-zinc-50 dark:bg-zinc-900/40 border border-zinc-200 dark:border-zinc-800 rounded-lg text-xs text-zinc-900 dark:text-white placeholder-zinc-400 dark:placeholder-zinc-500 focus:outline-none focus:border-zinc-400 dark:focus:border-zinc-700 font-mono transition"
          />
        </div>
        <div className="flex items-center gap-2">
          <span className="inline-flex items-center gap-1.5 text-[10px] font-mono px-2 py-0.5 rounded-full bg-emerald-500/10 text-emerald-600 dark:text-emerald-400 border border-emerald-500/20 font-semibold">
            <span className="w-1.5 h-1.5 rounded-full bg-emerald-500 animate-pulse" />
            LIVE STREAM ACTIVE
          </span>
          <span className="text-xs text-zinc-500 dark:text-slate-400 font-mono">
            SHA-256 Ledger Integrity • {auditLogs.length} Records {lastLiveEventTime ? `(Last: ${lastLiveEventTime})` : ''}
          </span>
        </div>
      </div>

      {/* Audit Log Table */}
      <div className="rounded-xl border border-zinc-200/80 dark:border-zinc-800 bg-white dark:bg-[#0c0c0e] overflow-hidden transition-colors">
        <div className="overflow-x-auto custom-scrollbar">
          <table className="w-full min-w-[860px] text-left text-xs font-mono">
            <thead>
              <tr className="border-b border-zinc-200 dark:border-zinc-800 bg-zinc-50 dark:bg-zinc-900/60 text-zinc-500 dark:text-slate-400">
                <th className="p-3">LOG ID</th>
                <th className="p-3">TIMESTAMP</th>
                <th className="p-3">OPERATOR / ACTOR</th>
                <th className="p-3">ACTION EVENT</th>
                <th className="p-3">TARGET RESOURCE</th>
                <th className="p-3">ORIGIN IP</th>
                <th className="p-3 text-right">EXECUTION</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-zinc-200 dark:divide-zinc-800">
              {loading && auditLogs.length === 0 ? (
                <tr>
                  <td colSpan={7} className="p-12 text-center text-zinc-500 dark:text-slate-400">
                    <RefreshCw className="w-6 h-6 animate-spin mx-auto text-zinc-400 dark:text-slate-500 mb-2" />
                    <span>Loading audit records from database...</span>
                  </td>
                </tr>
              ) : filtered.length === 0 ? (
                <tr>
                  <td colSpan={7} className="p-12 text-center text-zinc-500 dark:text-slate-400">
                    <ShieldCheck className="w-8 h-8 mx-auto text-zinc-400 dark:text-slate-500 mb-2" />
                    <div className="text-zinc-700 dark:text-zinc-300 font-semibold">NO DATA AVAILABLE</div>
                    <p className="text-xs text-zinc-400 dark:text-slate-500 mt-1">No administrative events found matching search criteria.</p>
                  </td>
                </tr>
              ) : (
                filtered.map(log => (
                  <tr key={log.id} className="hover:bg-zinc-100 dark:hover:bg-zinc-800 transition">
                    <td className="p-3 text-zinc-700 dark:text-zinc-300 font-bold">{log.id}</td>
                    <td className="p-3 text-zinc-500 dark:text-slate-400 whitespace-nowrap">
                      {formatDateTime(log.timestamp)}
                    </td>
                    <td className="p-3 font-sans font-medium text-zinc-800 dark:text-zinc-200">
                      <div>{log.user}</div>
                      <div className="text-[10px] text-zinc-400 dark:text-slate-500 font-mono">{log.role}</div>
                    </td>
                    <td className="p-3">
                      <span className="px-2 py-0.5 rounded text-[10px] uppercase font-bold tracking-wider bg-amber-500/10 text-amber-600 dark:text-amber-400 border border-amber-500/20">
                        {log.action}
                      </span>
                    </td>
                    <td className="p-3 text-zinc-700 dark:text-zinc-300">{log.resource}</td>
                    <td className="p-3 text-zinc-500 dark:text-slate-400">{log.ip}</td>
                    <td className="p-3 text-right">
                      <span className="px-2 py-0.5 rounded bg-emerald-500/10 text-emerald-600 dark:text-emerald-400 border border-emerald-500/20 text-[10px]">
                        {log.result || 'Success'}
                      </span>
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
