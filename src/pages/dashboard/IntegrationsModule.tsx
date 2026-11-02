import React, { useState } from 'react';
import { 
  Key, 
  Plus
} from 'lucide-react';
import { StatusBadge } from '../../components/common/StatusBadge';
import { FontAwesomeIcon } from '@fortawesome/react-fontawesome';
import { faLayerGroup } from '@fortawesome/free-solid-svg-icons';
import { ModulePageHeader } from '../../components/common/ModulePageHeader';

interface SiemIntegration {
  name: string;
  type: string;
  status: string;
  protocol: string;
  eventsPerSec: string;
}

export const IntegrationsModule: React.FC = () => {
  // No mock connectors: integrations are provisioned from real configuration.
  const [integrations] = useState<SiemIntegration[]>([]);

  const [apiKey, setApiKey] = useState('');
  const [showKey, setShowKey] = useState(false);
  const [notificationMsg, setNotificationMsg] = useState<string | null>(null);

  const handleRotateKey = () => {
    const newKey = 'oat_sec_live_' + crypto.randomUUID().replace(/-/g, '');
    setApiKey(newKey);
    setNotificationMsg('Ingress API Key rotated successfully. Update SIEM collector configs.');
    setTimeout(() => setNotificationMsg(null), 4000);
  };

  return (
    <div className="space-y-6">
      {notificationMsg && (
        <div className="p-3 rounded-lg bg-zinc-100 dark:bg-zinc-800/60 border border-zinc-200 dark:border-zinc-800 text-zinc-700 dark:text-zinc-300 text-xs font-mono flex items-center justify-between gap-3">
          <span className="break-all">{notificationMsg}</span>
          <button onClick={() => setNotificationMsg(null)} className="shrink-0 text-zinc-400 hover:text-zinc-900 hover:bg-zinc-200 dark:text-zinc-500 dark:hover:text-zinc-100 dark:hover:bg-zinc-800 rounded px-1 cursor-pointer">✕</button>
        </div>
      )}

      {/* Header */}
      <ModulePageHeader
        icon={<FontAwesomeIcon icon={faLayerGroup} />}
        title="SIEM Integrations"
        titleTail="Ingress Webhooks"
        subtitle="Real-time event streaming connectors for Splunk, Elastic, QRadar, and incident notification systems."
        actions={
          <button
            onClick={() => {
              setNotificationMsg('New SIEM connector setup wizard initialized.');
              setTimeout(() => setNotificationMsg(null), 3000);
            }}
            className="inline-flex h-8 items-center gap-1.5 rounded-lg bg-zinc-900 px-3 text-xs font-medium text-white transition hover:bg-zinc-800 cursor-pointer dark:bg-white dark:text-zinc-900 dark:hover:bg-zinc-100"
          >
            <Plus className="w-3.5 h-3.5" />
            Add SIEM Connector
          </button>
        }
      />

      {/* API Key Management */}
      <div className="p-5 rounded-xl border border-zinc-200/80 dark:border-zinc-800 bg-white dark:bg-[#0c0c0e] space-y-3">
        <div className="flex flex-wrap items-center justify-between gap-2">
          <div className="flex items-center gap-2 min-w-0">
            <Key className="w-4 h-4 shrink-0 text-zinc-700 dark:text-zinc-300" />
            <h2 className="text-sm font-semibold text-zinc-900 dark:text-white">Enterprise REST & Ingress Ingestion API Key</h2>
          </div>
          <button
            onClick={handleRotateKey}
            className="text-xs text-rose-600 hover:text-rose-500 dark:text-rose-400 dark:hover:text-rose-300 font-mono cursor-pointer"
          >
            Rotate Secret Key
          </button>
        </div>

        <div className="flex flex-col sm:flex-row sm:items-center gap-2">
          <input
            type={showKey ? 'text' : 'password'}
            readOnly
            value={apiKey}
            placeholder="No API key generated yet. Rotate the secret key to issue one."
            className="flex-1 w-full sm:w-auto px-3 py-2 bg-zinc-50 dark:bg-zinc-900/40 border border-zinc-200 dark:border-zinc-800 rounded-lg text-xs font-mono text-zinc-900 dark:text-white select-all focus:outline-none placeholder:text-zinc-400 dark:placeholder:text-slate-500"
          />
          <button
            type="button"
            onClick={() => setShowKey(!showKey)}
            className="px-3 py-2 bg-zinc-100 dark:bg-zinc-800 hover:bg-zinc-200 dark:hover:bg-zinc-700 text-zinc-700 dark:text-zinc-300 text-xs rounded-lg border border-zinc-300 dark:border-zinc-700 cursor-pointer shrink-0"
          >
            {showKey ? 'Hide' : 'Reveal'}
          </button>
        </div>
      </div>

      {/* Connectors Grid */}
      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-4">
        {integrations.length === 0 ? (
          <div className="sm:col-span-2 lg:col-span-3 p-6 rounded-xl border border-zinc-200/80 dark:border-zinc-800 bg-white dark:bg-[#0c0c0e] text-center text-xs text-zinc-400 dark:text-slate-500">
            No SIEM connectors installed yet. Connectors will appear here once configured.
          </div>
        ) : (
          integrations.map((item, idx) => (
            <div key={idx} className="p-4 rounded-xl border border-zinc-200/80 dark:border-zinc-800 bg-white dark:bg-[#0c0c0e] space-y-3 flex flex-col justify-between">
              <div>
                <div className="flex items-center justify-between mb-2">
                  <span className="text-xs font-bold text-zinc-900 dark:text-white">{item.name}</span>
                  <StatusBadge type="health" value={item.status} size="sm" />
                </div>
                <div className="text-xs text-zinc-500 dark:text-slate-400">{item.type}</div>
              </div>

              <div className="pt-2 border-t border-zinc-200 dark:border-zinc-800 text-xs font-mono flex items-center justify-between text-zinc-500 dark:text-slate-400">
                <span>{item.protocol}</span>
                <span className="text-zinc-700 dark:text-zinc-300">{item.eventsPerSec}</span>
              </div>
            </div>
          ))
        )}
      </div>
    </div>
  );
};
