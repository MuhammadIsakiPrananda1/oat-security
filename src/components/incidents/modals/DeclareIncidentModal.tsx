import React from 'react';
import { ShieldAlert, X } from 'lucide-react';
import { IncidentDraft, ThreatSeverity, SocTier, AssetOption } from '../types';
import { SEVERITIES } from '../constants';
import { User } from '../../../types';
import { translate } from '../../../i18n/translator';

interface DeclareIncidentModalProps {
  isOpen: boolean;
  onClose: () => void;
  draft: IncidentDraft;
  onDraftChange: (updater: (prev: IncidentDraft) => IncidentDraft) => void;
  onSubmit: (e: React.FormEvent) => void;
  assets?: AssetOption[];
  analysts?: User[];
  userEmail?: string;
  busy: boolean;
}

export const DeclareIncidentModal: React.FC<DeclareIncidentModalProps> = ({
  isOpen,
  onClose,
  draft,
  onDraftChange,
  onSubmit,
  assets = [],
  analysts = [],
  userEmail,
  busy
}) => {
  if (!isOpen) return null;

  const handleSeverityChange = (newSev: ThreatSeverity) => {
    let recTier: SocTier = 'L1';
    if (newSev === 'Critical') recTier = 'L3';
    else if (newSev === 'High') recTier = 'L2';
    else recTier = 'L1';
    onDraftChange(prev => ({ ...prev, severity: newSev, tier: recTier }));
  };

  const agentAssets = assets.filter(a => a.type === 'agent');
  const appAssets = assets.filter(a => a.type === 'application');

  return (
    <div className="fixed inset-0 z-50 bg-black/60 dark:bg-black/80 backdrop-blur-xs flex items-center justify-center p-3 sm:p-4 animate-fadeIn">
      <div className="relative w-full max-w-lg max-h-[90vh] overflow-y-auto rounded-2xl border border-zinc-200 dark:border-zinc-800 bg-white dark:bg-[#0c0c0e] shadow-2xl p-4 sm:p-6 text-zinc-900 dark:text-zinc-100">
        <div className="flex items-center justify-between pb-3 border-b border-zinc-200 dark:border-zinc-800 mb-4">
          <div className="flex items-center gap-2">
            <div className="w-8 h-8 rounded-lg bg-rose-500/10 text-rose-600 flex items-center justify-center shrink-0">
              <ShieldAlert className="w-4 h-4" />
            </div>
            <div>
              <h3 className="text-sm sm:text-base font-bold text-zinc-900 dark:text-white">Declare New Incident</h3>
              <p className="text-xs text-zinc-500">Live SOC Command Center Ingestion (Database Synced)</p>
            </div>
          </div>
          <button
            onClick={onClose}
            className="p-1.5 rounded-lg text-zinc-400 hover:text-zinc-600 dark:hover:text-zinc-200 cursor-pointer"
          >
            <X className="w-4 h-4" />
          </button>
        </div>

        <form onSubmit={onSubmit} className="space-y-4">
          <div>
            <label className="block text-xs font-semibold text-zinc-700 dark:text-zinc-300 mb-1">
              Incident Title <span className="text-rose-500">*</span>
            </label>
            <input
              type="text"
              required
              value={draft.title}
              onChange={e => onDraftChange(prev => ({ ...prev, title: e.target.value }))}
              placeholder="e.g. Exploitation attempt on Payment Gateway Ingress"
              className="w-full px-3.5 py-2 bg-zinc-50 dark:bg-zinc-900/60 border border-zinc-200 dark:border-zinc-800 rounded-lg text-xs text-zinc-900 dark:text-white placeholder-zinc-400 focus:outline-none"
            />
          </div>

          <div className="grid grid-cols-1 sm:grid-cols-2 gap-3.5">
            <div>
              <label className="block text-xs font-semibold text-zinc-700 dark:text-zinc-300 mb-1">
                Severity <span className="text-rose-500">*</span>
              </label>
              <select
                value={draft.severity}
                onChange={e => handleSeverityChange(e.target.value as ThreatSeverity)}
                className="w-full px-3.5 py-2 bg-zinc-50 dark:bg-zinc-900/60 border border-zinc-200 dark:border-zinc-800 rounded-lg text-xs text-zinc-900 dark:text-white font-mono focus:outline-none cursor-pointer"
              >
                {SEVERITIES.map(s => (
                  <option key={s} value={s}>{s}</option>
                ))}
              </select>
            </div>

            <div>
              <label className="block text-xs font-semibold text-zinc-700 dark:text-zinc-300 mb-1">
                Target SOC Tier <span className="text-rose-500">*</span>
              </label>
              <select
                value={draft.tier}
                onChange={e => onDraftChange(prev => ({ ...prev, tier: e.target.value as SocTier }))}
                className="w-full px-3.5 py-2 bg-zinc-50 dark:bg-zinc-900/60 border border-indigo-500/40 rounded-lg text-xs text-indigo-600 dark:text-indigo-400 font-mono font-bold focus:outline-none cursor-pointer"
              >
                <option value="L1">SOC L1 • Frontline Triage (&lt; 15m SLA)</option>
                <option value="L2">SOC L2 • Forensic Investigation (&lt; 60m SLA)</option>
                <option value="L3">SOC L3 • Crisis Commander (&lt; 120m SLA)</option>
              </select>
            </div>
          </div>

          <div className="grid grid-cols-1 sm:grid-cols-2 gap-3.5">
            <div>
              <label className="block text-xs font-semibold text-zinc-700 dark:text-zinc-300 mb-1">
                Affected Asset (Real Fleet &amp; Apps)
              </label>
              <div className="space-y-1.5">
                <select
                  value={draft.affectedAsset}
                  onChange={e => onDraftChange(prev => ({ ...prev, affectedAsset: e.target.value }))}
                  className="w-full px-3.5 py-2 bg-zinc-50 dark:bg-zinc-900/60 border border-zinc-200 dark:border-zinc-800 rounded-lg text-xs text-zinc-900 dark:text-white focus:outline-none cursor-pointer"
                >
                  <option value="">-- Select Real Asset --</option>
                  {agentAssets.length > 0 && (
                    <optgroup label="💻 Enrolled Agent Servers (Fleet)">
                      {agentAssets.map(ag => (
                        <option key={ag.id} value={ag.hostname || ag.name}>
                          {ag.hostname || ag.name} ({ag.ip || 'No IP'} • {ag.status})
                        </option>
                      ))}
                    </optgroup>
                  )}
                  {appAssets.length > 0 && (
                    <optgroup label="🌐 Protected Applications (WAF)">
                      {appAssets.map(app => (
                        <option key={app.id} value={app.name}>
                          {app.name} ({app.domain || app.ip || 'WAF Protected'})
                        </option>
                      ))}
                    </optgroup>
                  )}
                  <option value="Enterprise Perimeter">Enterprise Perimeter Gateway</option>
                  <option value="Custom">Custom / External Asset...</option>
                </select>

                {(!draft.affectedAsset || draft.affectedAsset === 'Custom') && (
                  <input
                    type="text"
                    value={draft.affectedAsset === 'Custom' ? '' : draft.affectedAsset}
                    onChange={e => onDraftChange(prev => ({ ...prev, affectedAsset: e.target.value }))}
                    placeholder="Or type custom asset name / IP..."
                    className="w-full px-3 py-1.5 bg-zinc-50 dark:bg-zinc-900/40 border border-dashed border-zinc-300 dark:border-zinc-700 rounded-lg text-xs text-zinc-900 dark:text-white placeholder-zinc-400 focus:outline-none font-mono"
                  />
                )}
              </div>
            </div>

            <div>
              <label className="block text-xs font-semibold text-zinc-700 dark:text-zinc-300 mb-1">
                Assign to Analyst (Real Users)
              </label>
              <select
                value={draft.assignedTo}
                onChange={e => onDraftChange(prev => ({ ...prev, assignedTo: e.target.value }))}
                className="w-full px-3.5 py-2 bg-zinc-50 dark:bg-zinc-900/60 border border-zinc-200 dark:border-zinc-800 rounded-lg text-xs text-zinc-900 dark:text-white focus:outline-none cursor-pointer"
              >
                <option value="">Open Queue (Unassigned)</option>
                {userEmail && <option value={userEmail}>{translate(`Myself (${userEmail})`)}</option>}
                {analysts.map(u => (
                  <option key={u.id} value={u.email}>
                    {u.name} — {u.role} ({u.email})
                  </option>
                ))}
              </select>
            </div>
          </div>

          <div>
            <label className="block text-xs font-semibold text-zinc-700 dark:text-zinc-300 mb-1">
              Initial Forensic Notes
            </label>
            <textarea
              rows={3}
              value={draft.notes}
              onChange={e => onDraftChange(prev => ({ ...prev, notes: e.target.value }))}
              placeholder="Attack indicators, anomalous symptoms, or telemetry details..."
              className="w-full px-3.5 py-2 bg-zinc-50 dark:bg-zinc-900/60 border border-zinc-200 dark:border-zinc-800 rounded-lg text-xs text-zinc-900 dark:text-white placeholder-zinc-400 focus:outline-none"
            />
          </div>

          <div className="pt-3 flex flex-col-reverse sm:flex-row items-stretch sm:items-center justify-end gap-2 border-t border-zinc-200 dark:border-zinc-800">
            <button
              type="button"
              onClick={onClose}
              className="w-full sm:w-auto px-4 py-2 rounded-lg text-xs text-zinc-600 dark:text-zinc-400 bg-zinc-100 dark:bg-zinc-800 cursor-pointer text-center"
            >
              Cancel
            </button>
            <button
              type="submit"
              disabled={busy}
              className="w-full sm:w-auto px-4 py-2 rounded-lg text-xs font-semibold text-white bg-rose-600 hover:bg-rose-500 disabled:opacity-50 cursor-pointer shadow-sm transition text-center"
            >
              {busy ? 'Declaring…' : `Save to [SOC ${draft.tier}] Queue`}
            </button>
          </div>
        </form>
      </div>
    </div>
  );
};
