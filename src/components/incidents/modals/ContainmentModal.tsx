import React from 'react';
import { Zap, X } from 'lucide-react';
import { Incident, AssetOption } from '../types';

interface ContainmentModalProps {
  isOpen: boolean;
  onClose: () => void;
  incident: Incident | null;
  action: string;
  onActionChange: (action: string) => void;
  target: string;
  onTargetChange: (target: string) => void;
  note: string;
  onNoteChange: (note: string) => void;
  onSubmit: (e: React.FormEvent) => void;
  assets?: AssetOption[];
  busy: boolean;
}

export const ContainmentModal: React.FC<ContainmentModalProps> = ({
  isOpen,
  onClose,
  incident,
  action,
  onActionChange,
  target,
  onTargetChange,
  note,
  onNoteChange,
  onSubmit,
  busy
}) => {
  if (!isOpen || !incident) return null;

  return (
    <div className="fixed inset-0 z-50 bg-black/60 dark:bg-black/80 backdrop-blur-xs flex items-center justify-center p-3 sm:p-4 animate-fadeIn">
      <div className="relative w-full max-w-md max-h-[90vh] overflow-y-auto rounded-2xl border border-zinc-200 dark:border-zinc-800 bg-white dark:bg-[#0c0c0e] shadow-2xl p-4 sm:p-6 text-zinc-900 dark:text-zinc-100">
        <div className="flex items-center justify-between pb-3 border-b border-zinc-200 dark:border-zinc-800 mb-4">
          <div className="flex items-center gap-2">
            <div className="w-8 h-8 rounded-lg bg-cyan-500/10 text-cyan-600 flex items-center justify-center shrink-0">
              <Zap className="w-4 h-4" />
            </div>
            <div>
              <h3 className="text-sm sm:text-base font-bold text-zinc-900 dark:text-white">Execute Live Containment</h3>
              <p className="text-xs text-zinc-500">Incident: {incident.id} • Asset: {incident.affectedAsset || 'Perimeter'}</p>
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
              Containment Action Type
            </label>
            <select
              value={action}
              onChange={e => onActionChange(e.target.value)}
              className="w-full px-3.5 py-2 bg-zinc-50 dark:bg-zinc-900/60 border border-zinc-200 dark:border-zinc-800 rounded-lg text-xs text-zinc-900 dark:text-white focus:outline-none cursor-pointer"
            >
              <option value="BLOCK_IP">1. Block Malicious IP at Perimeter Firewall (Emergency DENY)</option>
              <option value="QUARANTINE_HOST">2. Isolate Agent Host from Corporate Subnet (Agent Server)</option>
              <option value="WAF_CHALLENGE">3. Apply WAF Cryptographic Puzzle / Rate Limit</option>
              <option value="INVALIDATE_CREDENTIALS">4. Revoke Active User / Admin Sessions</option>
            </select>
          </div>

          <div>
            <label className="block text-xs font-semibold text-zinc-700 dark:text-zinc-300 mb-1">
              Target (IP Address / Agent Hostname / Application Domain) <span className="text-rose-500">*</span>
            </label>
            <input
              type="text"
              required
              value={target}
              onChange={e => onTargetChange(e.target.value)}
              placeholder="e.g. 185.220.101.42 or agent-prod-01"
              className="w-full px-3.5 py-2 bg-zinc-50 dark:bg-zinc-900/60 border border-zinc-200 dark:border-zinc-800 rounded-lg text-xs text-zinc-900 dark:text-white font-mono focus:outline-none"
            />
            {incident.affectedAsset && (
              <div className="flex items-center gap-1.5 mt-1 text-[11px] text-zinc-400">
                <span>Suggested Asset Target:</span>
                <button
                  type="button"
                  onClick={() => onTargetChange(incident.affectedAsset || '')}
                  className="font-mono text-cyan-600 dark:text-cyan-400 hover:underline cursor-pointer"
                >
                  {incident.affectedAsset}
                </button>
              </div>
            )}
          </div>

          <div>
            <label className="block text-xs font-semibold text-zinc-700 dark:text-zinc-300 mb-1">
              Containment Justification &amp; Audit Note
            </label>
            <textarea
              rows={2}
              value={note}
              onChange={e => onNoteChange(e.target.value)}
              placeholder="Operational justification for immediate isolation or edge perimeter block..."
              className="w-full px-3.5 py-2 bg-zinc-50 dark:bg-zinc-900/60 border border-zinc-200 dark:border-zinc-800 rounded-lg text-xs text-zinc-900 dark:text-white placeholder-zinc-400 focus:outline-none"
            />
          </div>

          <div className="p-3 rounded-xl bg-cyan-500/10 border border-cyan-500/20 text-xs text-cyan-800 dark:text-cyan-300">
            <div className="font-bold flex items-center gap-1.5 mb-1">
              <Zap className="w-3.5 h-3.5 shrink-0" />
              <span>Real-time Active Enforcement</span>
            </div>
            <p className="text-[11px] leading-relaxed opacity-90">
              {action === 'BLOCK_IP' && 'An emergency firewall rule will be injected at priority 1 and pushed to all active edge gateways and agent firewalls.'}
              {action === 'QUARANTINE_HOST' && 'Network isolation command will be dispatched to the endpoint agent, cutting internal subnet traffic while preserving security telemetry.'}
              {action === 'WAF_CHALLENGE' && 'Enforces strict cryptographic challenges against the attacker source across all WAF protected domains.'}
              {action === 'INVALIDATE_CREDENTIALS' && 'Terminates all active JWT tokens and sessions on the affected target service.'}
            </p>
          </div>

          <div className="pt-3 flex flex-col-reverse sm:flex-row items-stretch sm:items-center justify-end gap-2 border-t border-zinc-200 dark:border-zinc-800">
            <button
              type="button"
              onClick={onClose}
              className="w-full sm:w-auto px-3.5 py-2 rounded-lg text-xs text-zinc-600 dark:text-zinc-400 bg-zinc-100 dark:bg-zinc-800 cursor-pointer text-center"
            >
              Cancel
            </button>
            <button
              type="submit"
              disabled={busy}
              className="w-full sm:w-auto px-4 py-2 rounded-lg text-xs font-semibold text-white bg-cyan-600 hover:bg-cyan-500 disabled:opacity-50 cursor-pointer shadow-xs text-center transition"
            >
              {busy ? 'Enforcing…' : 'Execute Real Containment'}
            </button>
          </div>
        </form>
      </div>
    </div>
  );
};
