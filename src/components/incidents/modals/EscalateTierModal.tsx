import React from 'react';
import { TrendingUp, X } from 'lucide-react';
import { Incident, SocTier } from '../types';
import { User } from '../../../types';
import { translate } from '../../../i18n/translator';

interface EscalateTierModalProps {
  isOpen: boolean;
  onClose: () => void;
  incident: Incident | null;
  selectedTier: SocTier;
  targetTier: SocTier;
  onTargetTierChange: (tier: SocTier) => void;
  escalationAssignee: string;
  onEscalationAssigneeChange: (email: string) => void;
  escalationReason: string;
  onEscalationReasonChange: (reason: string) => void;
  onSubmit: (e: React.FormEvent) => void;
  analysts?: User[];
  userEmail?: string;
  busy: boolean;
}

export const EscalateTierModal: React.FC<EscalateTierModalProps> = ({
  isOpen,
  onClose,
  incident,
  selectedTier,
  targetTier,
  onTargetTierChange,
  escalationAssignee,
  onEscalationAssigneeChange,
  escalationReason,
  onEscalationReasonChange,
  onSubmit,
  analysts = [],
  userEmail,
  busy
}) => {
  if (!isOpen || !incident) return null;

  return (
    <div className="fixed inset-0 z-50 bg-black/60 dark:bg-black/80 backdrop-blur-xs flex items-center justify-center p-3 sm:p-4 animate-fadeIn">
      <div className="relative w-full max-w-md max-h-[90vh] overflow-y-auto rounded-2xl border border-zinc-200 dark:border-zinc-800 bg-white dark:bg-[#0c0c0e] shadow-2xl p-4 sm:p-6 text-zinc-900 dark:text-zinc-100">
        <div className="flex items-center justify-between pb-3 border-b border-zinc-200 dark:border-zinc-800 mb-4">
          <div className="flex items-center gap-2">
            <div className="w-8 h-8 rounded-lg bg-indigo-500/10 text-indigo-600 flex items-center justify-center shrink-0">
              <TrendingUp className="w-4 h-4" />
            </div>
            <div>
              <h3 className="text-sm sm:text-base font-bold text-zinc-900 dark:text-white">Escalate Incident SOC Tier</h3>
              <p className="text-xs text-zinc-500">
                {translate(`Target: ${incident.id} (Current Tier: ${selectedTier})`)}
              </p>
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
              Select Target SOC Tier
            </label>
            <div className="grid grid-cols-1 sm:grid-cols-2 gap-2">
              <button
                type="button"
                onClick={() => onTargetTierChange('L2')}
                className={`p-3 rounded-xl border text-left cursor-pointer transition ${
                  targetTier === 'L2'
                    ? 'border-amber-500 bg-amber-500/10 text-amber-700 dark:text-amber-400 font-bold ring-1 ring-amber-500'
                    : 'border-zinc-200 dark:border-zinc-800 text-zinc-500'
                }`}
              >
                <div className="text-xs font-bold">SOC Tier 2 (L2)</div>
                <div className="text-[10px] font-normal opacity-80">Forensic Investigation &amp; Hunting (&lt; 60m SLA)</div>
              </button>

              <button
                type="button"
                onClick={() => onTargetTierChange('L3')}
                className={`p-3 rounded-xl border text-left cursor-pointer transition ${
                  targetTier === 'L3'
                    ? 'border-rose-500 bg-rose-500/10 text-rose-700 dark:text-rose-400 font-bold ring-1 ring-rose-500'
                    : 'border-zinc-200 dark:border-zinc-800 text-zinc-500'
                }`}
              >
                <div className="text-xs font-bold">SOC Tier 3 (L3)</div>
                <div className="text-[10px] font-normal opacity-80">Crisis Commander / Core Impact (&lt; 120m SLA)</div>
              </button>
            </div>
          </div>

          <div>
            <label className="block text-xs font-semibold text-zinc-700 dark:text-zinc-300 mb-1">
              Assign Escalation Specialist (Real SOC Users)
            </label>
            <select
              value={escalationAssignee}
              onChange={e => onEscalationAssigneeChange(e.target.value)}
              className="w-full px-3.5 py-2 bg-zinc-50 dark:bg-zinc-900/60 border border-zinc-200 dark:border-zinc-800 rounded-lg text-xs text-zinc-900 dark:text-white focus:outline-none cursor-pointer"
            >
              <option value="">Keep Current Assignee ({incident.assignedAnalyst || 'Unassigned'})</option>
              {userEmail && <option value={userEmail}>{translate(`Myself (${userEmail})`)}</option>}
              {analysts.map(u => (
                <option key={u.id} value={u.email}>
                  {u.name} — {u.role} ({u.email})
                </option>
              ))}
            </select>
          </div>

          <div>
            <label className="block text-xs font-semibold text-zinc-700 dark:text-zinc-300 mb-1">
              Escalation Reason / Justification <span className="text-rose-500">*</span>
            </label>
            <textarea
              required
              rows={3}
              value={escalationReason}
              onChange={e => onEscalationReasonChange(e.target.value)}
              placeholder="e.g. Active malicious payload bypass detected on WAF; endpoint host memory capture and lateral movement forensics required."
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
              className="w-full sm:w-auto px-4 py-2 rounded-lg text-xs font-semibold text-white bg-indigo-600 hover:bg-indigo-500 disabled:opacity-50 cursor-pointer shadow-sm transition text-center"
            >
              {busy ? 'Escalating…' : `Confirm Escalation to [SOC ${targetTier}]`}
            </button>
          </div>
        </form>
      </div>
    </div>
  );
};
