import React from 'react';
import { FileText, X, Copy, Printer } from 'lucide-react';
import { Incident, SocTier, TierMetadata } from '../types';
import { formatTimelineClock } from '../utils';

interface ExportIncidentModalProps {
  isOpen: boolean;
  onClose: () => void;
  incident: Incident | null;
  tier: SocTier;
  tierMeta: TierMetadata;
  onCopyJson: () => void;
  onPrint: () => void;
}

export const ExportIncidentModal: React.FC<ExportIncidentModalProps> = ({
  isOpen,
  onClose,
  incident,
  tier,
  tierMeta,
  onCopyJson,
  onPrint
}) => {
  if (!isOpen || !incident) return null;

  return (
    <div className="fixed inset-0 z-50 bg-black/60 dark:bg-black/80 backdrop-blur-xs flex items-center justify-center p-3 sm:p-4 animate-fadeIn">
      <div className="relative w-full max-w-2xl max-h-[90vh] overflow-y-auto rounded-2xl border border-zinc-200 dark:border-zinc-800 bg-white dark:bg-[#0c0c0e] shadow-2xl p-4 sm:p-6 text-zinc-900 dark:text-zinc-100">
        <div className="flex items-center justify-between pb-3 border-b border-zinc-200 dark:border-zinc-800 mb-4">
          <div className="flex items-center gap-2">
            <FileText className="w-5 h-5 text-indigo-500 shrink-0" />
            <h3 className="text-sm sm:text-base font-bold text-zinc-900 dark:text-white">Forensic Incident Brief</h3>
          </div>
          <button
            onClick={onClose}
            className="p-1.5 rounded-lg text-zinc-400 hover:text-zinc-600 dark:hover:text-zinc-200 cursor-pointer"
          >
            <X className="w-4 h-4" />
          </button>
        </div>

        <div className="space-y-4 text-xs font-mono bg-zinc-50 dark:bg-zinc-900/40 p-3 sm:p-4 rounded-xl border border-zinc-200 dark:border-zinc-800 select-text overflow-x-auto">
          <div className="font-bold text-sm text-zinc-900 dark:text-white pb-2 border-b border-zinc-200 dark:border-zinc-800 font-sans">
            OAT SECURITY — FORENSIC INCIDENT BRIEF
          </div>
          <div>REFERENCE ID: {incident.id}</div>
          <div>INCIDENT TITLE: {incident.title}</div>
          <div>SOC TIER: {tierMeta.name} ({tier}) — {tierMeta.roleTitle}</div>
          <div>SEVERITY: {incident.severity}</div>
          <div>LIFECYCLE STATUS: {incident.status}</div>
          <div>AFFECTED ASSET: {incident.affectedAsset || 'Enterprise Perimeter'}</div>
          <div>INCIDENT OWNER: {incident.assignedAnalyst || 'Unassigned'}</div>
          <div>DECLARED AT: {incident.created}</div>
          <div>FORENSIC SUMMARY: {incident.notes || '—'}</div>
          <div className="pt-2 border-t border-zinc-200 dark:border-zinc-800">
            <div className="font-bold mb-1">CHRONOLOGICAL AUDIT TRAIL:</div>
            {(incident.timeline || []).map((t, idx) => (
              <div key={idx} className="text-zinc-600 dark:text-zinc-400 break-words">
                - [{formatTimelineClock(t.time)}] {t.note} (Authorized by: {t.author}{t.tier ? ` • SOC ${t.tier}` : ''})
              </div>
            ))}
          </div>
        </div>

        <div className="pt-4 flex flex-col sm:flex-row items-stretch sm:items-center justify-between gap-3 border-t border-zinc-200 dark:border-zinc-800 mt-4">
          <span className="text-[11px] text-zinc-400 font-mono text-center sm:text-left">Format: Standard Compliance Brief</span>
          <div className="flex flex-col-reverse sm:flex-row items-stretch sm:items-center gap-2">
            <button
              type="button"
              onClick={onCopyJson}
              className="w-full sm:w-auto px-3.5 py-2 rounded-lg text-xs font-medium border border-zinc-200 dark:border-zinc-700 bg-white dark:bg-zinc-800 hover:bg-zinc-50 cursor-pointer text-center"
            >
              <Copy className="w-3.5 h-3.5 inline mr-1" />
              Copy JSON
            </button>
            <button
              type="button"
              onClick={onPrint}
              className="w-full sm:w-auto px-4 py-2 rounded-lg text-xs font-semibold text-white bg-zinc-900 dark:bg-zinc-100 dark:text-zinc-900 cursor-pointer shadow-sm text-center"
            >
              <Printer className="w-3.5 h-3.5 inline mr-1" />
              Print Document
            </button>
          </div>
        </div>
      </div>
    </div>
  );
};
