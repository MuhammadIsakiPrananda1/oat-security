import React from 'react';
import {
  ArrowLeft,
  Download,
  Trash2,
  TrendingUp,
  Zap,
  CheckCircle2,
  Server,
  Globe,
  Clock,
  CheckSquare,
  Square,
  ShieldAlert,
  Activity,
  ChevronRight
} from 'lucide-react';
import { StatusBadge } from '../common/StatusBadge';
import { Incident, SocTier, TierMetadata, SlaInfo, MitreClassification, AssetOption } from './types';
import { QUICK_NOTE_SNIPPETS } from './constants';
import { formatDateTime, formatTimelineClock, statusChip } from './utils';
import { User } from '../../types';
import { translate } from '../../i18n/translator';

interface IncidentDetailWorkspaceProps {
  incident: Incident;
  tier: SocTier;
  tierMeta: TierMetadata;
  sla: SlaInfo;
  mitre: MitreClassification;
  workspaceTab: 'playbook' | 'timeline' | 'evidence';
  onWorkspaceTabChange: (tab: 'playbook' | 'timeline' | 'evidence') => void;
  playbookChecks: Record<string, Record<string, boolean>>;
  onTogglePlaybookCheck: (incidentId: string, key: string) => void;
  noteText: string;
  onNoteTextChange: (text: string) => void;
  onAddNote: (e: React.FormEvent) => void;
  onApplyQuickSnippet: (snippet: string) => void;
  onBack: () => void;
  onExport: () => void;
  onDelete: () => void;
  onQuickPromoteTier: (targetTier: SocTier) => void;
  onOpenContainmentModal: (asset: string) => void;
  onUpdateStatus: (newStatus: string, defaultNote?: string) => void;
  onOpenAssignModal: () => void;
  assets?: AssetOption[];
  analysts?: User[];
  userEmail?: string;
  busy: boolean;
}

export const IncidentDetailWorkspace: React.FC<IncidentDetailWorkspaceProps> = ({
  incident,
  tier,
  tierMeta,
  sla,
  mitre,
  workspaceTab,
  onWorkspaceTabChange,
  playbookChecks,
  onTogglePlaybookCheck,
  noteText,
  onNoteTextChange,
  onAddNote,
  onApplyQuickSnippet,
  onBack,
  onExport,
  onDelete,
  onQuickPromoteTier,
  onOpenContainmentModal,
  onUpdateStatus,
  onOpenAssignModal,
  assets = [],
  analysts = [],
  userEmail: _userEmail,
  busy
}) => {
  // Resolve real asset from the database directory
  const matchedAsset = (assets || []).find(
    a => (a.hostname && a.hostname.toLowerCase() === (incident.affectedAsset || '').toLowerCase()) ||
         (a.name && a.name.toLowerCase() === (incident.affectedAsset || '').toLowerCase()) ||
         (a.ip && a.ip === incident.affectedAsset)
  );

  // Resolve real analyst from the database users
  const matchedAnalyst = (analysts || []).find(
    u => u.email.toLowerCase() === (incident.assignedAnalyst || '').toLowerCase()
  );

  const isClosed = ['CLOSED', 'MITIGATED', 'RESOLVED'].includes((incident.status || '').toUpperCase());

  return (
    <div className="space-y-4 animate-fadeIn">
      {/* Top Navigation & Action Buttons */}
      <div className="flex flex-col sm:flex-row items-stretch sm:items-center justify-between gap-2.5">
        <button
          onClick={onBack}
          className="inline-flex items-center justify-center sm:justify-start gap-2 px-3 py-2 sm:py-1.5 rounded-lg border border-zinc-200 dark:border-zinc-800 bg-white dark:bg-zinc-900 text-xs font-semibold text-zinc-700 dark:text-zinc-300 hover:bg-zinc-50 dark:hover:bg-zinc-800 cursor-pointer shadow-xs transition"
        >
          <ArrowLeft className="w-3.5 h-3.5" />
          <span>Back to Incident Queue</span>
        </button>

        <div className="flex items-center justify-end gap-2">
          <button
            onClick={onExport}
            className="inline-flex items-center gap-1.5 px-3 py-2 sm:py-1.5 rounded-lg border border-zinc-200 dark:border-zinc-800 bg-white dark:bg-zinc-900 text-xs font-medium text-zinc-700 dark:text-zinc-300 hover:bg-zinc-50 dark:hover:bg-zinc-800 cursor-pointer shadow-xs"
          >
            <Download className="w-3.5 h-3.5 text-zinc-500" />
            <span>Export Forensic Brief</span>
          </button>
          <button
            onClick={onDelete}
            disabled={busy}
            className="p-2 sm:p-1.5 rounded-lg border border-zinc-200 dark:border-zinc-800 text-zinc-400 hover:text-rose-500 cursor-pointer transition"
            title="Delete incident"
          >
            <Trash2 className="w-4 h-4" />
          </button>
        </div>
      </div>

      {/* Interactive SOC L1 ➔ L2 ➔ L3 Operational Stepper Pipeline */}
      <div className="p-3.5 sm:p-4 rounded-2xl bg-white dark:bg-[#0c0c0e] border border-zinc-200 dark:border-zinc-800 shadow-sm space-y-3">
        <div className="flex items-center justify-between text-xs font-mono uppercase tracking-wider text-zinc-500 dark:text-zinc-400 font-bold">
          <span className="flex items-center gap-1.5">
            <Activity className="w-3.5 h-3.5 text-indigo-500 animate-pulse" />
            <span>SOC Operational Command Pipeline (L1 ➔ L3 Workflow)</span>
          </span>
          <span className="px-2 py-0.5 rounded bg-zinc-100 dark:bg-zinc-800 text-zinc-700 dark:text-zinc-300 font-mono text-[10px]">
            ACTIVE: {tierMeta.badgeLabel}
          </span>
        </div>

        <div className="grid grid-cols-1 md:grid-cols-3 gap-2.5">
          {/* Step 1: L1 Triage */}
          <div className={`p-3 rounded-xl border flex items-center justify-between gap-3 transition ${
            tier === 'L1'
              ? 'border-sky-500 bg-sky-500/10 text-sky-800 dark:text-sky-300 ring-1 ring-sky-500 font-semibold shadow-xs'
              : 'border-zinc-200 dark:border-zinc-800/80 bg-zinc-50/50 dark:bg-zinc-900/20 text-zinc-600 dark:text-zinc-400 opacity-80'
          }`}>
            <div className="flex items-center gap-2.5 min-w-0">
              <div className={`w-6 h-6 rounded-full flex items-center justify-center font-bold text-xs shrink-0 ${
                tier === 'L1' ? 'bg-sky-600 text-white' : 'bg-zinc-200 dark:bg-zinc-800 text-zinc-600 dark:text-zinc-400'
              }`}>1</div>
              <div className="min-w-0">
                <div className="text-xs font-bold truncate">SOC L1 • Frontline Triage</div>
                <div className="text-[10px] font-mono opacity-80">&lt; 15m SLA • Edge Verification</div>
              </div>
            </div>
            {tier === 'L1' && (
              <button
                type="button"
                onClick={() => onQuickPromoteTier('L2')}
                disabled={busy}
                className="px-2.5 py-1 rounded-lg bg-indigo-600 hover:bg-indigo-500 text-white text-[11px] font-semibold cursor-pointer shrink-0 transition shadow-xs flex items-center gap-1"
              >
                <span>Advance L2</span>
                <ChevronRight className="w-3 h-3" />
              </button>
            )}
          </div>

          {/* Step 2: L2 Investigation & Containment */}
          <div className={`p-3 rounded-xl border flex items-center justify-between gap-3 transition ${
            tier === 'L2'
              ? 'border-amber-500 bg-amber-500/10 text-amber-800 dark:text-amber-300 ring-1 ring-amber-500 font-semibold shadow-xs'
              : 'border-zinc-200 dark:border-zinc-800/80 bg-zinc-50/50 dark:bg-zinc-900/20 text-zinc-600 dark:text-zinc-400 opacity-80'
          }`}>
            <div className="flex items-center gap-2.5 min-w-0">
              <div className={`w-6 h-6 rounded-full flex items-center justify-center font-bold text-xs shrink-0 ${
                tier === 'L2' ? 'bg-amber-600 text-white' : 'bg-zinc-200 dark:bg-zinc-800 text-zinc-600 dark:text-zinc-400'
              }`}>2</div>
              <div className="min-w-0">
                <div className="text-xs font-bold truncate">SOC L2 • Deep Forensics</div>
                <div className="text-[10px] font-mono opacity-80">&lt; 60m SLA • Host Isolation</div>
              </div>
            </div>
            {tier === 'L2' && (
              <button
                type="button"
                onClick={() => onQuickPromoteTier('L3')}
                disabled={busy}
                className="px-2.5 py-1 rounded-lg bg-rose-600 hover:bg-rose-500 text-white text-[11px] font-semibold cursor-pointer shrink-0 transition shadow-xs flex items-center gap-1"
              >
                <span>Escalate L3</span>
                <ChevronRight className="w-3 h-3" />
              </button>
            )}
          </div>

          {/* Step 3: L3 Crisis Commander & Closure */}
          <div className={`p-3 rounded-xl border flex items-center justify-between gap-3 transition ${
            tier === 'L3'
              ? 'border-rose-500 bg-rose-500/10 text-rose-800 dark:text-rose-300 ring-1 ring-rose-500 font-semibold shadow-xs'
              : 'border-zinc-200 dark:border-zinc-800/80 bg-zinc-50/50 dark:bg-zinc-900/20 text-zinc-600 dark:text-zinc-400 opacity-80'
          }`}>
            <div className="flex items-center gap-2.5 min-w-0">
              <div className={`w-6 h-6 rounded-full flex items-center justify-center font-bold text-xs shrink-0 ${
                tier === 'L3' ? 'bg-rose-600 text-white' : 'bg-zinc-200 dark:bg-zinc-800 text-zinc-600 dark:text-zinc-400'
              }`}>3</div>
              <div className="min-w-0">
                <div className="text-xs font-bold truncate">SOC L3 • Crisis Commander</div>
                <div className="text-[10px] font-mono opacity-80">&lt; 120m SLA • RCA Sign-off</div>
              </div>
            </div>
            {tier === 'L3' && !isClosed && (
              <button
                type="button"
                onClick={() => onUpdateStatus('RESOLVED', 'Incident Commander closure: Root cause analysis and systemic hardening verified.')}
                disabled={busy}
                className="px-2.5 py-1 rounded-lg bg-emerald-600 hover:bg-emerald-500 text-white text-[11px] font-semibold cursor-pointer shrink-0 transition shadow-xs flex items-center gap-1"
              >
                <span>Close Incident</span>
                <CheckCircle2 className="w-3 h-3" />
              </button>
            )}
          </div>
        </div>
      </div>

      {/* Main Incident Dossier Card */}
      <div className="rounded-2xl border border-zinc-200 dark:border-zinc-800 bg-white dark:bg-[#0c0c0e] shadow-lg divide-y divide-zinc-200 dark:divide-zinc-800 overflow-hidden">
        {/* Header Metadata & Quick Controls */}
        <div className="p-4 sm:p-6 space-y-4">
          <div className="flex flex-col lg:flex-row items-start justify-between gap-4">
            <div className="space-y-2.5 max-w-2xl w-full">
              <div className="flex items-center gap-1.5 sm:gap-2 flex-wrap">
                <span className="text-xs font-mono font-bold text-zinc-500 dark:text-zinc-400">{incident.id}</span>

                {/* Badge SOC Tier */}
                <span className={`inline-flex items-center gap-1.5 px-2.5 py-0.5 rounded-full border text-xs font-mono font-bold ${tierMeta.badgeStyle}`}>
                  <tierMeta.icon className="w-3.5 h-3.5" />
                  <span>{tierMeta.badgeLabel}</span>
                </span>

                <StatusBadge type="severity" value={incident.severity} size="sm" />

                <span className={`px-2 py-0.5 rounded-full border text-[11px] font-mono ${statusChip(incident.status)}`}>
                  {incident.status}
                </span>

                {sla && (
                  <span className={`px-2 py-0.5 rounded-md text-[10px] font-mono border flex items-center gap-1 ${
                    sla.isBreached
                      ? 'bg-rose-500/10 text-rose-500 border-rose-500/20 font-bold'
                      : 'bg-zinc-100 dark:bg-zinc-800 text-zinc-600 dark:text-zinc-300 border-zinc-200 dark:border-zinc-700'
                  }`}>
                    <Clock className="w-3 h-3 shrink-0" />
                    <span>{sla.label}</span>
                  </span>
                )}
              </div>

              <h2 className="text-base sm:text-xl font-bold text-zinc-900 dark:text-white leading-snug break-words">
                {incident.title}
              </h2>

              <div className="text-xs text-zinc-500 dark:text-zinc-400 font-mono flex flex-wrap items-center gap-x-3 gap-y-1 pt-0.5">
                <span>Created: {formatDateTime(incident.created)}</span>
                <span>•</span>
                <span>SLA Target: <strong className={tierMeta.accentColor}>{tierMeta.targetSla}</strong></span>
              </div>
            </div>

            {/* Quick Actions Buttons */}
            <div className="grid grid-cols-1 sm:flex sm:items-center gap-2 w-full lg:w-auto">
              <button
                onClick={() => {
                  const nextTier: SocTier = tier === 'L1' ? 'L2' : 'L3';
                  onQuickPromoteTier(nextTier);
                }}
                disabled={busy}
                className="w-full sm:w-auto justify-center px-3.5 py-2.5 sm:py-2 rounded-xl bg-indigo-600 hover:bg-indigo-500 text-white text-xs font-semibold flex items-center gap-1.5 shadow-sm transition cursor-pointer"
              >
                <TrendingUp className="w-4 h-4" />
                <span>Escalate Tier</span>
              </button>

              <button
                onClick={() => onOpenContainmentModal(incident.affectedAsset || '')}
                disabled={busy}
                className="w-full sm:w-auto justify-center px-3.5 py-2.5 sm:py-2 rounded-xl bg-cyan-600 hover:bg-cyan-500 text-white text-xs font-semibold flex items-center gap-1.5 shadow-sm transition cursor-pointer"
              >
                <Zap className="w-4 h-4" />
                <span>Execute Containment</span>
              </button>

              {isClosed ? (
                <button
                  onClick={() => onUpdateStatus('INVESTIGATING', 'Incident reopened by operator')}
                  disabled={busy}
                  className="w-full sm:w-auto justify-center px-3.5 py-2.5 sm:py-2 rounded-xl border border-zinc-300 dark:border-zinc-700 bg-zinc-100 dark:bg-zinc-800 hover:bg-zinc-200 text-xs font-semibold text-zinc-800 dark:text-zinc-200 cursor-pointer"
                >
                  Reopen
                </button>
              ) : (
                <button
                  onClick={() => onUpdateStatus('MITIGATED', 'Threat neutralized and mitigated by SOC team')}
                  disabled={busy}
                  className="w-full sm:w-auto justify-center px-3.5 py-2.5 sm:py-2 rounded-xl bg-emerald-600 hover:bg-emerald-500 text-white text-xs font-semibold flex items-center gap-1.5 shadow-sm transition cursor-pointer"
                >
                  <CheckCircle2 className="w-4 h-4" />
                  <span>Mark Mitigated</span>
                </button>
              )}
            </div>
          </div>

          {/* Real Affected Asset Banner & Assigned Analyst */}
          <div className="grid grid-cols-1 md:grid-cols-2 gap-3 pt-2">
            {/* Asset Card */}
            <div className="p-3.5 rounded-xl bg-zinc-50 dark:bg-zinc-900/40 border border-zinc-200 dark:border-zinc-800 flex items-start gap-3">
              <div className="w-8 h-8 rounded-lg bg-zinc-200 dark:bg-zinc-800 text-zinc-700 dark:text-zinc-300 flex items-center justify-center shrink-0 mt-0.5">
                {matchedAsset?.type === 'agent' ? (
                  <Server className="w-4 h-4 text-sky-500" />
                ) : (
                  <Globe className="w-4 h-4 text-violet-500" />
                )}
              </div>
              <div className="min-w-0 flex-1">
                <div className="text-[10px] font-mono text-zinc-400 uppercase tracking-wider flex items-center gap-1.5">
                  <span>AFFECTED ASSET (REAL FLEET)</span>
                  {matchedAsset && (
                    <span className="w-2 h-2 rounded-full bg-emerald-500 shrink-0" title="Asset found in database" />
                  )}
                </div>
                <div className="font-bold text-xs text-zinc-900 dark:text-white truncate mt-0.5">
                  {incident.affectedAsset || 'Enterprise Perimeter'}
                </div>
                <div className="text-[11px] text-zinc-500 dark:text-zinc-400 font-mono truncate mt-0.5">
                  {matchedAsset ? (
                    matchedAsset.type === 'agent' ? (
                      `Agent Host • IP: ${matchedAsset.ip || 'Local'} • OS: ${matchedAsset.os || 'Linux'} • Status: ${matchedAsset.status}`
                    ) : (
                      `Web App • Domain: ${matchedAsset.domain || 'N/A'} • Env: ${matchedAsset.environment || 'Production'}`
                    )
                  ) : (
                    'Perimeter Edge / Unregistered Target'
                  )}
                </div>
              </div>
            </div>

            {/* Analyst Card */}
            <div className="p-3.5 rounded-xl bg-zinc-50 dark:bg-zinc-900/40 border border-zinc-200 dark:border-zinc-800 flex items-center justify-between gap-3">
              <div className="flex items-center gap-3 min-w-0">
                <div className="w-8 h-8 rounded-full bg-indigo-600 text-white flex items-center justify-center font-bold font-mono text-xs shrink-0">
                  {matchedAnalyst ? (matchedAnalyst.name || matchedAnalyst.email)[0].toUpperCase() : 'U'}
                </div>
                <div className="min-w-0">
                  <div className="text-[10px] font-mono text-zinc-400 uppercase tracking-wider">
                    ASSIGNED SOC OWNER ({tierMeta.badgeLabel})
                  </div>
                  <div className="font-bold text-xs text-zinc-900 dark:text-white truncate">
                    {matchedAnalyst ? matchedAnalyst.name : (incident.assignedAnalyst || 'Unassigned')}
                  </div>
                  <div className="text-[11px] text-zinc-500 dark:text-zinc-400 font-mono truncate">
                    {matchedAnalyst ? `${matchedAnalyst.role} • ${matchedAnalyst.email}` : (incident.assignedAnalyst || 'Open Queue')}
                  </div>
                </div>
              </div>

              <button
                type="button"
                onClick={onOpenAssignModal}
                className="px-2.5 py-1.5 rounded-lg border border-zinc-200 dark:border-zinc-700 bg-white dark:bg-zinc-800 hover:bg-zinc-50 dark:hover:bg-zinc-700 text-zinc-700 dark:text-zinc-300 text-xs font-medium cursor-pointer shadow-xs shrink-0"
              >
                Reassign
              </button>
            </div>
          </div>
        </div>

        {/* Tab Navigation Sub-Detail */}
        <div className="flex border-b border-zinc-200 dark:border-zinc-800 px-3 sm:px-6 bg-zinc-50/50 dark:bg-zinc-900/30 overflow-x-auto no-scrollbar scroll-smooth gap-1 sm:gap-0">
          <button
            onClick={() => onWorkspaceTabChange('playbook')}
            className={`flex items-center gap-2 py-3 px-3 sm:px-4 text-xs font-semibold border-b-2 transition -mb-px cursor-pointer shrink-0 whitespace-nowrap ${
              workspaceTab === 'playbook'
                ? 'border-indigo-600 dark:border-indigo-400 text-zinc-900 dark:text-white'
                : 'border-transparent text-zinc-500 hover:text-zinc-800'
            }`}
          >
            <Zap className="w-3.5 h-3.5" />
            <span>1. Response Runbook (SOC {tier} SOP)</span>
          </button>

          <button
            onClick={() => onWorkspaceTabChange('timeline')}
            className={`flex items-center gap-2 py-3 px-3 sm:px-4 text-xs font-semibold border-b-2 transition -mb-px cursor-pointer shrink-0 whitespace-nowrap ${
              workspaceTab === 'timeline'
                ? 'border-indigo-600 dark:border-indigo-400 text-zinc-900 dark:text-white'
                : 'border-transparent text-zinc-500 hover:text-zinc-800'
            }`}
          >
            <Clock className="w-3.5 h-3.5" />
            <span>2. Real-Time Timeline &amp; Notes ({incident.timeline?.length || 0})</span>
          </button>

          <button
            onClick={() => onWorkspaceTabChange('evidence')}
            className={`flex items-center gap-2 py-3 px-3 sm:px-4 text-xs font-semibold border-b-2 transition -mb-px cursor-pointer shrink-0 whitespace-nowrap ${
              workspaceTab === 'evidence'
                ? 'border-indigo-600 dark:border-indigo-400 text-zinc-900 dark:text-white'
                : 'border-transparent text-zinc-500 hover:text-zinc-800'
            }`}
          >
            <ShieldAlert className="w-3.5 h-3.5" />
            <span>3. Technical Evidence &amp; MITRE ATT&amp;CK</span>
          </button>
        </div>

        {/* Sub-Tab 1: SOP Playbook */}
        {workspaceTab === 'playbook' && (
          <div className="p-4 sm:p-6 space-y-4 sm:space-y-6">
            <div className={`p-4 rounded-xl border ${tierMeta.badgeStyle} space-y-1.5`}>
              <div className="flex items-center justify-between">
                <span className="font-bold text-xs uppercase tracking-wider flex items-center gap-1.5">
                  <tierMeta.icon className="w-4 h-4" />
                  SOP {tierMeta.name} — {tierMeta.roleTitle}
                </span>
                <span className="text-[11px] font-mono font-bold">
                  Target SLA: {tierMeta.targetSla}
                </span>
              </div>
              <p className="text-xs text-zinc-700 dark:text-zinc-300 leading-relaxed font-sans">
                {tierMeta.summary}
              </p>
            </div>

            <div className="space-y-3">
              <div className="text-xs font-mono text-zinc-500 dark:text-zinc-400 uppercase tracking-wider font-bold">
                Operational Runbook Checklist (Tier {tier}):
              </div>

              <div className="space-y-2 bg-zinc-50 dark:bg-zinc-900/40 p-4 rounded-xl border border-zinc-200 dark:border-zinc-800">
                {(tier === 'L1' ? [
                  { key: 'l1_verify', title: '1. Verify Alert & Threat Validity', desc: 'Confirm it is not a false positive from internal health checks or pen tests.' },
                  { key: 'l1_trace', title: '2. Identify Attacker Entity & GeoIP', desc: 'Inspect attacker IP, ASN, abuse reputation, and target API endpoint.' },
                  { key: 'l1_contain', title: '3. Rapid Containment at Perimeter', desc: 'Apply emergency perimeter IP blocking rule.' },
                  { key: 'l1_account', title: '4. Secure User Accounts / Sessions', desc: 'Invalidate active JWT tokens and challenge login sessions.' },
                  { key: 'l1_escalate', title: '5. Evaluate SOC L2 Escalation', desc: 'Escalate to L2 if malicious payload bypasses defenses or host anomaly persists.' }
                ] : tier === 'L2' ? [
                  { key: 'l2_payload', title: '1. Extract Payload & Raw Logs', desc: 'Capture raw HTTP/TLS records and decode injection/exploit patterns.' },
                  { key: 'l2_mitre', title: '2. MITRE ATT&CK Framework Mapping', desc: 'Classify attacker tactics (e.g. T1190, T1059) and associate CVEs.' },
                  { key: 'l2_endpoint', title: '3. Endpoint Agent Forensics & Host Isolation', desc: 'Isolate agent host network while keeping telemetry active.' },
                  { key: 'l2_lateral', title: '4. Lateral Movement Tracking', desc: 'Trace internal communication between microservices.' },
                  { key: 'l2_waf_tune', title: '5. WAF Signature Tuning', desc: 'Draft custom WAF regex signatures to permanently reject exploit vectors.' },
                  { key: 'l2_escalate', title: '6. Evaluate SOC L3 Escalation', desc: 'Escalate to L3 if core banking or sensitive databases are targeted.' }
                ] : [
                  { key: 'l3_crisis', title: '1. Cyber Crisis Declaration & War Room', desc: 'Activate dedicated emergency incident task force with CISO and Lead DevOps.' },
                  { key: 'l3_segment', title: '2. Zone Segmentation & Database Isolation', desc: 'Cut internal interconnects for sensitive data zones if breach is imminent.' },
                  { key: 'l3_integrity', title: '3. Data Integrity Audit & Exfiltration Check', desc: 'Verify transaction database checksums and assess data leakage.' },
                  { key: 'l3_ciso_report', title: '4. CISO Executive Briefing & Regulatory Brief', desc: 'Compile official forensic brief for regulatory reporting.' },
                  { key: 'l3_rca', title: '5. Root Cause Analysis (RCA) & Hardening', desc: 'Document post-mortem RCA, implement systemic hardening, and close incident.' }
                ]).map(item => {
                  const isChecked = !!playbookChecks[incident.id]?.[item.key];
                  return (
                    <button
                      key={item.key}
                      type="button"
                      onClick={() => onTogglePlaybookCheck(incident.id, item.key)}
                      className="w-full flex items-start gap-3 p-2.5 rounded-lg text-left transition hover:bg-zinc-100 dark:hover:bg-zinc-800/80 cursor-pointer"
                    >
                      <div className="pt-0.5">
                        {isChecked ? (
                          <CheckSquare className="w-4 h-4 text-emerald-500 shrink-0" />
                        ) : (
                          <Square className="w-4 h-4 text-zinc-400 shrink-0" />
                        )}
                      </div>
                      <div>
                        <div className={`text-xs font-semibold ${isChecked ? 'line-through text-zinc-400' : 'text-zinc-900 dark:text-white'}`}>
                          {item.title}
                        </div>
                        <div className="text-[11px] text-zinc-500 dark:text-zinc-400">
                          {item.desc}
                        </div>
                      </div>
                    </button>
                  );
                })}
              </div>
            </div>
          </div>
        )}

        {/* Sub-Tab 2: Timeline & Notes */}
        {workspaceTab === 'timeline' && (
          <div className="p-4 sm:p-6 space-y-6">
            <div className="space-y-4">
              <div className="text-xs font-mono text-zinc-500 dark:text-zinc-400 uppercase tracking-wider font-bold">
                Live Audit Trail Timeline:
              </div>

              <div className="space-y-3 relative before:absolute before:inset-0 before:left-3 before:w-0.5 before:bg-zinc-200 dark:before:bg-zinc-800">
                {(incident.timeline || []).map((t, idx) => (
                  <div key={idx} className="relative flex items-start gap-3.5 pl-1.5">
                    <div className="w-3.5 h-3.5 rounded-full bg-white dark:bg-zinc-900 border-2 border-indigo-500 shrink-0 mt-0.5 z-10" />
                    <div className="flex-1 p-3 rounded-xl bg-zinc-50 dark:bg-zinc-900/40 border border-zinc-200 dark:border-zinc-800 space-y-1">
                      <div className="flex items-center justify-between text-[11px] text-zinc-400 font-mono">
                        <span className="font-semibold text-zinc-700 dark:text-zinc-300">
                          {t.author || 'System'} {t.tier ? `[${t.tier}]` : ''}
                        </span>
                        <span>{formatTimelineClock(t.time)}</span>
                      </div>
                      <p className="text-xs text-zinc-800 dark:text-zinc-200 leading-relaxed font-sans">
                        {t.note}
                      </p>
                    </div>
                  </div>
                ))}
              </div>
            </div>

            {/* Add Note Form */}
            <form onSubmit={onAddNote} className="space-y-3 pt-4 border-t border-zinc-200 dark:border-zinc-800">
              <label className="block text-xs font-semibold text-zinc-700 dark:text-zinc-300">
                Append Forensic Audit Note (Logged to Database)
              </label>

              {/* Quick Snippets */}
              <div className="flex flex-wrap gap-1.5">
                {QUICK_NOTE_SNIPPETS.map((snip, i) => (
                  <button
                    key={i}
                    type="button"
                    onClick={() => onApplyQuickSnippet(snip)}
                    className="px-2 py-1 rounded-md bg-zinc-100 dark:bg-zinc-800/80 hover:bg-zinc-200 dark:hover:bg-zinc-700 text-[10px] text-zinc-600 dark:text-zinc-300 transition cursor-pointer"
                  >
                    + {translate(snip).slice(0, 36)}…
                  </button>
                ))}
              </div>

              <div className="flex gap-2">
                <input
                  type="text"
                  value={noteText}
                  onChange={e => onNoteTextChange(e.target.value)}
                  placeholder="Type investigation findings, containment hashes, or verification notes..."
                  className="flex-1 px-3.5 py-2 bg-zinc-50 dark:bg-zinc-900/60 border border-zinc-200 dark:border-zinc-800 rounded-lg text-xs text-zinc-900 dark:text-white placeholder-zinc-400 focus:outline-none"
                />
                <button
                  type="submit"
                  disabled={busy || !noteText.trim()}
                  className="px-4 py-2 rounded-lg text-xs font-semibold text-white bg-indigo-600 hover:bg-indigo-500 disabled:opacity-50 cursor-pointer shadow-xs transition"
                >
                  Save Note
                </button>
              </div>
            </form>
          </div>
        )}

        {/* Sub-Tab 3: Evidence & MITRE */}
        {workspaceTab === 'evidence' && (
          <div className="p-4 sm:p-6 space-y-4 sm:space-y-6">
            <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
              {/* MITRE Mapping */}
              <div className="p-4 rounded-xl border border-zinc-200 dark:border-zinc-800 bg-zinc-50 dark:bg-zinc-900/40 space-y-3">
                <div className="text-xs font-mono font-bold text-zinc-500 dark:text-zinc-400 uppercase tracking-wider">
                  MITRE ATT&amp;CK Framework Classification:
                </div>
                <div className="space-y-2">
                  <div className="flex items-center justify-between text-xs">
                    <span className="text-zinc-500">Tactic:</span>
                    <span className="font-semibold text-zinc-900 dark:text-white">{mitre.tactic}</span>
                  </div>
                  <div className="flex items-center justify-between text-xs">
                    <span className="text-zinc-500">Technique:</span>
                    <span className="font-semibold text-zinc-900 dark:text-white">{mitre.technique}</span>
                  </div>
                  <div className="flex items-center justify-between text-xs">
                    <span className="text-zinc-500">Technique ID:</span>
                    <span className="font-mono font-bold text-indigo-600 dark:text-indigo-400">{mitre.id}</span>
                  </div>
                </div>
              </div>

              {/* Initial Indicators */}
              <div className="p-4 rounded-xl border border-zinc-200 dark:border-zinc-800 bg-zinc-50 dark:bg-zinc-900/40 space-y-3">
                <div className="text-xs font-mono font-bold text-zinc-500 dark:text-zinc-400 uppercase tracking-wider">
                  Incident Technical Notes &amp; IoCs:
                </div>
                <p className="text-xs text-zinc-700 dark:text-zinc-300 leading-relaxed font-mono whitespace-pre-wrap">
                  {incident.notes || 'No initial technical payload attached.'}
                </p>
              </div>
            </div>
          </div>
        )}
      </div>
    </div>
  );
};
