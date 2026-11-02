import { Eye, Crosshair, Flame, ShieldAlert, FileText, BookOpen } from 'lucide-react';
import { ThreatSeverity, SocTier, SocAnalyst, TierMetadata, MitreClassification, WorkspaceOption } from './types';

export const SEVERITIES: ThreatSeverity[] = ['Critical', 'High', 'Medium', 'Low'];

/**
 * Standard SOC Team roster organized across Tier 1, Tier 2, and Tier 3.
 */
export const SOC_TEAM: SocAnalyst[] = [
  // SOC L1 - Frontline & Triage
  {
    name: 'Budi Santoso',
    email: 'budi.santoso@oat-security.id',
    role: 'SOC L1 Triage Analyst',
    tier: 'L1',
    shift: 'Morning Shift (24/7 Frontline)',
    skills: ['Alert Triage', 'WAF Filtering', 'Perimeter IP Block', 'False Positive Elimination']
  },
  {
    name: 'Putri Rahayu',
    email: 'putri.rahayu@oat-security.id',
    role: 'SOC L1 Incident Responder',
    tier: 'L1',
    shift: 'Night Shift (24/7 Frontline)',
    skills: ['Rapid Host Isolation', 'Credential Revocation', 'Log Ingestion']
  },
  {
    name: 'Automated SecOps Bot',
    email: 'automation@oat-security.id',
    role: 'SOC L1 Auto-Containment Bot',
    tier: 'L1',
    shift: 'Automated 24/7/365',
    skills: ['Auto-ACL Generation', 'Rate-limiting', 'IP Blacklist Sync']
  },

  // SOC L2 - Deep Forensics & Threat Hunting
  {
    name: 'Rizky Pratama',
    email: 'rizky.pratama@oat-security.id',
    role: 'SOC L2 Threat Hunter',
    tier: 'L2',
    shift: 'Day Shift (Advanced Forensics)',
    skills: ['MITRE ATT&CK Mapping', 'PCAP Analysis', 'Memory Dump Forensics', 'Lateral Movement Tracking']
  },
  {
    name: 'Siti Nurhaliza',
    email: 'siti.nurhaliza@oat-security.id',
    role: 'SOC L2 Senior Security Analyst',
    tier: 'L2',
    shift: 'Day Shift (Forensic Lead)',
    skills: ['Reverse Malware Triage', 'SIEM Log Correlation', 'Custom WAF Rule', 'Exploit Analysis']
  },

  // SOC L3 - Incident Commander & Crisis Management
  {
    name: 'Andi Firmansyah',
    email: 'andi.firmansyah@oat-security.id',
    role: 'SOC L3 Principal Incident Commander',
    tier: 'L3',
    shift: 'On-Call Crisis Lead',
    skills: ['Cyber Crisis Response', 'Enterprise-Scale Isolation', 'Executive Briefing', 'Forensic Root Cause Analysis']
  },
  {
    name: 'Dr. Farhan Hakim',
    email: 'farhan.hakim@oat-security.id',
    role: 'SOC L3 Threat Intel & Zero-Day SME',
    tier: 'L3',
    shift: 'Advisory & Red-Blue Lead',
    skills: ['Zero-Day Vulnerability', 'APT Adversary Tracking', 'Regulatory Compliance (OJK/BSSN)', 'Post-Mortem Hardening']
  }
];

/**
 * Metadata definitions for SOC Tier governance, SLAs, and escalation pathways.
 */
export const SOC_TIER_META: Record<SocTier, TierMetadata> = {
  L1: {
    name: 'SOC Tier 1',
    badgeLabel: 'SOC L1 • Triage',
    badgeStyle: 'bg-sky-500/10 text-sky-600 dark:text-sky-400 border-sky-500/30',
    borderStyle: 'border-l-4 border-l-sky-500',
    accentColor: 'text-sky-500',
    icon: Eye,
    targetSla: '< 15 Minutes',
    roleTitle: 'Frontline Triage & Response',
    summary: 'Initial alert validation, false-positive elimination, and fast perimeter containment (IP blocking, account isolation).',
    escalateCondition: 'Escalate to L2 when an active malicious payload, WAF bypass, or deep log correlation is detected.'
  },
  L2: {
    name: 'SOC Tier 2',
    badgeLabel: 'SOC L2 • Investigation',
    badgeStyle: 'bg-amber-500/10 text-amber-600 dark:text-amber-400 border-amber-500/30',
    borderStyle: 'border-l-4 border-l-amber-500',
    accentColor: 'text-amber-500',
    icon: Crosshair,
    targetSla: '< 60 Minutes',
    roleTitle: 'Forensic Investigation & Threat Hunting',
    summary: 'Attack trace analysis, MITRE ATT&CK mapping, memory/PCAP dumps, lateral movement tracking, and custom WAF rule creation.',
    escalateCondition: 'Escalate to L3 when Core Banking is impacted, a data breach is confirmed, or ransomware is involved.'
  },
  L3: {
    name: 'SOC Tier 3',
    badgeLabel: 'SOC L3 • Crisis Commander',
    badgeStyle: 'bg-rose-500/10 text-rose-600 dark:text-rose-400 border-rose-500/30',
    borderStyle: 'border-l-4 border-l-rose-500',
    accentColor: 'text-rose-500',
    icon: Flame,
    targetSla: '< 120 Minutes',
    roleTitle: 'Incident Commander & Crisis Management',
    summary: 'Enterprise crisis handling, core network zone isolation, Zero-Day/APT response, and executive & regulatory briefings.',
    escalateCondition: 'Highest tier. Coordinates infrastructure recovery, signs off incident closure, and leads the post-mortem RCA.'
  }
};

export const PRESET_ASSETS = [
  'Core Banking API',
  'Payment Gateway',
  'Mobile Banking Backend',
  'KYC Verification Service',
  'Core Banking Zone',
  'Internal Admin Console',
  'Customer Identity Provider (IdP)',
  'Enterprise Edge DMZ'
];

export const QUICK_NOTE_SNIPPETS = [
  'Attacker IP successfully blocked at the edge firewall perimeter.',
  'Escalated to SOC L2: active malicious injection payload detected.',
  'Escalated to SOC L3: critical impact suspected in the Core Banking zone.',
  'Endpoint host isolated from the internal subnet for forensic preservation.',
  'Memory snapshot and PCAP telemetry archived successfully.',
  'API sessions revoked and credentials rotated.',
  'Aggressive WAF CAPTCHA challenge enabled for the attacker ASN.',
  'Telemetry back to baseline; post-mitigation monitoring active.'
];

export const MITRE_MAPPINGS: Record<string, MitreClassification> = {
  'credential': { tactic: 'Credential Access', technique: 'Brute Force / Password Spraying', id: 'T1110.003' },
  'traversal': { tactic: 'Initial Access', technique: 'Exploit Public-Facing Application', id: 'T1190' },
  'scanner': { tactic: 'Reconnaissance', technique: 'Active Scanning / Vulnerability Sweep', id: 'T1595' },
  'brute': { tactic: 'Credential Access', technique: 'Brute Force', id: 'T1110' },
  'sql': { tactic: 'Initial Access', technique: 'SQL Injection Exploitation', id: 'T1190' },
  'beacon': { tactic: 'Command and Control', technique: 'Application Layer Protocol Beaconing', id: 'T1071' },
  'denial': { tactic: 'Impact', technique: 'Network Denial of Service', id: 'T1498' },
  'rce': { tactic: 'Execution', technique: 'Command and Scripting Interpreter', id: 'T1059' },
  'default': { tactic: 'Defense Evasion', technique: 'Exploit Public-Facing Surface', id: 'T1190' }
};

/**
 * Builds the list of available workspaces with real-time incident counters.
 */
export function getWorkspaceOptions(
  metrics: { total: number; l1Active: number; l2Active: number; l3Active: number },
  auditCount: number
): WorkspaceOption[] {
  return [
    {
      id: 'ALL',
      label: 'All Incidents',
      group: 'workspaces',
      icon: ShieldAlert,
      iconColor: 'text-zinc-500 dark:text-zinc-400',
      badgeText: `${metrics.total}`,
      badgeStyle: 'bg-zinc-200 dark:bg-zinc-800 text-zinc-700 dark:text-zinc-300',
      description: 'Unified queue across all response tiers'
    },
    {
      id: 'L1',
      label: 'SOC L1 Workspace (Triage)',
      group: 'workspaces',
      icon: Eye,
      iconColor: 'text-sky-500',
      badgeText: `${metrics.l1Active} Active`,
      badgeStyle: 'bg-sky-500/15 text-sky-600 dark:text-sky-400 border border-sky-500/20',
      description: 'Alert triage, false positive elimination & SLA < 15m'
    },
    {
      id: 'L2',
      label: 'SOC L2 Workspace (Investigation)',
      group: 'workspaces',
      icon: Crosshair,
      iconColor: 'text-amber-500',
      badgeText: `${metrics.l2Active} Active`,
      badgeStyle: 'bg-amber-500/15 text-amber-600 dark:text-amber-400 border border-amber-500/20',
      description: 'Root cause analysis, MITRE ATT&CK & SLA < 60m'
    },
    {
      id: 'L3',
      label: 'SOC L3 Workspace (Crisis)',
      group: 'workspaces',
      icon: Flame,
      iconColor: 'text-rose-500',
      badgeText: `${metrics.l3Active} Active`,
      badgeStyle: 'bg-rose-500/15 text-rose-600 dark:text-rose-400 border border-rose-500/20',
      description: 'Emergency crisis command, enterprise containment & SLA < 120m'
    },
    {
      id: 'AUDIT',
      label: 'Audit Trail',
      group: 'governance',
      icon: FileText,
      iconColor: 'text-emerald-500',
      badgeText: `${auditCount}`,
      badgeStyle: 'bg-emerald-500/15 text-emerald-600 dark:text-emerald-400 border border-emerald-500/20',
      description: 'Forensic event logs & compliance audit export'
    },
    {
      id: 'GUIDE',
      label: 'Runbooks & SOC Team',
      group: 'governance',
      icon: BookOpen,
      iconColor: 'text-indigo-500',
      badgeText: 'SOP & Roster',
      badgeStyle: 'bg-indigo-500/15 text-indigo-600 dark:text-indigo-400 border border-indigo-500/20',
      description: 'Operating procedures, playbooks & analyst directory'
    }
  ];
}
