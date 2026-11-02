import { formatDate, formatDateTime, formatTime, normalizeClockTime } from '../../utils/dateTime';
import { translate } from '../../i18n/translator';
import { ThreatSeverity, SocTier, Incident, MitreClassification, SlaInfo, IncidentAuditRow } from './types';
import { MITRE_MAPPINGS } from './constants';

export { formatDate, formatDateTime, formatTime, normalizeClockTime };


/**
 * Returns MITRE ATT&CK tactic and technique correlation based on incident indicators.
 */
export const getMitreContext = (title: string, notes?: string): MitreClassification => {
  const text = `${title} ${notes || ''}`.toLowerCase();
  for (const [key, val] of Object.entries(MITRE_MAPPINGS)) {
    if (key !== 'default' && text.includes(key)) {
      return val;
    }
  }
  return MITRE_MAPPINGS['default'];
};

/**
 * Resolves the designated SOC Tier (L1, L2, L3) for a given incident.
 */
export const getIncidentTier = (inc: Incident): SocTier => {
  if (inc.tier && ['L1', 'L2', 'L3'].includes(inc.tier)) return inc.tier;
  const s = (inc.severity || '').toLowerCase();
  if (s === 'critical') return 'L3';
  if (s === 'high') return 'L2';
  return 'L1';
};

/**
 * Returns styling classes for lifecycle status badges.
 */
export const statusChip = (status: string): string => {
  const s = (status || '').toUpperCase();
  if (s === 'MITIGATED' || s === 'CLOSED' || s === 'RESOLVED') {
    return 'bg-emerald-500/10 text-emerald-600 dark:text-emerald-400 border-emerald-500/30';
  }
  if (s === 'CONTAINED') {
    return 'bg-cyan-500/10 text-cyan-600 dark:text-cyan-400 border-cyan-500/30';
  }
  if (s === 'INVESTIGATING') {
    return 'bg-amber-500/10 text-amber-600 dark:text-amber-400 border-amber-500/30';
  }
  if (s === 'NEW') {
    return 'bg-rose-500/10 text-rose-600 dark:text-rose-400 border-rose-500/30';
  }
  return 'bg-zinc-500/10 text-zinc-600 dark:text-zinc-400 border-zinc-500/20';
};

/**
 * Returns left-border accent styling according to threat severity.
 */
export const severityBorder = (severity: string): string => {
  const s = (severity || '').toLowerCase();
  if (s === 'critical') return 'border-l-4 border-l-rose-500';
  if (s === 'high') return 'border-l-4 border-l-amber-500';
  if (s === 'medium') return 'border-l-4 border-l-yellow-500';
  return 'border-l-4 border-l-sky-500';
};

/**
 * Determines whether a timeline timestamp contains a full ISO calendar date.
 */
export const hasCalendarDate = (value: string): boolean => /\d{4}-\d{2}-\d{2}/.test(value || '');

/**
 * Renders chronological clock time, accepting ISO strings or clock-only values.
 */
export const formatTimelineClock = (value: string): string =>
  hasCalendarDate(value) ? formatTime(value) : normalizeClockTime(value);

/**
 * Formats audit trail timestamps into readable local format.
 */
export const formatAuditTime = (value: string): string => {
  if (!hasCalendarDate(value)) return normalizeClockTime(value) || '—';
  const formatted = formatDateTime(value);
  return formatted === '—' ? value : formatted;
};

/**
 * Formats declared-at dates for audit entries.
 */
export const formatDeclaredDate = (value: string): string => {
  const formatted = formatDate(value);
  return formatted === '—' ? value : formatted;
};

/**
 * Parses stored UTC ISO timestamp strings reliably into milliseconds.
 */
export const parseStoredTime = (value: string): number => {
  const raw = String(value || '').trim();
  if (!raw) return 0;
  const normalized = /^\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}(:\d{2}(\.\d+)?)?$/.test(raw)
    ? `${raw.replace(' ', 'T')}Z`
    : raw;
  const parsed = new Date(normalized).getTime();
  return isNaN(parsed) ? 0 : parsed;
};

/**
 * Computes seconds since midnight for legacy clock-only timeline entries.
 */
export const clockSeconds = (value: string): number => {
  const match = String(value || '').trim().match(/^(\d{1,2})[:.](\d{2})(?:[:.](\d{2}))?/);
  if (!match) return 0;
  return Number(match[1]) * 3600 + Number(match[2]) * 60 + Number(match[3] || 0);
};

/**
 * Computes SLA targets, remaining time, and breach status based on tier and severity.
 */
export const getSlaInfo = (
  severity: ThreatSeverity,
  createdAt: string,
  status: string,
  tier: SocTier = 'L1'
): SlaInfo => {
  const isClosed = ['MITIGATED', 'CLOSED', 'RESOLVED'].includes((status || '').toUpperCase());
  const severityMultiplier = severity === 'Critical' ? 0.75 : severity === 'High' ? 1 : 1.5;
  const baseMinutes = tier === 'L3' ? 120 : tier === 'L2' ? 60 : 15;
  const maxMinutes = Math.round(baseMinutes * severityMultiplier);

  const createdDate = new Date(createdAt);
  const diffMinutes = Math.max(0, Math.floor((Date.now() - (isNaN(createdDate.getTime()) ? Date.now() : createdDate.getTime())) / 60000));

  const remainingMinutes = maxMinutes - diffMinutes;
  const isBreached = remainingMinutes < 0 && !isClosed;

  return {
    maxMinutes,
    elapsedMinutes: diffMinutes,
    remainingMinutes,
    isBreached,
    isClosed,
    label: isClosed ? 'SLA Met' : isBreached ? `SLA Breached ${Math.abs(remainingMinutes)}m` : `SLA Remaining: ${remainingMinutes}m`
  };
};

/**
 * Exports audit trail rows into standard RFC-4180 CSV format and triggers browser download.
 */
export const exportAuditToCsv = (rows: IncidentAuditRow[]): void => {
  const header = ['Event Time', 'Incident Declared', 'Incident ID', 'Incident Title', 'SOC Tier', 'Severity', 'Status', 'Actor', 'Audit Note'].map(translate);
  const escape = (value: unknown) => `"${String(value ?? '').replace(/"/g, '""')}"`;
  const lines = [header.join(',')].concat(
    rows.map(row =>
      [row.time, row.declaredAt, row.incidentId, row.title, row.tier, row.severity, row.status, row.author, row.note]
        .map(escape)
        .join(',')
    )
  );
  const blob = new Blob([lines.join('\r\n')], { type: 'text/csv;charset=utf-8;' });
  const url = URL.createObjectURL(blob);
  const link = document.createElement('a');
  link.href = url;
  link.download = `incident-audit-trail-${new Date().toISOString().slice(0, 10)}.csv`;
  link.click();
  URL.revokeObjectURL(url);
};
