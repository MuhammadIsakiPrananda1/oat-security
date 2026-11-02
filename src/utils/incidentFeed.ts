import { Incident, SocTier, ThreatItem, User } from '../types';

/**
 * The Correlated Threat Intelligence screen shows both detections (`threats`)
 * and the SOC cases opened from them (`incidents`). Incidents live in their own
 * table with a different shape, so they are normalized into `ThreatItem` rows
 * here. This keeps one real-time feed while preserving the incident fields the
 * drawer needs (SOC tier, assignee, timeline).
 */

const CLOSED_INCIDENT_STATUSES = new Set(['RESOLVED', 'CLOSED', 'MITIGATED', 'CONTAINED']);
const SOC_TIERS: SocTier[] = ['L1', 'L2', 'L3'];

export function isClosedIncident(status?: string): boolean {
  return CLOSED_INCIDENT_STATUSES.has(String(status || '').toUpperCase());
}

/** Normalizes a stored/requested SOC tier value. */
export function normalizeSocTier(value: unknown): SocTier | null {
  const tier = String(value || '').toUpperCase();
  return SOC_TIERS.includes(tier as SocTier) ? (tier as SocTier) : null;
}

/**
 * Resolves the incident visibility scope for an operator.
 * Super Admins are intentionally unrestricted; every other account is scoped
 * only when an explicit SOC tier is assigned to it.
 */
export function resolveUserSocScope(
  user?: Pick<User, 'role' | 'socTier'> | null
): SocTier | null {
  if (!user || user.role === 'Super Admin') return null;
  if (user.socTier) return normalizeSocTier(user.socTier);
  const role = String(user.role || '').toUpperCase();
  if (role.includes('L1')) return 'L1';
  if (role.includes('L2')) return 'L2';
  if (role.includes('L3')) return 'L3';
  return null;
}

/** SOC tier of an incident/threat row, falling back to severity like the API. */
export function getItemSocTier(item: { tier?: string | null; severity?: string | null }): SocTier {
  const explicit = normalizeSocTier(item?.tier);
  if (explicit) return explicit;
  const severity = String(item?.severity || '').toLowerCase();
  if (severity === 'critical') return 'L3';
  if (severity === 'high') return 'L2';
  return 'L1';
}

/** True when the row belongs to the operator's assigned SOC workspace. */
export function incidentMatchesSocScope(
  item: { tier?: string | null; severity?: string | null },
  scope: SocTier | null
): boolean {
  return !scope || getItemSocTier(item) === scope;
}

/** Incidents do not store a source IP column; the correlation engine writes it
 * into the notes ("... from 203.0.113.9"). Fall back to an em dash. */
export function extractIncidentSourceIp(notes?: string): string {
  const match = String(notes || '').match(/\b(\d{1,3}(?:\.\d{1,3}){3})\b/);
  return match ? match[1] : '—';
}

type IncidentLike = Partial<Incident> & {
  id: string;
  affected_asset?: string;
  assigned_to?: string;
  created_at?: string;
  updated_at?: string;
};

export function incidentToThreatItem(incident: IncidentLike): ThreatItem {
  const status = String(incident.status || 'NEW').toUpperCase();
  const affectedAsset = incident.affectedAsset || incident.affected_asset || 'Enterprise Perimeter';
  const assignedAnalyst = incident.assignedAnalyst || incident.assigned_to || 'Unassigned (Triage Queue)';
  const timeline = Array.isArray(incident.timeline)
    ? incident.timeline
        .filter(entry => entry && (entry.note || entry.time))
        .map(entry => ({
          time: entry.time || new Date().toISOString(),
          event: entry.note || 'Incident timeline updated'
        }))
    : [];

  return {
    id: incident.id,
    kind: 'incident',
    incidentId: incident.id,
    tier: getItemSocTier(incident),
    assignedAnalyst,
    timestamp: incident.created || incident.created_at || new Date().toISOString(),
    sourceIp: extractIncidentSourceIp(incident.notes),
    target: affectedAsset,
    attackType: incident.title || 'Correlated Incident',
    category: 'Incident Response',
    severity: incident.severity || 'Medium',
    confidence: 100,
    action: status,
    status,
    summary: incident.notes || incident.title || 'Incident opened by the correlation engine.',
    detectionReason: `SOC ${getItemSocTier(incident)} case opened by the correlation engine.`,
    detectionSource: 'Incident Response',
    affectedApplication: affectedAsset,
    timeline,
    relatedEvents: [],
    recommendedAction: 'Open the Incidents module to triage, assign, and contain this case.'
  };
}
