import { db } from '../database/db';
import { SecurityEventBus } from '../utils/eventBus';
import { getSocTelemetry } from './socCopilotService';
import { listScans } from './malwareScanner';
import { getTelemetryAnalytics } from './analyticsService';

/**
 * Publishes authoritative tenant snapshots after server-side state changes.
 * The browser may render an event optimistically, but these snapshots are the
 * source of truth and make every open console converge to the same DB state.
 */
const SNAPSHOT_TRIGGERS = new Set([
  'security_event',
  'security_event.created',
  'threat.created',
  'threat.updated',
  'incident.created',
  'incident.updated',
  'incident.deleted',
  'malware.detected',
  'malware.scan_completed',
  'malware.action_updated',
  'rule.updated',
  'agent.ingested',
  'agent.updated',
  'agent.status',
  'endpoint.status',
  'threat_intel.ioc_created',
  'threat_intel.updated',
  'contact.created',
  'contact.updated'
]);

const pending = new Map<string, NodeJS.Timeout>();

function parseArray(value: unknown): any[] {
  if (Array.isArray(value)) return value;
  try {
    const parsed = JSON.parse(String(value || '[]'));
    return Array.isArray(parsed) ? parsed : [];
  } catch {
    return [];
  }
}

function threatSnapshot(organizationId: string) {
  const rows = db.prepare(`
    SELECT * FROM threats
    WHERE organization_id = ?
    ORDER BY timestamp DESC
    LIMIT 100
  `).all(organizationId) as any[];

  const metricsRow = db.prepare(`
    SELECT COUNT(*) AS total,
      SUM(CASE WHEN LOWER(severity) = 'critical' THEN 1 ELSE 0 END) AS critical,
      SUM(CASE WHEN LOWER(severity) = 'high' THEN 1 ELSE 0 END) AS high,
      SUM(CASE WHEN LOWER(severity) = 'medium' THEN 1 ELSE 0 END) AS medium,
      SUM(CASE WHEN LOWER(severity) = 'low' THEN 1 ELSE 0 END) AS low,
      SUM(CASE WHEN status NOT IN ('RESOLVED', 'MITIGATED', 'FALSE_POSITIVE', 'BLOCKED') THEN 1 ELSE 0 END) AS unresolved
    FROM threats WHERE organization_id = ?
  `).get(organizationId) as any;

  const metrics = {
    total: Number(metricsRow?.total) || 0,
    critical: Number(metricsRow?.critical) || 0,
    high: Number(metricsRow?.high) || 0,
    medium: Number(metricsRow?.medium) || 0,
    low: Number(metricsRow?.low) || 0,
    unresolved: Number(metricsRow?.unresolved) || 0
  };

  return {
    threats: rows.map(row => ({
      id: row.id,
      timestamp: row.timestamp,
      sourceIp: row.source_ip,
      target: row.target,
      attackType: row.attack_type,
      category: row.attack_type,
      severity: row.severity,
      confidence: row.confidence || 90,
      action: row.action || 'DETECT',
      status: row.status || 'ACTIVE',
      summary: row.summary,
      detectionReason: row.detection_reason,
      detectionSource: row.action === 'BLOCK' ? 'WAF' : 'Endpoint',
      affectedApplication: row.affected_application,
      destination: row.destination,
      relatedEvents: parseArray(row.related_events),
      recommendedAction: row.recommended_action
    })),
    total: metrics.total,
    metrics
  };
}

function incidentSnapshot(organizationId: string) {
  const rows = db.prepare(`
    SELECT * FROM incidents WHERE organization_id = ? ORDER BY created_at DESC
  `).all(organizationId) as any[];

  return {
    incidents: rows.map(row => ({
      id: row.id,
      title: row.title,
      severity: row.severity,
      status: row.status,
      tier: row.tier || 'L1',
      assignedAnalyst: row.assigned_to,
      affectedAsset: row.affected_asset,
      notes: row.notes,
      timeline: parseArray(row.timeline),
      created: row.created_at,
      updated: row.updated_at
    }))
  };
}

function malwareSnapshot(organizationId: string) {
  return listScans(organizationId, { limit: 120, offset: 0 });
}

function publishSnapshots(organizationId: string) {
  try {
    SecurityEventBus.publish('threat.snapshot', threatSnapshot(organizationId), organizationId);
    SecurityEventBus.publish('incident.snapshot', incidentSnapshot(organizationId), organizationId);
    SecurityEventBus.publish('malware.snapshot', malwareSnapshot(organizationId), organizationId);
    SecurityEventBus.publish('analytics.snapshot', getTelemetryAnalytics(organizationId), organizationId);
    SecurityEventBus.publish('ai.telemetry', { telemetry: getSocTelemetry(organizationId) }, organizationId);
  } catch (error) {
    console.warn('[RealtimeSnapshots] Could not publish tenant snapshot:', error);
  }
}

export function startRealtimeSnapshotService() {
  if (SecurityEventBus.listenerCount('event') > 100) return;

  SecurityEventBus.on('event', payload => {
    if (!payload.organizationId || !SNAPSHOT_TRIGGERS.has(payload.type)) return;
    const organizationId = payload.organizationId;
    const previous = pending.get(organizationId);
    if (previous) clearTimeout(previous);
    pending.set(organizationId, setTimeout(() => {
      pending.delete(organizationId);
      publishSnapshots(organizationId);
    }, 400));
  });
}
