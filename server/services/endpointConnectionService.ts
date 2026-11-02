import { db } from '../database/db';
import { SecurityEventBus } from '../utils/eventBus';

export interface EndpointSummary {
  id: string;
  name: string;
  hostname: string;
  ip: string;
  os: string;
  arch: string;
  version: string;
  status: 'ONLINE' | 'OFFLINE';
  lastSeen: string | null;
  organizationId: string;
}

export interface EndpointConnectionStatus {
  hasConnectedEndpoints: boolean;
  connectedCount: number;
  totalAgents: number;
  endpoints: EndpointSummary[];
  timestamp: string;
}

function toIso(value: string | null): string | null {
  if (!value) return null;
  if (value.includes('T')) return value;
  return `${value.replace(' ', 'T')}Z`;
}

const ONLINE_THRESHOLD_MS = 10 * 1000; // 10s fast offline detection // 2 minutes heartbeat window

export function getConnectedEndpoints(orgId?: string): EndpointConnectionStatus {
  const now = Date.now();
  let query = 'SELECT id, organization_id, name, hostname, ip, os, arch, version, status, last_seen FROM agents WHERE revoked_at IS NULL';
  const params: any[] = [];

  if (orgId) {
    query += ' AND organization_id = ?';
    params.push(orgId);
  }

  query += ' ORDER BY last_seen DESC';

  const rows = db.prepare(query).all(...params) as Array<{
    id: string;
    organization_id: string;
    name: string;
    hostname: string | null;
    ip: string | null;
    os: string | null;
    arch: string | null;
    version: string | null;
    status: string;
    last_seen: string | null;
  }>;

  const endpoints: EndpointSummary[] = rows.map(r => {
    const lastSeenMs = r.last_seen ? Date.parse(toIso(r.last_seen) || '') : NaN;
    const isOnline = Number.isFinite(lastSeenMs) && (now - lastSeenMs < ONLINE_THRESHOLD_MS);

    return {
      id: r.id,
      name: r.name,
      hostname: r.hostname || r.name,
      ip: r.ip || '127.0.0.1',
      os: r.os || 'Unknown OS',
      arch: r.arch || 'x64',
      version: r.version || '1.0.0',
      status: isOnline ? 'ONLINE' : 'OFFLINE',
      lastSeen: toIso(r.last_seen),
      organizationId: r.organization_id
    };
  });

  const onlineEndpoints = endpoints.filter(e => e.status === 'ONLINE');

  return {
    hasConnectedEndpoints: onlineEndpoints.length > 0,
    connectedCount: onlineEndpoints.length,
    totalAgents: endpoints.length,
    endpoints: onlineEndpoints,
    timestamp: new Date().toISOString()
  };
}

export function hasActiveEndpoint(orgId?: string): boolean {
  return getConnectedEndpoints(orgId).hasConnectedEndpoints;
}

export function broadcastEndpointStatus(orgId?: string) {
  const status = getConnectedEndpoints(orgId);
  SecurityEventBus.publish('endpoint.status', status, orgId);
  return status;
}

// Memory cache of last broadcast counts to detect transitions
const lastStateMap = new Map<string, number>();
let monitorInterval: NodeJS.Timeout | null = null;
let tickCounter = 0;

export function startEndpointMonitor() {
  if (monitorInterval) return;

  console.log('[OAT SECURITY] Endpoint real-time connectivity monitor started (3s ticker)');

  monitorInterval = setInterval(() => {
    tickCounter++;
    try {
      // Find all active organizations
      const orgs = db.prepare('SELECT id FROM organizations').all() as Array<{ id: string }>;
      const allOrgs = [{ id: '' }, ...orgs];

      for (const org of allOrgs) {
        const orgId = org.id;
        const current = getConnectedEndpoints(orgId || undefined);
        const prevCount = lastStateMap.get(orgId);

        // If connection count changed, or every 10 ticks (30 seconds), broadcast
        if (prevCount === undefined || prevCount !== current.connectedCount || tickCounter % 10 === 0) {
          lastStateMap.set(orgId, current.connectedCount);
          SecurityEventBus.publish('endpoint.status', current, orgId || undefined);

          if (prevCount !== undefined && prevCount !== current.connectedCount) {
            console.log(
              `[Endpoint Monitor] Real-time connectivity changed for org '${orgId || 'global'}': ${prevCount} -> ${current.connectedCount} online`
            );

            // Notify frontend when an endpoint goes offline (count dropped)
            if (prevCount > current.connectedCount) {
              const offlineEndpoints = current.endpoints.filter(e => e.status === 'OFFLINE');
              const firstName = offlineEndpoints[0]?.hostname || offlineEndpoints[0]?.name || 'endpoint';
              SecurityEventBus.publish('agent.offline', {
                type: 'agent.offline',
                severity: 'High',
                action: 'ALERT',
                source: 'monitor',
                eventType: 'agent_offline',
                sourceIp: offlineEndpoints[0]?.ip || '0.0.0.0',
                threat: `Endpoint Offline: ${firstName}`,
                message: `Agent ${firstName} tidak merespons. Terakhir terlihat: baru saja.`,
                offlineCount: prevCount - current.connectedCount,
                timestamp: new Date().toISOString(),
              }, orgId || undefined);
            }
          }
        }
      }
    } catch (err) {
      console.error('[Endpoint Monitor] Error checking endpoint status:', err);
    }
  }, 3000);
}

export function stopEndpointMonitor() {
  if (monitorInterval) {
    clearInterval(monitorInterval);
    monitorInterval = null;
  }
}
