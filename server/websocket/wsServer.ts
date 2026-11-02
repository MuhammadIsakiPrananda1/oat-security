import { Server as HttpServer } from 'http';
import { WebSocketServer, WebSocket } from 'ws';
import { SecurityEventBus, BusEventPayload } from '../utils/eventBus';
import { verifyToken } from '../auth/jwt';
import { db } from '../database/db';

import { getConnectedEndpoints } from '../services/endpointConnectionService';

interface ExtendedWebSocket extends WebSocket {
  isAlive: boolean;
  organizationId?: string;
  userRole?: string;
  socTier?: string | null;
  authenticated: boolean;
}

function normalizeSocTier(value: unknown): string | null {
  const tier = String(value || '').toUpperCase();
  return tier === 'L1' || tier === 'L2' || tier === 'L3' ? tier : null;
}

function incidentTierOf(row: any): string {
  return normalizeSocTier(row?.tier)
    || (row?.severity === 'Critical' ? 'L3' : row?.severity === 'High' ? 'L2' : 'L1');
}

/**
 * Filters incident frames per client so a tier-scoped operator never receives
 * another tier's queue over the realtime channel. Other event types pass
 * through untouched.
 */
function scopeIncidentPayload(type: string, data: any, scope: string | null): any | null {
  if (!scope) return data;

  if (type === 'incident.snapshot') {
    const incidents = Array.isArray(data?.incidents)
      ? data.incidents.filter((incident: any) => incidentTierOf(incident) === scope)
      : [];
    return { ...data, incidents };
  }

  if (type === 'incident.created') {
    const item = data?.data || data;
    if (item && incidentTierOf(item) !== scope) return null;
  }

  return data;
}

/** Reads the current SOC tier from the DB, which also covers pre-existing JWTs. */
function loadSocTier(userId?: string): string | null {
  if (!userId) return null;
  try {
    const row = db.prepare('SELECT soc_tier FROM users WHERE id = ?').get(userId) as any;
    return normalizeSocTier(row?.soc_tier);
  } catch {
    return null;
  }
}

export class SecurityWebSocketServer {
  private wss: WebSocketServer | null = null;
  private heartbeatInterval: NodeJS.Timeout | null = null;

  public init(server: HttpServer) {
    this.wss = new WebSocketServer({
      server,
      path: '/ws',
      perMessageDeflate: false,
      maxPayload: 1024 * 64
    });

    console.log('[WebSocket] Security WebSocket server attached to /ws');

    this.wss.on('connection', (ws: ExtendedWebSocket, req) => {
      ws.isAlive = true;
      ws.authenticated = false;

      // Extract auth / organization from URL query string if present (e.g. /ws?token=...&org=...)
      try {
        const url = new URL(req.url || '', `http://${req.headers.host}`);
        const token = url.searchParams.get('token');
        const org = url.searchParams.get('org');
        if (token) {
          const verified = verifyToken(token);
          if (verified) {
            ws.authenticated = true;
            ws.organizationId = verified.organizationId;
            ws.userRole = verified.role;
            ws.socTier = normalizeSocTier(verified.socTier) || loadSocTier(verified.userId);

            // Super Admin may switch tenants from the console. Other roles
            // are always pinned to the organization embedded in the token.
            if (org && verified.role === 'Super Admin') {
              ws.organizationId = org;
            }
          }
        }
      } catch {
        // Keep the socket connected for the handshake, but it cannot receive
        // tenant-scoped security events until a valid AUTH frame arrives.
      }

      ws.on('pong', () => {
        ws.isAlive = true;
      });

      ws.on('message', (raw) => {
        try {
          const msg = JSON.parse(raw.toString());
          if (msg.type === 'PING') {
            ws.send(JSON.stringify({ type: 'PONG', timestamp: new Date().toISOString() }));
          } else if (msg.type === 'SUBSCRIBE_ORG') {
            const requestedOrg = String(msg.organizationId || '').trim();
            if (!ws.authenticated || !requestedOrg) {
              ws.send(JSON.stringify({ type: 'SUBSCRIBE_ERROR', error: 'Authenticated organization subscription required' }));
              return;
            }
            if (ws.userRole !== 'Super Admin' && requestedOrg !== ws.organizationId) {
              ws.send(JSON.stringify({ type: 'SUBSCRIBE_ERROR', error: 'Organization is not allowed for this session' }));
              return;
            }
            ws.organizationId = requestedOrg;
            ws.send(JSON.stringify({
              type: 'SUBSCRIBED',
              organizationId: requestedOrg,
              status: 'CONNECTED'
            }));
            try {
              ws.send(JSON.stringify({
                type: 'endpoint.status',
                data: getConnectedEndpoints(requestedOrg),
                timestamp: new Date().toISOString()
              }));
            } catch {}
          } else if (msg.type === 'AUTH') {
            const verified = verifyToken(msg.token);
            if (verified) {
              ws.authenticated = true;
              ws.organizationId = verified.organizationId;
              ws.userRole = verified.role;
              ws.socTier = normalizeSocTier(verified.socTier) || loadSocTier(verified.userId);
              ws.send(JSON.stringify({ type: 'AUTH_OK', user: verified }));
              try {
                ws.send(JSON.stringify({
                  type: 'endpoint.status',
                  data: getConnectedEndpoints(verified.organizationId),
                  timestamp: new Date().toISOString()
                }));
              } catch {}
            }
          }
        } catch {
          // Ignore invalid JSON
        }
      });

      // Send initial handshake
      ws.send(JSON.stringify({
        type: 'CONNECTION_STATUS',
        status: 'CONNECTED',
        timestamp: new Date().toISOString()
      }));

      // Send initial real-time endpoint connection state immediately
      if (ws.authenticated && ws.organizationId) {
        try {
          ws.send(JSON.stringify({
            type: 'endpoint.status',
            data: getConnectedEndpoints(ws.organizationId),
            timestamp: new Date().toISOString()
          }));
        } catch {}
      }
    });

    // Heartbeat ping interval every 30 seconds
    this.heartbeatInterval = setInterval(() => {
      if (!this.wss) return;
      this.wss.clients.forEach((client) => {
        const extWs = client as ExtendedWebSocket;
        if (!extWs.isAlive) {
          extWs.terminate();
          return;
        }
        extWs.isAlive = false;
        extWs.ping();
      });
    }, 30000);

    // Listen to SecurityEventBus and broadcast to relevant WebSocket clients
    SecurityEventBus.on('event', (payload: BusEventPayload) => {
      this.broadcast(payload);
    });
  }

  public broadcast(payload: BusEventPayload) {
    if (!this.wss) return;

    this.wss.clients.forEach((client) => {
      const extWs = client as ExtendedWebSocket;
      if (extWs.readyState === WebSocket.OPEN) {
        // Multi-tenant filter: if event has organizationId and client specified organizationId
        const isAgentStatusEvent = payload.type === 'agent.heartbeat' ||
          payload.type === 'agent.enrolled' ||
          payload.type === 'agent.updated' ||
          payload.type === 'agent.restored' ||
          payload.type === 'endpoint.status' ||
          payload.type === 'agent.status' ||
          payload.type === 'waf.agent_status' ||
          payload.type === 'waf.deployment_queued' ||
          payload.type === 'firewall.agent_status' ||
          payload.type === 'firewall.deployment_queued' ||
          payload.type === 'rule.updated';

        const isSecurityTelemetryEvent = payload.type === 'security_event' ||
          payload.type === 'security_event.created' ||
          payload.type === 'security.alert' ||
          payload.type === 'threat.created' ||
          payload.type === 'threat.updated' ||
          payload.type === 'log.created' ||
          payload.type === 'waf.event' ||
          payload.type === 'waf.blocked' ||
          payload.type === 'malware.detected' ||
          payload.type === 'firewall.event';

        if (
          payload.organizationId &&
          !isAgentStatusEvent &&
          !isSecurityTelemetryEvent &&
          (!extWs.authenticated ||
            (!extWs.organizationId && extWs.userRole !== 'Super Admin') ||
            (extWs.organizationId !== payload.organizationId && extWs.userRole !== 'Super Admin'))
        ) {
          return;
        }

        // SOC tier scope: never leak another tier's incident queue.
        const scopeTier = extWs.userRole === 'Super Admin' ? null : normalizeSocTier(extWs.socTier);
        const scopedData = scopeIncidentPayload(payload.type, payload.data, scopeTier);
        if (scopedData === null) return;

        // Backpressure check: do not flood client if buffer > 1MB
        if (extWs.bufferedAmount > 1024 * 1024) {
          console.warn('[WebSocket] Dropping packet due to client backpressure buffer');
          return;
        }

        try {
          extWs.send(JSON.stringify({
            type: payload.type,
            data: scopedData,
            timestamp: payload.timestamp
          }));
        } catch (e) {
          console.error('[WebSocket] Send error:', e);
        }
      }
    });
  }

  /** Live channel state, consumed by the system health probe. */
  public getConnectionStats(): { initialized: boolean; clients: number } {
    return {
      initialized: this.wss !== null,
      clients: this.wss ? this.wss.clients.size : 0
    };
  }

  public close() {
    if (this.heartbeatInterval) {
      clearInterval(this.heartbeatInterval);
      this.heartbeatInterval = null;
    }
    if (this.wss) {
      this.wss.close();
      this.wss = null;
    }
  }
}

export const securityWebSocketServer = new SecurityWebSocketServer();
