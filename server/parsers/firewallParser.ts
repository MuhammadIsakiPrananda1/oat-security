import { NormalizedSecurityEvent } from './securityEvent';

export interface FirewallIngestPayload {
  timestamp?: string;
  source_ip: string;
  destination_ip: string;
  source_port?: number;
  destination_port?: number;
  protocol?: string;
  interface?: string;
  direction?: 'inbound' | 'outbound';
  action?: string;
  bytes?: number;
  packets?: number;
  rule_id?: string;
  reason?: string;
}

export function parseFirewallEvent(payload: FirewallIngestPayload, organizationId = ''): NormalizedSecurityEvent {
  const normAction = (a?: string): 'ALLOW' | 'BLOCK' | 'DENY' | 'DROP' | 'CHALLENGE' | 'RATE_LIMIT' | 'LOG' => {
    if (!a) return 'DENY';
    const u = a.toUpperCase();
    if (['ALLOW', 'DENY', 'DROP', 'LOG', 'BLOCK'].includes(u)) {
      return u === 'BLOCK' ? 'DENY' : (u as any);
    }
    return 'DENY';
  };

  const action = normAction(payload.action);
  const isDeny = action === 'DENY' || action === 'DROP';

  return {
    id: `EV-FW-${crypto.randomUUID()}`,
    organizationId,
    timestamp: payload.timestamp ? new Date(payload.timestamp).toISOString() : new Date().toISOString(),
    source: 'firewall',
    eventType: 'packet_filter',
    severity: isDeny ? 'High' : 'Low',
    sourceIp: payload.source_ip,
    destinationIp: payload.destination_ip,
    protocol: (payload.protocol || 'TCP').toUpperCase(),
    application: payload.interface ? `Firewall (${payload.interface})` : 'Network Perimeter',
    action,
    port: payload.destination_port || payload.source_port || undefined,
    threatName: payload.reason || (isDeny ? 'ACL Deny Rule' : 'Permitted Traffic'),
    metadata: {
      source_port: payload.source_port,
      destination_port: payload.destination_port,
      direction: payload.direction || 'inbound',
      interface: payload.interface,
      bytes: payload.bytes,
      packets: payload.packets,
      rule_id: payload.rule_id
    }
  };
}
