/**
 * Canonical event shape used by every server-side ingestion path.
 *
 * Telemetry now arrives from enrolled endpoint agents and the WAF/firewall
 * ingest APIs. There is no separate network sensor parser.
 */
export interface NormalizedSecurityEvent {
  id: string;
  organizationId: string;
  timestamp: string;
  source: 'waf' | 'firewall' | 'auth' | 'system' | 'agent';
  eventType: string;
  severity?: 'Low' | 'Medium' | 'High' | 'Critical' | 'Info' | null;
  sourceIp: string;
  destinationIp: string;
  protocol: string;
  application: string;
  action: 'ALLOW' | 'BLOCK' | 'DENY' | 'DROP' | 'CHALLENGE' | 'RATE_LIMIT' | 'QUARANTINE' | 'DETECT' | 'LOG';
  uri?: string;
  method?: string;
  port?: number;
  statusCode?: number;
  threatName?: string;
  payloadSnippet?: string;
  metadata?: Record<string, any>;
  agentId?: string;
}
