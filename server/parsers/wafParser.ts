import { NormalizedSecurityEvent } from './securityEvent';

export interface WafIngestPayload {
  timestamp?: string;
  source_ip: string;
  destination_ip?: string;
  host?: string;
  method?: string;
  uri?: string;
  status_code?: number;
  rule_id?: string;
  rule_name?: string;
  category?: string;
  severity?: string;
  action?: string;
  user_agent?: string;
  request_id?: string;
  payload_snippet?: string;
}

export function parseWafEvent(payload: WafIngestPayload, organizationId = ''): NormalizedSecurityEvent {
  const normSeverity = (s?: string): 'Low' | 'Medium' | 'High' | 'Critical' => {
    if (!s) return 'Medium';
    const l = s.toLowerCase();
    if (l === 'critical') return 'Critical';
    if (l === 'high') return 'High';
    if (l === 'low') return 'Low';
    return 'Medium';
  };

  const normAction = (a?: string): 'ALLOW' | 'BLOCK' | 'DENY' | 'DROP' | 'CHALLENGE' | 'RATE_LIMIT' | 'LOG' => {
    if (!a) return 'BLOCK';
    const u = a.toUpperCase();
    if (['ALLOW', 'BLOCK', 'DENY', 'DROP', 'CHALLENGE', 'RATE_LIMIT', 'LOG'].includes(u)) {
      return u as any;
    }
    return 'BLOCK';
  };

  return {
    id: `EV-WAF-${crypto.randomUUID()}`,
    organizationId,
    timestamp: payload.timestamp ? new Date(payload.timestamp).toISOString() : new Date().toISOString(),
    source: 'waf',
    eventType: 'waf_inspection',
    severity: normSeverity(payload.severity),
    sourceIp: payload.source_ip,
    destinationIp: payload.destination_ip || payload.host || '0.0.0.0',
    protocol: 'HTTPS',
    application: payload.host || 'Web Application Perimeter',
    action: normAction(payload.action),
    uri: payload.uri || '/',
    method: (payload.method || 'GET').toUpperCase(),
    port: 443,
    statusCode: payload.status_code || 403,
    threatName: payload.rule_name || payload.category || 'WAF Policy Violation',
    payloadSnippet: payload.payload_snippet,
    metadata: {
      rule_id: payload.rule_id,
      category: payload.category,
      user_agent: payload.user_agent,
      request_id: payload.request_id
    }
  };
}
