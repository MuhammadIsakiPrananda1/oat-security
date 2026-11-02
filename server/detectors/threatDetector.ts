import { db } from '../database/db';
import { NormalizedSecurityEvent } from '../parsers/securityEvent';
import { lookupIpLocation } from '../services/geoIpService';
import { SecurityEventBus } from '../utils/eventBus';
import { WafDeploymentService } from '../services/serverWafSync';

export interface ThreatRecord {
  id: string;
  organizationId: string;
  timestamp: string;
  sourceIp: string;
  target: string;
  attackType: string;
  severity: 'Low' | 'Medium' | 'High' | 'Critical';
  confidence: number;
  action: string;
  status: 'ACTIVE' | 'INVESTIGATING' | 'MITIGATED' | 'BLOCKED';
  summary: string;
  detectionReason: string;
  affectedApplication: string;
  destination: string;
  relatedEvents: string[];
  recommendedAction: string;
}

export function processSecurityEvent(event: NormalizedSecurityEvent) {
  // Dynamic WAF Policy evaluation
  if (event.source === 'waf' && event.organizationId) {
    try {
      const policy = db.prepare('SELECT * FROM waf_policy WHERE organization_id = ?').get(event.organizationId);
      if (policy) {
        const ip = event.sourceIp;
        // 1. IP Allowlist
        if (policy.ip_allowlist) {
          const allowed = String(policy.ip_allowlist).split(',').map(s => s.trim()).filter(Boolean);
          if (allowed.some(a => ip.startsWith(a.replace(/\/\d+$/, '')))) {
            event.action = 'ALLOW';
            event.severity = 'Low';
          }
        }
        // 2. IP Blocklist
        if (event.action !== 'ALLOW' && policy.ip_blocklist) {
          const blocked = String(policy.ip_blocklist).split(',').map(s => s.trim()).filter(Boolean);
          if (blocked.some(b => ip.startsWith(b.replace(/\/\d+$/, '')))) {
            event.action = 'BLOCK';
            event.severity = 'High';
            event.threatName = 'WAF IP Blocklist (' + ip + ')';
          }
        }
        // 3. Bot Protection
        if (event.action !== 'ALLOW' && policy.bot_protection_enabled && event.metadata && event.metadata.user_agent) {
          const ua = String(event.metadata.user_agent);
          if (/(nikto|nmap|masscan|sqlmap|nessus|openvas|acunetix|burpsuite|w3af|skipfish|dirbuster|scrapy|zgrab|python-requests|curl|wget)/i.test(ua)) {
            event.action = 'BLOCK';
            event.threatName = 'Automated Scanner / Bad Bot (' + ua.slice(0, 32) + ')';
          }
        }
        // 4. WAF Mode: monitor
        if (String(policy.mode || '').toLowerCase() === 'monitor' && (event.action === 'BLOCK' || event.action === 'DENY')) {
          event.action = 'LOG';
        }
      }
    } catch (e) {}
  }

  // 1. Persist to security_events table
  const insertEvent = db.prepare(`
    INSERT OR IGNORE INTO security_events (
      id, organization_id, timestamp, source, event_type, severity,
      source_ip, destination_ip, protocol, application, action,
      uri, method, port, status_code, threat_name, payload_snippet, metadata, agent_id
    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
  `);

  const insertResult = insertEvent.run(
    event.id,
    event.organizationId,
    event.timestamp,
    event.source,
    event.eventType,
    event.severity,
    event.sourceIp,
    event.destinationIp,
    event.protocol,
    event.application,
    event.action,
    event.uri || null,
    event.method || null,
    event.port || null,
    event.statusCode || null,
    event.threatName || null,
    event.payloadSnippet || null,
    event.metadata ? JSON.stringify(event.metadata) : null,
    event.agentId || null
  );

  if (Number(insertResult.changes) === 0) {
    // The same incident is already stored (duplicate delivery or a retried
    // batch). Skip logs, stream broadcast and threat correlation so one
    // incident produces exactly one notification.
    return;
  }

  // 1b. Ingest into Centralized Logs table
  const logLevel = event.severity === 'Critical' ? 'CRITICAL'
    : (event.severity === 'High' || ['BLOCK', 'DENY', 'DROP'].includes(event.action)) ? 'ERROR'
    : (event.severity === 'Medium' || ['CHALLENGE', 'RATE_LIMIT'].includes(event.action)) ? 'WARN'
    : (event.severity === 'Low') ? 'INFO' : 'DEBUG';

  const logId = `LOG-${crypto.randomUUID()}`;
  const logMessage = `[${event.source.toUpperCase()}] ${event.threatName || event.eventType}: ${event.method ? event.method + ' ' : ''}${event.uri || ''} (${event.sourceIp} -> ${event.destinationIp}) action=${event.action}`;
  const eventHost = String((event.metadata && event.metadata.hostname) || 'edge-gateway-01').slice(0, 128);
  
  try {
    db.prepare(`
      INSERT INTO logs (
        id, organization_id, timestamp, level, source, event_type,
        message, host, ip, correlation_id, metadata, raw_log, agent_id
      ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    `).run(
      logId,
      event.organizationId,
      event.timestamp,
      logLevel,
      event.source,
      event.eventType,
      logMessage,
      eventHost,
      event.sourceIp,
      event.id,
      event.metadata ? JSON.stringify(event.metadata) : null,
      JSON.stringify(event),
      event.agentId || null
    );

    const logItem = {
      id: logId,
      organizationId: event.organizationId,
      timestamp: event.timestamp,
      level: logLevel,
      source: event.source,
      eventType: event.eventType,
      message: logMessage,
      host: eventHost,
      ip: event.sourceIp,
      correlationId: event.id,
      metadata: event.metadata,
      rawLog: JSON.stringify(event)
    };
    SecurityEventBus.publish('log.created', logItem, event.organizationId);
  } catch (logErr) {
    console.warn('[ThreatDetector] Error inserting log:', logErr);
  }

  // Attach the GeoIP result to the live event so the realtime UI uses the same
  // country as the REST API instead of applying its own prefix guesses.
  const geo = lookupIpLocation(event.sourceIp);
  const eventWithGeo = {
    ...event,
    sourceCountry: geo.country,
    sourceCountryCode: geo.code,
    sourceCountryFlag: geo.flag
  };

  // Emit event to EventBus
  SecurityEventBus.publish('security_event.created', eventWithGeo, event.organizationId);
  SecurityEventBus.publish('security_event', eventWithGeo, event.organizationId);
  if (event.source === 'waf') {
    SecurityEventBus.publish('waf.event', eventWithGeo, event.organizationId);
  } else if (event.source === 'firewall') {
    SecurityEventBus.publish('firewall.event', eventWithGeo, event.organizationId);
  }

  // 2. Threat Evaluation
  const isAttackOrDenied = ['BLOCK', 'DENY', 'DROP', 'CHALLENGE', 'RATE_LIMIT'].includes(event.action) ||
    event.severity === 'High' || event.severity === 'Critical';

  if (isAttackOrDenied) {
    let attackCategory = 'Policy Violation';
    const threatLower = (event.threatName || '').toLowerCase();
    const uriLower = (event.uri || '').toLowerCase();

    if (threatLower.includes('sql') || uriLower.includes('select') || uriLower.includes('union')) {
      attackCategory = 'Web Attack (SQL Injection)';
    } else if (
      threatLower.includes('xss') ||
      threatLower.includes('cross site scripting') ||
      threatLower.includes('script tag') ||
      uriLower.includes('<script')
    ) {
      attackCategory = 'Web Attack (Cross-Site Scripting)';
    } else if (
      threatLower.includes('traversal') ||
      threatLower.includes('etc/passwd') ||
      threatLower.includes('local file inclusion') ||
      threatLower.includes('lfi') ||
      uriLower.includes('../')
    ) {
      attackCategory = 'Web Attack (Path Traversal)';
    } else if (threatLower.includes('bot') || threatLower.includes('scrape') || event.action === 'CHALLENGE') {
      attackCategory = 'Web Attack (Automated Bot / Scraping)';
    } else if (threatLower.includes('rate limit') || event.action === 'RATE_LIMIT') {
      attackCategory = 'Web Attack (Layer 7 Flood)';
    } else if (event.eventType === 'malware_upload_detected' || threatLower.includes('malware upload')) {
      attackCategory = 'Malware Upload (Webshell / Payload)';
    } else if (threatLower.includes('ssh') || event.port === 22 || threatLower.includes('brute force')) {
      attackCategory = 'Authentication Attack (Brute Force)';
    } else if (threatLower.includes('scan') || threatLower.includes('syn')) {
      attackCategory = 'Scanning (Network Reconnaissance)';
    } else if (threatLower.includes('anomaly')) {
      attackCategory = 'Anomaly (Protocol Deviation)';
    } else if (event.source === 'waf') {
      attackCategory = 'Web Attack';
    } else if (event.source === 'firewall') {
      attackCategory = 'Network Attack';
    } else if (event.source === 'agent') {
      attackCategory = 'Endpoint Attack';
    }

    // Check if there's already an active threat for this source_ip & attack_type in the last 15 minutes
    const existing = db.prepare(`
      SELECT * FROM threats
      WHERE organization_id = ? AND source_ip = ? AND attack_type = ? AND status != 'MITIGATED'
      ORDER BY timestamp DESC LIMIT 1
    `).get(event.organizationId, event.sourceIp, attackCategory) as any;

    if (existing) {
      // Append related event
      let related: string[] = [];
      try {
        related = JSON.parse(existing.related_events || '[]');
      } catch {
        related = [];
      }
      if (!related.includes(event.id)) {
        related.push(event.id);
      }

      db.prepare(`
        UPDATE threats
        SET timestamp = ?, related_events = ?, updated_at = datetime('now')
        WHERE id = ?
      `).run(event.timestamp, JSON.stringify(related), existing.id);

      SecurityEventBus.publish('threat.updated', {
        ...existing,
        id: existing.id,
        threatId: existing.id,
        timestamp: event.timestamp,
        sourceIp: existing.source_ip,
        target: existing.target,
        attackType: existing.attack_type,
        severity: existing.severity,
        status: existing.status,
        relatedEvents: related,
        related_events: related
      }, event.organizationId);
    } else {
      // Create new threat
      const threatId = `THR-${crypto.randomUUID()}`;
      const summary = `Detected ${attackCategory} from origin ${event.sourceIp} targeting ${event.application} (${event.destinationIp}). Mitigated via ${event.action}.`;
      const detectionReason = `Triggered by ${event.source.toUpperCase()} detection: ${event.threatName || 'Suspicious payload match'}.`;
      const confidence = event.severity === 'Critical' ? 99 : event.severity === 'High' ? 95 : 88;
      const recAction = event.action === 'BLOCK' || event.action === 'DENY'
        ? `Maintain IP quarantine for ${event.sourceIp} and review target endpoint parameters.`
        : `Apply rate-limiting and enforce strict WAF deny policy for ${event.sourceIp}.`;

      db.prepare(`
        INSERT INTO threats (
          id, organization_id, timestamp, source_ip, target, attack_type,
          severity, confidence, action, status, summary, detection_reason,
          affected_application, destination, related_events, recommended_action
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
      `).run(
        threatId,
        event.organizationId,
        event.timestamp,
        event.sourceIp,
        event.destinationIp,
        attackCategory,
        event.severity,
        confidence,
        event.action,
        'ACTIVE',
        summary,
        detectionReason,
        event.application,
        `${event.destinationIp}:${event.port || 443}`,
        JSON.stringify([event.id]),
        recAction
      );

      const newThreat: ThreatRecord = {
        id: threatId,
        organizationId: event.organizationId,
        timestamp: event.timestamp,
        sourceIp: event.sourceIp,
        target: event.destinationIp,
        attackType: attackCategory,
        severity: event.severity === 'Info' ? 'Low' : event.severity,
        confidence,
        action: event.action,
        status: 'ACTIVE',
        summary,
        detectionReason,
        affectedApplication: event.application,
        destination: `${event.destinationIp}:${event.port || 443}`,
        relatedEvents: [event.id],
        recommendedAction: recAction
      };

      SecurityEventBus.publish('threat.created', newThreat, event.organizationId);
      SecurityEventBus.publish('security.alert', newThreat, event.organizationId);

      // If Critical, also auto-create an Incident in 'NEW' status
      if (event.severity === 'Critical') {
        const incidentId = `INC-${Date.now()}`;
        const title = `Critical Security Incident: ${attackCategory} on ${event.application || 'Enterprise Perimeter'}`;
        const incidentTier = (attackCategory.includes('RCE') || attackCategory.includes('Command') || attackCategory.includes('SQL') || attackCategory.includes('Injection')) ? 'L2' : 'L1';
        const affectedAsset = event.application || 'Enterprise Perimeter';
        const nowIso = new Date().toISOString();

        const validOrgId = WafDeploymentService.resolveOrgId(event.organizationId);

        db.prepare(`
          INSERT INTO incidents (
            id, organization_id, title, severity, status, tier, assigned_to,
            affected_asset, notes, timeline, created_at, updated_at
          ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, datetime('now'), datetime('now'))
        `).run(
          incidentId,
          validOrgId,
          title,
          'Critical',
          'NEW',
          incidentTier,
          'Unassigned (Triage Queue)',
          affectedAsset,
          `Automated incident spawned by Threat Detection Engine for Threat ID ${threatId}. Correlated attack: ${attackCategory} from ${event.sourceIp}.`,
          JSON.stringify([{
            time: nowIso,
            note: `Incident spawned automatically into [SOC ${incidentTier}]: ${attackCategory} detected from ${event.sourceIp}`,
            author: 'Threat Correlation Engine',
            tier: incidentTier
          }])
        );

        SecurityEventBus.publish('incident.created', {
          id: incidentId,
          title,
          severity: 'Critical',
          status: 'NEW',
          tier: incidentTier,
          affected_asset: affectedAsset,
          assignedAnalyst: 'Unassigned (Triage Queue)',
          created: nowIso
        }, event.organizationId);
      }
    }
  }

  // SSH failed logins are Medium/LOG and do not create a threat by themselves.
  // If a brute-force threat already exists for the source, attach every
  // individual attempt so the threat detail lists all attempts, not only the
  // first IDS alert.
  if (event.eventType === 'ssh_failed_login' || event.eventType === 'ssh_invalid_user') {
    const existing = db.prepare(`
      SELECT * FROM threats
      WHERE organization_id = ? AND source_ip = ?
        AND attack_type = 'Authentication Attack (Brute Force)'
        AND status != 'MITIGATED'
      ORDER BY timestamp DESC LIMIT 1
    `).get(event.organizationId, event.sourceIp) as any;

    if (existing) {
      let related: string[] = [];
      try {
        related = JSON.parse(existing.related_events || '[]');
      } catch {
        related = [];
      }
      if (!related.includes(event.id)) {
        related.push(event.id);
        db.prepare(`
          UPDATE threats
          SET timestamp = ?, related_events = ?, updated_at = datetime('now')
          WHERE id = ?
        `).run(event.timestamp, JSON.stringify(related), existing.id);
        SecurityEventBus.publish('threat.updated', { ...existing, related_events: related }, event.organizationId);
      }
    }
  }

  return event;
}
