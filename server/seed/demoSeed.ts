import { db } from '../database/db';
export const DEMO_ORG_ID = 'org_urbannusacyber';

export const DEMO_ORG = {
  id: DEMO_ORG_ID,
  name: 'UrbanNusaCyber',
  domain: 'urbannusacyber.co.id',
  industry: 'Financial Services',
  tier: 'Enterprise'
};

// Deterministic PRNG so repeated runs produce a stable, reviewable dataset.
let rngState = 0x0a7e2026;
function rnd(): number {
  rngState = (rngState * 1664525 + 1013904223) >>> 0;
  return rngState / 4294967296;
}
function pick<T>(list: readonly T[]): T {
  return list[Math.floor(rnd() * list.length)];
}
function randInt(min: number, max: number): number {
  return Math.floor(rnd() * (max - min + 1)) + min;
}
/** UTC timestamp ("YYYY-MM-DD HH:MM:SS") `msAgo` ms in the past. */
function tsAgo(msAgo: number): string {
  return new Date(Date.now() - msAgo).toISOString().slice(0, 19).replace('T', ' ');
}

// ---------------------------------------------------------------------------
// Static inventory
// ---------------------------------------------------------------------------
interface AppDef {
  id: string;
  name: string;
  domain: string;
  originIp: string;
  environment: 'Production' | 'Staging';
  status: 'ONLINE' | 'DEGRADED' | 'OFFLINE';
  owner: string;
}

const APPLICATIONS: AppDef[] = [
  { id: 'app_core_banking', name: 'Core Banking API', domain: 'api.core.urbannusacyber.co.id', originIp: '10.240.10.11', environment: 'Production', status: 'ONLINE', owner: 'Core Platform Team' },
  { id: 'app_payment_gateway', name: 'Payment Gateway', domain: 'pay.urbannusacyber.co.id', originIp: '10.240.10.21', environment: 'Production', status: 'ONLINE', owner: 'Payments Engineering' },
  { id: 'app_customer_web', name: 'Customer Web Portal', domain: 'www.urbannusacyber.co.id', originIp: '10.240.10.31', environment: 'Production', status: 'ONLINE', owner: 'Digital Channels' },
  { id: 'app_mobile_backend', name: 'Mobile Banking Backend', domain: 'mbf.urbannusacyber.co.id', originIp: '10.240.10.41', environment: 'Production', status: 'DEGRADED', owner: 'Mobile Platform' },
  { id: 'app_admin_console', name: 'Internal Admin Console', domain: 'admin.urbannusacyber.co.id', originIp: '10.240.20.5', environment: 'Production', status: 'ONLINE', owner: 'Internal IT' },
  { id: 'app_open_banking', name: 'Open Banking Partner API', domain: 'ob.urbannusacyber.co.id', originIp: '10.240.10.51', environment: 'Production', status: 'ONLINE', owner: 'Partnership Integrations' },
  { id: 'app_kyc_service', name: 'KYC Verification Service', domain: 'kyc.urbannusacyber.co.id', originIp: '10.240.10.61', environment: 'Production', status: 'ONLINE', owner: 'Compliance Engineering' },
  { id: 'app_staging_gw', name: 'Staging API Gateway', domain: 'staging-api.urbannusacyber.co.id', originIp: '10.240.30.11', environment: 'Staging', status: 'OFFLINE', owner: 'QA Automation' }
];

const NETWORKS = [
  { id: 'net_edge_dmz', name: 'Edge DMZ', cidr: '10.240.10.0/24', gateway: '10.240.10.1', iface: 'eth0', description: 'Public-facing ingress DMZ terminating WAF and edge gateways', status: 'Online' },
  { id: 'net_core_cad', name: 'Core Banking Zone', cidr: '10.240.20.0/24', gateway: '10.240.20.1', iface: 'eth1', description: 'PCI-DSS scoped cardholder data environment', status: 'Online' },
  { id: 'net_management', name: 'Management & OOB', cidr: '10.240.30.0/24', gateway: '10.240.30.1', iface: 'eth2', description: 'Out-of-band administrative and orchestration network', status: 'Online' },
  { id: 'net_partner', name: 'Partner Interconnect', cidr: '10.240.40.0/24', gateway: '10.240.40.1', iface: 'vpn0', description: 'Open banking partner VPN tunnels', status: 'Degraded' },
  { id: 'net_secops', name: 'SecOps Telemetry', cidr: '10.240.50.0/24', gateway: '10.240.50.1', iface: 'eth3', description: 'SIEM, collectors, and monitoring subnet', status: 'Online' }
];

interface WafDef { ruleId: string; name: string; category: string; severity: string; action: string; enabled: number; description: string }

const WAF_RULES: WafDef[] = [
  { ruleId: 'OWASP-CRS-942100', name: 'SQL Injection Attack Detected via libinjection', category: 'SQL Injection', severity: 'Critical', action: 'BLOCK', enabled: 1, description: 'Detects common SQLi syntax in request parameters and bodies' },
  { ruleId: 'OWASP-CRS-941100', name: 'XSS Attack Detected via libinjection', category: 'Cross-Site Scripting', severity: 'High', action: 'BLOCK', enabled: 1, description: 'Detects reflected and stored XSS payloads in user input' },
  { ruleId: 'OWASP-CRS-930100', name: 'Path Traversal Attack (/../)', category: 'Path Traversal', severity: 'High', action: 'BLOCK', enabled: 1, description: 'Blocks dot-dot-slash directory traversal sequences' },
  { ruleId: 'OWASP-CRS-932100', name: 'Remote Command Execution (Unix)', category: 'Remote Code Execution', severity: 'Critical', action: 'BLOCK', enabled: 1, description: 'Detects shell metacharacters used for command injection' },
  { ruleId: 'OWASP-CRS-921110', name: 'HTTP Request Smuggling Attack', category: 'Request Smuggling', severity: 'Critical', action: 'BLOCK', enabled: 1, description: 'Flags conflicting Content-Length / Transfer-Encoding headers' },
  { ruleId: 'OWASP-CRS-949110', name: 'Inbound Anomaly Score Exceeded', category: 'Anomaly Scoring', severity: 'High', action: 'BLOCK', enabled: 1, description: 'Triggers when the aggregated inbound anomaly score exceeds the threshold' },
  { ruleId: 'OWASP-CRS-913100', name: 'User-Agent Associated with Security Scanner', category: 'Scanner Detection', severity: 'Medium', action: 'BLOCK', enabled: 1, description: 'Blocks known vulnerability scanners and automated recon tooling' },
  { ruleId: 'OWASP-CRS-920350', name: 'Host Header is a Numeric IP Address', category: 'Protocol Violation', severity: 'Medium', action: 'BLOCK', enabled: 1, description: 'Rejects requests that target a bare IP in the Host header' },
  { ruleId: 'OWASP-CRS-943100', name: 'Possible Session Fixation Attack', category: 'Session Fixation', severity: 'Medium', action: 'BLOCK', enabled: 1, description: 'Detects cookies injected before authentication is established' },
  { ruleId: 'OWASP-CRS-911100', name: 'Method Not Allowed by Policy', category: 'Method Enforcement', severity: 'Low', action: 'BLOCK', enabled: 1, description: 'Rejects HTTP verbs that are not permitted for the endpoint' },
  { ruleId: 'OAT-CUSTOM-0010', name: 'Rate-limit Credential Stuffing on /auth/login', category: 'Credential Stuffing', severity: 'High', action: 'RATE_LIMIT', enabled: 1, description: 'Throttles distributed login attempts against the authentication service' },
  { ruleId: 'OAT-CUSTOM-0020', name: 'Geo-challenge Sanctioned Regions on Payments', category: 'Geo Fencing', severity: 'Medium', action: 'CHALLENGE', enabled: 0, description: 'Issues a browser challenge for payment calls from restricted regions' }
];

interface FwDef { priority: number; source: string; destination: string; port: string; protocol: string; action: string; enabled: number; description: string }

const FIREWALL_RULES: FwDef[] = [
  { priority: 10, source: '0.0.0.0/0', destination: '10.240.10.0/24', port: '443', protocol: 'TCP', action: 'ALLOW', enabled: 1, description: 'Public ingress to the edge DMZ over HTTPS' },
  { priority: 20, source: '10.240.10.0/24', destination: '10.240.20.0/24', port: '8443', protocol: 'TCP', action: 'ALLOW', enabled: 1, description: 'Edge to core banking API gateway (mTLS)' },
  { priority: 30, source: '0.0.0.0/0', destination: '10.240.20.0/24', port: 'ANY', protocol: 'ANY', action: 'DENY', enabled: 1, description: 'Zero trust: deny direct internet access to the cardholder zone' },
  { priority: 40, source: '10.240.30.0/24', destination: '10.240.20.0/24', port: '22', protocol: 'TCP', action: 'ALLOW', enabled: 1, description: 'Out-of-band administrative SSH (MFA enforced)' },
  { priority: 50, source: '0.0.0.0/0', destination: '10.240.30.0/24', port: '22', protocol: 'TCP', action: 'DENY', enabled: 1, description: 'Block public SSH to the management network' },
  { priority: 60, source: '10.240.40.0/24', destination: '10.240.10.0/24', port: '443', protocol: 'TCP', action: 'ALLOW', enabled: 1, description: 'Partner interconnect to the edge DMZ' },
  { priority: 70, source: '185.220.101.0/24', destination: 'ANY', port: 'ANY', protocol: 'ANY', action: 'DENY', enabled: 1, description: 'Blocklist: Tor exit relay range' },
  { priority: 80, source: '10.240.50.0/24', destination: '10.240.20.0/24', port: '514', protocol: 'UDP', action: 'ALLOW', enabled: 1, description: 'Syslog forwarding to the SIEM subnet' },
  { priority: 90, source: '0.0.0.0/0', destination: '10.240.20.0/24', port: '3389', protocol: 'TCP', action: 'DENY', enabled: 1, description: 'Block RDP from the internet' },
  { priority: 100, source: '10.240.10.0/24', destination: '10.240.40.0/24', port: '53', protocol: 'UDP', action: 'ALLOW', enabled: 0, description: 'Partner DNS resolution (temporarily disabled)' }
];

// ---------------------------------------------------------------------------
// Event generation
// ---------------------------------------------------------------------------
const ATTACKER_IPS = [
  '185.220.101.42', '45.155.205.17', '103.214.68.9', '194.26.135.88', '89.248.165.73',
  '167.94.138.51', '198.98.51.189', '80.94.95.20', '141.98.10.61', '45.142.212.100',
  '31.210.20.77', '193.32.162.44', '91.240.118.23', '5.188.206.14', '195.123.246.99',
  '116.31.116.14', '121.52.155.10', '203.176.135.5', '36.66.188.251', '43.129.32.66',
  '152.32.128.9', '110.44.124.13', '182.253.140.77', '103.147.22.8'
];

const WAF_THREATS = [
  'SQL Injection Attack', 'Cross-Site Scripting (XSS)', 'Path Traversal Attack',
  'Remote Code Execution', 'HTTP Request Smuggling', 'Scanner / Bot Detection',
  'Credential Stuffing Burst', 'Malformed HTTP Request', 'Session Fixation Attempt',
  'Local File Inclusion Attempt'
];

const FW_THREATS = [
  'ACL Deny Rule', 'Blocklist Match: Tor Exit Relay', 'Port Scan Detection',
  'Geo-Block Enforcement', 'Invalid TCP Flag Combination', 'Permitted Traffic', 'Rate Limiter Drop'
];

const ENDPOINT_THREATS = [
  'Suspicious SSH Login Pattern', 'Malware Beacon Detected', 'Web Request SQL Injection Attempt',
  'Layer 7 Flood Detected', 'Malicious User-Agent Detected', 'Unexpected Outbound Connection',
  'Configuration Drift Detected'
];

const URIS = [
  '/api/v1/accounts/transfer', '/api/v1/payments', '/auth/login', '/api/v1/statements',
  '/admin/users', '/api/v1/kyc/verify', '/api/v1/cards', '/wp-login.php', '/.env',
  '/actuator/health', '/api/v1/beneficiaries', '/graphql'
];

const METHODS = ['GET', 'POST', 'PUT', 'DELETE', 'PATCH'];

interface EventBlueprint {
  source: 'waf' | 'firewall' | 'agent';
  eventType: string;
  severity: string;
  action: string;
  statusCode?: number;
}

function buildEvent(timestamp: string): any {
  const roll = rnd();
  const app = pick(APPLICATIONS);
  const sourceIp = pick(ATTACKER_IPS);

  let source: 'waf' | 'firewall' | 'agent';
  if (roll < 0.55) source = 'waf';
  else if (roll < 0.85) source = 'firewall';
  else source = 'agent';

  const blueprint: EventBlueprint = (() => {
    if (source === 'waf') {
      const a = rnd();
      if (a < 0.68) return { source, eventType: 'waf_inspection', severity: pick(['Critical', 'High', 'High', 'Medium', 'Medium', 'Low']), action: 'BLOCK', statusCode: 403 };
      if (a < 0.80) return { source, eventType: 'waf_inspection', severity: pick(['Low', 'Low', 'Medium']), action: 'ALLOW', statusCode: 200 };
      if (a < 0.90) return { source, eventType: 'waf_inspection', severity: 'Medium', action: 'CHALLENGE', statusCode: 401 };
      return { source, eventType: 'waf_inspection', severity: 'High', action: 'RATE_LIMIT', statusCode: 429 };
    }
    if (source === 'firewall') {
      const a = rnd();
      if (a < 0.55) return { source, eventType: 'packet_filter', severity: 'High', action: 'DENY' };
      if (a < 0.62) return { source, eventType: 'packet_filter', severity: 'High', action: 'DROP' };
      return { source, eventType: 'packet_filter', severity: 'Low', action: 'ALLOW' };
    }
    const a = rnd();
    if (a < 0.25) return { source, eventType: 'endpoint_alert', severity: pick(['High', 'Critical']), action: 'BLOCK' };
    if (a < 0.45) return { source, eventType: 'endpoint_alert', severity: pick(['Low', 'Medium']), action: 'LOG' };
    return { source, eventType: 'endpoint_inspection', severity: 'Low', action: 'ALLOW' };
  })();

  const threatName = source === 'waf' ? pick(WAF_THREATS) : source === 'firewall' ? pick(FW_THREATS) : pick(ENDPOINT_THREATS);
  const isHttp = source === 'waf' || blueprint.eventType === 'http';
  const uri = isHttp ? pick(URIS) : undefined;
  const method = isHttp ? pick(METHODS) : undefined;

  return {
    id: `EVT-${source.toUpperCase()}-${randInt(100000, 999999)}-${randInt(1000, 9999)}`,
    timestamp,
    source,
    event_type: blueprint.eventType,
    severity: blueprint.severity,
    source_ip: sourceIp,
    destination_ip: app.originIp,
    protocol: source === 'waf' ? 'HTTPS' : pick(['TCP', 'TCP', 'TCP', 'UDP', 'ICMP']),
    application: app.name,
    action: blueprint.action,
    uri,
    method,
    port: source === 'waf' ? 443 : pick([443, 22, 8443, 3389, 53, 514]),
    status_code: blueprint.statusCode ?? null,
    threat_name: threatName,
    payload_snippet: source === 'waf' ? `${method} ${uri} — payload flagged by ${pick(['OWASP CRS', 'OAT engine'])}` : null,
    metadata: JSON.stringify({ collector: source === 'waf' ? 'waf-edge-01' : source === 'firewall' ? 'fw-edge-01' : 'endpoint-agent', hostname: source === 'agent' ? 'debian-server' : undefined })
  };
}

// Volume per hour (index 0 = current hour) — business hours carry more traffic.
const HOURLY_VOLUME = [8, 6, 5, 4, 5, 7, 10, 16, 22, 28, 32, 34, 30, 33, 35, 32, 28, 24, 20, 18, 16, 14, 12, 9];

// ---------------------------------------------------------------------------
// Seed + clear
// ---------------------------------------------------------------------------
export interface SeedCounts {
  applications: number;
  networks: number;
  wafRules: number;
  firewallRules: number;
  securityEvents: number;
  threats: number;
  incidents: number;
  logs: number;
  auditLogs: number;
  integrations: number;
  apiKeys: number;
  healthServices: number;
}

export function clearDemoData(): void {
  const orgId = DEMO_ORG_ID;
  const orgScoped = [
    'security_events', 'threats', 'incidents', 'logs', 'audit_logs',
    'applications', 'networks', 'waf_rules', 'firewall_rules',
    'integration_configs', 'api_keys', 'notifications'
  ];
  db.exec('BEGIN');
  try {
    for (const table of orgScoped) {
      db.prepare(`DELETE FROM ${table} WHERE organization_id = ?`).run(orgId);
    }
    db.prepare('DELETE FROM system_health').run();
    db.prepare('DELETE FROM organizations WHERE id = ?').run(orgId);
    db.exec('COMMIT');
  } catch (err) {
    db.exec('ROLLBACK');
    throw err;
  }
}

export function seedDemoData(): SeedCounts {
  clearDemoData();

  const counts: SeedCounts = {
    applications: 0, networks: 0, wafRules: 0, firewallRules: 0,
    securityEvents: 0, threats: 0, incidents: 0, logs: 0, auditLogs: 0,
    integrations: 0, apiKeys: 0, healthServices: 0
  };
  const orgId = DEMO_ORG_ID;

  db.exec('BEGIN');
  try {
    // --- Organization -----------------------------------------------------
    db.prepare('INSERT INTO organizations (id, name, domain, industry, tier) VALUES (?, ?, ?, ?, ?)')
      .run(DEMO_ORG.id, DEMO_ORG.name, DEMO_ORG.domain, DEMO_ORG.industry, DEMO_ORG.tier);

    // --- Applications -----------------------------------------------------
    const insertApp = db.prepare(`
      INSERT INTO applications (id, organization_id, name, domain, origin_ip, environment, status, owner, protocol, port)
      VALUES (?, ?, ?, ?, ?, ?, ?, ?, 'HTTPS', 443)
    `);
    for (const a of APPLICATIONS) {
      insertApp.run(a.id, orgId, a.name, a.domain, a.originIp, a.environment, a.status, a.owner);
      counts.applications++;
    }

    // --- Networks ---------------------------------------------------------
    const insertNet = db.prepare(`
      INSERT INTO networks (id, organization_id, name, cidr, gateway, interface, description, status)
      VALUES (?, ?, ?, ?, ?, ?, ?, ?)
    `);
    for (const n of NETWORKS) {
      insertNet.run(n.id, orgId, n.name, n.cidr, n.gateway, n.iface, n.description, n.status);
      counts.networks++;
    }

    // --- WAF rules --------------------------------------------------------
    const insertWaf = db.prepare(`
      INSERT INTO waf_rules (id, organization_id, rule_id, name, category, severity, action, enabled, description)
      VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
    `);
    WAF_RULES.forEach((r, i) => {
      insertWaf.run(`waf_${String(i + 1).padStart(3, '0')}`, orgId, r.ruleId, r.name, r.category, r.severity, r.action, r.enabled, r.description);
      counts.wafRules++;
    });

    // --- Firewall rules ---------------------------------------------------
    const insertFw = db.prepare(`
      INSERT INTO firewall_rules (id, organization_id, priority, source, destination, port, protocol, action, enabled, description, created_by)
      VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    `);
    FIREWALL_RULES.forEach((r, i) => {
      insertFw.run(`fw_${String(i + 1).padStart(3, '0')}`, orgId, r.priority, r.source, r.destination, r.port, r.protocol, r.action, r.enabled, r.description, 'seed@demo');
      counts.firewallRules++;
    });

    // --- Security events (24h, one bucket per hour) -----------------------
    const events: any[] = [];
    HOURLY_VOLUME.forEach((volume, hoursAgo) => {
      for (let i = 0; i < volume; i++) {
        // Keep the current-hour bucket genuinely recent so the live health probe
        // sees fresh telemetry; older buckets stay spread across their hour.
        const withinHour = hoursAgo === 0 ? randInt(0, 9 * 60) : randInt(0, 3599);
        const timestamp = tsAgo(hoursAgo * 3_600_000 + withinHour * 1000);
        events.push(buildEvent(timestamp));
      }
    });

    const insertEvent = db.prepare(`
      INSERT INTO security_events (
        id, organization_id, timestamp, source, event_type, severity, source_ip, destination_ip,
        protocol, application, action, uri, method, port, status_code, threat_name, payload_snippet, metadata
      ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    `);
    for (const e of events) {
      insertEvent.run(
        e.id, orgId, e.timestamp, e.source, e.event_type, e.severity, e.source_ip, e.destination_ip,
        e.protocol, e.application, e.action, e.uri ?? null, e.method ?? null, e.port ?? null,
        e.status_code, e.threat_name, e.payload_snippet, e.metadata
      );
      counts.securityEvents++;
    }

    const eventIds = events.map(e => e.id);
    const relatedFor = () => Array.from({ length: randInt(2, 4) }, () => pick(eventIds));

    // --- Threats ----------------------------------------------------------
    interface ThreatDef {
      sourceIp: string; appIndex: number; attackType: string; severity: string; confidence: number;
      status: string; action: string; summary: string; reason: string; recommended: string; minutesAgo: number;
    }
    const THREATS: ThreatDef[] = [
      { sourceIp: '185.220.101.42', appIndex: 0, attackType: 'SQL Injection', severity: 'Critical', confidence: 97, status: 'ACTIVE', action: 'BLOCK', summary: 'Time-based blind SQL injection against the core banking transfer endpoint', reason: 'Correlated 18 WAF SQLi signatures from a single /24 with escalating payload length', recommended: 'Block /24 at edge and open a P1 incident', minutesAgo: 42 },
      { sourceIp: '45.155.205.17', appIndex: 1, attackType: 'Remote Code Execution', severity: 'Critical', confidence: 94, status: 'INVESTIGATING', action: 'BLOCK', summary: 'Command injection attempt against the payment gateway callback handler', reason: 'Shell metacharacters observed in a form field together with outbound beacon telemetry', recommended: 'Isolate the callback worker and rotate its secrets', minutesAgo: 96 },
      { sourceIp: '103.214.68.9', appIndex: 2, attackType: 'HTTP Request Smuggling', severity: 'Critical', confidence: 92, status: 'ACTIVE', action: 'BLOCK', summary: 'Conflicting Transfer-Encoding headers aimed at the customer web portal', reason: 'CRS-921110 matched plus malformed keep-alive sequence', recommended: 'Enforce strict header normalisation at the edge', minutesAgo: 143 },
      { sourceIp: '194.26.135.88', appIndex: 3, attackType: 'Credential Stuffing', severity: 'High', confidence: 90, status: 'ACTIVE', action: 'RATE_LIMIT', summary: 'Distributed credential stuffing burst against the mobile banking backend', reason: '4,120 failed logins across 640 source IPs in 12 minutes', recommended: 'Enable adaptive MFA challenge and notify fraud operations', minutesAgo: 65 },
      { sourceIp: '89.248.165.73', appIndex: 5, attackType: 'Cross-Site Scripting (XSS)', severity: 'High', confidence: 88, status: 'INVESTIGATING', action: 'BLOCK', summary: 'Stored XSS probe against the open banking partner console', reason: 'Reflected script tag in a partner supplied feedback field', recommended: 'Confirm output encoding on the partner console', minutesAgo: 187 },
      { sourceIp: '167.94.138.51', appIndex: 6, attackType: 'Path Traversal', severity: 'High', confidence: 86, status: 'BLOCKED', action: 'BLOCK', summary: 'Directory traversal against the KYC document retrieval service', reason: 'Repeated ../../ sequences targeting /etc/passwd and app config', recommended: 'Keep edge block in place; review path canonicalisation', minutesAgo: 231 },
      { sourceIp: '198.98.51.189', appIndex: 0, attackType: 'SSH Brute Force', severity: 'High', confidence: 83, status: 'MITIGATED', action: 'DROP', summary: 'Brute force against the core banking administrative jump host', reason: '2,900 failed key exchanges in 9 minutes from a single ASN', recommended: 'Confirm key-only authentication and alert the platform team', minutesAgo: 305 },
      { sourceIp: '80.94.95.20', appIndex: 4, attackType: 'Bot/Scanner Recon', severity: 'Medium', confidence: 78, status: 'ACTIVE', action: 'CHALLENGE', summary: 'Automated vulnerability scanner enumerating the admin console', reason: 'Sequential 404 sweep matching a known Nuclei template set', recommended: 'Serve challenge pages and rate-limit the source', minutesAgo: 58 },
      { sourceIp: '141.98.10.61', appIndex: 2, attackType: 'Bot/Scanner Recon', severity: 'Medium', confidence: 75, status: 'INVESTIGATING', action: 'CHALLENGE', summary: 'Content discovery sweep against the customer web portal', reason: 'High-entropy path enumeration hitting /.git, /.env, and backup paths', recommended: 'Add the source to the recidivist blocklist', minutesAgo: 268 },
      { sourceIp: '45.142.212.100', appIndex: 1, attackType: 'Local File Inclusion', severity: 'Medium', confidence: 72, status: 'MITIGATED', action: 'BLOCK', summary: 'LFI attempt against the payment gateway template loader', reason: 'php://filter chains observed in a query parameter', recommended: 'Harden template include paths', minutesAgo: 341 },
      { sourceIp: '31.210.20.77', appIndex: 5, attackType: 'Session Fixation', severity: 'Low', confidence: 66, status: 'RESOLVED', action: 'BLOCK', summary: 'Session fixation probe against the partner login form', reason: 'Pre-set session cookie supplied before authentication', recommended: 'Regenerate session identifiers on privilege change', minutesAgo: 402 },
      { sourceIp: '193.32.162.44', appIndex: 7, attackType: 'Bot/Scanner Recon', severity: 'Low', confidence: 62, status: 'RESOLVED', action: 'LOG', summary: 'Low-volume reconnaissance against the staging gateway', reason: 'Sparse scanner fingerprints below the block threshold', recommended: 'No action required; staging is not internet-exposed', minutesAgo: 488 },
      { sourceIp: '91.240.118.23', appIndex: 6, attackType: 'Malformed HTTP Request', severity: 'Low', confidence: 58, status: 'RESOLVED', action: 'LOG', summary: 'Malformed HTTP requests against the KYC verification service', reason: 'Invalid chunked encoding observed from a legacy client', recommended: 'Verify upstream proxy normalisation', minutesAgo: 540 },
      { sourceIp: '5.188.206.14', appIndex: 3, attackType: 'Bot/Scanner Recon', severity: 'Medium', confidence: 70, status: 'ACTIVE', action: 'CHALLENGE', summary: 'Sustained scanning of the mobile backend API surface', reason: 'Rotating user agents with an identical TLS fingerprint', recommended: 'Enable JA3-based throttling', minutesAgo: 21 }
    ];

    const insertThreat = db.prepare(`
      INSERT INTO threats (
        id, organization_id, timestamp, source_ip, target, attack_type, severity, confidence,
        action, status, summary, detection_reason, affected_application, destination, related_events, recommended_action
      ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    `);
    THREATS.forEach((t, i) => {
      const app = APPLICATIONS[t.appIndex];
      insertThreat.run(
        `THR-2026-${String(i + 1).padStart(4, '0')}`, orgId, tsAgo(t.minutesAgo * 60_000), t.sourceIp,
        app.domain, t.attackType, t.severity, t.confidence, t.action, t.status, t.summary,
        t.reason, app.name, app.originIp, JSON.stringify(relatedFor()), t.recommended
      );
      counts.threats++;
    });

    // --- Incidents --------------------------------------------------------
    interface IncidentDef {
      id: string; title: string; severity: string; status: string; tier: string; assignedTo: string;
      asset: string; notes: string; timeline: Array<{ time: string; note: string; author: string; tier?: string }>; minutesAgo: number;
    }
    const INCIDENTS: IncidentDef[] = [
      {
        id: 'INC-2026-0001', title: 'Critical SQL injection against Core Banking transfer API', severity: 'Critical', status: 'INVESTIGATING', tier: 'L3',
        assignedTo: 'andi.firmansyah@oat-security.id', asset: 'Core Banking API', minutesAgo: 42,
        notes: 'Edge block is holding. Payloads appear automated and parameterised; escalated to SOC L3 Crisis Team for core database integrity verification.',
        timeline: [
          { time: '09:14:02', note: 'Incident opened automatically from correlated WAF threat THR-2026-0001 (SOC L1 Triage)', author: 'correlation-engine', tier: 'L1' },
          { time: '09:19:44', note: 'Source /24 blocked at the edge firewall by SOC L1', author: 'siti.nurhaliza@oat-security.id', tier: 'L1' },
          { time: '09:25:10', note: 'Escalated to SOC L3 Commander due to critical Core Banking impact', author: 'siti.nurhaliza@oat-security.id', tier: 'L3' }
        ]
      },
      {
        id: 'INC-2026-0002', title: 'Remote code execution attempt on payment gateway callbacks', severity: 'Critical', status: 'NEW', tier: 'L3',
        assignedTo: 'andi.firmansyah@oat-security.id', asset: 'Payment Gateway', minutesAgo: 96,
        notes: 'Callback worker quarantined behind the WAF; awaiting forensic confirmation and executive signoff from the payments team.',
        timeline: [
          { time: '08:20:11', note: 'Threat promoted to incident (confidence 94) - Queued for SOC L3 Commander', author: 'correlation-engine', tier: 'L3' }
        ]
      },
      {
        id: 'INC-2026-0003', title: 'Distributed credential stuffing on mobile banking', severity: 'High', status: 'INVESTIGATING', tier: 'L2',
        assignedTo: 'rizky.pratama@oat-security.id', asset: 'Mobile Banking Backend', minutesAgo: 65,
        notes: 'Adaptive MFA challenge enabled. Fraud operations notified; SOC L2 threat hunter monitoring credential spray correlation.',
        timeline: [
          { time: '08:51:37', note: 'Rate-limit policy applied to /auth/login by SOC L1', author: 'siti.nurhaliza@oat-security.id', tier: 'L1' },
          { time: '08:58:09', note: 'Assigned to SOC L2: Adaptive MFA challenge enabled for affected ASNs', author: 'rizky.pratama@oat-security.id', tier: 'L2' }
        ]
      },
      {
        id: 'INC-2026-0004', title: 'Directory traversal against KYC document service', severity: 'High', status: 'MITIGATED', tier: 'L2',
        assignedTo: 'siti.nurhaliza@oat-security.id', asset: 'KYC Verification Service', minutesAgo: 231,
        notes: 'Edge block retained. Path canonicalisation review completed by SOC L2 and scheduled with compliance engineering.',
        timeline: [
          { time: '05:32:18', note: 'WAF rule CRS-930100 triggered 46 times from a single source', author: 'correlation-engine', tier: 'L1' },
          { time: '06:05:52', note: 'Mitigation confirmed by SOC L2; incident marked MITIGATED', author: 'siti.nurhaliza@oat-security.id', tier: 'L2' }
        ]
      },
      {
        id: 'INC-2026-0005', title: 'Brute force against core banking jump host', severity: 'Medium', status: 'CLOSED', tier: 'L1',
        assignedTo: 'budi.santoso@oat-security.id', asset: 'Core Banking Zone', minutesAgo: 305,
        notes: 'Key-only authentication confirmed; no successful logins. Source added to the permanent blocklist by SOC L1.',
        timeline: [
          { time: '04:18:40', note: 'Firewall DENY spike detected on port 22', author: 'correlation-engine', tier: 'L1' },
          { time: '04:44:03', note: 'Source ASN blocked; incident resolved and closed by SOC L1', author: 'budi.santoso@oat-security.id', tier: 'L1' }
        ]
      },
      {
        id: 'INC-2026-0006', title: 'Automated scanner sweep across admin console', severity: 'Low', status: 'INVESTIGATING', tier: 'L1',
        assignedTo: 'putri.rahayu@oat-security.id', asset: 'Internal Admin Console', minutesAgo: 58,
        notes: 'Challenge pages are throttling the sweep. SOC L1 reviewing exposure of internal-only routes.',
        timeline: [
          { time: '09:02:55', note: 'Scanner fingerprint matched a known Nuclei template set (SOC L1 Triage)', author: 'correlation-engine', tier: 'L1' }
        ]
      }
    ];

    const insertIncident = db.prepare(`
      INSERT INTO incidents (id, organization_id, title, severity, status, tier, assigned_to, affected_asset, notes, timeline, created_at, updated_at)
      VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    `);
    for (const inc of INCIDENTS) {
      const created = tsAgo(inc.minutesAgo * 60_000);
      insertIncident.run(
        inc.id, orgId, inc.title, inc.severity, inc.status, inc.tier, inc.assignedTo, inc.asset,
        inc.notes, JSON.stringify(inc.timeline), created, created
      );
      counts.incidents++;
    }

    // --- Centralized logs -------------------------------------------------
    const LOG_TEMPLATES: Array<{ level: string; source: string; eventType: string; message: string }> = [
      { level: 'INFO', source: 'WAF', eventType: 'rule_match', message: 'WAF rule OWASP-CRS-942100 matched on /api/v1/accounts/transfer from blocked source' },
      { level: 'INFO', source: 'Firewall', eventType: 'policy_applied', message: 'Firewall policy synced to edge node fw-edge-01 (revision 8421)' },
      { level: 'INFO', source: 'Agent', eventType: 'endpoint_alert', message: 'Endpoint agent detected a potential SSH scan on debian-server' },
      { level: 'WARN', source: 'WAF', eventType: 'anomaly_score', message: 'Inbound anomaly score 27 exceeded threshold for /auth/login' },
      { level: 'WARN', source: 'System', eventType: 'latency', message: 'Endpoint agent debian-server reporting elevated log ingestion latency (48ms)' },
      { level: 'ERROR', source: 'Application', eventType: 'upstream_error', message: 'Upstream 502 from staging-api gateway during health probe' },
      { level: 'ERROR', source: 'Authentication', eventType: 'login_failed', message: 'Repeated authentication failures for operator account from blocked ASN' },
      { level: 'CRITICAL', source: 'WAF', eventType: 'rule_match', message: 'WAF rule OWASP-CRS-932100 matched remote command execution pattern' },
      { level: 'CRITICAL', source: 'Agent', eventType: 'endpoint_alert', message: 'Endpoint agent detected command-and-control beacon activity on debian-server' },
      { level: 'INFO', source: 'Authentication', eventType: 'login_success', message: 'Operator session established with MFA on admin console' },
      { level: 'DEBUG', source: 'System', eventType: 'collector', message: 'Endpoint agent log collector advanced to offset 1048576' },
      { level: 'INFO', source: 'System', eventType: 'audit', message: 'Audit retention job completed; 0 records pruned (within 365-day window)' }
    ];

    const LOG_HOSTS = ['edge-gateway-01', 'edge-gateway-02', 'waf-node-01', 'debian-server', 'siem-collector-01'];
    const insertLog = db.prepare(`
      INSERT INTO logs (id, organization_id, timestamp, level, source, event_type, message, host, ip, correlation_id, metadata, raw_log)
      VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    `);
    for (let i = 0; i < 64; i++) {
      const tpl = pick(LOG_TEMPLATES);
      const ts = tsAgo(randInt(1, 1440) * 60_000);
      const host = pick(LOG_HOSTS);
      const ip = pick(ATTACKER_IPS);
      const correlationId = `corr-${randInt(100000, 999999)}`;
      insertLog.run(
        `LOG-${String(i + 1).padStart(5, '0')}`, orgId, ts, tpl.level, tpl.source, tpl.eventType, tpl.message,
        host, ip, correlationId,
        JSON.stringify({ host, source: tpl.source, level: tpl.level }),
        `${ts} ${host} ${tpl.source.toLowerCase()}: ${tpl.message}`
      );
      counts.logs++;
    }

    // --- Audit logs -------------------------------------------------------
    const AUDIT_USERS: Array<{ email: string; role: string }> = [
      { email: 'andi.firmansyah@oat-security.id', role: 'Super Admin' },
      { email: 'siti.nurhaliza@oat-security.id', role: 'Security Analyst' },
      { email: 'rizky.pratama@oat-security.id', role: 'Viewer' }
    ];
    const AUDIT_ACTIONS: Array<{ action: string; resource: string }> = [
      { action: 'User Login', resource: 'OAT Web Console' },
      { action: 'Enable WAF Rule', resource: 'OWASP-CRS-949110 (Inbound Anomaly Score Exceeded)' },
      { action: 'Disable WAF Rule', resource: 'OAT-CUSTOM-0020 (Geo-challenge Sanctioned Regions)' },
      { action: 'Create Firewall Rule', resource: 'Firewall Rule fw_010 (10.240.10.0/24 -> 10.240.40.0/24:53)' },
      { action: 'Update Incident Status to INVESTIGATING', resource: 'Incident INC-2026-0001 (Critical SQL injection)' },
      { action: 'Configure SIEM Integration', resource: 'SIEM Provider: splunk' },
      { action: 'Create API Key', resource: 'API Key key_siem_ingest (oat_live_9f2c...)' },
      { action: 'Generate Security Report', resource: 'Report REP-2026-0007 (Executive Summary)' },
      { action: 'Add Network Zone', resource: 'Partner Interconnect (10.240.40.0/24)' },
      { action: 'Mitigate Threat', resource: 'Threat THR-2026-0004 (Credential Stuffing)' }
    ];
    const insertAudit = db.prepare(`
      INSERT INTO audit_logs (id, organization_id, user_id, user_email, role, action, resource, resource_id, ip_address, user_agent, timestamp, metadata)
      VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    `);
    for (let i = 0; i < 32; i++) {
      const u = pick(AUDIT_USERS);
      const a = pick(AUDIT_ACTIONS);
      insertAudit.run(
        `AUD-${String(i + 1).padStart(5, '0')}`, orgId, `usr_${u.email}`, u.email, u.role,
        a.action, a.resource, `res_${randInt(1000, 9999)}`, pick(['10.240.30.14', '10.240.30.22', '10.240.50.9']),
        'Mozilla/5.0 (Windows NT 10.0; Win64; x64) OAT-Console/2026.1', tsAgo(randInt(1, 4320) * 60_000),
        JSON.stringify({ channel: 'web-console' })
      );
      counts.auditLogs++;
    }

    // --- SIEM integrations ------------------------------------------------
    const insertIntegration = db.prepare(`
      INSERT INTO integration_configs (id, organization_id, provider, config_json, status, updated_at)
      VALUES (?, ?, ?, ?, ?, ?)
    `);
    const INTEGRATIONS: Array<{ provider: string; config: any; status: string }> = [
      { provider: 'splunk', config: { endpoint: 'https://splunk-hec.urbannusacyber.co.id:8088', indexOrChannel: 'oat_security' }, status: 'CONNECTED' },
      { provider: 'elastic', config: { endpoint: 'https://elastic.urbannusacyber.co.id:9200', indexOrChannel: 'oat-security-events' }, status: 'CONNECTED' },
      { provider: 'syslog', config: {}, status: 'NOT CONFIGURED' },
      { provider: 'webhook', config: { endpoint: 'https://soar.urbannusacyber.co.id/hooks/oat' }, status: 'DISCONNECTED' }
    ];
    for (const int of INTEGRATIONS) {
      insertIntegration.run(`siem_${int.provider}_${orgId}`, orgId, int.provider, JSON.stringify(int.config), int.status, tsAgo(randInt(10, 600) * 60_000));
      counts.integrations++;
    }

    // --- API keys ---------------------------------------------------------
    const insertKey = db.prepare(`
      INSERT INTO api_keys (id, organization_id, name, prefix, key_hash, permissions, status, created_at, last_used_at)
      VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
    `);
    const KEYS: Array<{ name: string; prefix: string; permissions: string[]; status: string }> = [
      { name: 'SIEM Ingest Collector', prefix: 'oat_live_9f2c81ab...', permissions: ['telemetry:read', 'siem:write'], status: 'Active' },
      { name: 'Partner Telemetry Gateway', prefix: 'oat_live_4d7e20ff...', permissions: ['telemetry:read'], status: 'Active' }
    ];
    KEYS.forEach((k, i) => {
      insertKey.run(`key_${i + 1}`, orgId, k.name, k.prefix, `hash_${i + 1}_${DEMO_ORG_ID}`, JSON.stringify(k.permissions), k.status, tsAgo((i + 3) * 86_400_000), tsAgo(randInt(5, 900) * 60_000));
      counts.apiKeys++;
    });

    // --- System health ----------------------------------------------------
    const insertHealth = db.prepare('INSERT INTO system_health (service_name, status, latency_ms, last_check, details) VALUES (?, ?, ?, ?, ?)');
    const HEALTH: Array<{ service: string; status: string; latency: number; details: string }> = [
      { service: 'WAF Engine', status: 'Operational', latency: 3.2, details: 'OWASP CRS 4.0 loaded · 12 rules active' },
      { service: 'Next-Gen Firewall', status: 'Operational', latency: 4.8, details: 'Edge ACL synced · 10 rules active' },
      { service: 'Endpoint Detection', status: 'Operational', latency: 1.1, details: '1/1 endpoint agent online · last heartbeat 12s ago' },
      { service: 'Database Vault', status: 'Operational', latency: 2.1, details: 'WAL healthy · replication lag 0s' },
      { service: 'API Gateway', status: 'Operational', latency: 8.7, details: 'p99 12ms · 0 upstream errors' },
      { service: 'SIEM Monitor', status: 'Operational', latency: 15.3, details: '2 connectors streaming' },
      { service: 'WebSocket Stream', status: 'Operational', latency: 1.9, details: 'Realtime channel healthy' },
      { service: 'Threat Intel', status: 'Operational', latency: 22.6, details: 'Feed sync completed 6m ago' }
    ];
    for (const h of HEALTH) {
      insertHealth.run(h.service, h.status, h.latency, tsAgo(randInt(5, 120) * 1000), h.details);
      counts.healthServices++;
    }

    db.exec('COMMIT');
  } catch (err) {
    db.exec('ROLLBACK');
    throw err;
  }

  return counts;
}
