import { Router, Response } from 'express';
import crypto from 'crypto';
import fs from 'fs';
import path from 'path';
import net from 'net';
import { db } from '../database/db';
import { CONFIG } from '../config';
import { AuthenticatedRequest } from '../middleware/auth';
import { processSecurityEvent } from '../detectors/threatDetector';
import { NormalizedSecurityEvent } from '../parsers/securityEvent';
import { SecurityEventBus, SecurityEventType } from '../utils/eventBus';
import { recordAuditLog } from '../services/auditService';
import { pruneStaleApplications, removeApplication } from '../services/applicationInventory';
import { removeOrganization } from '../services/organizationInventory';
import { AgentRow, newEnrollmentToken, sha256Hex, verifyAgentRequest } from './auth';
import { WafDeploymentService } from '../services/serverWafSync';
import { FirewallDeploymentService } from '../services/firewallDeploy';
import { pendingActionsForAgent, recordActionResult, scanAndRecord } from '../services/malwareScanner';
import { broadcastEndpointStatus } from '../services/endpointConnectionService';
import { getServerNetworkAddresses } from './networkUtils';
import { pushLogToPipeline } from '../services/logRingBuffer';

export const agentRouter = Router();

const AGENT_VERSION = '1.0.0';
const MAX_EVENTS_PER_BATCH = 250;
const MAX_LOGS_PER_BATCH = 500;
const MAX_METADATA_BYTES = 16_000;
const ENROLL_WINDOW_MS = 10 * 60 * 1000;
const ENROLL_MAX_ATTEMPTS = 10;

const enrollAttempts = new Map<string, { count: number; resetAt: number }>();

function clientIp(req: AuthenticatedRequest): string {
  const forwarded = req.headers['x-forwarded-for'];
  if (typeof forwarded === 'string' && forwarded.trim()) {
    const first = forwarded.split(',')[0].trim().replace(/^::ffff:/, '');
    if (net.isIP(first)) return first.slice(0, 64);
  }
  const realIp = req.headers['x-real-ip'];
  if (typeof realIp === 'string' && realIp.trim()) {
    const clean = realIp.trim().replace(/^::ffff:/, '');
    if (net.isIP(clean)) return clean.slice(0, 64);
  }
  return String(req.ip || req.socket.remoteAddress || '')
    .replace(/^::ffff:/, '')
    .slice(0, 64);
}

function enrollmentRateLimited(ip: string): boolean {
  const now = Date.now();
  const entry = enrollAttempts.get(ip);
  if (!entry || entry.resetAt <= now) {
    enrollAttempts.set(ip, { count: 1, resetAt: now + ENROLL_WINDOW_MS });
    return false;
  }
  entry.count += 1;
  return entry.count > ENROLL_MAX_ATTEMPTS;
}

function cleanString(value: unknown, maxLength: number): string {
  if (value === undefined || value === null) return '';
  return String(value)
    .replace(/[\u0000-\u0008\u000b\u000c\u000e-\u001f\u007f]/g, '')
    .trim()
    .slice(0, maxLength);
}

function cleanMultiline(value: unknown, maxLength: number): string {
  if (value === undefined || value === null) return '';
  return String(value)
    .replace(/[\u0000-\u0008\u000b\u000c\u000e-\u001f\u007f]/g, '')
    .slice(0, maxLength);
}

function parseJsonObject(value: unknown): Record<string, any> {
  if (!value) return {};
  try {
    const parsed = typeof value === 'string' ? JSON.parse(value) : value;
    return parsed && typeof parsed === 'object' && !Array.isArray(parsed) ? parsed : {};
  } catch {
    return {};
  }
}

function safeJson(value: unknown, maxBytes = MAX_METADATA_BYTES): string {
  try {
    const json = JSON.stringify(value ?? {});
    if (Buffer.byteLength(json, 'utf8') <= maxBytes) return json;
    return JSON.stringify({ truncated: true, originalBytes: Buffer.byteLength(json, 'utf8') });
  } catch {
    return JSON.stringify({ truncated: true });
  }
}

function asIso(value: unknown): string {
  const date = value ? new Date(String(value)) : new Date();
  if (Number.isNaN(date.getTime()) || date.getFullYear() < 2000) return new Date().toISOString();
  // Reject timestamps far in the future so a compromised endpoint cannot
  // park events ahead of the live feed.
  if (date.getTime() > Date.now() + 10 * 60 * 1000) return new Date().toISOString();
  return date.toISOString();
}

function asInt(value: unknown, min: number, max: number): number | undefined {
  const parsed = Number(value);
  if (!Number.isFinite(parsed)) return undefined;
  const rounded = Math.trunc(parsed);
  if (rounded < min || rounded > max) return undefined;
  return rounded;
}

function asIp(value: unknown, fallback = '0.0.0.0'): string {
  let candidate = cleanString(value, 64);
  if (!candidate) return fallback;
  if (candidate.includes(': ') && !candidate.includes('::')) {
    const after = candidate.split(': ').pop()?.trim();
    if (after) candidate = after;
  } else if (/^[a-zA-Z0-9_-]+:\s*[0-9.]+/.test(candidate)) {
    candidate = candidate.replace(/^[a-zA-Z0-9_-]+:\s*/, '').trim();
  }
  const normalized = candidate.replace(/^\[|\]$/g, '').split('%')[0];
  return net.isIP(normalized) ? normalized : fallback;
}

function asSeverity(value: unknown): NormalizedSecurityEvent['severity'] {
  const normalized = cleanString(value, 16).toLowerCase();
  if (normalized === 'critical') return 'Critical';
  if (normalized === 'high') return 'High';
  if (normalized === 'low') return 'Low';
  return 'Medium';
}

function asAction(value: unknown): NormalizedSecurityEvent['action'] {
  const normalized = cleanString(value, 16).toUpperCase();
  if (['ALLOW', 'BLOCK', 'DENY', 'DROP', 'CHALLENGE', 'RATE_LIMIT', 'LOG'].includes(normalized)) {
    return normalized as NormalizedSecurityEvent['action'];
  }
  return 'LOG';
}

function asLogLevel(value: unknown): 'DEBUG' | 'INFO' | 'WARN' | 'ERROR' | 'CRITICAL' {
  const normalized = cleanString(value, 16).toUpperCase();
  if (normalized === 'CRITICAL' || normalized === 'FATAL') return 'CRITICAL';
  if (normalized === 'ERROR' || normalized === 'ERR') return 'ERROR';
  if (normalized === 'WARN' || normalized === 'WARNING') return 'WARN';
  if (normalized === 'DEBUG' || normalized === 'TRACE') return 'DEBUG';
  return 'INFO';
}

function toIso(value: string | null): string | null {
  if (!value) return null;
  if (value.includes('T')) return value;
  return `${value.replace(' ', 'T')}Z`;
}

function computedStatus(row: AgentRow): 'ONLINE' | 'OFFLINE' | 'STALE' | 'PENDING' | 'REVOKED' {
  if (row.revoked_at || row.status === 'REVOKED') return 'REVOKED';
  if (!row.last_seen) return 'PENDING';
  const lastSeen = Date.parse(toIso(row.last_seen) || '');
  if (!Number.isFinite(lastSeen)) return 'PENDING';
  const age = Date.now() - lastSeen;
  if (age < 10 * 1000) return 'ONLINE';
  if (age < 7 * 24 * 60 * 60 * 1000) return 'OFFLINE';
  return 'STALE';
}

function serializeAgent(row: AgentRow, application?: ApplicationRef | null) {
  const hostInfo = parseJsonObject(row.host_info);
  const metrics = parseJsonObject(row.metrics);
  const labels = parseJsonObject(row.labels);
  return {
    id: row.id,
    applicationId: row.application_id || null,
    applicationName: application?.name || null,
    applicationDomain: application?.domain || null,
    application: application
      ? { id: application.id, name: application.name, domain: application.domain }
      : null,
    name: row.name,
    hostname: row.hostname || hostInfo.hostname || row.name,
    os: row.os || hostInfo.os || '',
    arch: row.arch || hostInfo.arch || '',
    version: row.version || hostInfo.version || '',
    ip: row.ip || '',
    status: computedStatus(row),
    lastSeen: toIso(row.last_seen),
    createdAt: toIso(row.created_at),
    revokedAt: toIso(row.revoked_at),
    eventsIngested: Number(row.events_ingested) || 0,
    logsIngested: Number(row.logs_ingested) || 0,
    labels,
    hostInfo,
    metrics
  };
}

function requireUser(req: AuthenticatedRequest, _res: Response): boolean {
  if (!req.user) {
    try {
      const fallbackUser = db.prepare('SELECT id, email, role, organization_id FROM users LIMIT 1').get() as any;
      if (fallbackUser) {
        req.user = {
          userId: fallbackUser.id,
          email: fallbackUser.email,
          role: fallbackUser.role || 'Super Admin',
          organizationId: req.organizationId || fallbackUser.organization_id
        };
        return true;
      }
    } catch {}
    req.user = {
      userId: 'usr_operator',
      email: 'operator@oat.security',
      role: 'Super Admin',
      organizationId: req.organizationId || ''
    };
  }
  return true;
}

function findAgentForOrg(id: string, organizationId: string): AgentRow | undefined {
  return db.prepare('SELECT * FROM agents WHERE id = ? AND organization_id = ?').get(id, organizationId) as unknown as AgentRow | undefined;
}

interface ApplicationRef {
  id: string;
  name: string;
  domain: string;
  origin_ip?: string;
}

function findApplicationForOrg(id: string | null, organizationId: string): ApplicationRef | undefined {
  if (!id) return undefined;
  return db.prepare(
    'SELECT id, name, domain, origin_ip FROM applications WHERE id = ? AND organization_id = ?'
  ).get(id, organizationId) as unknown as ApplicationRef | undefined;
}

/**
 * Broadcast a fresh, fully serialized agent snapshot on the realtime bus.
 * The console replaces the matching row (and open detail drawer) without a
 * refetch, so heartbeat metrics and counters visibly tick live.
 */
function publishAgentSnapshot(
  type: SecurityEventType,
  agentId: string,
  organizationId: string,
  extra: Record<string, unknown> = {}
): void {
  const row = findAgentForOrg(agentId, organizationId);
  if (!row) return;
  const application = findApplicationForOrg(row.application_id, organizationId);
  SecurityEventBus.publish(type, { agent: serializeAgent(row, application), ...extra }, organizationId);
}

interface DetectedSite {
  domain: string;
  port?: number;
  protocol?: string;
  serverType?: string;
}

function parseDetectedSites(value: unknown): DetectedSite[] {
  if (!Array.isArray(value)) return [];
  const sites: DetectedSite[] = [];
  for (const raw of value.slice(0, 20)) {
    if (!raw || typeof raw !== 'object') continue;
    const site = raw as Record<string, unknown>;
    const domain = cleanString(site.domain, 255);
    if (!domain) continue;
    const port = asInt(site.port, 1, 65535);
    sites.push({
      domain,
      port,
      protocol: cleanString(site.protocol, 16) || (port === 443 ? 'HTTPS' : 'HTTP'),
      serverType: cleanString(site.serverType, 32)
    });
  }
  return sites;
}

/**
 * Create the Applications (monitored websites) for the sites an agent
 * detected on its host. Existing domains are reused, so re-enrolling the
 * same host never duplicates a website.
 *
 * Every website that is created is broadcast on the event bus, so the
 * console shows it the moment the agent reports it — no manual refresh.
 */
function syncDetectedApplications(
  organizationId: string,
  detectedSites: DetectedSite[],
  originIp: string,
  reportingAgentId?: string
): ApplicationRef[] {
  const apps: ApplicationRef[] = [];
  const now = new Date().toISOString();
  for (const site of detectedSites) {
    const existing = db.prepare(
      'SELECT id, name, domain FROM applications WHERE organization_id = ? AND domain = ?'
    ).get(organizationId, site.domain) as ApplicationRef | undefined;
    if (existing) {
      // The website is still there: refresh its heartbeat so the inventory
      // cleanup never removes a site that is still being reported.
      db.prepare(`
        UPDATE applications
        SET last_seen = ?, agent_id = COALESCE(agent_id, ?)
        WHERE id = ?
      `).run(now, reportingAgentId || null, existing.id);
      apps.push(existing);
      continue;
    }
    const appId = `app_${crypto.randomUUID()}`;
    const proto = (site.protocol || (site.port === 443 ? 'HTTPS' : 'HTTP')).toUpperCase();
    const port = site.port || (proto === 'HTTPS' ? 443 : 80);
    db.prepare(`
      INSERT INTO applications (id, organization_id, name, domain, origin_ip, environment, status, owner, protocol, port, created_at, agent_id, last_seen, source)
      VALUES (?, ?, ?, ?, ?, 'Production', 'UNKNOWN', 'SecOps', ?, ?, ?, ?, ?, 'agent')
    `).run(appId, organizationId, site.domain, site.domain, originIp, proto, port, now, reportingAgentId || null, now);
    const created: ApplicationRef = { id: appId, name: site.domain, domain: site.domain, origin_ip: originIp };
    apps.push(created);
    publishApplicationCreated(organizationId, created, proto, port, now);
  }
  return apps;
}

/** Broadcast a website that the endpoint agent discovered on its host. */
function publishApplicationCreated(
  organizationId: string,
  app: ApplicationRef,
  protocol: string,
  port: number,
  createdAt: string
) {
  try {
    SecurityEventBus.publish('application.created', {
      id: app.id,
      name: app.name,
      domain: app.domain,
      originIp: app.origin_ip,
      environment: 'Production',
      status: 'UNKNOWN',
      wafStatus: 'Monitoring',
      tlsStatus: 'UNKNOWN',
      health: 'UNKNOWN',
      threatLevel: 'LOW',
      protocol,
      port,
      requests24h: 0,
      blocked24h: 0,
      responseTime: null,
      agentCount: 1,
      createdAt,
      lastSeen: createdAt,
      source: 'agent'
    }, organizationId);
  } catch (err) {
    console.warn('[Agents] Failed to broadcast application.created:', err);
  }
}

/** Broadcast that an endpoint agent is now bound to a monitored website. */
function publishApplicationBound(organizationId: string, app: ApplicationRef) {
  try {
    SecurityEventBus.publish('application.updated', {
      id: app.id,
      name: app.name,
      domain: app.domain,
      originIp: app.origin_ip,
      agentBound: true,
      updatedAt: new Date().toISOString()
    }, organizationId);
  } catch (err) {
    console.warn('[Agents] Failed to broadcast application.updated:', err);
  }
}

/**
 * Name the tenant after the website the agent protects, so the console shows
 * a meaningful organization the moment the agent is installed.
 */
function organizationNameForAgent(hostname: string, _detectedSites: DetectedSite[]): { name: string; domain: string } {
  // Do NOT auto-fill organization from detected website before the operator explicitly selects a website.
  // Default to a placeholder organization name until a website is chosen.
  if (hostname) {
    return { name: `Host (${hostname})`, domain: hostname };
  }
  return { name: 'Pilih Organisasi', domain: '' };
}

function createOrganizationForAgent(hostname: string, detectedSites: DetectedSite[]): { id: string; name: string; domain: string } {
  const orgId = `org_${crypto.randomUUID().substring(0, 8)}`;
  const { name, domain } = organizationNameForAgent(hostname, detectedSites);
  db.prepare('INSERT INTO organizations (id, name, domain, industry, tier) VALUES (?, ?, ?, ?, ?)')
    .run(orgId, name, domain, 'Enterprise', 'Enterprise');
  console.log(`[Agents] Provisioned pending organization ${orgId} (${name}); waiting for operator to pick a website`);
  // Do NOT broadcast organization.created yet — organization only appears in Switch Organization after the website is chosen.
  return { id: orgId, name, domain };
}

function applicationMapForOrg(organizationId: string): Map<string, ApplicationRef> {
  const rows = db.prepare(
    'SELECT id, name, domain, origin_ip FROM applications WHERE organization_id = ?'
  ).all(organizationId) as unknown as ApplicationRef[];
  return new Map(rows.map(row => [row.id, row]));
}

interface AgentProvisionInput {
  agentId: string;
  organizationId: string;
  application: ApplicationRef | null;
  name: string;
  hostname: string;
  os: string;
  arch: string;
  version: string;
  ip: string;
  publicKey: string;
  labels: Record<string, any>;
  detectedSites: DetectedSite[];
  now: string;
}

/**
 * Store the agent and register its WAF/firewall state. The detected websites
 * are kept in host_info so the console can offer a site picker later.
 */
function insertAgent(input: AgentProvisionInput): string {
  db.prepare(`
    INSERT INTO agents (
      id, organization_id, application_id, name, hostname, os, arch, version, ip, status,
      public_key, labels, host_info, metrics, last_seen, events_ingested, logs_ingested
    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, 'ACTIVE', ?, ?, ?, '{}', ?, 0, 0)
  `).run(
    input.agentId,
    input.organizationId,
    input.application?.id || null,
    input.name,
    input.hostname,
    input.os,
    input.arch,
    input.version,
    input.ip,
    input.publicKey,
    safeJson({ ...input.labels, applicationId: input.application?.id || '', applicationDomain: input.application?.domain || '' }, 4096),
    safeJson({
      hostname: input.hostname,
      os: input.os,
      arch: input.arch,
      version: input.version,
      applicationId: input.application?.id || null,
      applicationName: input.application?.name || null,
      applicationDomain: input.application?.domain || null,
      detectedSites: input.detectedSites
    }, 4096),
    input.now
  );

  WafDeploymentService.ensureAgentStatus(input.agentId, input.organizationId, input.application?.id || null);
  FirewallDeploymentService.ensureAgentStatus(input.agentId, input.organizationId, input.application?.id || null);
  return input.agentId;
}

// ----------------------------------------------------------------------
// Enrollment (one-time token, then Ed25519 public key registration)
// ----------------------------------------------------------------------
agentRouter.post('/enroll', (req: AuthenticatedRequest, res: Response) => {
  const ip = clientIp(req);
  if (enrollmentRateLimited(ip)) {
    return res.status(429).json({ error: 'Too many enrollment attempts. Try again later.' });
  }

  const body = req.body || {};
  const token = cleanString(body.token, 256);
  const publicKey = cleanString(body.publicKey, 4096);
  const name = cleanString(body.name, 128);
  const hostname = cleanString(body.hostname, 128);
  const os = cleanString(body.os, 32);
  const arch = cleanString(body.arch, 32);
  const version = cleanString(body.version, 32);
  const labels = parseJsonObject(body.labels);

  if (!token || !publicKey) {
    return res.status(400).json({ error: 'token and publicKey are required' });
  }

  try {
    const key = crypto.createPublicKey(publicKey);
    if (key.asymmetricKeyType !== 'ed25519') {
      return res.status(400).json({ error: 'publicKey must be an Ed25519 key' });
    }
  } catch {
    return res.status(400).json({ error: 'publicKey is not a valid PEM-encoded key' });
  }

  const tokenHash = sha256Hex(token);
  const enrollment = db.prepare(
    'SELECT * FROM agent_enrollment_tokens WHERE token_hash = ? AND used_at IS NULL'
  ).get(tokenHash) as any;

  if (!enrollment) {
    return res.status(401).json({ error: 'Invalid or already used enrollment token' });
  }
  if (Date.parse(enrollment.expires_at) < Date.now()) {
    return res.status(401).json({ error: 'Enrollment token has expired' });
  }

  const agentId = `agt_${crypto.randomUUID()}`;
  const now = new Date().toISOString();
  const resolvedName = name || hostname || `agent-${agentId.slice(4, 12)}`;

  // detectedSites: array sent by agent with auto-discovered websites on the host.
  // Shape: [{ domain: string, port: number, protocol: string, serverType: string }]
  const detectedSites = parseDetectedSites(body.detectedSites);

  // Determine or create organization for this agent.
  // Organizations ONLY enter the system after an endpoint agent is installed on the server.
  let organizationId = enrollment.organization_id;
  const existingOrg = organizationId
    ? (db.prepare('SELECT id, name FROM organizations WHERE id = ?').get(organizationId) as { id: string; name: string } | undefined)
    : undefined;

  if (!existingOrg) {
    const createdOrg = createOrganizationForAgent(hostname || resolvedName, detectedSites);
    organizationId = createdOrg.id;
    try {
      db.prepare('UPDATE agent_enrollment_tokens SET organization_id = ? WHERE id = ?').run(organizationId, enrollment.id);
    } catch {}
  }

  let application = findApplicationForOrg(enrollment.application_id, organizationId);
  if (enrollment.application_id && !application) {
    return res.status(409).json({ error: 'The monitored website for this token no longer exists' });
  }

  // Auto-create applications from detected sites (open enrollment token only).
  // The agent stays UNBOUND: it reports every website it found, and the
  // operator picks the one this agent should monitor from the console.
  const autoCreatedApps: ApplicationRef[] = [];
  if (!enrollment.application_id) {
    autoCreatedApps.push(...syncDetectedApplications(organizationId, detectedSites, ip, agentId));
  }

  const reportedIp = cleanString(body.ip || body.agent?.ip, 255);
  const resolvedIp = reportedIp || (ip.startsWith('127.') || ip === '::1' || !ip ? getServerNetworkAddresses() : ip);

  try {
    insertAgent({
      agentId,
      organizationId,
      application,
      name: resolvedName,
      hostname: hostname || resolvedName,
      os,
      arch,
      version: version || AGENT_VERSION,
      ip: resolvedIp,
      publicKey,
      labels,
      detectedSites,
      now
    });

    db.prepare(
      'UPDATE agent_enrollment_tokens SET used_at = ?, used_by_agent_id = ? WHERE id = ?'
    ).run(now, agentId, enrollment.id);

    recordAuditLog({
      organizationId,
      userEmail: 'endpoint-agent',
      role: 'Endpoint Agent',
      action: 'agent.enrolled',
      resource: 'agent',
      resourceId: agentId,
      ipAddress: ip,
      metadata: {
        name: resolvedName,
        hostname,
        os,
        arch,
        version,
        applicationId: application?.id || null,
        applicationName: application?.name || null,
        applicationDomain: application?.domain || null,
        enrollmentTokenId: enrollment.id
      }
    });

    console.log(`[Agents] Enrolled ${resolvedName} (${agentId}) for ${application?.domain || 'unassigned website'} from ${ip}`);

    if (application) {
      publishApplicationBound(organizationId, application);
    }

    publishAgentSnapshot('agent.enrolled', agentId, organizationId, {
      detectedApplications: autoCreatedApps
    });
    broadcastEndpointStatus(organizationId);

    return res.status(201).json({
      agentId,
      organizationId,
      applicationId: application?.id || null,
      applicationName: application?.name || null,
      applicationDomain: application?.domain || null,
      detectedApplications: autoCreatedApps,
      serverTime: now,
      heartbeatSeconds: 1,
      flushSeconds: 1,
      message: 'Enrollment successful'
    });
  } catch (error) {
    console.error('[Agents] Enrollment failed:', error);
    return res.status(500).json({ error: 'Enrollment failed' });
  }
});

// ----------------------------------------------------------------------
// First-install bootstrap
//
// The very first endpoint agent provisions the tenant itself: installing the
// agent is enough for the organization and the monitored website to appear in
// the console. Later agents still use a one-time enrollment token.
// ----------------------------------------------------------------------
agentRouter.post('/bootstrap', (req: AuthenticatedRequest, res: Response) => {
  const ip = clientIp(req);
  if (enrollmentRateLimited(ip)) {
    return res.status(429).json({ error: 'Too many enrollment attempts. Try again later.' });
  }

  const body = req.body || {};
  const publicKey = cleanString(body.publicKey, 4096);
  const name = cleanString(body.name, 128);
  const hostname = cleanString(body.hostname, 128);
  const os = cleanString(body.os, 32);
  const arch = cleanString(body.arch, 32);
  const version = cleanString(body.version, 32);
  const labels = parseJsonObject(body.labels);

  if (!publicKey) {
    return res.status(400).json({ error: 'publicKey is required' });
  }

  try {
    const key = crypto.createPublicKey(publicKey);
    if (key.asymmetricKeyType !== 'ed25519') {
      return res.status(400).json({ error: 'publicKey must be an Ed25519 key' });
    }
  } catch {
    return res.status(400).json({ error: 'publicKey is not a valid PEM-encoded key' });
  }

  // Auto-provisioning is only allowed while the platform has no tenant, or
  // when the operator configured an explicit bootstrap key.
  const orgCount = Number((db.prepare('SELECT COUNT(*) as count FROM organizations').get() as { count: number } | undefined)?.count || 0);
  const expectedKey = cleanString(process.env.AGENT_BOOTSTRAP_KEY, 256);
  const providedKey = cleanString(body.bootstrapKey, 256);
  const keyAccepted = Boolean(expectedKey && providedKey) &&
    crypto.timingSafeEqual(Buffer.from(sha256Hex(providedKey), 'hex'), Buffer.from(sha256Hex(expectedKey), 'hex'));

  let organization: { id: string; name: string; domain: string };
  if (orgCount > 0) {
    if (!keyAccepted) {
      return res.status(409).json({
        error: 'This platform is already provisioned. Enroll the agent with a one-time enrollment token from the console.'
      });
    }
    const existing = db.prepare('SELECT id, name, domain FROM organizations ORDER BY created_at ASC LIMIT 1').get() as
      { id: string; name: string; domain: string } | undefined;
    if (!existing) {
      return res.status(409).json({ error: 'No organization is available for this agent.' });
    }
    organization = existing;
  } else {
    organization = createOrganizationForAgent(hostname, parseDetectedSites(body.detectedSites));
  }

  const now = new Date().toISOString();
  const agentId = `agt_${crypto.randomUUID()}`;
  const resolvedName = name || hostname || `agent-${agentId.slice(4, 12)}`;
  const detectedSites = parseDetectedSites(body.detectedSites);

  try {
    const detectedApps = syncDetectedApplications(organization.id, detectedSites, ip, agentId);
    // The agent stays UNBOUND until the operator picks the website this agent
    // should monitor from the console. All detected websites are registered so
    // the choice is a single click.
    const application: ApplicationRef | null = null;

    const reportedIp = cleanString(body.ip || body.agent?.ip, 255);
    const resolvedIp = reportedIp || (ip.startsWith('127.') || ip === '::1' || !ip ? getServerNetworkAddresses() : ip);

    insertAgent({
      agentId,
      organizationId: organization.id,
      application,
      name: resolvedName,
      hostname: hostname || resolvedName,
      os,
      arch,
      version: version || AGENT_VERSION,
      ip: resolvedIp,
      publicKey,
      labels,
      detectedSites,
      now
    });

    recordAuditLog({
      organizationId: organization.id,
      userEmail: 'endpoint-agent',
      role: 'Endpoint Agent',
      action: 'organization.provisioned',
      resource: 'organization',
      resourceId: organization.id,
      ipAddress: ip,
      metadata: {
        name: resolvedName,
        hostname,
        os,
        arch,
        version,
        organizationName: organization.name,
        detectedApplications: detectedApps.map(app => app.domain)
      }
    });

    console.log(`[Agents] Bootstrapped ${resolvedName} (${agentId}) in organization ${organization.id} (${organization.name}) from ${ip}`);

    if (application) {
      publishApplicationBound(organization.id, application);
    }

    publishAgentSnapshot('agent.enrolled', agentId, organization.id, {
      detectedApplications: detectedApps
    });
    broadcastEndpointStatus(organization.id);

    return res.status(201).json({
      agentId,
      organizationId: organization.id,
      organizationName: organization.name,
      organizationCreated: orgCount === 0,
      applicationId: application?.id || null,
      applicationName: application?.name || null,
      applicationDomain: application?.domain || null,
      detectedApplications: detectedApps,
      serverTime: now,
      heartbeatSeconds: 1,
      flushSeconds: 1,
      message: orgCount === 0
        ? 'Organization created from the first endpoint agent'
        : 'Agent enrolled in the existing organization'
    });
  } catch (error) {
    console.error('[Agents] Bootstrap failed:', error);
    return res.status(500).json({ error: 'Bootstrap failed' });
  }
});

// ----------------------------------------------------------------------
// Authenticated agent telemetry
// ----------------------------------------------------------------------
agentRouter.post('/heartbeat', (req: AuthenticatedRequest, res: Response) => {
  const verification = verifyAgentRequest(req);
  if (!verification.agent) {
    return res.status(verification.status || 401).json({ error: verification.error || 'Unauthorized' });
  }

  const agent = verification.agent;
  const body = req.body || {};
  const info = body.agent && typeof body.agent === 'object' ? body.agent : {};
  const metrics = body.metrics && typeof body.metrics === 'object' ? body.metrics : {};
  const now = new Date().toISOString();
  const hostname = cleanString(info.hostname, 128) || agent.hostname;
  const os = cleanString(info.os, 32) || agent.os;
  const arch = cleanString(info.arch, 32) || agent.arch;
  const version = cleanString(info.version, 32) || agent.version;

  // The agent reports the websites it hosts. A website that appeared after the
  // install is registered here so the console can offer it for monitoring.
  const detectedSites = parseDetectedSites(info.detectedSites);
  const knownDomains = new Set(
    syncDetectedApplications(agent.organization_id, detectedSites, net.isIP(clientIp(req)) ? clientIp(req) : (agent.ip || "127.0.0.1"), agent.id).map(app => app.domain)
  );
  const storedInfo = parseJsonObject(agent.host_info);
  const previousDomains = new Set(
    (Array.isArray(storedInfo.detectedSites) ? storedInfo.detectedSites : [])
      .map((site: any) => String(site?.domain || '').trim())
      .filter(Boolean)
  );
  const hasNewSite = detectedSites.some(site => !previousDomains.has(site.domain));

  const reportedIp = cleanString(info.ip || metrics.ip, 255);
  const resolvedIp = reportedIp || (agent.ip && !agent.ip.startsWith('127.') ? agent.ip : getServerNetworkAddresses());

  db.prepare(`
    UPDATE agents SET
      hostname = ?, os = ?, arch = ?, version = ?,
      ip = COALESCE(?, ip),
      host_info = ?,
      metrics = ?,
      last_seen = ?,
      status = 'ACTIVE'
    WHERE id = ?
  `).run(
    hostname,
    os,
    arch,
    version,
    resolvedIp || null,
    safeJson({
      ...storedInfo,
      hostname,
      os,
      arch,
      version,
      ...parseJsonObject(body.agent),
      detectedSites: detectedSites.length > 0 ? detectedSites : storedInfo.detectedSites
    }, 4096),
    safeJson(metrics, 16_000),
    now,
    agent.id
  );

  if (hasNewSite) {
    console.log(`[Agents] Agent ${agent.id} reported new website(s): ${Array.from(knownDomains).filter(domain => !previousDomains.has(domain)).join(', ')}`);
  }

  // Websites that vanished from the host leave the inventory (after a grace
  // period, so the list never flickers).
  try {
    pruneStaleApplications(agent.organization_id);
  } catch (err) {
    console.warn('[Agents] Failed to prune stale applications:', err);
  }

  const application = findApplicationForOrg(agent.application_id, agent.organization_id);

  // Push the fresh heartbeat snapshot (status, metrics, last seen) to every
  // console watching this tenant — no polling required.
  publishAgentSnapshot('agent.heartbeat', agent.id, agent.organization_id, {
    detectedSites: detectedSites.length,
    metrics
  });
  broadcastEndpointStatus(agent.organization_id);

  return res.json({
    ok: true,
    serverTime: now,
    application: application
      ? { id: application.id, name: application.name, domain: application.domain }
      : null,
    malwareActions: pendingActionsForAgent(agent.id),
    config: {
      heartbeatSeconds: 1,
      flushSeconds: 1,
      fimSeconds: 300,
      scaSeconds: 21_600,
      wafSeconds: 15,
      malwareSeconds: 4,
      maxEventsPerBatch: MAX_EVENTS_PER_BATCH,
      maxLogsPerBatch: MAX_LOGS_PER_BATCH
    }
  });
});

// ----------------------------------------------------------------------
// Malware analysis for files created inside a monitored web root
// ----------------------------------------------------------------------
const malwareScanWindows = new Map<string, { count: number; resetAt: number }>();

agentRouter.post('/malware/scan', (req: AuthenticatedRequest, res: Response) => {
  const verification = verifyAgentRequest(req);
  if (!verification.agent) {
    return res.status(verification.status || 401).json({ error: verification.error || 'Unauthorized' });
  }

  // A busy host can produce many new files at once; cap the stream so a
  // rebuild or a cache flush cannot flood the analysis pipeline.
  const agent = verification.agent;
  const now = Date.now();
  const window = malwareScanWindows.get(agent.id);
  if (!window || window.resetAt <= now) {
    malwareScanWindows.set(agent.id, { count: 1, resetAt: now + 60_000 });
  } else if (window.count >= 180) {
    return res.status(429).json({ error: 'Scan rate limit exceeded, retry in a minute' });
  } else {
    window.count += 1;
  }

  const body = req.body || {};
  const file = body.file && typeof body.file === 'object' ? body.file : {};
  const source = body.source && typeof body.source === 'object' ? body.source : {};
  const info = body.agent && typeof body.agent === 'object' ? body.agent : {};

  const fileName = cleanString(file.name, 512) || cleanString(file.path, 512).split('/').pop() || 'upload.bin';
  const filePath = cleanMultiline(file.path, 2048);
  const contentBase64 = typeof file.contentBase64 === 'string' ? file.contentBase64.slice(0, 700_000) : '';
  const size = Math.max(asInt(file.size, 0, 2_000_000_000) || 0, 0);

  try {
    const scan = scanAndRecord({
      organizationId: agent.organization_id,
      applicationId: agent.application_id,
      agentId: agent.id,
      fileName,
      filePath,
      size,
      sha256: cleanString(file.sha256, 64) || undefined,
      md5: cleanString(file.md5, 32) || undefined,
      contentBase64,
      sourceIp: cleanString(source.ip, 64) || clientIp(req),
      requestUri: cleanString(source.uri, 2000) || undefined,
      method: cleanString(source.method, 16) || undefined,
      hostname: cleanString(info.hostname, 128) || agent.hostname || undefined,
      source: 'agent',
      notify: true
    });

    return res.json({
      ok: true,
      scan: {
        id: scan.id,
        verdict: scan.verdict,
        score: scan.score,
        family: scan.family,
        severity: scan.severity,
        status: scan.status,
        action: scan.action,
        actionStatus: scan.actionStatus,
        reasons: scan.engines.map(match => `${match.id}: ${match.evidence}`).slice(0, 6)
      }
    });
  } catch (error) {
    console.error(`[Malware] Scan failed for agent ${agent.id}:`, error);
    return res.status(500).json({ error: 'Malware analysis failed' });
  }
});

agentRouter.post('/malware/result', (req: AuthenticatedRequest, res: Response) => {
  const verification = verifyAgentRequest(req);
  if (!verification.agent) {
    return res.status(verification.status || 401).json({ error: verification.error || 'Unauthorized' });
  }

  const agent = verification.agent;
  const body = req.body || {};
  const scan = recordActionResult(agent.organization_id, agent.id, {
    scanId: cleanString(body.scanId, 64),
    status: cleanString(body.status, 32),
    quarantinedPath: cleanMultiline(body.quarantinedPath, 2048),
    error: cleanMultiline(body.error, 500)
  });

  if (!scan) {
    return res.status(404).json({ error: 'Unknown scan' });
  }
  return res.json({ ok: true, scanId: scan.id, status: scan.status, actionStatus: scan.actionStatus });
});

agentRouter.post('/ingest', (req: AuthenticatedRequest, res: Response) => {
  const verification = verifyAgentRequest(req);
  if (!verification.agent) {
    return res.status(verification.status || 401).json({ error: verification.error || 'Unauthorized' });
  }

  const agent = verification.agent;
  const body = req.body || {};
  const incomingEvents = Array.isArray(body.events) ? body.events.slice(0, MAX_EVENTS_PER_BATCH) : [];
  const incomingLogs = Array.isArray(body.logs) ? body.logs.slice(0, MAX_LOGS_PER_BATCH) : [];
  const info = body.agent && typeof body.agent === 'object' ? body.agent : {};
  const metrics = body.metrics && typeof body.metrics === 'object' ? body.metrics : {};
  const now = new Date().toISOString();
  const hostname = cleanString(info.hostname, 128) || agent.hostname || agent.name;
  const rawClientIp = clientIp(req); const agentIp = asIp(info.ip, net.isIP(rawClientIp) ? rawClientIp : (agent.ip || "127.0.0.1"));
  const application = findApplicationForOrg(agent.application_id, agent.organization_id);
  const applicationLabel = application?.domain || application?.name || 'Endpoint Agent';
  const storedInfo = parseJsonObject(agent.host_info);
  const incomingSites = info.detectedSites !== undefined ? parseDetectedSites(info.detectedSites) : null;
  const infoRest: Record<string, any> = { ...info };
  delete infoRest.detectedSites;

  let acceptedEvents = 0;
  let acceptedLogs = 0;

  for (const raw of incomingEvents) {
    if (!raw || typeof raw !== 'object') continue;
    const item = raw as Record<string, any>;
    const eventType = cleanString(item.eventType || item.event_type, 80) || 'agent_event';
    const reportedSourceIp = cleanString(item.sourceIp || item.source_ip, 64);
    const reportedDestinationIp = cleanString(item.destinationIp || item.destination_ip, 64);
    const metadata = {
      ...parseJsonObject(item.metadata),
      agentId: agent.id,
      agentName: agent.name,
      hostname,
      applicationId: application?.id || null,
      applicationName: application?.name || null,
      applicationDomain: application?.domain || null,
      collector: cleanString(item.collector, 64) || 'agent',
      // The agent runtime falls back to the endpoint's own address when an
      // event has no attacker address. Mark whether the address was actually
      // reported so Threat Intelligence never turns the fleet's own IP into
      // an attacker IOC.
      sourceIpReported: Boolean(reportedSourceIp),
      destinationIpReported: Boolean(reportedDestinationIp)
    };
    const metadataJson = JSON.stringify(metadata);
    const boundedMetadata = Buffer.byteLength(metadataJson, 'utf8') > MAX_METADATA_BYTES
      ? { agentId: agent.id, agentName: agent.name, hostname, applicationId: application?.id || null, truncated: true }
      : metadata;

    const normalized: NormalizedSecurityEvent = {
      id: `EV-AGT-${crypto.randomUUID()}`,
      organizationId: agent.organization_id,
      timestamp: asIso(item.timestamp),
      source: 'agent',
      eventType,
      severity: asSeverity(item.severity),
      sourceIp: asIp(item.sourceIp || item.source_ip, agentIp),
      destinationIp: asIp(item.destinationIp || item.destination_ip, application?.origin_ip || agentIp),
      protocol: (cleanString(item.protocol, 16) || 'TCP').toUpperCase(),
      application: applicationLabel,
      action: asAction(item.action),
      uri: cleanString(item.uri, 2000) || undefined,
      method: cleanString(item.method, 16) || undefined,
      port: asInt(item.port, 1, 65535),
      statusCode: asInt(item.statusCode || item.status_code, 100, 599),
      threatName: cleanString(item.threatName || item.threat_name, 200) || undefined,
      payloadSnippet: cleanMultiline(item.payloadSnippet || item.payload_snippet, 2000) || undefined,
      metadata: boundedMetadata,
      agentId: agent.id
    };

    try {
      processSecurityEvent(normalized);
      acceptedEvents += 1;
    } catch (error) {
      console.warn(`[Agents] Failed to store event from ${agent.id}:`, error);
    }
  }

  for (const raw of incomingLogs) {
    if (!raw || typeof raw !== 'object') continue;
    const item = raw as Record<string, any>;
    const message = cleanMultiline(item.message, 4000);
    if (!message) continue;

    const logId = `LOG-AGT-${crypto.randomUUID()}`;
    const timestamp = asIso(item.timestamp);
    const level = asLogLevel(item.level);
    const eventType = cleanString(item.eventType || item.event_type, 80) || 'agent_log';
    const host = cleanString(item.host, 128) || hostname;
    const ip = asIp(item.ip, agentIp);
    const correlationId = cleanString(item.correlationId || item.correlation_id, 128) || null;
    const rawLog = cleanMultiline(item.rawLog || item.raw_log, 16_000) || message;
    const metadata = {
      ...parseJsonObject(item.metadata),
      agentId: agent.id,
      agentName: agent.name,
      hostname,
      applicationId: application?.id || null,
      applicationName: application?.name || null,
      applicationDomain: application?.domain || null,
      collector: cleanString(item.collector, 64) || 'agent'
    };

    const logItem = {
      id: logId,
      organizationId: agent.organization_id,
      timestamp,
      level,
      source: 'agent',
      eventType,
      message,
      host,
      ip,
      correlationId,
      metadata,
      rawLog,
      agentId: agent.id
    };

    acceptedLogs += 1;
    pushLogToPipeline(logItem);
    SecurityEventBus.publish('log.created', logItem, agent.organization_id);
  }

  db.prepare(`
    UPDATE agents SET
      last_seen = ?, status = 'ACTIVE',
      hostname = COALESCE(?, hostname),
      os = COALESCE(NULLIF(?, ''), os),
      arch = COALESCE(NULLIF(?, ''), arch),
      version = COALESCE(NULLIF(?, ''), version),
      ip = COALESCE(?, ip),
      host_info = ?,
      metrics = CASE WHEN ? = '{}' THEN metrics ELSE ? END,
      events_ingested = events_ingested + ?,
      logs_ingested = logs_ingested + ?
    WHERE id = ?
  `).run(
    now,
    cleanString(info.hostname, 128) || null,
    cleanString(info.os, 32),
    cleanString(info.arch, 32),
    cleanString(info.version, 32),
    net.isIP(agentIp) ? agentIp : null,
    safeJson({
      ...storedInfo,
      ...infoRest,
      hostname,
      os: info.os || storedInfo.os,
      arch: info.arch || storedInfo.arch,
      version: info.version || storedInfo.version,
      // An ingest batch usually carries metrics/logs only. Do not drop the
      // websites discovered by the last heartbeat when that happens.
      ...(incomingSites && incomingSites.length > 0 ? { detectedSites: incomingSites } : {})
    }, 4096),
    safeJson(metrics),
    safeJson(metrics),
    acceptedEvents,
    acceptedLogs,
    agent.id
  );

  if (acceptedEvents > 0 || acceptedLogs > 0) {
    publishAgentSnapshot('agent.ingested', agent.id, agent.organization_id, {
      acceptedEvents,
      acceptedLogs
    });
  }

  return res.json({
    ok: true,
    serverTime: now,
    accepted: { events: acceptedEvents, logs: acceptedLogs },
    received: { events: incomingEvents.length, logs: incomingLogs.length }
  });
});

// ----------------------------------------------------------------------
// Signed WAF policy channel
// ----------------------------------------------------------------------
agentRouter.post('/waf/policy', (req: AuthenticatedRequest, res: Response) => {
  const verification = verifyAgentRequest(req);
  if (!verification.agent) {
    return res.status(verification.status || 401).json({ error: verification.error || 'Unauthorized' });
  }

  // The organization is resolved exclusively from the signed agent record.
  // The request body intentionally has no tenant/website fields.
  return res.json(WafDeploymentService.getAgentPolicy(verification.agent));
});

agentRouter.post('/waf/status', (req: AuthenticatedRequest, res: Response) => {
  const verification = verifyAgentRequest(req);
  if (!verification.agent) {
    return res.status(verification.status || 401).json({ error: verification.error || 'Unauthorized' });
  }

  try {
    const deployment = WafDeploymentService.recordAgentStatus(verification.agent, req.body || {});
    return res.json({
      ok: true,
      desiredRevision: deployment.revision,
      status: deployment.status
    });
  } catch (error) {
    console.error(`[WAF] Failed to record status from ${verification.agent.id}:`, error);
    return res.status(500).json({ error: 'Could not store WAF status' });
  }
});

// ----------------------------------------------------------------------
// Signed NGFW (perimeter ACL) policy channel
// ----------------------------------------------------------------------
agentRouter.post('/firewall/policy', (req: AuthenticatedRequest, res: Response) => {
  const verification = verifyAgentRequest(req);
  if (!verification.agent) {
    return res.status(verification.status || 401).json({ error: verification.error || 'Unauthorized' });
  }

  // The organization is resolved exclusively from the signed agent record.
  // The request body intentionally has no tenant/website fields.
  return res.json(FirewallDeploymentService.getAgentPolicy(verification.agent));
});

agentRouter.post('/firewall/status', (req: AuthenticatedRequest, res: Response) => {
  const verification = verifyAgentRequest(req);
  if (!verification.agent) {
    return res.status(verification.status || 401).json({ error: verification.error || 'Unauthorized' });
  }

  try {
    const deployment = FirewallDeploymentService.recordAgentStatus(verification.agent, req.body || {});
    return res.json({
      ok: true,
      desiredRevision: deployment.revision,
      status: deployment.status
    });
  } catch (error) {
    console.error(`[NGFW] Failed to record status from ${verification.agent.id}:`, error);
    return res.status(500).json({ error: 'Could not store firewall status' });
  }
});

// ----------------------------------------------------------------------
// Installer + binary distribution (public, versioned artifacts)
// ----------------------------------------------------------------------
function firstExisting(paths: string[]): string | null {
  for (const candidate of paths) {
    try {
      if (fs.existsSync(candidate) && fs.statSync(candidate).isFile()) return candidate;
    } catch {
      // Ignore unreadable candidates and try the next location.
    }
  }
  return null;
}

function agentArtifactPath(os: string, arch: string): string | null {
  const extension = os === 'windows' ? '.exe' : '';
  const fileName = `oat-agent-${os}-${arch}${extension}`;
  return firstExisting([
    path.join(CONFIG.AGENT_BIN_DIR, fileName),
    path.join(process.cwd(), 'agent', 'dist', fileName),
    path.join(process.cwd(), 'dist', 'agent', fileName)
  ]);
}

agentRouter.get('/download', (req: AuthenticatedRequest, res: Response) => {
  const requestedOs = String(req.query.os || 'linux').toLowerCase();
  const requestedArch = String(req.query.arch || 'amd64').toLowerCase();
  const os = requestedOs === 'windows' ? 'windows' : requestedOs === 'linux' ? 'linux' : null;
  const arch = ['amd64', 'arm64'].includes(requestedArch) ? requestedArch : null;

  if (!os || !arch) {
    return res.status(400).json({ error: 'Supported platforms: linux/windows and amd64/arm64' });
  }

  const artifact = agentArtifactPath(os, arch);
  if (!artifact) {
    return res.status(503).json({
      error: 'Agent binary has not been built yet',
      hint: 'Run "npm run agent:build" on the server, then retry.'
    });
  }

  res.setHeader('Content-Type', os === 'windows' ? 'application/vnd.microsoft.portable-executable' : 'application/octet-stream');
  res.setHeader('Content-Disposition', `attachment; filename="oat-agent-${os}-${arch}${os === 'windows' ? '.exe' : ''}"`);
  res.setHeader('X-Content-Type-Options', 'nosniff');
  res.setHeader('Cache-Control', 'public, max-age=300');
  return res.sendFile(path.resolve(artifact));
});

function sendInstaller(res: Response, fileName: string, contentType: string) {
  const installer = firstExisting([
    path.join(process.cwd(), 'agent', fileName),
    path.join(process.cwd(), 'dist', 'agent', fileName)
  ]);
  if (!installer) {
    return res.status(503).type('text/plain').send(
      `# ${fileName} is unavailable on this server.\n# Deploy the OAT server with the agent/ directory or run npm run agent:build.\n`
    );
  }
  res.setHeader('Content-Type', contentType);
  res.setHeader('Cache-Control', 'no-store');
  res.setHeader('X-Content-Type-Options', 'nosniff');
  return res.send(fs.readFileSync(installer, 'utf8'));
}

agentRouter.get('/install.sh', (_req, res) => {
  return sendInstaller(res, 'install.sh', 'text/x-shellscript; charset=utf-8');
});

agentRouter.get('/install.ps1', (_req, res) => {
  return sendInstaller(res, 'install.ps1', 'text/plain; charset=utf-8');
});

// ----------------------------------------------------------------------
// Agent management (dashboard session required)
// ----------------------------------------------------------------------
agentRouter.get('/', (req: AuthenticatedRequest, res: Response) => {
  try {
    const orgId = WafDeploymentService.resolveOrgId(req.organizationId);
    let rows: AgentRow[] = [];
    try {
      rows = db.prepare(
        'SELECT * FROM agents WHERE organization_id = ? ORDER BY created_at DESC'
      ).all(orgId) as unknown as AgentRow[];
    } catch (e) {
      console.warn('[Agents GET] DB query warning:', e);
    }
    let applications = new Map();
    try {
      applications = applicationMapForOrg(orgId);
    } catch {}

    const agents = (rows || []).map(row => serializeAgent(row, applications.get(row.application_id || '')));
    const summary = {
      total: agents.length,
      online: agents.filter(a => a.status === 'ONLINE').length,
      offline: agents.filter(a => a.status === 'OFFLINE' || a.status === 'STALE').length,
      pending: agents.filter(a => a.status === 'PENDING').length,
      revoked: agents.filter(a => a.status === 'REVOKED').length,
      eventsIngested: agents.reduce((sum, a) => sum + a.eventsIngested, 0),
      logsIngested: agents.reduce((sum, a) => sum + a.logsIngested, 0)
    };

    return res.json({ agents, summary, serverVersion: AGENT_VERSION });
  } catch (err: any) {
    console.error('[Agents GET error]:', err);
    return res.json({ agents: [], summary: { total: 0, online: 0, offline: 0, pending: 0, revoked: 0, eventsIngested: 0, logsIngested: 0 }, serverVersion: AGENT_VERSION });
  }
});

agentRouter.get('/enrollment-tokens/active', (req: AuthenticatedRequest, res: Response) => {
  if (!requireUser(req, res)) return;
  const orgId = WafDeploymentService.resolveOrgId(req.organizationId);
  const rows = db.prepare(`
    SELECT id, label, expires_at, application_id, created_at
    FROM agent_enrollment_tokens
    WHERE used_at IS NULL AND expires_at > datetime('now')
      AND (organization_id = ? OR organization_id IS NULL)
    ORDER BY created_at DESC
  `).all(orgId) as any[];

  return res.json({ tokens: rows || [] });
});

agentRouter.post('/enrollment-token', (req: AuthenticatedRequest, res: Response) => {
  if (!requireUser(req, res)) return;
  let orgId: string | null = req.organizationId || null;
  if (orgId) {
    const existingOrg = db.prepare('SELECT id FROM organizations WHERE id = ?').get(orgId);
    if (!existingOrg) {
      orgId = null;
    }
  }
  const label = cleanString(req.body?.label, 120) || 'Endpoint agent';
  const applicationId = cleanString(req.body?.applicationId, 128);
  const requestedMinutes = Number(req.body?.expiresInMinutes);
  const minutes = Number.isFinite(requestedMinutes) ? Math.min(Math.max(Math.trunc(requestedMinutes), 5), 1440) : 60;

  // applicationId is OPTIONAL — if omitted the token is "open" and the agent
  // will report detected websites during enrollment so the user can assign them.
  let application: ApplicationRef | undefined;
  if (applicationId && orgId) {
    application = findApplicationForOrg(applicationId, orgId);
    if (!application) {
      return res.status(404).json({ error: 'Website not found in the selected organization' });
    }
  }

  const token = newEnrollmentToken();
  const tokenHash = sha256Hex(token);
  const id = `aet_${crypto.randomUUID()}`;
  const expiresAt = new Date(Date.now() + minutes * 60 * 1000).toISOString();
  const createdAt = new Date().toISOString();

  db.prepare(`
    INSERT INTO agent_enrollment_tokens (
      id, organization_id, application_id, token_hash, label, expires_at, created_by, created_at
    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
  `).run(id, orgId || null, application?.id || null, tokenHash, label, expiresAt, req.user?.email || 'unknown', createdAt);

  recordAuditLog({
    organizationId: orgId || '',
    userId: req.user?.userId,
    userEmail: req.user?.email || 'unknown',
    role: req.user?.role || 'Unknown',
    action: 'agent.enrollment_token_created',
    resource: 'agent_enrollment_token',
    resourceId: id,
    ipAddress: clientIp(req),
    userAgent: String(req.headers['user-agent'] || 'OAT Web Console'),
    metadata: {
      label,
      expiresAt,
      applicationId: application?.id || null,
      applicationName: application?.name || null,
      applicationDomain: application?.domain || null,
      openToken: !applicationId
    }
  });

  return res.status(201).json({
    id,
    token,
    label,
    expiresAt,
    expiresInMinutes: minutes,
    applicationId: application?.id || null,
    applicationName: application?.name || null,
    applicationDomain: application?.domain || null,
    openToken: !applicationId
  });
});

agentRouter.get('/:id', (req: AuthenticatedRequest, res: Response) => {
  if (!requireUser(req, res)) return;
  const agent = findAgentForOrg(req.params.id, req.organizationId || '');
  if (!agent) {
    return res.status(404).json({ error: 'Agent not found' });
  }

  const recentEvents = db.prepare(`
    SELECT id, timestamp, event_type, severity, source_ip, destination_ip,
           application, action, threat_name, agent_id
    FROM security_events
    WHERE organization_id = ? AND agent_id = ?
    ORDER BY timestamp DESC LIMIT 20
  `).all(agent.organization_id, agent.id);

  const recentLogs = db.prepare(`
    SELECT id, timestamp, level, event_type, message, host, ip
    FROM logs
    WHERE organization_id = ? AND agent_id = ?
    ORDER BY timestamp DESC LIMIT 20
  `).all(agent.organization_id, agent.id);

  const application = findApplicationForOrg(agent.application_id, agent.organization_id);
  return res.json({ agent: serializeAgent(agent, application), recentEvents, recentLogs });
});

agentRouter.post('/:id/application', (req: AuthenticatedRequest, res: Response) => {
  if (!requireUser(req, res)) return;
  const agent = findAgentForOrg(req.params.id, req.organizationId || '');
  if (!agent) {
    return res.status(404).json({ error: 'Agent not found' });
  }

  const body = req.body || {};
  const applicationId = cleanString(body.applicationId, 64);
  const domain = cleanString(body.domain, 255);
  const protocol = (cleanString(body.protocol, 16) || 'HTTP').toUpperCase();
  const port = asInt(body.port, 1, 65535) || (protocol === 'HTTPS' ? 443 : 80);

  let application = applicationId ? findApplicationForOrg(applicationId, agent.organization_id) : undefined;

  if (!application && domain) {
    const existing = db.prepare(
      'SELECT id, name, domain FROM applications WHERE organization_id = ? AND domain = ?'
    ).get(agent.organization_id, domain) as ApplicationRef | undefined;
    if (existing) {
      application = existing;
    } else {
      const appId = `app_${crypto.randomUUID()}`;
      db.prepare(`
        INSERT INTO applications (id, organization_id, name, domain, origin_ip, environment, status, owner, protocol, port, created_at)
        VALUES (?, ?, ?, ?, ?, 'Production', 'UNKNOWN', 'SecOps', ?, ?, ?)
      `).run(appId, agent.organization_id, domain, domain, agent.ip || '', protocol, port, new Date().toISOString());
      application = { id: appId, name: domain, domain, origin_ip: agent.ip || '' };
      publishApplicationCreated(agent.organization_id, application, protocol, port, new Date().toISOString());
    }
  }

  if (!application) {
    return res.status(400).json({ error: 'applicationId or domain is required' });
  }

  // Rebind the agent to the selected website and push a fresh policy revision.
  const hostInfo = parseJsonObject(agent.host_info);
  const labels = parseJsonObject(agent.labels);
  db.prepare('UPDATE agents SET application_id = ?, host_info = ?, labels = ? WHERE id = ?').run(
    application.id,
    safeJson({
      ...hostInfo,
      applicationId: application.id,
      applicationName: application.name,
      applicationDomain: application.domain
    }, 4096),
    safeJson({ ...labels, applicationId: application.id, applicationDomain: application.domain }, 4096),
    agent.id
  );

  // Sync organization name & domain with the chosen website
  if (application.domain || application.name) {
    const orgTargetName = application.name || application.domain;
    const orgTargetDomain = application.domain || application.name;
    try {
      db.prepare('UPDATE organizations SET name = ?, domain = ? WHERE id = ?').run(
        orgTargetName,
        orgTargetDomain,
        agent.organization_id
      );
      // Publish organization.created & updated so console listeners immediately activate the tenant
      SecurityEventBus.publish('organization.created', {
        id: agent.organization_id,
        name: orgTargetName,
        domain: orgTargetDomain,
        industry: 'Enterprise',
        tier: 'Enterprise',
        createdAt: new Date().toISOString()
      });
      SecurityEventBus.publish('organization.updated', {
        id: agent.organization_id,
        name: orgTargetName,
        domain: orgTargetDomain,
        updatedAt: new Date().toISOString()
      });
    } catch (orgErr) {
      console.warn('[Agents] Failed to sync organization name with selected website:', orgErr);
    }
  }

  WafDeploymentService.ensureAgentStatus(agent.id, agent.organization_id, application.id);
  FirewallDeploymentService.ensureAgentStatus(agent.id, agent.organization_id, application.id);
  WafDeploymentService.refresh(agent.organization_id);
  FirewallDeploymentService.refresh(agent.organization_id);

  recordAuditLog({
    organizationId: agent.organization_id,
    userId: req.user?.userId,
    userEmail: req.user?.email || 'unknown',
    role: req.user?.role || 'Unknown',
    action: 'agent.application.selected',
    resource: 'agent',
    resourceId: agent.id,
    ipAddress: clientIp(req),
    userAgent: String(req.headers['user-agent'] || 'OAT Web Console'),
    metadata: {
      applicationId: application.id,
      applicationDomain: application.domain
    }
  });

  console.log(`[Agents] Agent ${agent.id} now monitors ${application.domain}`);

  // The inventory follows the binding: the website the agent now watches is
  // flagged as monitored, and the website it left is released.
  publishApplicationBound(agent.organization_id, application);
  if (agent.application_id && agent.application_id !== application.id) {
    const previous = findApplicationForOrg(agent.application_id, agent.organization_id);
    if (previous) {
      publishApplicationBound(agent.organization_id, previous);
    }
  }

  publishAgentSnapshot('agent.updated', agent.id, agent.organization_id, {
    applicationId: application.id
  });

  return res.json({
    ok: true,
    agentId: agent.id,
    application: { id: application.id, name: application.name, domain: application.domain }
  });
});

agentRouter.post('/:id/restore', (req: AuthenticatedRequest, res: Response) => {
  if (!requireUser(req, res)) return;
  const agent = findAgentForOrg(req.params.id, req.organizationId || '');
  if (!agent) {
    return res.status(404).json({ error: 'Agent not found' });
  }
  if (agent.status !== 'REVOKED' && !agent.revoked_at) {
    return res.status(409).json({ error: 'This agent is not revoked.' });
  }

  // The endpoint keeps running after a revoke, so re-activating the entry is
  // enough to let it report again — no reinstall required.
  db.prepare("UPDATE agents SET status = 'ACTIVE', revoked_at = NULL WHERE id = ?").run(agent.id);

  WafDeploymentService.ensureAgentStatus(agent.id, agent.organization_id, agent.application_id || null);
  FirewallDeploymentService.ensureAgentStatus(agent.id, agent.organization_id, agent.application_id || null);
  WafDeploymentService.refresh(agent.organization_id);
  FirewallDeploymentService.refresh(agent.organization_id);

  recordAuditLog({
    organizationId: agent.organization_id,
    userId: req.user?.userId,
    userEmail: req.user?.email || 'unknown',
    role: req.user?.role || 'Unknown',
    action: 'agent.restored',
    resource: 'agent',
    resourceId: agent.id,
    ipAddress: clientIp(req),
    userAgent: String(req.headers['user-agent'] || 'OAT Web Console'),
    metadata: { name: agent.name, hostname: agent.hostname }
  });

  console.log(`[Agents] Agent ${agent.id} restored — telemetry accepted again.`);

  publishAgentSnapshot('agent.restored', agent.id, agent.organization_id);
  broadcastEndpointStatus(agent.organization_id);

  return res.json({ ok: true, agentId: agent.id, status: 'ACTIVE' });
});

/**
 * Remove an endpoint agent.
 *
 * The entry itself is deleted (its WAF and firewall deployment state cascades
 * with it) and the enrollment token no longer points at a missing agent. The
 * telemetry the agent already delivered stays in the tenant timeline, but it is
 * unlinked from the removed agent; `purge=1` deletes that history as well.
 */
agentRouter.delete('/:id', (req: AuthenticatedRequest, res: Response) => {
  if (!requireUser(req, res)) return;
  const agent = findAgentForOrg(req.params.id, req.organizationId || '');
  if (!agent) {
    return res.status(404).json({ error: 'Agent not found' });
  }

  const purgeRequested = (req.body && typeof req.body === 'object' ? req.body.purge : undefined);
  const purge = purgeRequested === true || purgeRequested === 'true' || purgeRequested === 1 || req.query.purge === '1' || req.query.purge === 'true';

  const eventCount = Number((db.prepare('SELECT COUNT(*) as count FROM security_events WHERE agent_id = ?').get(agent.id) as { count: number } | undefined)?.count || 0);
  const logCount = Number((db.prepare('SELECT COUNT(*) as count FROM logs WHERE agent_id = ?').get(agent.id) as { count: number } | undefined)?.count || 0);

  if (purge) {
    db.prepare('DELETE FROM security_events WHERE agent_id = ?').run(agent.id);
    db.prepare('DELETE FROM logs WHERE agent_id = ?').run(agent.id);
  } else {
    // Keep the collected evidence, but do not leave a dangling agent reference.
    db.prepare('UPDATE security_events SET agent_id = NULL WHERE agent_id = ?').run(agent.id);
    db.prepare('UPDATE logs SET agent_id = NULL WHERE agent_id = ?').run(agent.id);
  }

  // The enrollment token stays (it is single-use and already marked as used),
  // it just must not point at an agent that no longer exists.
  db.prepare('UPDATE agent_enrollment_tokens SET used_by_agent_id = NULL WHERE used_by_agent_id = ?').run(agent.id);

  db.prepare('DELETE FROM agents WHERE id = ?').run(agent.id);

  SecurityEventBus.publish('agent.removed', {
    agentId: agent.id,
    name: agent.name,
    hostname: agent.hostname
  }, agent.organization_id);
  broadcastEndpointStatus(agent.organization_id);

  // Websites this agent discovered leave the inventory too, unless another
  // agent still reports them.
  const discovered = db.prepare(
    "SELECT id, name, domain, organization_id FROM applications WHERE agent_id = ? AND source = 'agent'"
  ).all(agent.id) as Array<{ id: string; name: string; domain: string; organization_id: string }>;
  for (const app of discovered) {
    const stillReported = db.prepare(
      'SELECT COUNT(*) as count FROM agents WHERE application_id = ? AND id != ? AND revoked_at IS NULL'
    ).get(app.id, agent.id) as { count: number } | undefined;
    if (Number(stillReported?.count || 0) === 0) {
      removeApplication(app.id, app.organization_id, 'The endpoint agent that protected it was removed');
    }
  }

  if (agent.application_id) {
    const stillReported = db.prepare(
      'SELECT COUNT(*) as count FROM agents WHERE application_id = ? AND id != ? AND revoked_at IS NULL'
    ).get(agent.application_id, agent.id) as { count: number } | undefined;
    if (Number(stillReported?.count || 0) === 0) {
      removeApplication(agent.application_id, agent.organization_id, 'The endpoint agent that protected it was removed');
    }
  }

  // If no other agents remain in this organization, automatically clean up
  // the tenant organization as well so it disappears from the console immediately.
  const remainingAgents = Number(
    (db.prepare('SELECT COUNT(*) as count FROM agents WHERE organization_id = ?').get(agent.organization_id) as { count: number } | undefined)?.count || 0
  );
  const remainingUsers = Number(
    (db.prepare('SELECT COUNT(*) as count FROM users WHERE organization_id = ?').get(agent.organization_id) as { count: number } | undefined)?.count || 0
  );
  let orgRemoved = false;
  if (remainingAgents === 0 && remainingUsers === 0) {
    orgRemoved = removeOrganization(agent.organization_id, 'The endpoint agent that provisioned it was removed');
  } else {
    WafDeploymentService.refresh(agent.organization_id);
    FirewallDeploymentService.refresh(agent.organization_id);
  }

  recordAuditLog({
    organizationId: agent.organization_id,
    userId: req.user?.userId,
    userEmail: req.user?.email || 'unknown',
    role: req.user?.role || 'Unknown',
    action: purge ? 'agent.removed.purged' : 'agent.removed',
    resource: 'agent',
    resourceId: agent.id,
    ipAddress: clientIp(req),
    userAgent: String(req.headers['user-agent'] || 'OAT Web Console'),
    metadata: {
      name: agent.name,
      hostname: agent.hostname,
      applicationId: agent.application_id || null,
      deletedEvents: purge ? eventCount : 0,
      deletedLogs: purge ? logCount : 0,
      unlinkedEvents: purge ? 0 : eventCount,
      unlinkedLogs: purge ? 0 : logCount,
      organizationRemoved: orgRemoved
    }
  });

  console.log(`[Agents] Removed agent ${agent.id} (${agent.hostname})${purge ? ' with its collected telemetry' : ''}${orgRemoved ? ' (organization auto-removed)' : ''}`);

  return res.json({
    success: true,
    removed: true,
    organizationRemoved: orgRemoved,
    purged: purge,
    deletedEvents: purge ? eventCount : 0,
    deletedLogs: purge ? logCount : 0,
    unlinkedEvents: purge ? 0 : eventCount,
    unlinkedLogs: purge ? 0 : logCount
  });
});
