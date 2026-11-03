import { Router, Response } from 'express';
import { db } from '../database/db';
import { AuthenticatedRequest, requireRole } from '../middleware/auth';
import { collectSystemHealth } from '../services/systemHealthService';

export const superAdminRouter = Router();

// Helper to hash passwords in Super Admin operations
import { hashPassword } from '../auth/jwt';

// Strictly guard all endpoints in this router for 'Super Admin' or 'Admin' role
superAdminRouter.use(requireRole('Super Admin', 'Admin'));

/** Validates the optional SOC response tier assigned to an operator. */
function normalizeSocTierInput(value: unknown): string | null {
  const tier = String(value || '').trim().toUpperCase();
  return tier === 'L1' || tier === 'L2' || tier === 'L3' ? tier : null;
}

function parseJsonSafe(val: unknown): Record<string, any> {
  if (!val) return {};
  try {
    return typeof val === 'string' ? JSON.parse(val) : (val as Record<string, any>);
  } catch {
    return {};
  }
}

function computedAgentStatus(row: any): 'ONLINE' | 'OFFLINE' | 'STALE' | 'PENDING' | 'REVOKED' {
  if (row.revoked_at || row.status === 'REVOKED') return 'REVOKED';
  if (!row.last_seen) return 'PENDING';
  const lastSeen = Date.parse(row.last_seen.includes('T') ? row.last_seen : `${row.last_seen.replace(' ', 'T')}Z`);
  if (!Number.isFinite(lastSeen)) return 'PENDING';
  const diff = Date.now() - lastSeen;
  if (diff < 2 * 60 * 1000) return 'ONLINE';
  if (diff < 7 * 24 * 60 * 60 * 1000) return 'OFFLINE';
  return 'STALE';
}

/**
 * Global Super Admin Observability Overview:
 * Aggregates all tenants, fleet agents, recent cross-tenant security events,
 * and system health for pure monitoring and executive oversight.
 */
superAdminRouter.get('/overview', (_req: AuthenticatedRequest, res: Response) => {
  try {
    // 1. Tenants / Organizations with sub-resource counters
    const organizations = db.prepare(`
      SELECT o.id, o.name, o.domain, o.industry, o.tier, o.created_at,
        (SELECT COUNT(*) FROM agents a WHERE a.organization_id = o.id) as agent_count,
        (SELECT COUNT(*) FROM applications app WHERE app.organization_id = o.id) as app_count,
        (SELECT COUNT(*) FROM security_events e WHERE e.organization_id = o.id) as event_count,
        (SELECT COUNT(*) FROM logs l WHERE l.organization_id = o.id) as log_count
      FROM organizations o
      ORDER BY o.name ASC
    `).all() as any[];

    // 2. Global Fleet Agents across all organizations
    const agentRows = db.prepare(`
      SELECT a.*, o.name as organization_name, o.domain as organization_domain,
             app.name as application_name, app.domain as application_domain
      FROM agents a
      LEFT JOIN organizations o ON a.organization_id = o.id
      LEFT JOIN applications app ON a.application_id = app.id
      ORDER BY a.last_seen DESC
    `).all() as any[];

    const agents = agentRows.map(row => {
      const hostInfo = parseJsonSafe(row.host_info);
      const metrics = parseJsonSafe(row.metrics);
      const labels = parseJsonSafe(row.labels);
      const status = computedAgentStatus(row);
      return {
        id: row.id,
        organizationId: row.organization_id,
        organizationName: row.organization_name || 'Unassigned Tenant',
        organizationDomain: row.organization_domain || '',
        name: row.name,
        hostname: row.hostname || hostInfo.hostname || row.name,
        os: row.os || hostInfo.os || '',
        arch: row.arch || hostInfo.arch || '',
        version: row.version || hostInfo.version || '',
        ip: row.ip || '',
        status,
        lastSeen: row.last_seen,
        createdAt: row.created_at,
        eventsIngested: Number(row.events_ingested) || 0,
        logsIngested: Number(row.logs_ingested) || 0,
        applicationId: row.application_id || null,
        applicationName: row.application_name || null,
        applicationDomain: row.application_domain || null,
        metrics,
        hostInfo,
        labels
      };
    });

    // 3. Cross-Tenant Security Events (most recent 50)
    const recentEvents = db.prepare(`
      SELECT e.id, e.organization_id, e.timestamp, e.source, e.event_type, e.severity, e.source_ip,
             e.destination_ip, e.application, e.action, e.threat_name, e.agent_id, e.uri, e.method,
             e.status_code, e.payload_snippet, e.metadata,
             o.name as organization_name
      FROM security_events e
      LEFT JOIN organizations o ON e.organization_id = o.id
      ORDER BY e.timestamp DESC
      LIMIT 50
    `).all() as any[];

    // 4. Global Core Defense & Infrastructure Health
    const systemHealth = collectSystemHealth();

    // 5. Aggregated Summary Counters
    const totalTenants = organizations.length;
    const totalAgents = agents.length;
    const onlineAgents = agents.filter(a => a.status === 'ONLINE').length;
    const offlineAgents = agents.filter(a => a.status === 'OFFLINE' || a.status === 'STALE').length;
    const totalApplications = Number(
      (db.prepare('SELECT COUNT(*) as count FROM applications').get() as any)?.count || 0
    );
    const totalSecurityEvents = Number(
      (db.prepare('SELECT COUNT(*) as count FROM security_events').get() as any)?.count || 0
    );
    const totalLogs = Number(
      (db.prepare('SELECT COUNT(*) as count FROM logs').get() as any)?.count || 0
    );
    const oneDayAgo = new Date(Date.now() - 24 * 3600 * 1000).toISOString();
    const blockedEvents24h = Number(
      (db.prepare(`
        SELECT COUNT(*) as count FROM security_events
        WHERE action IN ('BLOCK', 'DROP', 'DENY')
          AND timestamp >= ?
      `).get(oneDayAgo) as any)?.count || 0
    );
    const criticalThreats24h = Number(
      (db.prepare(`
        SELECT COUNT(*) as count FROM security_events
        WHERE severity IN ('Critical', 'High')
          AND timestamp >= ?
      `).get(oneDayAgo) as any)?.count || 0
    );

    return res.json({
      summary: {
        totalTenants,
        totalAgents,
        onlineAgents,
        offlineAgents,
        totalApplications,
        totalSecurityEvents,
        totalLogs,
        blockedEvents24h,
        criticalThreats24h,
        systemUptimeSeconds: Math.floor(process.uptime()),
        timestamp: new Date().toISOString()
      },
      organizations,
      agents,
      recentEvents,
      systemHealth
    });
  } catch (error) {
    console.error('[SuperAdmin] Failed to build overview:', error);
    return res.status(500).json({ error: String(error) });
  }
});

/**
 * Filtered Cross-Tenant Security Events stream for Super Admin monitoring
 */
superAdminRouter.get('/events', (req: AuthenticatedRequest, res: Response) => {
  try {
    const limit = Math.min(Math.max(Number(req.query.limit) || 50, 10), 200);
    const severity = req.query.severity ? String(req.query.severity) : null;
    const action = req.query.action ? String(req.query.action) : null;
    const organizationId = req.query.organizationId ? String(req.query.organizationId) : null;

    let query = `
      SELECT e.id, e.organization_id, e.timestamp, e.source, e.event_type, e.severity, e.source_ip,
             e.destination_ip, e.application, e.action, e.threat_name, e.agent_id, e.uri, e.method,
             e.status_code, e.payload_snippet, e.metadata,
             o.name as organization_name
      FROM security_events e
      LEFT JOIN organizations o ON e.organization_id = o.id
      WHERE 1=1
    `;
    const params: any[] = [];

    if (severity) {
      query += ' AND e.severity = ?';
      params.push(severity);
    }
    if (action) {
      query += ' AND e.action = ?';
      params.push(action);
    }
    if (organizationId) {
      query += ' AND e.organization_id = ?';
      params.push(organizationId);
    }

    query += ' ORDER BY e.timestamp DESC LIMIT ?';
    params.push(limit);

    const events = db.prepare(query).all(...params) as any[];
    return res.json({ events });
  } catch (error) {
    console.error('[SuperAdmin] Failed to query events:', error);
    return res.status(500).json({ error: 'Failed to query global events' });
  }
});

/**
 * Super Admin Management: Users & Roles across all organizations
 */
superAdminRouter.get('/users', (_req: AuthenticatedRequest, res: Response) => {
  try {
    const users = db.prepare(`
      SELECT u.id, u.organization_id, u.name, u.email, u.username, u.role, u.soc_tier, u.mfa_enabled, u.last_login, u.created_at,
             o.name as organization_name
      FROM users u
      LEFT JOIN organizations o ON u.organization_id = o.id
      ORDER BY u.created_at DESC
    `).all();
    return res.json({ users });
  } catch (err: any) {
    return res.status(500).json({ error: err.message || 'Failed to list users' });
  }
});

superAdminRouter.post('/users', async (req: AuthenticatedRequest, res: Response) => {
  try {
    const { name, email, username, password, role, organizationId, socTier } = req.body || {};
    if (!name || !email || !password || !role) {
      return res.status(400).json({ error: 'Name, email, password, and role are required' });
    }
    const cleanEmail = String(email).trim().toLowerCase();
    const cleanUsername = username ? String(username).trim().toLowerCase() : cleanEmail.split('@')[0];
    const cleanSocTier = normalizeSocTierInput(socTier);
    
    // Check duplication
    const existing = db.prepare('SELECT id FROM users WHERE email = ? OR username = ?').get(cleanEmail, cleanUsername) as any;
    if (existing) {
      return res.status(409).json({ error: 'Email or username already in use' });
    }

    const userId = `usr_${Date.now()}_${Math.random().toString(36).substring(2, 7)}`;
    const hashedPassword = await hashPassword(String(password));
    let targetOrgId = organizationId;

    if (!targetOrgId) {
      // Auto-provision a dedicated isolated workspace for this user so they are NOT mixed with other users
      const randomSuffix = crypto.randomUUID().substring(0, 6);
      targetOrgId = `org_${cleanUsername}_${randomSuffix}`;
      const orgName = `${name}'s Workspace`;
      const orgDomain = cleanEmail.includes('@') ? cleanEmail.split('@')[1] : `${cleanUsername}.internal`;

      db.prepare(`
        INSERT INTO organizations (id, name, domain, industry, tier, created_at)
        VALUES (?, ?, ?, 'Enterprise', 'Standard', UTC_TIMESTAMP())
      `).run(targetOrgId, orgName, orgDomain);

      try {
        db.prepare(`
          INSERT INTO waf_policy (
            id, organization_id, engine_enabled, mode, rate_limit_requests, rate_limit_window_s,
            ip_allowlist, ip_blocklist, geo_block_countries, bot_protection_enabled, sync_to_server, revision, server_status
          ) VALUES (?, ?, 1, 'block', 100, 10, '[]', '[]', '[]', 1, 1, 1, 'ACTIVE')
        `).run(`waf_pol_${targetOrgId}`, targetOrgId);
      } catch (e) {
        console.warn('[SuperAdmin Create User] Waf policy auto-init warning:', e);
      }
    }

    db.prepare(`
      INSERT INTO users (id, organization_id, name, email, username, password_hash, role, soc_tier, mfa_enabled, created_at)
      VALUES (?, ?, ?, ?, ?, ?, ?, ?, 1, UTC_TIMESTAMP())
    `).run(userId, targetOrgId, name, cleanEmail, cleanUsername, hashedPassword, role, cleanSocTier);

    return res.status(201).json({
      ok: true,
      user: {
        id: userId,
        name,
        email: cleanEmail,
        username: cleanUsername,
        role,
        socTier: cleanSocTier,
        organizationId: targetOrgId
      }
    });
  } catch (err: any) {
    return res.status(500).json({ error: err.message || 'Failed to create user' });
  }
});

/**
 * Update an operator's SOC response scope. A null/empty value removes the
 * restriction and lets the account see every tier.
 */
superAdminRouter.put('/users/:id/soc-tier', (req: AuthenticatedRequest, res: Response) => {
  try {
    const body = req.body || {};
    if (!Object.prototype.hasOwnProperty.call(body, 'socTier')) {
      return res.status(400).json({ error: 'socTier is required (L1, L2, L3, or null)' });
    }
    const raw = body.socTier;
    const cleanSocTier = raw === null || raw === '' ? null : normalizeSocTierInput(raw);
    if (raw !== null && raw !== '' && !cleanSocTier) {
      return res.status(400).json({ error: 'Invalid SOC tier. Use L1, L2, L3, or null.' });
    }

    const target = db.prepare('SELECT id FROM users WHERE id = ?').get(req.params.id) as any;
    if (!target?.id) return res.status(404).json({ error: 'User not found' });

    db.prepare('UPDATE users SET soc_tier = ? WHERE id = ?').run(cleanSocTier, req.params.id);
    return res.json({ ok: true, socTier: cleanSocTier });
  } catch (err: any) {
    return res.status(500).json({ error: err.message || 'Failed to update SOC tier' });
  }
});

superAdminRouter.delete('/users/:id', (req: AuthenticatedRequest, res: Response) => {
  try {
    const targetId = req.params.id;
    if (targetId === req.user?.userId) {
      return res.status(400).json({ error: 'Cannot delete the currently signed-in Super Admin account' });
    }
    db.prepare('DELETE FROM users WHERE id = ?').run(targetId);
    return res.json({ ok: true, message: 'User deleted successfully' });
  } catch (err: any) {
    return res.status(500).json({ error: err.message || 'Failed to delete user' });
  }
});

superAdminRouter.get('/roles', (_req: AuthenticatedRequest, res: Response) => {
  try {
    let roles = db.prepare('SELECT * FROM roles ORDER BY name ASC').all() as any[];
    if (!roles || roles.length === 0) {
      // Default roles if table is empty
      const defaultRoles = [
        { id: 'role_super_admin', name: 'Super Admin', description: 'Full global system administration & multi-tenant visibility' },
        { id: 'role_security_admin', name: 'Security Admin', description: 'Policy management, tenant security controls and rule enforcement' },
        { id: 'role_security_analyst', name: 'Security Analyst', description: 'Investigation, threat analysis, incident response and containment' },
        { id: 'role_org_admin', name: 'Organization Admin', description: 'Tenant administration, asset onboarding and operational metrics' },
        { id: 'role_auditor_viewer', name: 'Auditor / Viewer', description: 'Read-only access for compliance, auditing and reports' }
      ];
      for (const r of defaultRoles) {
        db.prepare('INSERT IGNORE INTO roles (id, name, description) VALUES (?, ?, ?)').run(r.id, r.name, r.description);
      }
      roles = db.prepare('SELECT * FROM roles ORDER BY name ASC').all() as any[];
    }
    return res.json({ roles });
  } catch (err: any) {
    return res.status(500).json({ error: err.message || 'Failed to list roles' });
  }
});

superAdminRouter.post('/roles', (req: AuthenticatedRequest, res: Response) => {
  try {
    const { name, description } = req.body || {};
    if (!name || !String(name).trim()) {
      return res.status(400).json({ error: 'Role name is required' });
    }
    const roleId = `role_${String(name).toLowerCase().replace(/[^a-z0-9]/g, '_')}_${Math.random().toString(36).substring(2, 6)}`;
    db.prepare('INSERT INTO roles (id, name, description) VALUES (?, ?, ?)').run(
      roleId,
      String(name).trim(),
      description ? String(description).trim() : 'Custom enterprise role'
    );
    return res.status(201).json({ ok: true, role: { id: roleId, name, description } });
  } catch (err: any) {
    return res.status(500).json({ error: err.message || 'Failed to create role' });
  }
});

superAdminRouter.delete('/roles/:id', (req: AuthenticatedRequest, res: Response) => {
  try {
    const roleId = req.params.id;
    const reserved = ['role_super_admin', 'Super Admin'];
    const role = db.prepare('SELECT name FROM roles WHERE id = ?').get(roleId) as any;
    if (role && (reserved.includes(roleId) || reserved.includes(role.name))) {
      return res.status(400).json({ error: 'Cannot delete primary Super Admin role' });
    }
    db.prepare('DELETE FROM roles WHERE id = ?').run(roleId);
    return res.json({ ok: true, message: 'Role deleted successfully' });
  } catch (err: any) {
    return res.status(500).json({ error: err.message || 'Failed to delete role' });
  }
});