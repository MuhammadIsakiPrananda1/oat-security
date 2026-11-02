import { db } from '../database/db';
import { SecurityEventBus } from '../utils/eventBus';

/**
 * WAF deployment coordinator.
 *
 * The dashboard owns the desired policy. Enrolled endpoint agents pull that
 * policy over the same Ed25519-signed channel they use for telemetry, apply it
 * locally (Apache + nftables on Debian), and report the result back here.
 *
 * There are deliberately no stored SSH credentials and no remote-shell path.
 */

export interface WafPolicyRecord {
  id: string;
  organization_id: string;
  engine_enabled: number;
  mode: string;
  rate_limit_requests: number;
  rate_limit_window_s: number;
  ip_allowlist: string;
  ip_blocklist: string;
  geo_block_countries: string;
  bot_protection_enabled: number;
  sync_to_server: number;
  revision: number;
  last_applied_at: string | null;
  server_status: string;
  server_log: string | null;
  updated_at: string;
}

export type AgentWafState = 'PENDING' | 'APPLIED' | 'FAILED' | 'UNSUPPORTED';
export type AgentComputedStatus = 'ONLINE' | 'OFFLINE' | 'STALE' | 'PENDING' | 'REVOKED';
export type DeploymentStatus = 'NO_AGENT' | 'PENDING' | 'APPLIED' | 'FAILED' | 'PARTIAL' | 'UNSUPPORTED';

export interface AgentDetectedSite {
  domain: string;
  port?: number;
  protocol?: string;
  serverType?: string;
}

export interface AgentWafTarget {
  id: string;
  name: string;
  hostname: string;
  os: string;
  ip: string;
  applicationId: string | null;
  applicationName: string | null;
  applicationDomain: string | null;
  detectedSites: AgentDetectedSite[];
  agentStatus: AgentComputedStatus;
  status: AgentWafState;
  wafCapable: boolean | null;
  message: string;
  target: string;
  rulesApplied: number;
  appliedRevision: number;
  desiredRevision: number;
  appliedAt: string | null;
  lastSeen: string | null;
}

export interface WafDeployment {
  revision: number;
  engineEnabled: boolean;
  mode: string;
  totalAgents: number;
  onlineAgents: number;
  appliedAgents: number;
  pendingAgents: number;
  failedAgents: number;
  unsupportedAgents: number;
  status: DeploymentStatus;
  lastAppliedAt: string | null;
  agents: AgentWafTarget[];
}

export interface AgentWafPolicy {
  revision: number;
  engineEnabled: boolean;
  mode: string;
  rateLimitRequests: number;
  rateLimitWindowSeconds: number;
  ipAllowlist: string[];
  ipBlocklist: string[];
  geoBlockCountries: string[];
  botProtectionEnabled: boolean;
  policyUpdatedAt: string | null;
  rules: Array<{
    id: string;
    ruleId: string;
    name: string;
    category: string;
    severity: string;
    action: string;
    pattern: string;
    description: string;
  }>;
}

export interface WafStatusInput {
  revision?: unknown;
  status?: unknown;
  message?: unknown;
  target?: unknown;
  rulesApplied?: unknown;
  engineEnabled?: unknown;
  mode?: unknown;
  appliedAt?: unknown;
}

export function toIso(value: string | null | undefined): string | null {
  if (!value) return null;
  if (value.includes('T')) return value;
  return `${value.replace(' ', 'T')}Z`;
}

export function computedAgentStatus(row: {
  revoked_at?: string | null;
  status?: string | null;
  last_seen?: string | null;
}): AgentComputedStatus {
  if (row.revoked_at || row.status === 'REVOKED') return 'REVOKED';
  if (!row.last_seen) return 'PENDING';
  const lastSeen = Date.parse(toIso(row.last_seen) || '');
  if (!Number.isFinite(lastSeen)) return 'PENDING';
  const age = Date.now() - lastSeen;
  if (age < 2 * 60 * 1000) return 'ONLINE';
  if (age < 7 * 24 * 60 * 60 * 1000) return 'OFFLINE';
  return 'STALE';
}

export function splitWafList(value: string | null | undefined): string[] {
  return String(value || '')
    .split(/[\n,]/)
    .map(entry => entry.trim())
    .filter(Boolean);
}

export function normalizeWafAction(value: unknown): 'BLOCK' | 'LOG' | 'CHALLENGE' {
  const action = String(value || '').trim().toUpperCase();
  if (action === 'LOG' || action === 'ALLOW' || action === 'PASS') return 'LOG';
  if (action === 'CHALLENGE') return 'CHALLENGE';
  return 'BLOCK';
}

export function normalizeWafPattern(value: unknown): { pattern: string; error?: string } {
  const pattern = value === undefined || value === null ? '' : String(value).trim();
  if (!pattern) return { pattern: '' };
  if (pattern.length > 500) {
    return { pattern: '', error: 'Pattern is too long (max 500 characters)' };
  }
  if (/[\r\n\u0000"]/.test(pattern)) {
    return { pattern: '', error: 'Pattern cannot contain line breaks, NUL bytes, or double quotes' };
  }
  const trailingBackslashes = (pattern.match(/\\+$/) || [''])[0].length;
  if (trailingBackslashes % 2 === 1) {
    return { pattern: '', error: 'Pattern cannot end with an unescaped backslash' };
  }
  try {
    // JavaScript does not understand PCRE inline flags such as (?i). Strip
    // them for a syntax smoke test; Apache configtest on the endpoint remains
    // the authoritative PCRE validation before a revision is activated.
    new RegExp(pattern.replace(/\(\?[imsx]+\)/gi, ''));
  } catch {
    // PCRE-only constructs are allowed. The agent rolls back if Apache
    // configtest rejects the generated configuration.
  }
  return { pattern };
}

export function serializeWafRule(row: any) {
  const action = normalizeWafAction(row?.action);
  return {
    id: String(row?.id || ''),
    ruleId: String(row?.rule_id || row?.ruleId || row?.id || ''),
    name: String(row?.name || ''),
    category: String(row?.category || ''),
    severity: String(row?.severity || 'Medium'),
    action: action === 'BLOCK' ? 'Block' : action === 'CHALLENGE' ? 'Challenge' : 'Log',
    enabled: Number(row?.enabled) ? 1 : 0,
    status: Number(row?.enabled) ? 'Active' : 'Disabled',
    pattern: String(row?.pattern || ''),
    description: String(row?.description || ''),
    createdAt: toIso(row?.created_at),
    updatedAt: toIso(row?.updated_at)
  };
}

export class WafDeploymentService {
  public static resolveOrgId(orgId?: string): string {
    if (orgId && orgId.trim()) {
      try {
        const orgExists = db.prepare('SELECT id FROM organizations WHERE id = ?').get(orgId.trim()) as any;
        if (orgExists?.id) return orgExists.id;
      } catch {}
    }
    try {
      const firstOrg = db.prepare('SELECT id FROM organizations ORDER BY created_at ASC LIMIT 1').get() as any;
      if (firstOrg?.id) return firstOrg.id;
    } catch {}

    return orgId?.trim() || '';
  }

  public static ensurePolicy(orgId?: string): WafPolicyRecord {
    const validOrgId = this.resolveOrgId(orgId);
    let policy = db.prepare('SELECT * FROM waf_policy WHERE organization_id = ?').get(validOrgId) as unknown as WafPolicyRecord | undefined;

    if (!policy) {
      const id = `WAF-POL-${Date.now()}`;
      try {
        db.prepare(`
          INSERT INTO waf_policy (
            id, organization_id, engine_enabled, mode,
            rate_limit_requests, rate_limit_window_s,
            ip_allowlist, ip_blocklist, geo_block_countries,
            bot_protection_enabled, sync_to_server, revision, server_status
          ) VALUES (?, ?, 1, 'block', 100, 10, '', '', '', 1, 1, 1, 'NO_TARGET')
        `).run(id, validOrgId);
      } catch {
        // A concurrent request may have inserted the row first.
      }
      policy = db.prepare('SELECT * FROM waf_policy WHERE organization_id = ?').get(validOrgId) as unknown as WafPolicyRecord;
    }

    if (!policy) {
      return {
        id: `WAF-POL-${Date.now()}`,
        organization_id: validOrgId,
        engine_enabled: 1,
        mode: 'block',
        rate_limit_requests: 100,
        rate_limit_window_s: 10,
        ip_allowlist: '',
        ip_blocklist: '',
        geo_block_countries: '',
        bot_protection_enabled: 1,
        sync_to_server: 1,
        revision: 1,
        last_applied_at: null,
        server_status: 'NO_TARGET',
        server_log: '',
        updated_at: new Date().toISOString()
      };
    }

    return policy;
  }

  /**
   * Bump the desired revision and mark every active agent as waiting for the
   * new policy. Agents poll this revision and apply it at their next check-in.
   */
  public static publish(orgId: string, reason: string): WafDeployment {
    const validOrgId = this.resolveOrgId(orgId);
    const policy = this.ensurePolicy(validOrgId);
    const revision = (Number(policy?.revision) || 0) + 1;
    const now = new Date().toISOString();
    const agents = db.prepare(`
      SELECT id, organization_id, application_id
      FROM agents
      WHERE organization_id = ? AND revoked_at IS NULL
    `).all(validOrgId) as Array<{ id: string; organization_id: string; application_id: string | null }>;
    const activeRules = db.prepare(
      'SELECT COUNT(*) as count FROM waf_rules WHERE organization_id = ? AND enabled = 1'
    ).get(validOrgId) as { count: number };

    const summary = `Revision ${revision} queued for ${agents.length} endpoint agent(s) · ${Number(activeRules?.count) || 0} active rule(s) · ${reason}`;

    db.prepare(`
      UPDATE waf_policy
      SET revision = ?, server_status = ?, server_log = ?, updated_at = ?
      WHERE organization_id = ?
    `).run(revision, agents.length === 0 ? 'NO_TARGET' : 'PENDING', summary, now, validOrgId);

    const upsert = db.prepare(`
      INSERT INTO agent_waf_status (
        agent_id, organization_id, application_id, desired_revision,
        applied_revision, status, engine_enabled, mode, target, message,
        rules_applied, applied_at, updated_at
      ) VALUES (?, ?, ?, ?, 0, 'PENDING', ?, ?, NULL, ?, 0, NULL, ?)
      ON DUPLICATE KEY UPDATE
        organization_id = VALUES(organization_id),
        application_id = VALUES(application_id),
        desired_revision = VALUES(desired_revision),
        status = 'PENDING',
        engine_enabled = VALUES(engine_enabled),
        mode = VALUES(mode),
        message = VALUES(message),
        updated_at = VALUES(updated_at)
    `);

    for (const agent of agents) {
      upsert.run(
        agent.id,
        agent.organization_id,
        agent.application_id,
        revision,
        Number(policy.engine_enabled) ? 1 : 0,
        policy.mode || 'block',
        'Waiting for the endpoint agent to check in',
        now
      );
    }

    const deployment = this.getDeployment(validOrgId);
    SecurityEventBus.publish('waf.deployment_queued', {
      revision,
      agents: deployment.totalAgents,
      reason
    }, validOrgId);

    return deployment;
  }

  /**
   * Called during enrollment so a newly enrolled agent already has a target
   * row in the WAF status view.
   */
  public static ensureAgentStatus(agentId: string, organizationId: string, applicationId: string | null): void {
    const policy = this.ensurePolicy(organizationId);
    const now = new Date().toISOString();
    try {
      db.prepare(`
        INSERT INTO agent_waf_status (
          agent_id, organization_id, application_id, desired_revision,
          applied_revision, status, engine_enabled, mode, message, rules_applied, updated_at
        ) VALUES (?, ?, ?, ?, 0, 'PENDING', ?, ?, ?, 0, ?)
        ON DUPLICATE KEY UPDATE
          organization_id = VALUES(organization_id),
          application_id = VALUES(application_id),
          updated_at = VALUES(updated_at)
      `).run(
        agentId,
        organizationId,
        applicationId,
        Number(policy.revision) || 1,
        Number(policy.engine_enabled) ? 1 : 0,
        policy.mode || 'block',
        'Waiting for the endpoint agent to check in',
        now
      );
    } catch (error) {
      console.warn(`[WAF] Could not create status row for ${agentId}:`, error);
    }
    try {
      this.refreshPolicyAggregate(organizationId);
    } catch {
      // The agent is still enrolled even if the aggregate refresh fails.
    }
  }

  public static recordAgentStatus(
    agent: { id: string; organization_id: string; application_id: string | null },
    input: WafStatusInput
  ): WafDeployment {
    const policy = this.ensurePolicy(agent.organization_id);
    const revision = Math.min(2_147_483_647, Math.max(0, Math.trunc(Number(input.revision) || 0)));
    const rawStatus = String(input.status || '').trim().toUpperCase();
    const status: AgentWafState = rawStatus === 'APPLIED' || rawStatus === 'FAILED' || rawStatus === 'UNSUPPORTED'
      ? rawStatus
      : 'PENDING';
    const now = new Date().toISOString();
    const appliedAt = status === 'APPLIED' ? now : null;
    const message = String(input.message || '').replace(/[\u0000-\u0008\u000b\u000c\u000e-\u001f\u007f]/g, '').slice(0, 4000);
    const target = String(input.target || '').slice(0, 255);
    const rulesApplied = Math.min(100_000, Math.max(0, Math.trunc(Number(input.rulesApplied) || 0)));
    const engineEnabled = input.engineEnabled === undefined
      ? Number(policy.engine_enabled) ? 1 : 0
      : input.engineEnabled ? 1 : 0;
    const mode = String(input.mode || policy.mode || 'block').toLowerCase() === 'monitor' ? 'monitor' : 'block';

    db.prepare(`
      INSERT INTO agent_waf_status (
        agent_id, organization_id, application_id, desired_revision,
        applied_revision, status, engine_enabled, mode, target, message,
        rules_applied, applied_at, updated_at
      ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
      ON DUPLICATE KEY UPDATE
        organization_id = VALUES(organization_id),
        application_id = VALUES(application_id),
        desired_revision = VALUES(desired_revision),
        applied_revision = IF(VALUES(status) = 'APPLIED', VALUES(applied_revision), applied_revision),
        status = VALUES(status),
        engine_enabled = VALUES(engine_enabled),
        mode = VALUES(mode),
        target = VALUES(target),
        message = VALUES(message),
        rules_applied = VALUES(rules_applied),
        applied_at = IF(VALUES(status) = 'APPLIED', VALUES(applied_at), applied_at),
        updated_at = VALUES(updated_at)
    `).run(
      agent.id,
      agent.organization_id,
      agent.application_id,
      revision,
      status === 'APPLIED' ? revision : 0,
      status,
      engineEnabled,
      mode,
      target || null,
      message,
      rulesApplied,
      appliedAt,
      now
    );

    const deployment = this.refreshPolicyAggregate(agent.organization_id);
    SecurityEventBus.publish('waf.agent_status', {
      agentId: agent.id,
      revision,
      status,
      target,
      message,
      appliedAt
    }, agent.organization_id);

    return deployment;
  }

  public static getDeployment(orgId?: string): WafDeployment {
    const validOrgId = this.resolveOrgId(orgId);
    const policy = this.ensurePolicy(validOrgId);
    const currentRevision = Number(policy?.revision) || 1;

    const rows = db.prepare(`
      SELECT
        a.id, a.name, a.hostname, a.os, a.ip, a.status AS agent_status,
        a.last_seen, a.revoked_at, a.application_id, a.host_info,
        app.name AS application_name, app.domain AS application_domain,
        s.status AS waf_status, s.applied_revision, s.desired_revision,
        s.message, s.target, s.applied_at, s.rules_applied
      FROM agents a
      LEFT JOIN applications app ON app.id = a.application_id
      LEFT JOIN agent_waf_status s ON s.agent_id = a.id
      WHERE a.organization_id = ? AND a.revoked_at IS NULL
      ORDER BY a.created_at DESC
    `).all(validOrgId) as any[];

    const agents: AgentWafTarget[] = rows.map(row => {
      const stored = String(row.waf_status || '').toUpperCase();
      const appliedRevision = Number(row.applied_revision) || 0;
      const desiredRevision = Number(row.desired_revision) || 0;
      let status: AgentWafState = 'PENDING';

      if (stored === 'APPLIED' && appliedRevision === currentRevision) {
        status = 'APPLIED';
      } else if (stored === 'FAILED' && desiredRevision === currentRevision) {
        status = 'FAILED';
      } else if (stored === 'UNSUPPORTED' && desiredRevision === currentRevision) {
        status = 'UNSUPPORTED';
      }

      let hostInfo: Record<string, any> = {};
      try {
        const parsed = JSON.parse(String(row.host_info || '{}'));
        if (parsed && typeof parsed === 'object' && !Array.isArray(parsed)) hostInfo = parsed;
      } catch {
        // Older agents may have malformed host_info; treat capability as unknown.
      }
      const wafCapable = typeof hostInfo.wafEnabled === 'boolean' ? hostInfo.wafEnabled : null;
      // Websites the agent found on its host — the console uses them to offer a
      // "monitored website" picker when the server hosts more than one site.
      const detectedSites: AgentDetectedSite[] = Array.isArray(hostInfo.detectedSites)
        ? (hostInfo.detectedSites as any[])
          .filter(site => site && typeof site === 'object' && typeof site.domain === 'string' && site.domain.trim())
          .map(site => ({
            domain: String(site.domain).trim(),
            port: Number(site.port) || undefined,
            protocol: site.protocol ? String(site.protocol) : undefined,
            serverType: site.serverType ? String(site.serverType) : undefined
          }))
        : [];
      const agentStatus = computedAgentStatus(row);
      let message = row.message || '';
      if (status === 'PENDING') {
        if (wafCapable === null) {
          if (agentStatus === 'ONLINE') {
            message = 'Agent is online, but it has not reported WAF support. Reinstall the current agent without --no-waf, or verify wafEnabled=true in its config.';
          } else if (agentStatus === 'OFFLINE' || agentStatus === 'STALE') {
            message = 'This agent has not reported WAF support and is offline. Reinstall the current agent on the host, then revoke this entry.';
          } else {
            message = 'This agent has not reported WAF support yet. Reinstall the current agent, then revoke this entry if it was replaced.';
          }
        } else if (wafCapable === false) {
          message = 'WAF enforcement is disabled in the agent configuration (--no-waf).';
        } else if (agentStatus === 'ONLINE') {
          message = `Waiting for the agent to report revision ${currentRevision}.`;
        } else if (agentStatus === 'OFFLINE' || agentStatus === 'STALE') {
          message = 'Agent is offline; waiting for the next check-in.';
        }
      }

      return {
        id: row.id,
        name: row.name,
        hostname: row.hostname || row.name,
        os: row.os || '',
        ip: row.ip || '',
        applicationId: row.application_id || null,
        applicationName: row.application_name || null,
        applicationDomain: row.application_domain || null,
        detectedSites,
        agentStatus,
        status,
        wafCapable,
        message,
        target: row.target || '',
        rulesApplied: Number(row.rules_applied) || 0,
        appliedRevision,
        desiredRevision,
        appliedAt: toIso(row.applied_at),
        lastSeen: toIso(row.last_seen)
      };
    });

    const appliedAgents = agents.filter(agent => agent.status === 'APPLIED').length;
    const failedAgents = agents.filter(agent => agent.status === 'FAILED').length;
    const unsupportedAgents = agents.filter(agent => agent.status === 'UNSUPPORTED').length;
    const pendingAgents = agents.length - appliedAgents - failedAgents - unsupportedAgents;
    const onlineAgents = agents.filter(agent => agent.agentStatus === 'ONLINE').length;
    const appliedTimes = agents
      .map(agent => agent.appliedAt)
      .filter((value): value is string => Boolean(value))
      .sort();
    const lastAppliedAt = appliedTimes.length ? appliedTimes[appliedTimes.length - 1] : null;

    let status: DeploymentStatus = 'NO_AGENT';
    if (agents.length > 0) {
      if (failedAgents > 0) status = 'FAILED';
      else if (pendingAgents > 0) status = 'PENDING';
      else if (unsupportedAgents === agents.length) status = 'UNSUPPORTED';
      else if (appliedAgents === agents.length) status = 'APPLIED';
      else if (appliedAgents + unsupportedAgents === agents.length) status = 'PARTIAL';
      else status = 'PENDING';
    }

    return {
      revision: currentRevision,
      engineEnabled: Boolean(policy.engine_enabled),
      mode: policy.mode || 'block',
      totalAgents: agents.length,
      onlineAgents,
      appliedAgents,
      pendingAgents,
      failedAgents,
      unsupportedAgents,
      status,
      lastAppliedAt,
      agents
    };
  }

  /**
   * Full desired state for one enrolled agent. Organization and website are
   * always resolved from the signed agent record, never from request body.
   */
  public static getAgentPolicy(agent: { organization_id: string }): AgentWafPolicy {
    const policy = this.ensurePolicy(agent.organization_id);
    const rules = db.prepare(`
      SELECT * FROM waf_rules
      WHERE organization_id = ? AND enabled = 1
      ORDER BY created_at ASC
    `).all(agent.organization_id) as any[];

    return {
      revision: Number(policy.revision) || 1,
      engineEnabled: Boolean(policy.engine_enabled),
      mode: String(policy.mode || 'block').toLowerCase() === 'monitor' ? 'monitor' : 'block',
      rateLimitRequests: Number(policy.rate_limit_requests) || 0,
      rateLimitWindowSeconds: Number(policy.rate_limit_window_s) || 0,
      ipAllowlist: splitWafList(policy.ip_allowlist),
      ipBlocklist: splitWafList(policy.ip_blocklist),
      geoBlockCountries: splitWafList(policy.geo_block_countries).map(code => code.toUpperCase()),
      botProtectionEnabled: Boolean(policy.bot_protection_enabled),
      policyUpdatedAt: toIso(policy.updated_at),
      rules: rules.map(rule => ({
        id: rule.id,
        ruleId: rule.rule_id,
        name: rule.name,
        category: rule.category,
        severity: rule.severity,
        action: normalizeWafAction(rule.action),
        pattern: String(rule.pattern || ''),
        description: String(rule.description || '')
      }))
    };
  }

  private static refreshPolicyAggregate(orgId: string): WafDeployment {
    const deployment = this.getDeployment(orgId);
    let serverStatus = 'PENDING';

    if (deployment.totalAgents === 0) serverStatus = 'NO_TARGET';
    else if (deployment.failedAgents > 0) serverStatus = 'SYNC_ERROR';
    else if (deployment.pendingAgents > 0) serverStatus = 'PENDING';
    else if (deployment.unsupportedAgents === deployment.totalAgents) serverStatus = 'UNSUPPORTED';
    else if (deployment.appliedAgents === deployment.totalAgents) {
      serverStatus = deployment.engineEnabled ? 'ACTIVE' : 'DISABLED';
    } else if (deployment.appliedAgents + deployment.unsupportedAgents === deployment.totalAgents) {
      serverStatus = 'PARTIAL';
    }

    const failed = deployment.agents.find(agent => agent.status === 'FAILED');
    const summary = [
      `Revision ${deployment.revision}`,
      `${deployment.appliedAgents}/${deployment.totalAgents} applied`,
      `${deployment.pendingAgents} pending`,
      `${deployment.unsupportedAgents} unsupported`,
      `${deployment.failedAgents} failed`
    ].join(' · ') + (failed?.message ? ` · ${failed.message}` : '');

    db.prepare(`
      UPDATE waf_policy
      SET server_status = ?, server_log = ?,
          last_applied_at = COALESCE(?, last_applied_at),
          updated_at = ?
      WHERE organization_id = ?
    `).run(serverStatus, summary, deployment.lastAppliedAt, new Date().toISOString(), orgId);

    return deployment;
  }

  /**
   * Recompute the stored policy status after agents are added, revoked, or
   * removed outside the normal status-report path.
   */
  public static refresh(orgId: string): WafDeployment {
    return this.refreshPolicyAggregate(this.resolveOrgId(orgId));
  }

  /**
   * Compatibility shim for callers that previously requested an SSH sync.
   * A deploy now means "publish a new signed revision and let agents pull it".
   */
  public static queueDeployment(orgId: string, reason: string): WafDeployment {
    return this.publish(orgId, reason);
  }
}

// Backwards-compatible alias for older imports in the codebase.
export const ServerWafSyncService = WafDeploymentService;
