import { db } from '../database/db';
import { SecurityEventBus } from '../utils/eventBus';
import { computedAgentStatus, toIso } from './serverWafSync';
export type AgentFirewallState = 'PENDING' | 'APPLIED' | 'FAILED' | 'UNSUPPORTED';
export type FirewallDeploymentStatus = 'NO_AGENT' | 'PENDING' | 'APPLIED' | 'FAILED' | 'PARTIAL' | 'UNSUPPORTED';

export interface FirewallPolicyRecord {
  id: string;
  organization_id: string;
  sync_to_server: number;
  revision: number;
  last_applied_at: string | null;
  server_status: string;
  server_log: string | null;
  updated_at: string;
}

export interface AgentFirewallRule {
  id: string;
  priority: number;
  source: string;
  destination: string;
  port: string;
  protocol: string;
  action: string;
  description: string;
}

export interface AgentFirewallPolicy {
  revision: number;
  policyUpdatedAt: string | null;
  rules: AgentFirewallRule[];
}

export interface FirewallStatusInput {
  revision?: unknown;
  status?: unknown;
  message?: unknown;
  target?: unknown;
  rulesApplied?: unknown;
  appliedAt?: unknown;
}

export interface AgentFirewallTarget {
  id: string;
  name: string;
  hostname: string;
  os: string;
  ip: string;
  applicationId: string | null;
  applicationName: string | null;
  applicationDomain: string | null;
  agentStatus: 'ONLINE' | 'OFFLINE' | 'STALE' | 'PENDING' | 'REVOKED';
  status: AgentFirewallState;
  message: string;
  target: string;
  rulesApplied: number;
  appliedRevision: number;
  desiredRevision: number;
  appliedAt: string | null;
  lastSeen: string | null;
}

export interface FirewallDeployment {
  revision: number;
  totalAgents: number;
  onlineAgents: number;
  appliedAgents: number;
  pendingAgents: number;
  failedAgents: number;
  unsupportedAgents: number;
  status: FirewallDeploymentStatus;
  lastAppliedAt: string | null;
  agents: AgentFirewallTarget[];
}

function normalizeFirewallAction(value: unknown): 'ALLOW' | 'DENY' | 'LOG' {
  const action = String(value || '').trim().toUpperCase();
  if (action === 'ALLOW' || action === 'ACCEPT' || action === 'PASS') return 'ALLOW';
  if (action === 'LOG') return 'LOG';
  return 'DENY';
}

function normalizeFirewallProtocol(value: unknown): 'TCP' | 'UDP' | 'ICMP' | 'ANY' {
  const protocol = String(value || '').trim().toUpperCase();
  if (protocol === 'UDP' || protocol === 'ICMP' || protocol === 'ANY') return protocol;
  return 'TCP';
}

export class FirewallDeploymentService {
  public static resolveOrgId(orgId?: string): string {
    if (orgId && orgId.trim()) {
      try {
        const orgExists = db.prepare('SELECT id FROM organizations WHERE id = ?').get(orgId.trim()) as any;
        if (orgExists?.id) return orgExists.id;
      } catch {}
    }
    const firstOrg = db.prepare('SELECT id FROM organizations LIMIT 1').get() as any;
    return firstOrg?.id || 'org_522bbdc7';
  }

  public static ensurePolicy(orgId?: string): FirewallPolicyRecord {
    const validOrgId = this.resolveOrgId(orgId);
    let policy = db.prepare('SELECT * FROM firewall_policy WHERE organization_id = ?').get(validOrgId) as unknown as FirewallPolicyRecord | undefined;

    if (!policy) {
      const id = `FW-POL-${Date.now()}`;
      try {
        db.prepare(`
          INSERT INTO firewall_policy (
            id, organization_id, sync_to_server, revision, server_status
          ) VALUES (?, ?, 1, 1, 'NO_TARGET')
        `).run(id, validOrgId);
      } catch {
        // Concurrent creation during enrollment/startup races lose safely:
        // re-read whichever row landed first.
      }
      policy = db.prepare('SELECT * FROM firewall_policy WHERE organization_id = ?').get(validOrgId) as unknown as FirewallPolicyRecord;
    }

    if (!policy) {
      return {
        id: '',
        organization_id: validOrgId,
        sync_to_server: 1,
        revision: 1,
        last_applied_at: null,
        server_status: 'NO_TARGET',
        server_log: null,
        updated_at: new Date().toISOString()
      };
    }
    return policy;
  }

  /**
   * Bump the desired revision and mark every active agent PENDING. Called after
   * every console side-effect on firewall_rules (create/toggle/delete).
   */
  public static publish(orgId: string, reason: string): FirewallDeployment {
    const validOrgId = this.resolveOrgId(orgId);
    const policy = this.ensurePolicy(validOrgId);
    const revision = (Number(policy.revision) || 0) + 1;
    const now = new Date().toISOString();
    const agents = db.prepare(`
      SELECT id, organization_id, application_id
      FROM agents
      WHERE organization_id = ? AND revoked_at IS NULL
    `).all(validOrgId) as Array<{ id: string; organization_id: string; application_id: string | null }>;
    const activeRules = db.prepare(
      'SELECT COUNT(*) as count FROM firewall_rules WHERE organization_id = ? AND enabled = 1'
    ).get(validOrgId) as { count: number };

    const summary = `Revision ${revision} queued for ${agents.length} endpoint agent(s) · ${Number(activeRules?.count) || 0} active rule(s) · ${reason}`;

    db.prepare(`
      UPDATE firewall_policy
      SET revision = ?, server_status = ?, server_log = ?, updated_at = ?
      WHERE organization_id = ?
    `).run(revision, agents.length === 0 ? 'NO_TARGET' : 'PENDING', summary, now, validOrgId);

    const upsert = db.prepare(`
      INSERT INTO agent_firewall_status (
        agent_id, organization_id, application_id, desired_revision,
        applied_revision, status, message, rules_applied, updated_at
      ) VALUES (?, ?, ?, ?, 0, 'PENDING', ?, 0, ?)
      ON DUPLICATE KEY UPDATE
        organization_id = VALUES(organization_id),
        application_id = VALUES(application_id),
        desired_revision = VALUES(desired_revision),
        status = 'PENDING',
        message = VALUES(message),
        updated_at = VALUES(updated_at)
    `);

    for (const agent of agents) {
      upsert.run(
        agent.id,
        agent.organization_id,
        agent.application_id,
        revision,
        'Waiting for the endpoint agent to check in',
        now
      );
    }

    const deployment = this.getDeployment(validOrgId);
    SecurityEventBus.publish('firewall.deployment_queued', {
      revision,
      agents: deployment.totalAgents,
      reason
    }, validOrgId);

    return deployment;
  }

  /** Compatibility alias matching the WAF service naming. */
  public static queueDeployment(orgId: string, reason: string): FirewallDeployment {
    return this.publish(orgId, reason);
  }

  /**
   * Called during enrollment so a newly enrolled agent already has a target
   * row in the NGFW deployment view.
   */
  public static ensureAgentStatus(agentId: string, organizationId: string, applicationId: string | null): void {
    const policy = this.ensurePolicy(organizationId);
    const now = new Date().toISOString();
    try {
      db.prepare(`
        INSERT INTO agent_firewall_status (
          agent_id, organization_id, application_id, desired_revision,
          applied_revision, status, message, rules_applied, updated_at
        ) VALUES (?, ?, ?, ?, 0, 'PENDING', ?, 0, ?)
        ON DUPLICATE KEY UPDATE
          organization_id = VALUES(organization_id),
          application_id = VALUES(application_id),
          updated_at = VALUES(updated_at)
      `).run(
        agentId,
        organizationId,
        applicationId,
        Number(policy.revision) || 1,
        'Waiting for the endpoint agent to check in',
        now
      );
    } catch (error) {
      console.warn(`[NGFW] Could not create status row for ${agentId}:`, error);
    }
    try {
      this.refreshPolicyAggregate(organizationId);
    } catch {
      // The agent is still enrolled even if the aggregate refresh fails.
    }
  }

  public static recordAgentStatus(
    agent: { id: string; organization_id: string; application_id: string | null },
    input: FirewallStatusInput
  ): FirewallDeployment {
    this.ensurePolicy(agent.organization_id);
    const revision = Math.min(2_147_483_647, Math.max(0, Math.trunc(Number(input.revision) || 0)));
    const rawStatus = String(input.status || '').trim().toUpperCase();
    const status: AgentFirewallState = rawStatus === 'APPLIED' || rawStatus === 'FAILED' || rawStatus === 'UNSUPPORTED'
      ? rawStatus
      : 'PENDING';
    const now = new Date().toISOString();
    const appliedAt = status === 'APPLIED' ? now : null;
    // Strip control characters: nft error output can contain terminal codes.
    const message = String(input.message || '').replace(/[\u0000-\u0008\u000b\u000c\u000e-\u001f\u007f]/g, '').slice(0, 4000);
    const target = String(input.target || '').slice(0, 255);
    const rulesApplied = Math.min(100_000, Math.max(0, Math.trunc(Number(input.rulesApplied) || 0)));

    db.prepare(`
      INSERT INTO agent_firewall_status (
        agent_id, organization_id, application_id, desired_revision,
        applied_revision, status, target, message, rules_applied, applied_at, updated_at
      ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
      ON DUPLICATE KEY UPDATE
        organization_id = VALUES(organization_id),
        application_id = VALUES(application_id),
        desired_revision = VALUES(desired_revision),
        applied_revision = IF(VALUES(status) = 'APPLIED', VALUES(applied_revision), applied_revision),
        status = VALUES(status),
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
      target || null,
      message,
      rulesApplied,
      appliedAt,
      now
    );

    const deployment = this.refreshPolicyAggregate(agent.organization_id);
    SecurityEventBus.publish('firewall.agent_status', {
      agentId: agent.id,
      revision,
      status,
      target,
      message,
      appliedAt
    }, agent.organization_id);

    return deployment;
  }

  public static getDeployment(orgId?: string): FirewallDeployment {
    const validOrgId = this.resolveOrgId(orgId);
    const policy = this.ensurePolicy(validOrgId);
    const currentRevision = Number(policy.revision) || 1;

    const rows = db.prepare(`
      SELECT
        a.id, a.name, a.hostname, a.os, a.ip, a.status AS agent_status,
        a.last_seen, a.revoked_at, a.application_id,
        app.name AS application_name, app.domain AS application_domain,
        s.status AS fw_status, s.applied_revision, s.desired_revision,
        s.message, s.target, s.applied_at, s.rules_applied
      FROM agents a
      LEFT JOIN applications app ON app.id = a.application_id
      LEFT JOIN agent_firewall_status s ON s.agent_id = a.id
      WHERE a.organization_id = ? AND a.revoked_at IS NULL
      ORDER BY a.created_at DESC
    `).all(validOrgId) as any[];

    const agents: AgentFirewallTarget[] = rows.map(row => {
      const stored = String(row.fw_status || '').toUpperCase();
      const appliedRevision = Number(row.applied_revision) || 0;
      const desiredRevision = Number(row.desired_revision) || 0;
      let status: AgentFirewallState = 'PENDING';

      if (stored === 'APPLIED' && appliedRevision === currentRevision) {
        status = 'APPLIED';
      } else if (stored === 'FAILED' && desiredRevision === currentRevision) {
        status = 'FAILED';
      } else if (stored === 'UNSUPPORTED' && desiredRevision === currentRevision) {
        status = 'UNSUPPORTED';
      }

      const agentStatus = computedAgentStatus(row);
      let message = row.message || '';
      if (status === 'PENDING') {
        if (agentStatus === 'ONLINE') {
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
        agentStatus,
        status,
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

    let status: FirewallDeploymentStatus = 'NO_AGENT';
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
   * Full desired state for one enrolled agent. Organization is resolved from
   * the signed agent record, never from the request body. Only enabled rules
   * are shipped; the agent rebuilds the whole nftables table per revision.
   */
  public static getAgentPolicy(agent: { organization_id: string }): AgentFirewallPolicy {
    const policy = this.ensurePolicy(agent.organization_id);
    const rules = db.prepare(`
      SELECT * FROM firewall_rules
      WHERE organization_id = ? AND enabled = 1
      ORDER BY priority ASC, id ASC
    `).all(agent.organization_id) as any[];

    return {
      revision: Number(policy.revision) || 1,
      policyUpdatedAt: toIso(policy.updated_at),
      rules: rules.map(rule => ({
        id: String(rule.id),
        priority: Number(rule.priority) || 100,
        source: String(rule.source || ''),
        destination: String(rule.destination || ''),
        port: String(rule.port || 'ANY'),
        protocol: normalizeFirewallProtocol(rule.protocol),
        action: normalizeFirewallAction(rule.action),
        description: String(rule.description || '')
      }))
    };
  }

  private static refreshPolicyAggregate(orgId: string): FirewallDeployment {
    const deployment = this.getDeployment(orgId);
    let serverStatus = 'PENDING';

    if (deployment.totalAgents === 0) serverStatus = 'NO_TARGET';
    else if (deployment.failedAgents > 0) serverStatus = 'SYNC_ERROR';
    else if (deployment.pendingAgents > 0) serverStatus = 'PENDING';
    else if (deployment.unsupportedAgents === deployment.totalAgents) serverStatus = 'UNSUPPORTED';
    else if (deployment.appliedAgents === deployment.totalAgents) serverStatus = 'ACTIVE';
    else if (deployment.appliedAgents + deployment.unsupportedAgents === deployment.totalAgents) serverStatus = 'PARTIAL';

    const failed = deployment.agents.find(agent => agent.status === 'FAILED');
    const summary = [
      `Revision ${deployment.revision}`,
      `${deployment.appliedAgents}/${deployment.totalAgents} applied`,
      `${deployment.pendingAgents} pending`,
      `${deployment.unsupportedAgents} unsupported`,
      `${deployment.failedAgents} failed`
    ].join(' · ') + (failed?.message ? ` · ${failed.message}` : '');

    db.prepare(`
      UPDATE firewall_policy
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
  public static refresh(orgId: string): FirewallDeployment {
    return this.refreshPolicyAggregate(this.resolveOrgId(orgId));
  }
}
