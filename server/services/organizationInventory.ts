import { db } from '../database/db';
import { SecurityEventBus } from '../utils/eventBus';

/**
 * Remove an organization and all its tenant-scoped resources.
 * Broadcasts organization.deleted & organization.removed so the frontend
 * switcher and modules update in real-time without needing a manual refresh.
 */
export function removeOrganization(organizationId: string, reason = 'All associated endpoint agents were removed'): boolean {
  if (!organizationId) return false;

  const org = db.prepare('SELECT id, name, domain FROM organizations WHERE id = ?').get(organizationId) as
    { id: string; name: string; domain: string } | undefined;
  if (!org) return false;

  const orgScopedTables = [
    'security_events',
    'threats',
    'incidents',
    'logs',
    'audit_logs',
    'applications',
    'networks',
    'waf_rules',
    'waf_policy',
    'waf_agent_status',
    'firewall_rules',
    'firewall_agent_status',
    'agent_enrollment_tokens',
    'integration_configs',
    'api_keys',
    'notifications'
  ];

  try {
    for (const table of orgScopedTables) {
      try {
        db.prepare(`DELETE FROM ${table} WHERE organization_id = ?`).run(organizationId);
      } catch {
        // In case a table does not exist or has slightly different schema
      }
    }

    // Delete the organization row itself
    db.prepare('DELETE FROM organizations WHERE id = ?').run(organizationId);

    try {
      SecurityEventBus.publish('organization.deleted', {
        id: org.id,
        name: org.name,
        domain: org.domain,
        reason
      });
      SecurityEventBus.publish('organization.removed', {
        id: org.id,
        name: org.name,
        domain: org.domain,
        reason
      });
    } catch (err) {
      console.warn('[Organizations] Failed to broadcast organization.deleted:', err);
    }

    console.log(`[Organizations] Automatically removed tenant organization "${org.name}" (${org.id}) - ${reason}`);
    return true;
  } catch (err) {
    console.error(`[Organizations] Failed to remove organization ${organizationId}:`, err);
    return false;
  }
}

/**
 * Get active default organization if one exists.
 * Does not create dummy organizations — organizations only enter after an agent enrolls from a server.
 */
export function ensureDefaultOrganization(): { id: string; name: string } | null {
  const org = db.prepare(`
    SELECT o.id, o.name FROM organizations o
    WHERE EXISTS (
      SELECT 1 FROM agents a 
      WHERE a.organization_id = o.id 
        AND a.application_id IS NOT NULL 
        AND a.application_id != ''
    )
    LIMIT 1
  `).get() as { id: string; name: string } | undefined;
  return org || null;
}

/**
 * Clean up any organizations that no longer have any active agents.
 * When all agents of an organization are removed, the organization is removed.
 * If 0 agents exist across the system, 0 organizations remain.
 */
export function pruneOrphanedOrganizations(): number {
  try {
    const orphaned = db.prepare(`
      SELECT o.id, o.name FROM organizations o
      WHERE NOT EXISTS (SELECT 1 FROM agents a WHERE a.organization_id = o.id)
        AND NOT EXISTS (SELECT 1 FROM users u WHERE u.organization_id = o.id)
    `).all() as Array<{ id: string; name: string }>;

    let removed = 0;
    for (const org of orphaned) {
      if (removeOrganization(org.id, 'No agents or users remain in this organization')) {
        removed++;
      }
    }
    return removed;
  } catch (err) {
    console.warn('[Organizations] Error pruning orphaned organizations:', err);
    return 0;
  }
}
