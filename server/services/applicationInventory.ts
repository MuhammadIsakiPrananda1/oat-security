import { db } from '../database/db';
import { SecurityEventBus } from '../utils/eventBus';

/**
 * Application inventory housekeeping.
 *
 * Websites are discovered by the endpoint agent, so the inventory has to follow
 * reality: a site that disappeared from the host must disappear from the
 * console instead of lingering forever. To avoid a flickering list, a
 * discovered website is only removed after a grace period during which no
 * agent reported it any more, and never while a live agent is bound to it.
 */

// A website has to be missing from every agent for this long before it is
// considered gone. The agent heartbeats every 30 seconds, so a few minutes of
// silence already means the site is really not there any more.
const GRACE_MINUTES = Number(process.env.APP_PRUNE_GRACE_MINUTES) || 10;
const GRACE_MS = GRACE_MINUTES * 60 * 1000;

export function applicationGraceMinutes(): number {
  return GRACE_MINUTES;
}

/**
 * Delete one application and tell the console about it.
 * Returns true when a row was actually removed.
 */
export function removeApplication(applicationId: string, organizationId: string, reason: string): boolean {
  const app = db.prepare('SELECT id, name, domain FROM applications WHERE id = ?').get(applicationId) as
    { id: string; name: string; domain: string } | undefined;
  if (!app) return false;

  db.prepare('DELETE FROM applications WHERE id = ?').run(applicationId);

  try {
    SecurityEventBus.publish('application.removed', {
      id: app.id,
      name: app.name,
      domain: app.domain,
      reason
    }, organizationId);
  } catch (err) {
    console.warn('[Applications] Failed to broadcast application.removed:', err);
  }

  console.log(`[Applications] Removed "${app.domain}" (${reason})`);
  return true;
}

/**
 * Remove discovered websites that no agent reports any more.
 *
 * Only agent-discovered websites are touched: a website an operator added by
 * hand stays in the inventory until it is deleted explicitly.
 */
export function pruneStaleApplications(organizationId?: string): number {
  const cutoff = new Date(Date.now() - GRACE_MS).toISOString();
  const params: any[] = [cutoff];
  let scope = '';
  if (organizationId) {
    scope = ' AND organization_id = ?';
    params.push(organizationId);
  }

  const stale = db.prepare(`
    SELECT a.id, a.name, a.domain, a.organization_id
    FROM applications a
    WHERE a.source = 'agent'
      AND (a.last_seen IS NULL OR a.last_seen < ?)${scope}
      AND NOT EXISTS (
        SELECT 1 FROM agents g
        WHERE g.application_id = a.id AND g.revoked_at IS NULL
      )
  `).all(...params) as Array<{ id: string; name: string; domain: string; organization_id: string }>;

  let removed = 0;
  for (const app of stale) {
    if (removeApplication(app.id, app.organization_id, 'No agent reports this website any more')) {
      removed += 1;
    }
  }
  return removed;
}
