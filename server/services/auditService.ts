import crypto from 'crypto';
import { db } from '../database/db';
import { SecurityEventBus } from '../utils/eventBus';

export interface AuditLogParams {
  organizationId?: string | null;
  userId?: string;
  userEmail: string;
  role: string;
  action: string;
  resource: string;
  resourceId?: string;
  ipAddress?: string;
  userAgent?: string;
  metadata?: Record<string, any>;
}

export function recordAuditLog(params: AuditLogParams) {
  try {
    const id = `AUD-${crypto.randomUUID()}`;
    const timestamp = new Date().toISOString();
    let orgId = params.organizationId?.trim() || null;
    if (orgId) {
      try {
        const orgExists = db.prepare('SELECT id FROM organizations WHERE id = ?').get(orgId);
        if (!orgExists) orgId = null;
      } catch {
        orgId = null;
      }
    }

    db.prepare(`
      INSERT INTO audit_logs (
        id, organization_id, user_id, user_email, role, action,
        resource, resource_id, ip_address, user_agent, timestamp, metadata
      ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, datetime('now'), ?)
    `).run(
      id,
      orgId,
      params.userId || null,
      params.userEmail,
      params.role,
      params.action,
      params.resource,
      params.resourceId || null,
      params.ipAddress || '127.0.0.1',
      params.userAgent || 'OAT Web Console',
      params.metadata ? JSON.stringify(params.metadata) : null
    );

    SecurityEventBus.publish('audit.created', {
      id,
      user: params.userEmail,
      role: params.role,
      action: params.action,
      resource: params.resource,
      timestamp,
      ip: params.ipAddress || '127.0.0.1',
      result: 'Success',
      metadata: params.metadata
    }, params.organizationId);

    return id;
  } catch (err) {
    console.error('[AuditService] Failed to record audit log:', err);
    return null;
  }
}
