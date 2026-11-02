import crypto from 'crypto';
import { db } from '../database/db';
import { SecurityEventBus } from '../utils/eventBus';

export type ContactStatus = 'OPEN' | 'IN_REVIEW' | 'RESOLVED';

export interface ContactMessage {
  id: string;
  organizationId: string | null;
  userId: string | null;
  name: string;
  email: string;
  company: string | null;
  topic: string;
  severity: string;
  message: string;
  status: ContactStatus;
  source: string;
  createdAt: string;
  updatedAt: string;
}

export interface ContactMessageInput {
  organizationId?: string | null;
  userId?: string | null;
  name?: string;
  email?: string;
  company?: string | null;
  topic?: string;
  severity?: string;
  message: string;
  source?: string;
}

const TOPICS = new Set([
  'General',
  'Technical Support',
  'Incident Response',
  'Billing',
  'Security Disclosure',
  'Partnership'
]);

const SEVERITIES = new Set(['Low', 'Normal', 'High', 'Critical']);

function toRecord(row: any): ContactMessage {
  return {
    id: row.id,
    organizationId: row.organization_id ?? null,
    userId: row.user_id ?? null,
    name: row.name,
    email: row.email,
    company: row.company ?? null,
    topic: row.topic,
    severity: row.severity,
    message: row.message,
    status: (row.status || 'OPEN') as ContactStatus,
    source: row.source || 'console',
    createdAt: row.created_at,
    updatedAt: row.updated_at
  };
}

function assertEmail(email: string) {
  if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) {
    throw new Error('A valid email address is required.');
  }
}

export function createContactMessage(input: ContactMessageInput): ContactMessage {
  const message = String(input.message || '').trim();
  if (message.length < 10) {
    throw new Error('Please describe your request in at least 10 characters.');
  }
  if (message.length > 8000) {
    throw new Error('Message is too long (8000 characters max).');
  }

  const email = String(input.email || '').trim();
  assertEmail(email);

  const name = String(input.name || '').trim() || email.split('@')[0];
  const topic = TOPICS.has(String(input.topic)) ? String(input.topic) : 'General';
  const severity = SEVERITIES.has(String(input.severity)) ? String(input.severity) : 'Normal';
  const id = `MSG-${crypto.randomUUID()}`;

  db.prepare(`
    INSERT INTO contact_messages (
      id, organization_id, user_id, name, email, company, topic, severity,
      message, status, source
    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, 'OPEN', ?)
  `).run(
    id,
    input.organizationId || null,
    input.userId || null,
    name.slice(0, 255),
    email.slice(0, 255),
    input.company ? String(input.company).slice(0, 255) : null,
    topic,
    severity,
    message,
    input.source || 'console'
  );

  const row = db.prepare('SELECT * FROM contact_messages WHERE id = ?').get(id);
  const record = toRecord(row);

  SecurityEventBus.publish('contact.created', record, record.organizationId || undefined);
  return record;
}

export function listContactMessages(
  organizationId: string,
  options: { status?: string; limit?: number; offset?: number } = {}
): { messages: ContactMessage[]; total: number; open: number } {
  const limit = Math.min(Math.max(Number(options.limit) || 50, 1), 200);
  const offset = Math.max(Number(options.offset) || 0, 0);
  const status = String(options.status || '').toUpperCase();

  const params: unknown[] = [organizationId];
  let where = 'organization_id = ?';
  if (status) {
    where += ' AND status = ?';
    params.push(status);
  }

  const rows = db.prepare(`
    SELECT * FROM contact_messages
    WHERE ${where}
    ORDER BY created_at DESC
    LIMIT ? OFFSET ?
  `).all(...params, limit, offset) as any[];

  const total = Number((db.prepare(
    `SELECT COUNT(*) AS count FROM contact_messages WHERE ${where}`
  ).get(...params) as any)?.count) || 0;

  const open = Number((db.prepare(
    "SELECT COUNT(*) AS count FROM contact_messages WHERE organization_id = ? AND status <> 'RESOLVED'"
  ).get(organizationId) as any)?.count) || 0;

  return { messages: rows.map(toRecord), total, open };
}

export function updateContactMessageStatus(
  organizationId: string,
  id: string,
  status: string
): ContactMessage {
  const normalized = String(status || '').toUpperCase();
  if (!['OPEN', 'IN_REVIEW', 'RESOLVED'].includes(normalized)) {
    throw new Error('Status must be OPEN, IN_REVIEW or RESOLVED.');
  }

  const existing = db.prepare(
    'SELECT * FROM contact_messages WHERE id = ? AND organization_id = ?'
  ).get(id, organizationId) as any;
  if (!existing) {
    throw new Error('Contact message not found');
  }

  db.prepare(`
    UPDATE contact_messages
    SET status = ?, updated_at = DATE_FORMAT(UTC_TIMESTAMP(), '%Y-%m-%d %H:%i:%s')
    WHERE id = ? AND organization_id = ?
  `).run(normalized, id, organizationId);

  const record = toRecord(db.prepare('SELECT * FROM contact_messages WHERE id = ?').get(id));
  SecurityEventBus.publish('contact.updated', record, organizationId);
  return record;
}

/**
 * Support channels exposed to the console and the public contact page.
 * Values come from the environment so a deployment can publish its own real
 * mailbox/phone instead of hard-coded placeholders.
 */
export function getContactChannels(organizationDomain?: string | null) {
  const domain = (organizationDomain || '').trim();
  const fallbackEmail = domain ? `security@${domain}` : 'support@oatsecurity.com';
  return {
    email: process.env.SUPPORT_EMAIL || fallbackEmail,
    phone: process.env.SUPPORT_PHONE || '',
    address: process.env.SUPPORT_ADDRESS || '',
    hours: process.env.SUPPORT_HOURS || '24/7 SOC',
    responseSla: process.env.SUPPORT_SLA || 'Critical incidents: 15 minutes · Standard requests: 1 business day'
  };
}
