import crypto from 'crypto';
import { Request } from 'express';
import { db } from '../database/db';

export interface AgentRow {
  id: string;
  organization_id: string;
  application_id: string | null;
  name: string;
  hostname: string | null;
  os: string | null;
  arch: string | null;
  version: string | null;
  ip: string | null;
  status: string;
  public_key: string;
  labels: string | null;
  host_info: string | null;
  metrics: string | null;
  last_seen: string | null;
  events_ingested: number;
  logs_ingested: number;
  created_at: string;
  revoked_at: string | null;
}

export interface AgentVerification {
  agent?: AgentRow;
  status?: number;
  error?: string;
}

const MAX_CLOCK_SKEW_MS = 24 * 60 * 60 * 1000;
const NONCE_TTL_MS = 24 * 60 * 60 * 1000;

// Replay protection. Node handles requests on one event loop, so a Map is
// sufficient; expired nonces are pruned lazily to avoid a background timer.
const seenNonces = new Map<string, number>();

export function sha256Hex(value: string | Buffer): string {
  return crypto.createHash('sha256').update(value).digest('hex');
}

export function newEnrollmentToken(): string {
  return `oat_enr_${crypto.randomBytes(32).toString('base64url')}`;
}

function headerValue(req: Request, name: string): string {
  const value = req.headers[name];
  return Array.isArray(value) ? String(value[0] || '') : String(value || '');
}

function pruneNonces(now: number) {
  if (seenNonces.size < 2048) return;
  for (const [key, expiresAt] of seenNonces) {
    if (expiresAt <= now) seenNonces.delete(key);
  }
}

/**
 * Verifies an Ed25519-signed request from an enrolled endpoint agent.
 *
 * Canonical string (newline separated):
 *   METHOD \n originalUrl \n unix-ms-timestamp \n nonce \n sha256(rawBody)
 *
 * The private key never leaves the endpoint. The server stores only the
 * public key, so a database leak cannot be used to impersonate an agent.
 */
export function verifyAgentRequest(req: Request): AgentVerification {
  const agentId = headerValue(req, 'x-oat-agent').trim();
  const timestamp = headerValue(req, 'x-oat-timestamp').trim();
  const nonce = headerValue(req, 'x-oat-nonce').trim();
  const signature = headerValue(req, 'x-oat-signature').trim();

  if (!agentId || !timestamp || !nonce || !signature) {
    return { status: 401, error: 'Missing agent authentication headers' };
  }
  if (!/^agt_[a-f0-9-]{20,64}$/i.test(agentId) || !/^[a-f0-9]{24,64}$/i.test(nonce)) {
    return { status: 401, error: 'Invalid agent authentication headers' };
  }

  const sentAt = Number(timestamp);
  if (!Number.isFinite(sentAt) || Math.abs(Date.now() - sentAt) > MAX_CLOCK_SKEW_MS) {
    return { status: 401, error: 'Agent request timestamp is outside the allowed window' };
  }

  const agent = db.prepare('SELECT * FROM agents WHERE id = ?').get(agentId) as unknown as AgentRow | undefined;
  if (!agent) {
    return { status: 401, error: 'Unknown agent' };
  }
  if (agent.revoked_at || agent.status === 'REVOKED') {
    return { status: 403, error: 'Agent has been revoked' };
  }

  const now = Date.now();
  pruneNonces(now);
  const nonceKey = `${agentId}:${nonce}`;
  if (seenNonces.has(nonceKey)) {
    return { status: 409, error: 'Replay detected: nonce already used' };
  }

  const rawBody = (req as Request & { rawBody?: Buffer | string }).rawBody;
  const body = Buffer.isBuffer(rawBody)
    ? rawBody
    : Buffer.from(typeof rawBody === 'string' ? rawBody : '', 'utf8');
  const canonical = `${req.method}\n${req.originalUrl}\n${sentAt}\n${nonce}\n${sha256Hex(body)}`;

  try {
    const publicKey = crypto.createPublicKey(agent.public_key);
    const signatureBytes = Buffer.from(signature, 'base64');
    if (signatureBytes.length !== 64) {
      return { status: 401, error: 'Invalid agent signature' };
    }
    const valid = crypto.verify(null, Buffer.from(canonical, 'utf8'), publicKey, signatureBytes);
    if (!valid) {
      return { status: 401, error: 'Invalid agent signature' };
    }
  } catch {
    return { status: 401, error: 'Invalid agent public key' };
  }

  // Only consume the nonce after a valid signature, so unauthenticated
  // traffic cannot burn an agent's nonces.
  seenNonces.set(nonceKey, now + NONCE_TTL_MS);

  try {
    db.prepare(
      "UPDATE agents SET last_seen = ?, status = CASE WHEN status = 'REVOKED' THEN status ELSE 'ACTIVE' END WHERE id = ?"
    ).run(new Date().toISOString(), agent.id);
  } catch {
    // A failed last_seen update must not reject valid telemetry.
  }

  return { agent };
}
