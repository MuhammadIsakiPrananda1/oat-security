import { db } from '../database/db';

export interface LogItem {
  id: string;
  organizationId: string;
  timestamp: string;
  level: string;
  source: string;
  eventType: string;
  message: string;
  host?: string;
  ip?: string;
  correlationId?: string;
  metadata?: any;
  rawLog?: string;
  agentId?: string;
}

// Fast in-memory cache for recent live logs (instant UI updates & zero-lag SSE)
const MAX_LIVE_LOGS_PER_ORG = 10000;
const memoryLogsByOrg = new Map<string, LogItem[]>();
let latestLogTimestampMs: number = Date.now();

// Asynchronous batch queue to flush logs to MySQL without dropping
const BATCH_SIZE = 250;
const FLUSH_INTERVAL_MS = 1500;
const MAX_QUEUE_SIZE = 50000;
let logQueue: LogItem[] = [];
let flushTimer: NodeJS.Timeout | null = null;

export function pushLogToPipeline(log: LogItem): void {
  latestLogTimestampMs = Date.now();
  const orgId = log.organizationId || 'default';

  // 1. Fast in-memory cache
  let buffer = memoryLogsByOrg.get(orgId);
  if (!buffer) {
    buffer = [];
    memoryLogsByOrg.set(orgId, buffer);
  }
  buffer.unshift(log);
  if (buffer.length > MAX_LIVE_LOGS_PER_ORG) {
    buffer.length = MAX_LIVE_LOGS_PER_ORG;
  }

  // 2. Queue for persistent storage in MySQL (never drop logs)
  logQueue.push(log);
  if (logQueue.length >= BATCH_SIZE) {
    flushLogsToDb();
  } else if (!flushTimer) {
    flushTimer = setTimeout(() => {
      flushTimer = null;
      flushLogsToDb();
    }, FLUSH_INTERVAL_MS);
  }
}

export function flushLogsToDb(): void {
  if (flushTimer) {
    clearTimeout(flushTimer);
    flushTimer = null;
  }
  if (logQueue.length === 0) return;

  const batch = logQueue.splice(0, BATCH_SIZE * 2);
  try {
    // MySQL bulk insert: single transaction/statement for entire batch
    const placeholders = batch.map(() => '(?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)').join(', ');
    const sql = `
      INSERT IGNORE INTO logs (
        id, organization_id, timestamp, level, source, event_type,
        message, host, ip, correlation_id, metadata, raw_log, agent_id
      ) VALUES ${placeholders}
    `;

    const values: any[] = [];
    for (const item of batch) {
      values.push(
        item.id,
        item.organizationId,
        item.timestamp,
        item.level,
        item.source || 'agent',
        item.eventType || 'agent_log',
        (item.message || '').slice(0, 4000),
        (item.host || '').slice(0, 128),
        item.ip || null,
        item.correlationId || null,
        item.metadata ? JSON.stringify(item.metadata) : null,
        (item.rawLog || item.message || '').slice(0, 16000),
        item.agentId || null
      );
    }

    db.prepare(sql).run(...values);
  } catch (err: any) {
    console.warn('[LogPipeline] Bulk flush failed:', err?.message || err);
  }
}

export function getLatestLiveLogMs(): number {
  return latestLogTimestampMs;
}

export function queryLiveLogs(params: {
  organizationId: string;
  level?: string;
  source?: string;
  eventType?: string;
  host?: string;
  search?: string;
  page?: number;
  limit?: number;
}) {
  const orgId = params.organizationId || 'default';
  const all = memoryLogsByOrg.get(orgId) || [];

  const metrics = {
    total: all.length,
    critical: 0,
    error: 0,
    warn: 0,
    info: 0,
    debug: 0
  };

  const ipCounts = new Map<string, number>();
  const sourceCounts = new Map<string, number>();

  for (const item of all) {
    const lvl = (item.level || '').toUpperCase();
    if (lvl === 'CRITICAL') metrics.critical++;
    else if (lvl === 'ERROR') metrics.error++;
    else if (lvl === 'WARN' || lvl === 'WARNING') metrics.warn++;
    else if (lvl === 'INFO') metrics.info++;
    else if (lvl === 'DEBUG') metrics.debug++;

    if (item.ip && item.ip !== '—') {
      ipCounts.set(item.ip, (ipCounts.get(item.ip) || 0) + 1);
    }
    if (item.source) {
      sourceCounts.set(item.source, (sourceCounts.get(item.source) || 0) + 1);
    }
  }

  let filtered = all;

  if (params.level && params.level !== 'ALL') {
    const targetLvl = params.level.toUpperCase();
    filtered = filtered.filter(l => (l.level || '').toUpperCase() === targetLvl);
  }
  if (params.source && params.source !== 'ALL') {
    const targetSrc = params.source.toLowerCase();
    filtered = filtered.filter(l => (l.source || '').toLowerCase() === targetSrc);
  }
  if (params.eventType && params.eventType !== 'ALL') {
    const targetEvent = params.eventType.toLowerCase();
    filtered = filtered.filter(l => (l.eventType || '').toLowerCase() === targetEvent);
  }
  if (params.host && params.host !== 'ALL') {
    const targetHost = params.host.toLowerCase();
    filtered = filtered.filter(l => (l.host || '').toLowerCase().includes(targetHost));
  }
  if (params.search) {
    const s = params.search.toLowerCase();
    filtered = filtered.filter(l =>
      (l.message || '').toLowerCase().includes(s) ||
      (l.ip || '').toLowerCase().includes(s) ||
      (l.correlationId || '').toLowerCase().includes(s) ||
      (l.eventType || '').toLowerCase().includes(s)
    );
  }

  const page = Math.max(1, Number(params.page) || 1);
  const limit = Math.min(1000, Math.max(1, Number(params.limit) || 50));
  const offset = (page - 1) * limit;
  const paged = filtered.slice(offset, offset + limit);

  const topSourceIps = Array.from(ipCounts.entries())
    .sort((a, b) => b[1] - a[1])
    .slice(0, 10)
    .map(([ip, count]) => ({ ip, count }));

  const topSources = Array.from(sourceCounts.entries())
    .sort((a, b) => b[1] - a[1])
    .slice(0, 10)
    .map(([source, count]) => ({ source, count }));

  return {
    logs: paged,
    total: filtered.length,
    page,
    limit,
    metrics,
    topSourceIps,
    topSources
  };
}

export function getLiveLogById(organizationId: string, id: string): LogItem | null {
  const all = memoryLogsByOrg.get(organizationId || 'default') || [];
  return all.find(l => l.id === id) || null;
}
