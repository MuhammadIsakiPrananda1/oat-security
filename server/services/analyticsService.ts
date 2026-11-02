import { db } from '../database/db';
import { lookupIpLocation } from './geoIpService';

/**
 * Security Telemetry Analytics.
 *
 * Every figure is derived from `security_events` rows written by the WAF,
 * firewall and endpoint agents. There is no synthetic baseline: an empty
 * database produces an empty report.
 */

export interface TelemetryAnalytics {
  generatedAt: string;
  windowHours: number;
  metrics: {
    totalRequests: number;
    blocked: number;
    allowed: number;
    challenged: number;
    rateLimited: number;
    logged: number;
    uniqueSources: number;
    blockRate: string;
  };
  topAttackingIps: Array<{
    ip: string;
    country: string;
    countryCode: string;
    asn: string;
    count: number;
    threat: string;
  }>;
  topTargetedApps: Array<{
    name: string;
    requests: number;
    blocked: number;
    pctBlocked: string;
  }>;
  responseCodes: Array<{
    code: string;
    count: number;
    pct: string;
    color: string;
  }>;
  actions: Array<{
    action: string;
    count: number;
    pct: string;
    color: string;
  }>;
  timeline: Array<{
    hour: string;
    total: number;
    blocked: number;
  }>;
}

const BLOCK_ACTIONS = ['BLOCK', 'BLOCKED', 'DENY', 'DROP'];

const ACTION_COLORS: Record<string, string> = {
  BLOCK: 'bg-rose-500',
  BLOCKED: 'bg-rose-500',
  DENY: 'bg-rose-500',
  DROP: 'bg-rose-500',
  RATE_LIMIT: 'bg-amber-500',
  CHALLENGE: 'bg-amber-500',
  LOG: 'bg-sky-500',
  ALLOW: 'bg-emerald-500',
  DETECT: 'bg-indigo-500'
};

function sinceIso(hours: number): string {
  return new Date(Date.now() - hours * 60 * 60 * 1000).toISOString();
}

function bucketKey(date: Date): string {
  const d = new Date(date);
  d.setMinutes(0, 0, 0);
  const pad = (n: number) => String(n).padStart(2, '0');
  return `${d.getFullYear()}-${pad(d.getMonth() + 1)}-${pad(d.getDate())} ${pad(d.getHours())}:00`;
}

export function getTelemetryAnalytics(organizationId: string, windowHours = 24): TelemetryAnalytics {
  const hours = Math.min(Math.max(windowHours, 1), 24 * 30);
  const since = sinceIso(hours);

  const totals = db.prepare(`
    SELECT
      COUNT(*) AS total,
      SUM(CASE WHEN action IN ('BLOCK','BLOCKED','DENY','DROP') THEN 1 ELSE 0 END) AS blocked,
      SUM(CASE WHEN action IN ('CHALLENGE') THEN 1 ELSE 0 END) AS challenged,
      SUM(CASE WHEN action IN ('RATE_LIMIT') THEN 1 ELSE 0 END) AS rate_limited,
      SUM(CASE WHEN action IN ('LOG') THEN 1 ELSE 0 END) AS logged,
      COUNT(DISTINCT source_ip) AS unique_sources
    FROM security_events
    WHERE organization_id = ? AND timestamp >= ?
  `).get(organizationId, since) as any;

  const total = Number(totals?.total) || 0;
  const blocked = Number(totals?.blocked) || 0;
  const challenged = Number(totals?.challenged) || 0;
  const rateLimited = Number(totals?.rate_limited) || 0;
  const logged = Number(totals?.logged) || 0;

  const attackingIps = db.prepare(`
    SELECT source_ip AS ip, MAX(threat_name) AS threat, COUNT(*) AS count
    FROM security_events
    WHERE organization_id = ?
      AND timestamp >= ?
      AND action IN ('BLOCK','BLOCKED','DENY','DROP','CHALLENGE','RATE_LIMIT')
    GROUP BY source_ip
    ORDER BY count DESC
    LIMIT 5
  `).all(organizationId, since) as Array<{ ip: string; threat: string | null; count: number }>;

  const topAttackingIps = attackingIps.map(item => {
    const geo = lookupIpLocation(item.ip);
    return {
      ip: item.ip,
      country: geo.country,
      countryCode: geo.code,
      // The local GeoIP database has no ASN data. Empty beats invented.
      asn: '',
      count: Number(item.count) || 0,
      threat: item.threat || 'Perimeter Ingress Violation'
    };
  });

  const appRows = db.prepare(`
    SELECT application AS name,
           COUNT(*) AS requests,
           SUM(CASE WHEN action IN ('BLOCK','BLOCKED','DENY','DROP') THEN 1 ELSE 0 END) AS blocked
    FROM security_events
    WHERE organization_id = ? AND timestamp >= ?
    GROUP BY application
    ORDER BY requests DESC
    LIMIT 5
  `).all(organizationId, since) as Array<{ name: string; requests: number; blocked: number }>;

  const topTargetedApps = appRows.map(app => {
    const requests = Number(app.requests) || 0;
    const blockedCount = Number(app.blocked) || 0;
    return {
      name: app.name,
      requests,
      blocked: blockedCount,
      pctBlocked: requests > 0 ? `${((blockedCount / requests) * 100).toFixed(2)}%` : '0.00%'
    };
  });

  const codeRows = db.prepare(`
    SELECT status_code AS code, COUNT(*) AS count
    FROM security_events
    WHERE organization_id = ? AND timestamp >= ? AND status_code IS NOT NULL
    GROUP BY status_code
    ORDER BY count DESC
  `).all(organizationId, since) as Array<{ code: number; count: number }>;

  const totalStatus = codeRows.reduce((acc, row) => acc + (Number(row.count) || 0), 0);
  const responseCodes = codeRows.map(row => {
    const code = Number(row.code);
    const count = Number(row.count) || 0;
    let label = String(code);
    let color = 'bg-zinc-500';
    if (code >= 200 && code < 300) { label = `${code} OK`; color = 'bg-emerald-500'; }
    else if (code >= 300 && code < 400) { label = `${code} Redirect`; color = 'bg-sky-500'; }
    else if (code === 401) { label = `${code} Unauthorized`; color = 'bg-amber-500'; }
    else if (code === 403) { label = `${code} Forbidden (Blocked)`; color = 'bg-rose-500'; }
    else if (code === 404) { label = `${code} Not Found`; color = 'bg-zinc-500'; }
    else if (code === 429) { label = `${code} Rate Limited`; color = 'bg-amber-500'; }
    else if (code >= 500) { label = `${code} Server Error`; color = 'bg-purple-500'; }

    return {
      code: label,
      count,
      pct: totalStatus > 0 ? `${((count / totalStatus) * 100).toFixed(2)}%` : '0%',
      color
    };
  });

  const actionRows = db.prepare(`
    SELECT action, COUNT(*) AS count
    FROM security_events
    WHERE organization_id = ? AND timestamp >= ?
    GROUP BY action
    ORDER BY count DESC
  `).all(organizationId, since) as Array<{ action: string; count: number }>;

  const totalActions = actionRows.reduce((acc, row) => acc + (Number(row.count) || 0), 0);
  const actions = actionRows.map(row => {
    const action = String(row.action || 'LOG').toUpperCase();
    const count = Number(row.count) || 0;
    return {
      action,
      count,
      pct: totalActions > 0 ? `${((count / totalActions) * 100).toFixed(2)}%` : '0%',
      color: ACTION_COLORS[action] || 'bg-zinc-500'
    };
  });

  const timelineRows = db.prepare(`
    SELECT DATE_FORMAT(REPLACE(timestamp, 'T', ' '), '%Y-%m-%d %H:00') AS hour,
           COUNT(*) AS total,
           SUM(CASE WHEN action IN ('BLOCK','BLOCKED','DENY','DROP') THEN 1 ELSE 0 END) AS blocked
    FROM security_events
    WHERE organization_id = ? AND timestamp >= ?
    GROUP BY hour
    ORDER BY hour ASC
  `).all(organizationId, since) as Array<{ hour: string; total: number; blocked: number }>;

  const timelineMap = new Map<string, { total: number; blocked: number }>();
  for (const row of timelineRows) {
    timelineMap.set(String(row.hour), {
      total: Number(row.total) || 0,
      blocked: Number(row.blocked) || 0
    });
  }

  const timeline: TelemetryAnalytics['timeline'] = [];
  const now = new Date();
  for (let i = hours - 1; i >= 0; i -= 1) {
    const hourDate = new Date(now.getTime() - i * 60 * 60 * 1000);
    const key = bucketKey(hourDate);
    const value = timelineMap.get(key);
    timeline.push({ hour: key, total: value?.total || 0, blocked: value?.blocked || 0 });
  }

  return {
    generatedAt: new Date().toISOString(),
    windowHours: hours,
    metrics: {
      totalRequests: total,
      blocked,
      allowed: Math.max(total - blocked - challenged - rateLimited, 0),
      challenged,
      rateLimited,
      logged,
      uniqueSources: Number(totals?.unique_sources) || 0,
      blockRate: total > 0 ? `${((blocked / total) * 100).toFixed(2)}%` : '0.00%'
    },
    topAttackingIps,
    topTargetedApps,
    responseCodes,
    actions,
    timeline
  };
}

// Re-exported for callers that only need the blocking predicate.
export { BLOCK_ACTIONS };
