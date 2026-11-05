import { db } from '../database/db';

/**
 * Protected network (subnet) inventory.
 *
 * The operator declares the subnets that the platform protects (CIDR + zone +
 * firewall engine). Everything else on the Networks screen is derived from
 * real telemetry: traffic volume, observed hosts and risk level all come from
 * `security_events` and enrolled agents inside the subnet — never from
 * hard-coded demo values.
 */

export const NETWORK_ZONES = [
  'DMZ',
  'Internal Core',
  'Cloud VPC',
  'Corporate Office',
  'Database Cluster',
  'Payment Gateway',
  'Edge Proxy'
] as const;

export type NetworkZone = (typeof NETWORK_ZONES)[number];

export const DEFAULT_FIREWALL_ENGINE = 'OAT NGFW';

export interface ParsedCidr {
  cidr: string;
  network: number;
  mask: number;
  prefix: number;
}

export interface NetworkInput {
  name: string;
  cidr: string;
  gateway: string;
  zone: string;
  firewall: string;
  interfaceName: string;
  description: string;
}

const SEVERITY_RANK: Record<string, number> = {
  info: 0,
  low: 1,
  medium: 2,
  high: 3,
  critical: 4
};

const RANK_SEVERITY = ['Low', 'Low', 'Medium', 'High', 'Critical'];

export function ipv4ToInt(value: string): number | null {
  const parts = String(value || '').trim().split('.');
  if (parts.length !== 4) return null;
  let result = 0;
  for (const part of parts) {
    if (!/^\d{1,3}$/.test(part)) return null;
    const octet = Number(part);
    if (!Number.isInteger(octet) || octet < 0 || octet > 255) return null;
    result = (result * 256) + octet;
  }
  return result >>> 0;
}

export function intToIpv4(value: number): string {
  const int = value >>> 0;
  return [
    (int >>> 24) & 255,
    (int >>> 16) & 255,
    (int >>> 8) & 255,
    int & 255
  ].join('.');
}

/**
 * Accepts `10.0.0.0/24` or a bare address (treated as /32) and returns a
 * canonical, network-aligned CIDR. Returns null when the input is invalid.
 */
export function parseCidr(input: string): ParsedCidr | null {
  const raw = String(input || '').trim();
  if (!raw) return null;

  const [addressPart, prefixPart] = raw.split('/');
  const address = ipv4ToInt(addressPart);
  if (address === null) return null;

  let prefix = 32;
  if (prefixPart !== undefined) {
    if (!/^\d{1,2}$/.test(prefixPart)) return null;
    prefix = Number(prefixPart);
    if (prefix < 0 || prefix > 32) return null;
  }

  const mask = prefix === 0 ? 0 : (0xffffffff << (32 - prefix)) >>> 0;
  const network = (address & mask) >>> 0;

  return {
    cidr: `${intToIpv4(network)}/${prefix}`,
    network,
    mask,
    prefix
  };
}

export function ipInCidr(ip: string, parsed: ParsedCidr): boolean {
  const value = ipv4ToInt(ip);
  if (value === null) return false;
  return ((value & parsed.mask) >>> 0) === parsed.network;
}

/** `10.0.0.5:443` / `10.0.0.5` → `10.0.0.5`; leaves other values untouched. */
function extractIpCandidate(value: string): string {
  const raw = String(value || '').trim();
  if (!raw) return '';
  if (raw.startsWith('[')) {
    const end = raw.indexOf(']');
    return end > 0 ? raw.slice(1, end) : raw;
  }
  const first = raw.indexOf(':');
  const last = raw.lastIndexOf(':');
  return first > -1 && first === last ? raw.slice(0, first) : raw;
}

/** First usable host of the subnet, used when the operator leaves gateway blank. */
export function suggestGateway(parsed: ParsedCidr): string {
  if (parsed.prefix >= 31) return intToIpv4(parsed.network);
  return intToIpv4(parsed.network + 1);
}

function text(value: unknown, maxLength: number): string {
  return String(value ?? '').trim().slice(0, maxLength);
}

export type ValidationResult =
  | { ok: true; value: NetworkInput }
  | { ok: false; error: string };

export function validateNetworkInput(body: any): ValidationResult {
  const name = text(body?.name, 255);
  if (!name) return { ok: false, error: 'Subnet name is required.' };

  const parsed = parseCidr(body?.cidr);
  if (!parsed) {
    return {
      ok: false,
      error: 'CIDR is invalid. Use IPv4 notation such as 10.240.10.0/24 (or a single address for /32).'
    };
  }

  const rawGateway = text(body?.gateway, 64);
  const gateway = rawGateway || suggestGateway(parsed);
  if (ipv4ToInt(gateway) === null) {
    return { ok: false, error: 'Default gateway must be a valid IPv4 address.' };
  }

  const requestedZone = text(body?.zone, 64);
  const zone = requestedZone || 'DMZ';

  const firewall = text(body?.firewall, 128) || DEFAULT_FIREWALL_ENGINE;
  const interfaceName = text(body?.interface ?? body?.interfaceName, 64) || 'eth0';
  const description = text(body?.description, 1000);

  return {
    ok: true,
    value: {
      name,
      cidr: parsed.cidr,
      gateway,
      zone,
      firewall,
      interfaceName,
      description
    }
  };
}

interface NetworkStats {
  devicesCount: number;
  riskLevel: string;
  trafficVolume: number;
}

/**
 * Aggregate the last 24h of real telemetry per declared subnet in one pass.
 */
export function collectNetworkStats(orgId: string, rows: any[]): Map<string, NetworkStats> {
  const stats = new Map<string, NetworkStats>();
  if (!rows.length) return stats;

  // `security_events.timestamp` stores both ISO strings (ingested events) and
  // MySQL datetime strings (manually inserted rows). A space-separated cutoff
  // compares correctly against both because 'T' sorts after ' '.
  const since = new Date(Date.now() - 24 * 60 * 60 * 1000)
    .toISOString()
    .slice(0, 19)
    .replace('T', ' ');

  let events: Array<{ destination_ip: string | null; severity: string | null }> = [];
  try {
    events = db.prepare(`
      SELECT destination_ip, severity
        FROM security_events
       WHERE organization_id = ? AND timestamp >= ?
    `).all(orgId, since) as any[];
  } catch {
    events = [];
  }

  let agentIps: Array<{ ip: string | null }> = [];
  try {
    agentIps = db.prepare(`
      SELECT ip FROM agents
       WHERE organization_id = ? AND revoked_at IS NULL AND ip IS NOT NULL AND ip <> ''
    `).all(orgId) as any[];
  } catch {
    agentIps = [];
  }

  // Detected threats carry the normalized severity from the detection engine,
  // which is more reliable than the raw event severity for risk scoring.
  let threats: Array<{ target: string | null; destination: string | null; severity: string | null }> = [];
  try {
    threats = db.prepare(`
      SELECT target, destination, severity
        FROM threats
       WHERE organization_id = ? AND timestamp >= ?
    `).all(orgId, since) as any[];
  } catch {
    threats = [];
  }

  for (const row of rows) {
    const parsed = parseCidr(row.cidr);
    if (!parsed) continue;

    const hosts = new Set<string>();
    let trafficVolume = 0;
    let maxRank = 0;

    for (const event of events) {
      const ip = String(event.destination_ip || '');
      if (!ipInCidr(ip, parsed)) continue;
      trafficVolume += 1;
      hosts.add(ip);
      const rank = SEVERITY_RANK[String(event.severity || '').toLowerCase()] ?? 0;
      if (rank > maxRank) maxRank = rank;
    }

    for (const agent of agentIps) {
      const ip = String(agent.ip || '');
      if (ipInCidr(ip, parsed)) hosts.add(ip);
    }

    for (const threat of threats) {
      const candidate = extractIpCandidate(threat.destination || '') || extractIpCandidate(threat.target || '');
      if (!ipInCidr(candidate, parsed)) continue;
      const rank = SEVERITY_RANK[String(threat.severity || '').toLowerCase()] ?? 0;
      if (rank > maxRank) maxRank = rank;
    }

    stats.set(String(row.id), {
      devicesCount: hosts.size,
      riskLevel: RANK_SEVERITY[maxRank] || 'Low',
      trafficVolume
    });
  }

  return stats;
}

export function serializeNetwork(row: any, stats?: NetworkStats) {
  return {
    id: row.id,
    name: row.name,
    cidr: row.cidr,
    gateway: row.gateway,
    zone: row.zone || 'DMZ',
    firewall: row.firewall || DEFAULT_FIREWALL_ENGINE,
    interface: row.interface || 'eth0',
    description: row.description || '',
    status: row.status || 'Online',
    createdAt: row.created_at || '',
    devicesCount: stats?.devicesCount ?? 0,
    riskLevel: stats?.riskLevel ?? 'Low',
    trafficVolume: stats?.trafficVolume ?? 0
  };
}

export function listNetworks(orgId: string) {
  const rows = db.prepare(
    'SELECT * FROM networks WHERE organization_id = ? ORDER BY created_at DESC'
  ).all(orgId) as any[];

  const stats = collectNetworkStats(orgId, rows);
  return rows.map(row => serializeNetwork(row, stats.get(String(row.id))));
}

export function getNetworkRow(orgId: string, id: string) {
  return db.prepare(
    'SELECT * FROM networks WHERE id = ? AND organization_id = ?'
  ).get(id, orgId) as any;
}

export function findDuplicateCidr(orgId: string, cidr: string, excludeId?: string) {
  const parsed = parseCidr(cidr);
  if (!parsed) return null;
  const rows = db.prepare(
    'SELECT id, cidr FROM networks WHERE organization_id = ?'
  ).all(orgId) as Array<{ id: string; cidr: string }>;
  return rows.find(row => row.id !== excludeId && parseCidr(row.cidr)?.cidr === parsed.cidr) || null;
}
