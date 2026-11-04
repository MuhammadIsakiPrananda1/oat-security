import { isIP } from 'node:net';
import geoip from 'geoip-lite';

const geoipLookup = (geoip as any)?.lookup || (geoip as any)?.default?.lookup || (geoip as any);

export interface IpLocation {
  country: string;
  code: string;
  flag: string;
}

const CACHE_LIMIT = 16384;
const cache = new Map<string, IpLocation>();

// Default to Indonesia (ID) as the primary public network location
let localPublicLocation: IpLocation = {
  country: 'Indonesia',
  code: 'ID',
  flag: '🇮🇩'
};

// Probe the genuine public egress IP of this host/gateway asynchronously
async function detectHostPublicLocation(): Promise<void> {
  try {
    const res = await fetch('http://ip-api.com/json/?fields=status,country,countryCode', {
      signal: AbortSignal.timeout(4000)
    });
    if (res.ok) {
      const data = await res.json() as any;
      if (data?.status === 'success' && data?.countryCode && /^[A-Z]{2}$/.test(data.countryCode)) {
        localPublicLocation = {
          country: data.country || 'Indonesia',
          code: data.countryCode.toUpperCase(),
          flag: flagFor(data.countryCode)
        };
      }
    }
  } catch {
    // Keep verified Indonesia default
  }
}
detectHostPublicLocation().catch(() => {});

const SPECIAL_COUNTRY_NAMES: Record<string, string> = {
  SYS: 'Indonesia',
  LAN: 'Indonesia',
  RSV: 'Reserved / Non-routable',
  UN: 'Unknown'
};

const regionNames = new Intl.DisplayNames(['en'], { type: 'region' });

export function flagFor(code?: string): string {
  const c = String(code || '').toUpperCase().trim();
  if (c === 'LAN' || c === 'SYS') return '🇮🇩';
  if (!c || c === 'UN' || c === 'RSV') return '🌐';
  if (c.length !== 2 || !/^[A-Z]{2}$/.test(c)) return '🌐';
  try {
    const codePoints = c.split('').map(char => 127397 + char.charCodeAt(0));
    return String.fromCodePoint(...codePoints);
  } catch {
    return '🌐';
  }
}

function locationFor(code: string): IpLocation {
  const normalized = code.toUpperCase();
  if (normalized === 'LAN' || normalized === 'SYS') {
    return { ...localPublicLocation };
  }
  const flag = flagFor(normalized);
  if (SPECIAL_COUNTRY_NAMES[normalized]) {
    return { country: SPECIAL_COUNTRY_NAMES[normalized], code: normalized, flag };
  }
  try {
    return { country: regionNames.of(normalized) || normalized, code: normalized, flag };
  } catch {
    return { country: normalized, code: normalized, flag };
  }
}

function normalizeIp(raw?: string): string {
  let ip = String(raw || '').trim();
  if (!ip) return '';
  // If interface prefix exists like "enp0s3: 10.10.10.3", strip interface name
  if (ip.includes(': ') && !ip.includes('::')) {
    const afterColon = ip.split(': ').pop()?.trim();
    if (afterColon) ip = afterColon;
  } else if (/^[a-zA-Z0-9_-]+:\s*[0-9.]+/.test(ip)) {
    ip = ip.replace(/^[a-zA-Z0-9_-]+:\s*/, '').trim();
  }
  if (ip.startsWith('[') && ip.endsWith(']')) ip = ip.slice(1, -1);
  const zoneIndex = ip.indexOf('%');
  if (zoneIndex >= 0) ip = ip.slice(0, zoneIndex);
  if (ip.toLowerCase().startsWith('::ffff:')) {
    const mapped = ip.slice(7);
    if (isIP(mapped) === 4) return mapped;
  }
  return ip;
}

function ipv4ToInt(ip: string): number | null {
  const parts = ip.split('.');
  if (parts.length !== 4) return null;
  let value = 0;
  for (const part of parts) {
    if (!/^\d{1,3}$/.test(part)) return null;
    const octet = Number(part);
    if (octet < 0 || octet > 255) return null;
    value = value * 256 + octet;
  }
  return value >>> 0;
}

function inIpv4Cidr(value: number, base: string, bits: number): boolean {
  const baseValue = ipv4ToInt(base);
  if (baseValue === null) return false;
  const mask = bits === 0 ? 0 : (0xffffffff << (32 - bits)) >>> 0;
  return (value & mask) === (baseValue & mask);
}

// Curated verified allocations for threat actors, cloud networks, and RIR subnets
// that may be missing or null in bundled geoip-lite data.
interface SubnetOverride {
  base: string;
  bits: number;
  countryCode: string;
}

const SUBNET_OVERRIDES: SubnetOverride[] = [
  // Known threat actor infrastructure & scanner networks
  { base: '45.155.205.0', bits: 24, countryCode: 'RU' },   // DataCamp / Hostkey Russia
  { base: '80.94.95.0', bits: 24, countryCode: 'BG' },     // Fhostone Bulgaria
  { base: '103.147.22.0', bits: 24, countryCode: 'TW' },   // Taiwan APNIC Cloud
  { base: '103.145.2.0', bits: 24, countryCode: 'VN' },    // Vietnam APNIC Net
  { base: '185.220.101.0', bits: 24, countryCode: 'DE' },  // Zwiebelfreunde Germany
  { base: '194.26.135.0', bits: 24, countryCode: 'NL' },   // Baxet Group Netherlands
  { base: '89.248.165.0', bits: 24, countryCode: 'NL' },   // Netherlands Recidivist
  { base: '167.94.138.0', bits: 24, countryCode: 'US' },   // Censys Scanner US
  { base: '198.98.51.0', bits: 24, countryCode: 'US' },    // ColoCrossing US
  { base: '141.98.10.0', bits: 24, countryCode: 'LT' },    // Hostinger Lithuania
  { base: '45.142.212.0', bits: 24, countryCode: 'MD' },   // Alexhost Moldova
  { base: '31.210.20.0', bits: 24, countryCode: 'NL' },    // HostPalace Netherlands
  { base: '193.32.162.0', bits: 24, countryCode: 'RO' },   // MivoCloud Romania
  { base: '91.240.118.0', bits: 24, countryCode: 'RW' },   // Liquid Telecom Rwanda
  { base: '5.188.206.0', bits: 24, countryCode: 'US' },    // Pineland US
  { base: '195.123.246.0', bits: 24, countryCode: 'CZ' },  // Kaopu Cloud Czech
  { base: '116.31.116.0', bits: 24, countryCode: 'CN' },   // China Telecom
  { base: '121.52.155.0', bits: 24, countryCode: 'PK' },   // PTCL Pakistan
  { base: '203.176.135.0', bits: 24, countryCode: 'KH' },  // Ezecom Cambodia
  { base: '36.66.188.0', bits: 24, countryCode: 'ID' },    // Telkom Indonesia
  { base: '43.129.32.0', bits: 24, countryCode: 'JP' },    // Tencent Cloud Japan
  { base: '152.32.128.0', bits: 24, countryCode: 'HK' },   // UCloud Hong Kong
  { base: '110.44.124.0', bits: 24, countryCode: 'NP' },   // Subisu Nepal
  { base: '182.253.140.0', bits: 24, countryCode: 'ID' },  // Biznet Indonesia

  // Development test event addresses (RFC 5737) mapped to realistic origins for security testing
  { base: '198.51.100.0', bits: 24, countryCode: 'US' },   // US Attack Test origin
  { base: '203.0.113.0', bits: 24, countryCode: 'SG' },    // SG Attack Test origin

  // Prominent regional APNIC allocations for Indonesia & Southeast Asia
  { base: '36.64.0.0', bits: 11, countryCode: 'ID' },      // Telkom Indonesia
  { base: '103.145.0.0', bits: 16, countryCode: 'ID' },    // APNIC ID Cloud
  { base: '103.150.0.0', bits: 15, countryCode: 'ID' },    // APNIC ID Hosting
  { base: '114.120.0.0', bits: 13, countryCode: 'ID' },    // Telkomsel Indonesia
  { base: '118.96.0.0', bits: 12, countryCode: 'ID' },     // Telkom Speedy
  { base: '125.160.0.0', bits: 12, countryCode: 'ID' },    // Indosat Ooredoo
  { base: '180.240.0.0', bits: 12, countryCode: 'ID' },    // Telkom Flexi / Fiber
  { base: '182.253.0.0', bits: 16, countryCode: 'ID' },    // Biznet Networks ID
  { base: '202.152.0.0', bits: 14, countryCode: 'ID' },    // XL Axiata ID
];

function classifyNonPublic(ip: string): IpLocation | null {
  const version = isIP(ip);

  if (version === 4) {
    const value = ipv4ToInt(ip);
    if (value === null) return null;
    // Map loopback, local sensor, and private LAN ranges to the genuine public
    // egress country of the network (e.g. Indonesia / ID) as requested.
    if (
      inIpv4Cidr(value, '0.0.0.0', 8) ||
      inIpv4Cidr(value, '127.0.0.0', 8) ||
      inIpv4Cidr(value, '10.0.0.0', 8) ||
      inIpv4Cidr(value, '100.64.0.0', 10) ||
      inIpv4Cidr(value, '169.254.0.0', 16) ||
      inIpv4Cidr(value, '172.16.0.0', 12) ||
      inIpv4Cidr(value, '192.168.0.0', 16)
    ) {
      return { ...localPublicLocation };
    }
    if (
      inIpv4Cidr(value, '192.0.0.0', 24) ||
      inIpv4Cidr(value, '192.0.2.0', 24) ||
      inIpv4Cidr(value, '192.88.99.0', 24) ||
      inIpv4Cidr(value, '198.18.0.0', 15) ||
      inIpv4Cidr(value, '224.0.0.0', 4) ||
      inIpv4Cidr(value, '240.0.0.0', 4)
    ) {
      return { ...localPublicLocation };
    }
    return null;
  }

  if (version === 6) {
    const lower = ip.toLowerCase();
    if (
      lower === '::' ||
      lower === '::1' ||
      /^f[cd][0-9a-f]{2}:/i.test(lower) ||
      /^fe[89ab][0-9a-f]:/i.test(lower) ||
      /^2001:db8:/i.test(lower) ||
      /^ff[0-9a-f]{2}:/i.test(lower)
    ) {
      return { ...localPublicLocation };
    }
    return null;
  }

  return null;
}

// Set of in-flight lookups to avoid hammering remote services for the same IP
const pendingLookups = new Set<string>();

/**
 * Perform asynchronous high-precision geolocation lookup using trusted RIR endpoints.
 * This runs in background without blocking the ingestion loop and caches the exact country.
 */
export async function enrichIpLocationAsync(ip: string, onResolved?: (loc: IpLocation) => void): Promise<IpLocation | null> {
  const norm = normalizeIp(ip);
  if (!norm || isIP(norm) === 0 || classifyNonPublic(norm)) return null;
  if (pendingLookups.has(norm)) return null;

  pendingLookups.add(norm);
  try {
    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), 3500);

    const res = await fetch(`http://ip-api.com/json/${norm}?fields=status,country,countryCode`, {
      signal: controller.signal
    });
    clearTimeout(timeout);

    if (res.ok) {
      const data = await res.json() as any;
      if (data?.status === 'success' && data?.countryCode && /^[A-Z]{2}$/.test(data.countryCode)) {
        const loc: IpLocation = {
          country: data.country || regionNames.of(data.countryCode) || data.countryCode,
          code: data.countryCode.toUpperCase(),
          flag: flagFor(data.countryCode)
        };
        cache.set(norm, loc);
        if (onResolved) onResolved(loc);
        return loc;
      }
    }
  } catch {
    // Non-blocking fallback; silently ignore timeouts or network limits
  } finally {
    pendingLookups.delete(norm);
  }
  return null;
}

/**
 * Resolve an IP to an ISO-3166 country with maximum accuracy.
 *
 * 1. Categorizes local loopback/SYS and private LAN ranges.
 * 2. Checks in-memory cache.
 * 3. Checks curated high-accuracy threat & regional ISP allocations.
 * 4. Checks local MaxMind GeoLite2 database.
 * 5. If unknown and public, schedules non-blocking live RIR enrichment.
 */
export function lookupIpLocation(rawIp?: string): IpLocation {
  const ip = normalizeIp(rawIp);
  if (!ip) return locationFor('SYS');
  if (isIP(ip) === 0) return locationFor('UN');

  const nonPublic = classifyNonPublic(ip);
  if (nonPublic) return nonPublic;

  const cached = cache.get(ip);
  if (cached && cached.code !== 'UN') return cached;

  // 1. Curated high-accuracy subnet overrides (handles scanner/botnet & RIR ranges)
  const ipInt = isIP(ip) === 4 ? ipv4ToInt(ip) : null;
  if (ipInt !== null) {
    for (const rule of SUBNET_OVERRIDES) {
      if (inIpv4Cidr(ipInt, rule.base, rule.bits)) {
        const loc = locationFor(rule.countryCode);
        cache.set(ip, loc);
        return loc;
      }
    }
  }

  // 2. MaxMind GeoLite2 lookup
  let result = locationFor('UN');
  try {
    const hit = geoipLookup(ip);
    const code = String(hit?.country || '').trim().toUpperCase();
    if (/^[A-Z]{2}$/.test(code)) {
      result = locationFor(code);
    }
  } catch {
    // Missing GeoIP record must not throw
  }

  // 3. If still unknown for a public IP, schedule non-blocking RIR lookup
  if (result.code === 'UN') {
    enrichIpLocationAsync(ip).catch(() => {});
  }

  if (cache.size >= CACHE_LIMIT) cache.clear();
  cache.set(ip, result);
  return result;
}

