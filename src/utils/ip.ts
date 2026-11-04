/**
 * Classify private/loopback addresses locally. Public IP geolocation is done
 * on the server with a GeoIP database; this helper only prevents client-side
 * fallbacks from labelling LAN traffic as a random country.
 */
export type LocalIpClass = 'SYS' | 'LAN' | null;

export function extractIpOnly(raw?: string): string {
  let s = String(raw || '').trim();
  if (!s) return '0.0.0.0';
  if (s.includes(': ') && !s.includes('::')) {
    const after = s.split(': ').pop()?.trim();
    if (after) s = after;
  } else if (/^[a-zA-Z0-9_-]+:\s*[0-9.]+/.test(s)) {
    s = s.replace(/^[a-zA-Z0-9_-]+:\s*/, '').trim();
  }
  return s;
}

export function classifyLocalIp(ip?: string): LocalIpClass {
  const raw = extractIpOnly(ip).toLowerCase();
  if (!raw) return 'SYS';
  if (raw === '0.0.0.0' || raw === '::' || raw === '127.0.0.1' || raw === '::1') return 'SYS';

  const v4 = raw.startsWith('::ffff:') ? raw.slice(7) : raw;
  if (/^127\./.test(v4) || v4 === '0.0.0.0') return 'SYS';
  if (
    /^10\./.test(v4) ||
    /^192\.168\./.test(v4) ||
    /^172\.(1[6-9]|2\d|3[01])\./.test(v4) ||
    /^169\.254\./.test(v4) ||
    /^100\.(6[4-9]|[7-9]\d|1[01]\d|12[0-7])\./.test(v4)
  ) {
    return 'LAN';
  }
  if (raw === '::1' || /^fe[89ab][0-9a-f]:/.test(raw) || /^f[cd][0-9a-f]{2}:/.test(raw)) {
    return raw === '::1' ? 'SYS' : 'LAN';
  }
  return null;
}

const regionNames = typeof Intl !== 'undefined' && Intl.DisplayNames
  ? new Intl.DisplayNames(['en'], { type: 'region' })
  : null;

/**
 * Returns a high-quality emoji flag for a given ISO 2-letter country code.
 * Local/LAN addresses resolve to the genuine public network origin (Indonesia 🇮🇩).
 */
export function getCountryFlag(countryCode?: string): string {
  const code = String(countryCode || '').toUpperCase().trim();
  if (code === 'LAN' || code === 'SYS') return '🇮🇩';
  if (!code || code === 'UN' || code === '—') return '🌐';
  if (code === 'RSV') return '🔒';
  if (code.length !== 2 || !/^[A-Z]{2}$/.test(code)) return '🌐';
  try {
    const codePoints = code.split('').map(char => 127397 + char.charCodeAt(0));
    return String.fromCodePoint(...codePoints);
  } catch {
    return '🌐';
  }
}

/**
 * Resolve display name for country code with clean fallbacks.
 * Local/LAN addresses resolve to genuine public origin (Indonesia).
 */
export function getCountryName(countryCode?: string, fallbackName?: string): string {
  if (fallbackName && fallbackName !== 'Unknown' && fallbackName !== 'UN' && fallbackName !== '—' && fallbackName !== 'Local Network' && fallbackName !== 'Local Sensor') {
    return fallbackName;
  }
  const code = String(countryCode || '').toUpperCase().trim();
  if (code === 'LAN' || code === 'SYS') return 'Indonesia';
  if (code === 'RSV') return 'Reserved / Lab';
  if (code === 'UN' || !code) return 'Unknown Origin';
  if (code.length === 2 && regionNames) {
    try {
      return regionNames.of(code) || code;
    } catch {
      return code;
    }
  }
  return code;
}

