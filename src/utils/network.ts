/**
 * Client-side helpers for the Networks module. They mirror the validation in
 * `server/services/networkInventory.ts` so operators get instant feedback
 * before the request reaches the API.
 */

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

export interface ParsedCidr {
  cidr: string;
  network: number;
  mask: number;
  prefix: number;
}

/** Accepts `10.0.0.0/24` or a bare IPv4 address (treated as /32). */
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

/** First usable host of the subnet (used when gateway is left blank). */
export function suggestGateway(cidr: string): string {
  const parsed = parseCidr(cidr);
  if (!parsed) return '';
  return intToIpv4(parsed.prefix >= 31 ? parsed.network : parsed.network + 1);
}

export function isIpv4(value: string): boolean {
  return ipv4ToInt(value) !== null;
}
