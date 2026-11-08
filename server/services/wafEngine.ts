import { Request, Response, NextFunction } from 'express';
import { db } from '../database/db';
import { lookupIpLocation } from './geoIpService';
import { SecurityEventBus } from '../utils/eventBus';

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

export interface WafPolicy {
  engine_enabled: number;        // 0 | 1
  mode: string;                  // 'block' | 'monitor'
  rate_limit_requests: number;   // requests per window
  rate_limit_window_s: number;   // window in seconds
  ip_allowlist: string;          // comma-separated CIDRs / IPs
  ip_blocklist: string;          // comma-separated CIDRs / IPs
  geo_block_countries: string;   // comma-separated country codes
  bot_protection_enabled: number; // 0 | 1
  updated_at: string;
}

export interface WafRule {
  id: string;
  rule_id: string;
  name: string;
  category: string;
  severity: string;
  action: string;   // 'BLOCK' | 'LOG' | 'CHALLENGE'
  enabled: number;  // 0 | 1
  description: string | null;
  pattern: string | null;
}

export interface WafDecision {
  allowed: boolean;
  action: 'PASS' | 'BLOCK' | 'CHALLENGE' | 'RATE_LIMIT';
  reason: string;
  ruleId?: string;
  severity?: string;
}

// ---------------------------------------------------------------------------
// Rate-limit store  (in-memory, per-IP sliding window)
// ---------------------------------------------------------------------------

interface RateEntry { hits: number; windowStart: number }
const rateLimitStore = new Map<string, RateEntry>();

function checkRateLimit(ip: string, maxRequests: number, windowSec: number): boolean {
  const now = Date.now();
  const windowMs = windowSec * 1000;
  const entry = rateLimitStore.get(ip);

  if (!entry || now - entry.windowStart > windowMs) {
    rateLimitStore.set(ip, { hits: 1, windowStart: now });
    return true; // within limit
  }
  entry.hits++;
  if (entry.hits > maxRequests) return false; // exceeded
  return true;
}

// ---------------------------------------------------------------------------
// Geo classification
// ---------------------------------------------------------------------------

/** Returns a 2-letter ISO country code or 'LAN' / 'SYS' / 'RSV' / 'UN'. */
function classifyIp(ip: string): string {
  return lookupIpLocation(ip).code;
}

// ---------------------------------------------------------------------------
// Pattern matching for rule categories
// ---------------------------------------------------------------------------

function requestHaystack(req: Request): string {
  const url = req.url || '';
  let decodedUrl = '';
  try {
    decodedUrl = decodeURIComponent(url);
  } catch {
    decodedUrl = unescape(url);
  }
  const body = typeof req.body === 'string' ? req.body : JSON.stringify(req.body || {});
  const ua = String(req.headers['user-agent'] || '');
  return `${url} ${decodedUrl} ${body} ${ua}`;
}

/** Returns the matching pattern string if the request matches a rule pattern. */
function matchesRuleCategory(category: string, req: Request): string | null {
  const haystack = requestHaystack(req);
  const ua = String(req.headers['user-agent'] || '');

  switch (category.toLowerCase()) {
    case 'sql injection':
      return /(\bselect\b|\bunion\b|\bdrop\b|\binsert\b|\bupdate\b|\bdelete\b|\bexec\b|--|\/\*|\bor\b\s+\d+=\d+)/i.test(haystack)
        ? 'SQL injection pattern in request' : null;

    case 'xss': case 'xss filter': case 'cross-site scripting':
      return /(<script|javascript:|onerror=|onload=|<img[^>]+src=|<svg|alert\(|document\.cookie)/i.test(haystack)
        ? 'XSS pattern detected' : null;

    case 'path traversal': case 'lfi':
      return /(\.\.\/|\.\.\\|%2e%2e%2f|%252e)/i.test(haystack)
        ? 'Path traversal attempt' : null;

    case 'rce': case 'command injection': case 'remote code execution':
      return /(\$\(|`|;.*sh|cmd\.exe|\/bin\/|powershell|eval\(|exec\()/i.test(haystack)
        ? 'Command injection pattern' : null;

    case 'scanner': case 'vulnerability scanner':
      return /(nikto|nmap|masscan|sqlmap|nessus|openvas|acunetix|burpsuite|w3af|skipfish|dirbuster)/i.test(ua)
        ? 'Security scanner User-Agent' : null;

    case 'bad bot': case 'bot': case 'bot protection':
      return /(scrapy|zgrab|python-requests\/|go-http-client|curl\/|wget\/|libwww-perl)/i.test(ua)
        ? 'Bad bot User-Agent' : null;

    case 'rfi': case 'remote file inclusion':
      return /(https?:\/\/[^/]+\/.*\.(php|sh|py|rb|pl))/i.test(haystack)
        ? 'Remote file inclusion attempt' : null;

    default:
      return null;
  }
}

/**
 * A rule with an explicit pattern uses that PCRE as the match. Rules without a
 * pattern fall back to the built-in category detector. This is what makes
 * dashboard-created custom rules executable on the endpoint.
 */
function matchesWafRule(rule: WafRule, req: Request): string | null {
  const pattern = String(rule.pattern || '').trim();
  if (pattern) {
    try {
      const jsPattern = pattern.replace(/\(\?[imsx]+\)/gi, '');
      return new RegExp(jsPattern, 'i').test(requestHaystack(req))
        ? `Custom rule pattern matched: ${pattern}`
        : null;
    } catch {
      return null;
    }
  }
  return matchesRuleCategory(rule.category, req);
}

// ---------------------------------------------------------------------------
// Main WAF policy loader
// ---------------------------------------------------------------------------

function loadPolicy(orgId: string): WafPolicy | null {
  try {
    return (db.prepare('SELECT * FROM waf_policy WHERE organization_id = ?').get(orgId) as unknown) as WafPolicy | null;
  } catch {
    return null;
  }
}

function loadRules(orgId: string): WafRule[] {
  try {
    return (db.prepare('SELECT * FROM waf_rules WHERE organization_id = ? AND enabled = 1 ORDER BY created_at ASC').all(orgId) as unknown) as WafRule[];
  } catch {
    return [];
  }
}

// ---------------------------------------------------------------------------
// Decision engine
// ---------------------------------------------------------------------------

export function evaluateRequest(req: Request, orgId: string): WafDecision {
  const policy = loadPolicy(orgId);

  // --- 0. Engine kill-switch ---
  if (!policy || !policy.engine_enabled) {
    return { allowed: true, action: 'PASS', reason: 'WAF engine disabled' };
  }

  const ip = (req.headers['x-forwarded-for'] as string || req.ip || '').split(',')[0].trim();
  const mode = policy.mode || 'block';

  // --- 1. IP Allowlist (always pass) ---
  const allowlist = policy.ip_allowlist ? policy.ip_allowlist.split(',').map(s => s.trim()).filter(Boolean) : [];
  if (allowlist.length && allowlist.some(allowed => ip.startsWith(allowed.replace(/\/\d+$/, '')))) {
    return { allowed: true, action: 'PASS', reason: 'IP in allowlist' };
  }

  // --- 2. IP Blocklist ---
  const blocklist = policy.ip_blocklist ? policy.ip_blocklist.split(',').map(s => s.trim()).filter(Boolean) : [];
  if (blocklist.length && blocklist.some(blocked => ip.startsWith(blocked.replace(/\/\d+$/, '')))) {
    return mode === 'block'
      ? { allowed: false, action: 'BLOCK', reason: `IP ${ip} is in blocklist`, severity: 'High' }
      : { allowed: true, action: 'PASS', reason: `Monitor mode: IP ${ip} in blocklist (would block)` };
  }

  // --- 3. Rate limiting ---
  if (policy.rate_limit_requests > 0) {
    const withinLimit = checkRateLimit(ip, policy.rate_limit_requests, policy.rate_limit_window_s || 60);
    if (!withinLimit) {
      return mode === 'block'
        ? { allowed: false, action: 'RATE_LIMIT', reason: `Rate limit exceeded (>${policy.rate_limit_requests} req/${policy.rate_limit_window_s}s)`, severity: 'Medium' }
        : { allowed: true, action: 'PASS', reason: 'Monitor mode: rate limit exceeded (would block)' };
    }
  }

  // --- 4. Geo-blocking ---
  const geoBlocked = policy.geo_block_countries ? policy.geo_block_countries.split(',').map(s => s.trim().toUpperCase()).filter(Boolean) : [];
  if (geoBlocked.length) {
    const country = classifyIp(ip);
    if (geoBlocked.includes(country)) {
      return mode === 'block'
        ? { allowed: false, action: 'BLOCK', reason: `Geo-blocked country: ${country}`, severity: 'Medium' }
        : { allowed: true, action: 'PASS', reason: `Monitor mode: geo-blocked ${country} (would block)` };
    }
  }

  // --- 5. Bot protection ---
  if (policy.bot_protection_enabled) {
    const botMatch = matchesRuleCategory('bad bot', req);
    if (botMatch) {
      return mode === 'block'
        ? { allowed: false, action: 'BLOCK', reason: botMatch, severity: 'Low' }
        : { allowed: true, action: 'PASS', reason: `Monitor: ${botMatch}` };
    }
  }

  // --- 6. Active WAF rules (pattern matching) ---
  const rules = loadRules(orgId);
  for (const rule of rules) {
    const match = matchesWafRule(rule, req);
    if (match) {
      const action = (rule.action || 'BLOCK').toUpperCase() as 'BLOCK' | 'LOG' | 'CHALLENGE';
      if (action === 'LOG') {
        // Log only, don't block
        return { allowed: true, action: 'PASS', reason: `Rule matched (LOG only): ${rule.name}`, ruleId: rule.rule_id };
      }
      if (action === 'CHALLENGE') {
        return { allowed: false, action: 'CHALLENGE', reason: match, ruleId: rule.rule_id, severity: rule.severity };
      }
      return mode === 'block'
        ? { allowed: false, action: 'BLOCK', reason: match, ruleId: rule.rule_id, severity: rule.severity }
        : { allowed: true, action: 'PASS', reason: `Monitor mode: matched rule ${rule.name}` };
    }
  }

  return { allowed: true, action: 'PASS', reason: 'No rule matched' };
}

// ---------------------------------------------------------------------------
// Express middleware
// ---------------------------------------------------------------------------

export function wafMiddleware(req: Request, res: Response, next: NextFunction) {
  // Only inspect ingest endpoints that receive external traffic.
  // The WAF does NOT gate the dashboard API itself.
  const INGEST_PREFIXES = ['/ingest', '/api/ingest', '/webhook'];
  const isIngest = INGEST_PREFIXES.some(p => req.path.startsWith(p));
  if (!isIngest) {
    return next();
  }

  // Resolve org from request (mirrors auth middleware)
  const orgId = (req as any).organizationId || '';
  const decision = evaluateRequest(req, orgId);

  if (decision.allowed) {
    return next();
  }

  // Publish a real-time event so Live Traffic & logs see WAF blocks
  SecurityEventBus.publish('waf.blocked', {
    ip: (req.headers['x-forwarded-for'] as string || req.ip || '').split(',')[0].trim(),
    path: req.path,
    method: req.method,
    action: decision.action,
    reason: decision.reason,
    ruleId: decision.ruleId,
    severity: decision.severity || 'Medium',
  }, orgId);

  if (decision.action === 'CHALLENGE') {
    return res.status(403).json({
      error: 'WAF Challenge Required',
      code: 'WAF_CHALLENGE',
      reason: decision.reason,
    });
  }

  if (decision.action === 'RATE_LIMIT') {
    res.setHeader('Retry-After', '60');
    return res.status(429).json({
      error: 'Too Many Requests',
      code: 'WAF_RATE_LIMIT',
      reason: decision.reason,
    });
  }

  return res.status(403).json({
    error: 'Forbidden – blocked by WAF',
    code: 'WAF_BLOCK',
    reason: decision.reason,
    ruleId: decision.ruleId,
  });
}
