import { execSync } from 'child_process';
import crypto from 'crypto';
import { db } from '../database/db';

export interface DetectedRule {
  priority: number;
  source: string;
  destination: string;
  port: string;
  protocol: string;
  action: 'ALLOW' | 'DENY';
  description: string;
}

// Ignore interfaces & chains related to containers / internal loops
const IGNORED_CHAIN_OR_IFACE_PATTERNS = [
  'podman',
  'docker',
  'cni',
  'br-',
  'veth',
  'lo',
  'loopback'
];

function shouldIgnore(text: string): boolean {
  const lower = text.toLowerCase();
  return IGNORED_CHAIN_OR_IFACE_PATTERNS.some(pat => lower.includes(pat));
}

function normalizeAction(act: string): 'ALLOW' | 'DENY' {
  const upper = act.toUpperCase();
  if (upper === 'ACCEPT' || upper === 'ALLOW') return 'ALLOW';
  return 'DENY';
}

function parseNftRules(): DetectedRule[] {
  const detected: DetectedRule[] = [];
  try {
    // Try listing inet filter table or full ruleset
    let output = '';
    try {
      output = execSync('nft list table inet filter 2>/dev/null', { timeout: 3000 }).toString();
    } catch {
      output = execSync('nft list ruleset 2>/dev/null', { timeout: 3000 }).toString();
    }

    if (!output) return detected;

    const lines = output.split('\n');
    let currentChain = '';

    for (const line of lines) {
      const trimmed = line.trim();
      if (!trimmed || trimmed.startsWith('#')) continue;

      if (trimmed.startsWith('chain ')) {
        const parts = trimmed.split(/\s+/);
        currentChain = parts[1] || '';
        continue;
      }

      if (shouldIgnore(currentChain) || shouldIgnore(trimmed)) {
        continue;
      }

      // Check for accept or drop/reject
      if (!/\b(accept|drop|reject)\b/.test(trimmed)) {
        continue;
      }

      const action = /\baccept\b/.test(trimmed) ? 'ALLOW' : 'DENY';

      // Parse protocol
      let protocol = 'TCP';
      if (/\budp\b/.test(trimmed)) protocol = 'UDP';
      else if (/\bicmp\b/.test(trimmed) || /\bicmpv6\b/.test(trimmed)) protocol = 'ICMP';
      else if (/\btcp\b/.test(trimmed)) protocol = 'TCP';

      // Parse port
      let port = 'ANY';
      const dportMatch = trimmed.match(/(?:dport|dports)\s+([0-9,\s-]+|\{[^}]+\})/);
      if (dportMatch) {
        port = dportMatch[1].replace(/[\{\}\s]/g, '');
      } else if (protocol === 'ICMP') {
        port = 'ALL';
      }

      // Parse source IP/CIDR
      let source = '0.0.0.0/0';
      const saddrMatch = trimmed.match(/(?:saddr|ip saddr|ip6 saddr)\s+([0-9a-fA-F:\.\/]+)/);
      if (saddrMatch) {
        source = saddrMatch[1];
      }

      // Parse destination IP/CIDR
      let destination = '0.0.0.0/0';
      const daddrMatch = trimmed.match(/(?:daddr|ip daddr|ip6 daddr)\s+([0-9a-fA-F:\.\/]+)/);
      if (daddrMatch) {
        destination = daddrMatch[1];
      }

      // Skip generic state/lo tracking like "ct state established,related accept" or loopback accepts
      if (trimmed.includes('ct state established') || trimmed.includes('iifname "lo"')) {
        continue;
      }

      // If no specific port, source, or protocol match, skip generic chain policies
      if (port === 'ANY' && source === '0.0.0.0/0' && destination === '0.0.0.0/0' && protocol !== 'ICMP') {
        continue;
      }

      detected.push({
        priority: 100,
        source,
        destination,
        port,
        protocol,
        action,
        description: `Imported from nftables (${currentChain || 'filter'})`
      });
    }
  } catch {}
  return detected;
}

function parseUfwRules(): DetectedRule[] {
  const detected: DetectedRule[] = [];
  try {
    const output = execSync('ufw status numbered 2>/dev/null', { timeout: 3000 }).toString();
    if (!output || output.includes('Status: inactive')) return detected;

    const lines = output.split('\n');
    for (const line of lines) {
      const match = line.match(/^\[\s*(\d+)\]\s+([^\s]+)\s+(ALLOW|DENY|REJECT)\s+(IN|OUT)?\s*(.*)$/i);
      if (!match) continue;

      const [, num, targetStr, actStr, , srcStr] = match;
      if (shouldIgnore(line)) continue;

      const action = normalizeAction(actStr);
      let protocol = 'TCP';
      let port = 'ANY';

      if (targetStr.includes('/')) {
        const [p, proto] = targetStr.split('/');
        port = p;
        protocol = proto.toUpperCase();
      } else if (!isNaN(Number(targetStr))) {
        port = targetStr;
      }

      let source = '0.0.0.0/0';
      if (srcStr && !srcStr.toLowerCase().includes('anywhere')) {
        source = srcStr.trim();
      }

      detected.push({
        priority: Number(num) * 10,
        source,
        destination: '0.0.0.0/0',
        port,
        protocol,
        action,
        description: `Imported from UFW rule #${num}`
      });
    }
  } catch {}
  return detected;
}

function parseIptablesRules(): DetectedRule[] {
  const detected: DetectedRule[] = [];
  try {
    const output = execSync('iptables -S INPUT 2>/dev/null', { timeout: 3000 }).toString();
    if (!output) return detected;

    const lines = output.split('\n');
    for (const line of lines) {
      const trimmed = line.trim();
      if (!trimmed.startsWith('-A INPUT')) continue;
      if (shouldIgnore(trimmed)) continue;

      // Skip connection tracking defaults & loopback
      if (trimmed.includes('RELATED,ESTABLISHED') || trimmed.includes('-i lo')) continue;

      const action = trimmed.includes('-j ACCEPT') ? 'ALLOW' : trimmed.includes('-j DROP') || trimmed.includes('-j REJECT') ? 'DENY' : null;
      if (!action) continue;

      let protocol = 'TCP';
      const protoMatch = trimmed.match(/-p\s+([a-zA-Z]+)/);
      if (protoMatch) {
        protocol = protoMatch[1].toUpperCase();
      }

      let port = 'ANY';
      const portMatch = trimmed.match(/--(?:dport|destination-port)\s+([0-9:]+)/);
      if (portMatch) {
        port = portMatch[1];
      }

      let source = '0.0.0.0/0';
      const srcMatch = trimmed.match(/-s\s+([0-9\.\/]+)/);
      if (srcMatch) {
        source = srcMatch[1];
      }

      let destination = '0.0.0.0/0';
      const dstMatch = trimmed.match(/-d\s+([0-9\.\/]+)/);
      if (dstMatch) {
        destination = dstMatch[1];
      }

      if (port === 'ANY' && source === '0.0.0.0/0' && destination === '0.0.0.0/0' && protocol !== 'ICMP') {
        continue;
      }

      detected.push({
        priority: 100,
        source,
        destination,
        port,
        protocol,
        action,
        description: 'Imported from iptables (INPUT)'
      });
    }
  } catch {}
  return detected;
}

export function detectAndSyncServerFirewall(orgId: string): { importedCount: number; rules: any[] } {
  if (!orgId) return { importedCount: 0, rules: [] };

  // Fetch from all sources in order: nftables -> ufw -> iptables
  const allDetected = [...parseNftRules(), ...parseUfwRules(), ...parseIptablesRules()];

  if (allDetected.length === 0) {
    const currentRules = db.prepare('SELECT * FROM firewall_rules WHERE organization_id = ? ORDER BY priority ASC').all(orgId);
    return { importedCount: 0, rules: currentRules };
  }

  // Deduplicate against database and within detected batch
  const existingRules = db.prepare('SELECT source, destination, port, protocol, action FROM firewall_rules WHERE organization_id = ?').all(orgId) as any[];
  const existingSet = new Set(
    existingRules.map(r => `${r.protocol}:${r.port}:${r.source}:${r.action}`)
  );

  let importedCount = 0;
  const insertStmt = db.prepare(`
    INSERT INTO firewall_rules (id, organization_id, priority, source, destination, port, protocol, action, enabled, description, created_by)
    VALUES (?, ?, ?, ?, ?, ?, ?, ?, 1, ?, 'system_detector')
  `);

  for (const rule of allDetected) {
    const key = `${rule.protocol}:${rule.port}:${rule.source}:${rule.action}`;
    if (existingSet.has(key)) continue;

    existingSet.add(key);
    const ruleId = `fw_detected_${crypto.randomBytes(6).toString('hex')}`;
    try {
      insertStmt.run(
        ruleId,
        orgId,
        rule.priority,
        rule.source,
        rule.destination,
        rule.port,
        rule.protocol,
        rule.action,
        rule.description
      );
      importedCount++;
    } catch {}
  }

  const updatedRules = db.prepare('SELECT * FROM firewall_rules WHERE organization_id = ? ORDER BY priority ASC').all(orgId);
  return { importedCount, rules: updatedRules };
}
