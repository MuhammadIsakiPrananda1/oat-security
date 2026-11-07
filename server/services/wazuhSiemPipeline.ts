import net from 'net';
import dgram from 'dgram';
import fs from 'fs';
import path from 'path';
import { db } from '../database/db';
import { SecurityEventBus } from '../utils/eventBus';
import { pushLogToPipeline, LogItem } from './logRingBuffer';

// Wazuh-style ports and queue directory
export const WAZUH_TCP_PORT = 1514;
export const WAZUH_UDP_PORT = 1514;
const QUEUE_DIR = path.join(process.cwd(), '.system_generated', 'wazuh_queue');
const ALERTS_LOG_FILE = path.join(QUEUE_DIR, 'alerts.json');

// Ensure local file queue directory exists (Wazuh: queue/alerts)
try {
  if (!fs.existsSync(QUEUE_DIR)) {
    fs.mkdirSync(QUEUE_DIR, { recursive: true });
  }
} catch (e) {
  // non-blocking
}

/**
 * Wazuh Analysis Engine (Ruleset & Decoder):
 * Log biasa (level rendah/noise) dilewati/disaring.
 * Log anomali / security rule violation diproses jadi Alert.
 */
function analyzeAndDecodeRawLog(rawMsg: string, sourceIp: string, protocol: 'tcp' | 'udp'): LogItem | null {
  const line = String(rawMsg || '').trim();
  if (!line) return null;

  let parsed: any = null;
  if (line.startsWith('{') && line.endsWith('}')) {
    try {
      parsed = JSON.parse(line);
    } catch {
      parsed = null;
    }
  }

  const message = parsed?.message || parsed?.log || line;
  const lowerMsg = message.toLowerCase();

  // Rule Decoder: Assign Severity Level like Wazuh ruleset
  let level = 'INFO';
  let isSecurityAlert = false;
  let ruleDescription = 'Standard System Telemetry';

  if (/(crit|emerg|fatal|rce|sqli|xss|backdoor|trojan|exploit|unauthorized|segfault)/i.test(lowerMsg)) {
    level = 'CRITICAL';
    isSecurityAlert = true;
    ruleDescription = 'Wazuh Alert Level 12+ (Critical Threat Signature)';
  } else if (/(error|fail|deny|drop|block|refused|attack|intrusion|malware|violation)/i.test(lowerMsg)) {
    level = 'ERROR';
    isSecurityAlert = true;
    ruleDescription = 'Wazuh Alert Level 7-11 (Security Event Detected)';
  } else if (/(warn|suspicious|anom|timeout|retry|invalid|overflow)/i.test(lowerMsg)) {
    level = 'WARN';
    isSecurityAlert = true;
    ruleDescription = 'Wazuh Alert Level 4-6 (Warning / Anomaly)';
  } else if (/(debug|trace|verbose)/i.test(lowerMsg)) {
    level = 'DEBUG';
  }

  // Filter Noise: Log biasa level INFO/DEBUG tanpa indikasi anomali tidak perlu dibesarkan
  const logItem: LogItem = {
    id: `WAZUH-${Date.now()}-${Math.random().toString(36).slice(2, 7)}`,
    organizationId: parsed?.organizationId || parsed?.orgId || 'org_default',
    timestamp: parsed?.timestamp || new Date().toISOString(),
    level,
    source: parsed?.source || 'wazuh-remoted',
    eventType: isSecurityAlert ? 'wazuh_alert' : 'wazuh_log',
    message: `${ruleDescription}: ${message}`,
    host: parsed?.host || parsed?.hostname || sourceIp,
    ip: sourceIp,
    correlationId: parsed?.correlationId || null,
    metadata: {
      protocol,
      wazuhPort: 1514,
      isSecurityAlert,
      raw: parsed ? undefined : line.slice(0, 500)
    },
    rawLog: line.slice(0, 4000)
  };

  return logItem;
}

/**
 * Wazuh FileQueue Writer (Local disk queue: queue/alerts/alerts.json)
 * Ditulis secara append, decoupled dari database.
 */
function appendToFileQueue(logItem: LogItem) {
  try {
    const jsonLine = JSON.stringify(logItem) + '\n';
    fs.appendFile(ALERTS_LOG_FILE, jsonLine, (err) => {
      if (err) {
        // silent fail to avoid process crashing
      }
    });
  } catch {
    // ignore
  }
}

/**
 * Handle ingested raw log item into Wazuh pipeline
 */
export function processWazuhIncomingLog(rawMsg: string, sourceIp: string, protocol: 'tcp' | 'udp') {
  const decoded = analyzeAndDecodeRawLog(rawMsg, sourceIp, protocol);
  if (!decoded) return;

  // 1. Tulis ke Disk Queue (queue/alerts)
  appendToFileQueue(decoded);

  // 2. Kirim ke In-Memory Buffer & Batch Flush ke DB (Indexer)
  pushLogToPipeline(decoded);

  // 3. Tembak langsung real-time WebSocket ke Web UI (Dashboard)
  SecurityEventBus.publish('log.created', decoded, decoded.organizationId);
}

/**
 * Start Wazuh-compatible listeners on TCP & UDP port 1514
 */
export function startWazuhManagerListener() {
  // 1. TCP Server (Port 1514)
  const tcpServer = net.createServer((socket) => {
    const remoteIp = socket.remoteAddress?.replace(/^::ffff:/, '') || '127.0.0.1';
    let buffer = '';

    socket.on('data', (chunk) => {
      buffer += chunk.toString('utf8');
      const lines = buffer.split('\n');
      buffer = lines.pop() || '';

      for (const line of lines) {
        if (line.trim()) {
          processWazuhIncomingLog(line.trim(), remoteIp, 'tcp');
        }
      }
    });

    socket.on('error', () => {
      socket.destroy();
    });
  });

  tcpServer.on('error', (err: any) => {
    if (err.code === 'EADDRINUSE' || err.code === 'EACCES') {
      console.warn(`[Wazuh Manager] TCP Port ${WAZUH_TCP_PORT} unavailable (${err.code}). Pipeline tetap aktif via REST API.`);
    } else {
      console.warn('[Wazuh Manager] TCP listener error:', err.message);
    }
  });

  try {
    tcpServer.listen(WAZUH_TCP_PORT, '0.0.0.0', () => {
      console.log(`[Wazuh Manager] TCP listener active on 0.0.0.0:${WAZUH_TCP_PORT}`);
    });
  } catch (err: any) {
    console.warn(`[Wazuh Manager] TCP listen failed on port ${WAZUH_TCP_PORT}`);
  }

  // 2. UDP Server (Port 1514)
  try {
    const udpServer = dgram.createSocket('udp4');
    udpServer.on('message', (msg, rinfo) => {
      const raw = msg.toString('utf8').trim();
      if (raw) {
        processWazuhIncomingLog(raw, rinfo.address, 'udp');
      }
    });

    udpServer.on('error', (err: any) => {
      console.warn(`[Wazuh Manager] UDP Port ${WAZUH_UDP_PORT} unavailable (${err.code}).`);
    });

    udpServer.bind(WAZUH_UDP_PORT, '0.0.0.0', () => {
      console.log(`[Wazuh Manager] UDP listener active on 0.0.0.0:${WAZUH_UDP_PORT}`);
    });
  } catch (err: any) {
    console.warn(`[Wazuh Manager] UDP listen failed on port ${WAZUH_UDP_PORT}`);
  }
}

