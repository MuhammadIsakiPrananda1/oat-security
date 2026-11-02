import { CONFIG } from '../config';
import { MysqlBridge } from './mysqlBridge';
import { MYSQL_INDEXES, MYSQL_SCHEMA } from './mysqlSchema';

/**
 * OAT Security now stores everything in MySQL (Laragon on the lab host).
 *
 * The public `db` object deliberately mirrors the small part of the
 * node:sqlite API the rest of the server uses: prepare().get()/all()/run()
 * and exec(). That keeps the ingestion pipeline, API routes and seed scripts
 * unchanged while the storage engine is MySQL.
 */
const bridge = new MysqlBridge({
  host: CONFIG.DB_HOST,
  port: CONFIG.DB_PORT,
  user: CONFIG.DB_USER,
  password: CONFIG.DB_PASSWORD,
  database: CONFIG.DB_NAME,
});

/**
 * Translate the few SQLite idioms that survived in the query strings.
 * Schema DDL lives in mysqlSchema.ts and is already MySQL-native.
 */
function toMysql(sql: string): string {
  return sql
    .replace(/datetime\s*\(\s*'now'\s*\)/gi, 'UTC_TIMESTAMP()')
    .replace(/\bINSERT\s+OR\s+IGNORE\b/gi, 'INSERT IGNORE')
    .replace(/\bINSERT\s+OR\s+REPLACE\b/gi, 'REPLACE');
}

class MysqlStatement {
  constructor(private readonly sql: string) {}

  get(...params: unknown[]): any {
    return bridge.query('get', toMysql(this.sql), params).row;
  }

  all(...params: unknown[]): any[] {
    return bridge.query('all', toMysql(this.sql), params).rows;
  }

  run(...params: unknown[]) {
    const result = bridge.query('run', toMysql(this.sql), params);
    return {
      changes: result.affectedRows,
      lastInsertRowid: result.insertId,
    };
  }
}

export const db = {
  prepare(sql: string) {
    return new MysqlStatement(sql);
  },
  exec(sql: string) {
    bridge.exec(toMysql(sql));
  },
};

function waitSync(ms: number) {
  // Atomics.wait is allowed on the Node main thread and keeps this module's
  // synchronous contract while backing off from a DDL deadlock.
  Atomics.wait(new Int32Array(new SharedArrayBuffer(4)), 0, 0, ms);
}

function execWithRetry(sql: string, attempts = 4) {
  let lastError: any;
  for (let attempt = 0; attempt < attempts; attempt += 1) {
    try {
      db.exec(sql);
      return;
    } catch (err: any) {
      lastError = err;
      const retryable = err?.errno === 1213 || err?.errno === 1205 ||
        err?.code === 'ER_LOCK_DEADLOCK' || err?.code === 'ER_LOCK_WAIT_TIMEOUT';
      if (!retryable || attempt === attempts - 1) throw err;
      waitSync(500 * (attempt + 1));
    }
  }
  throw lastError;
}

function ensureColumn(table: string, column: string, definition: string) {
  const existing = db
    .prepare(
      `SELECT COLUMN_NAME AS name
         FROM information_schema.COLUMNS
        WHERE TABLE_SCHEMA = DATABASE()
          AND TABLE_NAME = ?
          AND COLUMN_NAME = ?`
    )
    .get(table, column) as { name?: string } | undefined;

  if (!existing) {
    execWithRetry(`ALTER TABLE \`${table}\` ADD COLUMN \`${column}\` ${definition}`);
  }
}

export function runMigrations() {
  execWithRetry(MYSQL_SCHEMA);

  // Columns added after the initial schema shipped. MySQL has no
  // "ADD COLUMN IF NOT EXISTS", so information_schema is the source of truth.
  ensureColumn('security_events', 'agent_id', 'VARCHAR(64)');
  ensureColumn('logs', 'agent_id', 'VARCHAR(64)');
  ensureColumn('agents', 'application_id', 'VARCHAR(64)');
  ensureColumn('agent_enrollment_tokens', 'application_id', 'VARCHAR(64)');
  // Application inventory: which agent discovered the website, when it was
  // last reported, and whether it was discovered or added by an operator.
  ensureColumn('applications', 'agent_id', 'VARCHAR(64)');
  ensureColumn('applications', 'last_seen', 'VARCHAR(40)');
  ensureColumn('applications', 'updated_at', 'VARCHAR(40)');
  ensureColumn('applications', 'source', "VARCHAR(32) NOT NULL DEFAULT 'manual'");
  ensureColumn('networks', 'zone', "VARCHAR(64) NOT NULL DEFAULT 'DMZ'");
  ensureColumn('networks', 'firewall', "VARCHAR(128) NOT NULL DEFAULT 'OAT NGFW'");
  ensureColumn('waf_rules', 'pattern', 'TEXT');
  ensureColumn('waf_policy', 'revision', 'INT NOT NULL DEFAULT 1');
  ensureColumn('users', 'avatar_url', 'LONGTEXT');
  ensureColumn('users', 'username', 'VARCHAR(64)');
  ensureColumn('users', 'phone', 'VARCHAR(32)');
  ensureColumn('users', 'telegram_bot_token', 'VARCHAR(255)');
  ensureColumn('users', 'bio', 'TEXT');
  ensureColumn('users', 'social_url', 'VARCHAR(512)');
  ensureColumn('users', 'linkedin_url', 'VARCHAR(512)');
  ensureColumn('users', 'github_url', 'VARCHAR(512)');
  ensureColumn('users', 'twitter_url', 'VARCHAR(512)');
  ensureColumn('users', 'instagram_url', 'VARCHAR(512)');
  ensureColumn('users', 'soc_tier', 'VARCHAR(16)');
  ensureColumn('incidents', 'tier', "VARCHAR(16) NOT NULL DEFAULT 'L1'");

  try {
    execWithRetry('ALTER TABLE agent_enrollment_tokens MODIFY organization_id VARCHAR(64) NULL');
  } catch {}
  try {
    execWithRetry('ALTER TABLE users MODIFY organization_id VARCHAR(64) NULL');
  } catch {}
  try {
    execWithRetry('ALTER TABLE audit_logs MODIFY organization_id VARCHAR(64) NULL');
  } catch {}
  try {
    execWithRetry('ALTER TABLE fail2ban_config DROP FOREIGN KEY fk_fail2ban_cfg_org');
  } catch {}
  try {
    execWithRetry('ALTER TABLE fail2ban_bans DROP FOREIGN KEY fk_fail2ban_ban_org');
  } catch {}
  try {
    execWithRetry('ALTER TABLE nat_rules DROP FOREIGN KEY fk_nat_rules_org');
  } catch {}

  // Ensure baseline organization exists in MySQL so all FK references always pass
  try {
    const existingOrg = db.prepare('SELECT id FROM organizations LIMIT 1').get() as any;
    if (!existingOrg) {
      db.prepare(`
        INSERT IGNORE INTO organizations (id, name, slug, status, plan, created_at)
        VALUES ('org_default', 'Default Organization', 'default-org', 'ACTIVE', 'Enterprise', UTC_TIMESTAMP())
      `).run();
    }
  } catch {}

  for (const indexSql of MYSQL_INDEXES) {
    try {
      execWithRetry(indexSql);
    } catch (err: any) {
      // 1061 / ER_DUP_KEYNAME means the index already exists.
      if (err?.errno !== 1061 && err?.code !== 'ER_DUP_KEYNAME') {
        throw err;
      }
    }
  }

  // The database starts clean: no demo/seed data is inserted.
  // All records (organizations, users, rules, events, etc.) must come from
  // real-time ingestion and real tenant provisioning.
}
