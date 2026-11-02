/**
 * MySQL 8 schema for OAT Security.
 *
 * The application used to run on SQLite. MySQL is stricter about indexed
 * column types, reserved words and expression defaults, so the schema is kept
 * explicit here instead of trying to translate the old SQLite DDL at runtime.
 *
 * Timestamp columns stay VARCHAR on purpose: the ingestion pipeline writes
 * ISO-8601 strings and the UI already handles both ISO and "YYYY-MM-DD HH:MM:SS"
 * forms. This also keeps ordering identical to the old store.
 */

const TABLE_OPTIONS = 'ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci';
const CREATED_AT = "VARCHAR(40) NOT NULL DEFAULT (DATE_FORMAT(UTC_TIMESTAMP(), '%Y-%m-%d %H:%i:%s'))";
const UPDATED_AT = "VARCHAR(40) NOT NULL DEFAULT (DATE_FORMAT(UTC_TIMESTAMP(), '%Y-%m-%d %H:%i:%s'))";

export const MYSQL_SCHEMA = `
CREATE TABLE IF NOT EXISTS organizations (
  id VARCHAR(64) NOT NULL PRIMARY KEY,
  name VARCHAR(255) NOT NULL,
  domain VARCHAR(255) NOT NULL,
  industry VARCHAR(100) NOT NULL DEFAULT 'Enterprise',
  tier VARCHAR(50) NOT NULL DEFAULT 'Enterprise',
  created_at ${CREATED_AT}
) ${TABLE_OPTIONS};

CREATE TABLE IF NOT EXISTS roles (
  id VARCHAR(64) NOT NULL PRIMARY KEY,
  name VARCHAR(128) NOT NULL UNIQUE,
  description TEXT
) ${TABLE_OPTIONS};

CREATE TABLE IF NOT EXISTS permissions (
  id VARCHAR(64) NOT NULL PRIMARY KEY,
  role_id VARCHAR(64) NOT NULL,
  permission VARCHAR(128) NOT NULL,
  CONSTRAINT fk_permissions_role FOREIGN KEY (role_id) REFERENCES roles(id) ON DELETE CASCADE
) ${TABLE_OPTIONS};

CREATE TABLE IF NOT EXISTS users (
  id VARCHAR(64) NOT NULL PRIMARY KEY,
  organization_id VARCHAR(64),
  name VARCHAR(255) NOT NULL,
  email VARCHAR(255) NOT NULL UNIQUE,
  password_hash VARCHAR(255) NOT NULL,
  role VARCHAR(64) NOT NULL DEFAULT 'Security Analyst',
  soc_tier VARCHAR(16),
  mfa_enabled TINYINT NOT NULL DEFAULT 1,
  mfa_secret VARCHAR(255),
  avatar_url LONGTEXT,
  username VARCHAR(64),
  phone VARCHAR(32),
  telegram_bot_token VARCHAR(255),
  bio TEXT,
  social_url VARCHAR(512),
  linkedin_url VARCHAR(512),
  github_url VARCHAR(512),
  twitter_url VARCHAR(512),
  instagram_url VARCHAR(512),
  created_at ${CREATED_AT},
  last_login VARCHAR(40),
  CONSTRAINT fk_users_org FOREIGN KEY (organization_id) REFERENCES organizations(id) ON DELETE CASCADE
) ${TABLE_OPTIONS};

CREATE TABLE IF NOT EXISTS applications (
  id VARCHAR(64) NOT NULL PRIMARY KEY,
  organization_id VARCHAR(64) NOT NULL,
  name VARCHAR(255) NOT NULL,
  domain VARCHAR(255) NOT NULL,
  origin_ip VARCHAR(64) NOT NULL DEFAULT '127.0.0.1',
  environment VARCHAR(64) NOT NULL DEFAULT 'Production',
  status VARCHAR(32) NOT NULL DEFAULT 'UNKNOWN',
  owner VARCHAR(128) NOT NULL DEFAULT 'SecOps',
  protocol VARCHAR(16) NOT NULL DEFAULT 'HTTPS',
  port INT NOT NULL DEFAULT 443,
  created_at ${CREATED_AT},
  updated_at VARCHAR(40),
  CONSTRAINT fk_apps_org FOREIGN KEY (organization_id) REFERENCES organizations(id) ON DELETE CASCADE
) ${TABLE_OPTIONS};

CREATE TABLE IF NOT EXISTS networks (
  id VARCHAR(64) NOT NULL PRIMARY KEY,
  organization_id VARCHAR(64) NOT NULL,
  name VARCHAR(255) NOT NULL,
  cidr VARCHAR(64) NOT NULL,
  gateway VARCHAR(64) NOT NULL,
  interface VARCHAR(64) NOT NULL DEFAULT 'eth0',
  zone VARCHAR(64) NOT NULL DEFAULT 'DMZ',
  firewall VARCHAR(128) NOT NULL DEFAULT 'OAT NGFW',
  description TEXT,
  status VARCHAR(32) NOT NULL DEFAULT 'Online',
  created_at ${CREATED_AT},
  CONSTRAINT fk_networks_org FOREIGN KEY (organization_id) REFERENCES organizations(id) ON DELETE CASCADE
) ${TABLE_OPTIONS};

CREATE TABLE IF NOT EXISTS waf_rules (
  id VARCHAR(64) NOT NULL PRIMARY KEY,
  organization_id VARCHAR(64) NOT NULL,
  rule_id VARCHAR(64) NOT NULL,
  name VARCHAR(255) NOT NULL,
  category VARCHAR(128) NOT NULL,
  severity VARCHAR(32) NOT NULL DEFAULT 'Medium',
  action VARCHAR(32) NOT NULL DEFAULT 'BLOCK',
  enabled TINYINT NOT NULL DEFAULT 1,
  description TEXT,
  pattern TEXT,
  created_at ${CREATED_AT},
  updated_at ${UPDATED_AT},
  CONSTRAINT fk_waf_rules_org FOREIGN KEY (organization_id) REFERENCES organizations(id) ON DELETE CASCADE
) ${TABLE_OPTIONS};

CREATE TABLE IF NOT EXISTS waf_policy (
  id VARCHAR(64) NOT NULL PRIMARY KEY,
  organization_id VARCHAR(64) NOT NULL UNIQUE,
  engine_enabled TINYINT NOT NULL DEFAULT 1,
  mode VARCHAR(32) NOT NULL DEFAULT 'block',
  rate_limit_requests INT NOT NULL DEFAULT 100,
  rate_limit_window_s INT NOT NULL DEFAULT 10,
  ip_allowlist TEXT NOT NULL,
  ip_blocklist TEXT NOT NULL,
  geo_block_countries TEXT NOT NULL,
  bot_protection_enabled TINYINT NOT NULL DEFAULT 1,
  sync_to_server TINYINT NOT NULL DEFAULT 1,
  revision INT NOT NULL DEFAULT 1,
  last_applied_at VARCHAR(40),
  server_status VARCHAR(32) DEFAULT 'ACTIVE',
  server_log TEXT,
  updated_at ${UPDATED_AT},
  CONSTRAINT fk_waf_policy_org FOREIGN KEY (organization_id) REFERENCES organizations(id) ON DELETE CASCADE
) ${TABLE_OPTIONS};

CREATE TABLE IF NOT EXISTS firewall_rules (
  id VARCHAR(64) NOT NULL PRIMARY KEY,
  organization_id VARCHAR(64) NOT NULL,
  priority INT NOT NULL DEFAULT 100,
  source VARCHAR(128) NOT NULL,
  destination VARCHAR(128) NOT NULL,
  port VARCHAR(32) NOT NULL DEFAULT 'ANY',
  protocol VARCHAR(16) NOT NULL DEFAULT 'TCP',
  action VARCHAR(16) NOT NULL DEFAULT 'DENY',
  enabled TINYINT NOT NULL DEFAULT 1,
  description TEXT,
  created_by VARCHAR(128) NOT NULL DEFAULT 'system',
  created_at ${CREATED_AT},
  updated_at ${UPDATED_AT},
  CONSTRAINT fk_firewall_rules_org FOREIGN KEY (organization_id) REFERENCES organizations(id) ON DELETE CASCADE
) ${TABLE_OPTIONS};

CREATE TABLE IF NOT EXISTS security_events (
  id VARCHAR(64) NOT NULL PRIMARY KEY,
  organization_id VARCHAR(64) NOT NULL,
  timestamp VARCHAR(40) NOT NULL,
  source VARCHAR(32) NOT NULL,
  event_type VARCHAR(64) NOT NULL,
  severity VARCHAR(16) NOT NULL DEFAULT 'Low',
  source_ip VARCHAR(64) NOT NULL,
  destination_ip VARCHAR(64) NOT NULL,
  protocol VARCHAR(16) NOT NULL DEFAULT 'TCP',
  application VARCHAR(128) NOT NULL DEFAULT 'Perimeter Edge',
  action VARCHAR(32) NOT NULL DEFAULT 'LOG',
  uri TEXT,
  method VARCHAR(16),
  port INT,
  status_code INT,
  threat_name VARCHAR(512),
  payload_snippet TEXT,
  metadata TEXT,
  agent_id VARCHAR(64),
  created_at ${CREATED_AT},
  CONSTRAINT fk_events_org FOREIGN KEY (organization_id) REFERENCES organizations(id) ON DELETE CASCADE
) ${TABLE_OPTIONS};

CREATE TABLE IF NOT EXISTS threats (
  id VARCHAR(64) NOT NULL PRIMARY KEY,
  organization_id VARCHAR(64) NOT NULL,
  timestamp VARCHAR(40) NOT NULL,
  source_ip VARCHAR(64) NOT NULL,
  target VARCHAR(255) NOT NULL,
  attack_type VARCHAR(128) NOT NULL,
  severity VARCHAR(16) NOT NULL DEFAULT 'Medium',
  confidence INT NOT NULL DEFAULT 90,
  action VARCHAR(32) NOT NULL DEFAULT 'LOG',
  status VARCHAR(32) NOT NULL DEFAULT 'ACTIVE',
  summary TEXT NOT NULL,
  detection_reason TEXT,
  affected_application VARCHAR(255),
  destination VARCHAR(128),
  related_events TEXT,
  recommended_action TEXT,
  created_at ${CREATED_AT},
  updated_at ${UPDATED_AT},
  CONSTRAINT fk_threats_org FOREIGN KEY (organization_id) REFERENCES organizations(id) ON DELETE CASCADE
) ${TABLE_OPTIONS};

CREATE TABLE IF NOT EXISTS incidents (
  id VARCHAR(64) NOT NULL PRIMARY KEY,
  organization_id VARCHAR(64) NOT NULL,
  title VARCHAR(512) NOT NULL,
  severity VARCHAR(16) NOT NULL DEFAULT 'Medium',
  status VARCHAR(32) NOT NULL DEFAULT 'NEW',
  tier VARCHAR(16) NOT NULL DEFAULT 'L1',
  assigned_to VARCHAR(255),
  affected_asset VARCHAR(255),
  notes TEXT,
  timeline TEXT,
  created_at ${CREATED_AT},
  updated_at ${UPDATED_AT},
  CONSTRAINT fk_incidents_org FOREIGN KEY (organization_id) REFERENCES organizations(id) ON DELETE CASCADE
) ${TABLE_OPTIONS};

CREATE TABLE IF NOT EXISTS notifications (
  id VARCHAR(64) NOT NULL PRIMARY KEY,
  organization_id VARCHAR(64) NOT NULL,
  title VARCHAR(255) NOT NULL,
  message TEXT NOT NULL,
  severity VARCHAR(16) NOT NULL DEFAULT 'Info',
  \`read\` TINYINT NOT NULL DEFAULT 0,
  created_at ${CREATED_AT},
  CONSTRAINT fk_notifications_org FOREIGN KEY (organization_id) REFERENCES organizations(id) ON DELETE CASCADE
) ${TABLE_OPTIONS};

CREATE TABLE IF NOT EXISTS audit_logs (
  id VARCHAR(64) NOT NULL PRIMARY KEY,
  organization_id VARCHAR(64),
  user_id VARCHAR(64),
  user_email VARCHAR(255) NOT NULL,
  role VARCHAR(64) NOT NULL,
  action VARCHAR(128) NOT NULL,
  resource VARCHAR(255) NOT NULL,
  resource_id VARCHAR(64),
  ip_address VARCHAR(64) NOT NULL,
  user_agent VARCHAR(512),
  timestamp VARCHAR(40) NOT NULL DEFAULT (DATE_FORMAT(UTC_TIMESTAMP(), '%Y-%m-%d %H:%i:%s')),
  metadata TEXT,
  CONSTRAINT fk_audit_org FOREIGN KEY (organization_id) REFERENCES organizations(id) ON DELETE CASCADE
) ${TABLE_OPTIONS};

CREATE TABLE IF NOT EXISTS api_keys (
  id VARCHAR(64) NOT NULL PRIMARY KEY,
  organization_id VARCHAR(64) NOT NULL,
  name VARCHAR(255) NOT NULL,
  prefix VARCHAR(32) NOT NULL,
  key_hash VARCHAR(255) NOT NULL,
  permissions TEXT NOT NULL,
  status VARCHAR(32) NOT NULL DEFAULT 'Active',
  created_at ${CREATED_AT},
  last_used_at VARCHAR(40),
  CONSTRAINT fk_api_keys_org FOREIGN KEY (organization_id) REFERENCES organizations(id) ON DELETE CASCADE
) ${TABLE_OPTIONS};

CREATE TABLE IF NOT EXISTS agents (
  id VARCHAR(64) NOT NULL PRIMARY KEY,
  organization_id VARCHAR(64) NOT NULL,
  application_id VARCHAR(64),
  name VARCHAR(255) NOT NULL,
  hostname VARCHAR(255),
  os VARCHAR(64),
  arch VARCHAR(64),
  version VARCHAR(64),
  ip VARCHAR(64),
  status VARCHAR(32) NOT NULL DEFAULT 'PENDING',
  public_key TEXT NOT NULL,
  labels TEXT,
  host_info TEXT,
  metrics TEXT,
  last_seen VARCHAR(40),
  events_ingested BIGINT NOT NULL DEFAULT 0,
  logs_ingested BIGINT NOT NULL DEFAULT 0,
  created_at ${CREATED_AT},
  revoked_at VARCHAR(40),
  CONSTRAINT fk_agents_org FOREIGN KEY (organization_id) REFERENCES organizations(id) ON DELETE CASCADE
) ${TABLE_OPTIONS};

CREATE TABLE IF NOT EXISTS agent_enrollment_tokens (
  id VARCHAR(64) NOT NULL PRIMARY KEY,
  organization_id VARCHAR(64),
  application_id VARCHAR(64),
  token_hash VARCHAR(255) NOT NULL UNIQUE,
  label VARCHAR(255),
  expires_at VARCHAR(40) NOT NULL,
  used_at VARCHAR(40),
  used_by_agent_id VARCHAR(64),
  created_by VARCHAR(255),
  created_at ${CREATED_AT},
  CONSTRAINT fk_agent_tokens_org FOREIGN KEY (organization_id) REFERENCES organizations(id) ON DELETE CASCADE
) ${TABLE_OPTIONS};

CREATE TABLE IF NOT EXISTS agent_waf_status (
  agent_id VARCHAR(64) NOT NULL PRIMARY KEY,
  organization_id VARCHAR(64) NOT NULL,
  application_id VARCHAR(64),
  desired_revision INT NOT NULL DEFAULT 0,
  applied_revision INT NOT NULL DEFAULT 0,
  status VARCHAR(32) NOT NULL DEFAULT 'PENDING',
  engine_enabled TINYINT,
  mode VARCHAR(32),
  target VARCHAR(255),
  message TEXT,
  rules_applied INT NOT NULL DEFAULT 0,
  applied_at VARCHAR(40),
  updated_at ${UPDATED_AT},
  CONSTRAINT fk_agent_waf_agent FOREIGN KEY (agent_id) REFERENCES agents(id) ON DELETE CASCADE,
  CONSTRAINT fk_agent_waf_org FOREIGN KEY (organization_id) REFERENCES organizations(id) ON DELETE CASCADE
) ${TABLE_OPTIONS};

CREATE TABLE IF NOT EXISTS firewall_policy (
  id VARCHAR(64) NOT NULL PRIMARY KEY,
  organization_id VARCHAR(64) NOT NULL UNIQUE,
  sync_to_server TINYINT NOT NULL DEFAULT 1,
  revision INT NOT NULL DEFAULT 1,
  last_applied_at VARCHAR(40),
  server_status VARCHAR(32) DEFAULT 'NO_TARGET',
  server_log TEXT,
  updated_at ${UPDATED_AT},
  CONSTRAINT fk_firewall_policy_org FOREIGN KEY (organization_id) REFERENCES organizations(id) ON DELETE CASCADE
) ${TABLE_OPTIONS};

CREATE TABLE IF NOT EXISTS agent_firewall_status (
  agent_id VARCHAR(64) NOT NULL PRIMARY KEY,
  organization_id VARCHAR(64) NOT NULL,
  application_id VARCHAR(64),
  desired_revision INT NOT NULL DEFAULT 0,
  applied_revision INT NOT NULL DEFAULT 0,
  status VARCHAR(32) NOT NULL DEFAULT 'PENDING',
  target VARCHAR(255),
  message TEXT,
  rules_applied INT NOT NULL DEFAULT 0,
  applied_at VARCHAR(40),
  updated_at ${UPDATED_AT},
  CONSTRAINT fk_agent_fw_agent FOREIGN KEY (agent_id) REFERENCES agents(id) ON DELETE CASCADE,
  CONSTRAINT fk_agent_fw_org FOREIGN KEY (organization_id) REFERENCES organizations(id) ON DELETE CASCADE
) ${TABLE_OPTIONS};

CREATE TABLE IF NOT EXISTS system_health (
  service_name VARCHAR(64) NOT NULL PRIMARY KEY,
  status VARCHAR(32) NOT NULL DEFAULT 'OPERATIONAL',
  latency_ms DOUBLE NOT NULL DEFAULT 0,
  last_check VARCHAR(40) NOT NULL DEFAULT (DATE_FORMAT(UTC_TIMESTAMP(), '%Y-%m-%d %H:%i:%s')),
  details TEXT
) ${TABLE_OPTIONS};

CREATE TABLE IF NOT EXISTS integration_configs (
  id VARCHAR(64) NOT NULL PRIMARY KEY,
  organization_id VARCHAR(64) NOT NULL,
  provider VARCHAR(64) NOT NULL,
  config_json TEXT NOT NULL,
  status VARCHAR(32) NOT NULL DEFAULT 'NOT CONFIGURED',
  updated_at ${UPDATED_AT},
  CONSTRAINT fk_integrations_org FOREIGN KEY (organization_id) REFERENCES organizations(id) ON DELETE CASCADE
) ${TABLE_OPTIONS};

CREATE TABLE IF NOT EXISTS uptime_records (
  id INT NOT NULL AUTO_INCREMENT PRIMARY KEY,
  service VARCHAR(64) NOT NULL,
  status VARCHAR(32) NOT NULL,
  latency_ms DOUBLE NOT NULL,
  timestamp VARCHAR(40) NOT NULL DEFAULT (DATE_FORMAT(UTC_TIMESTAMP(), '%Y-%m-%d %H:%i:%s'))
) ${TABLE_OPTIONS};

CREATE TABLE IF NOT EXISTS logs (
  id VARCHAR(64) NOT NULL PRIMARY KEY,
  organization_id VARCHAR(64) NOT NULL,
  timestamp VARCHAR(40) NOT NULL,
  level VARCHAR(16) NOT NULL,
  source VARCHAR(32) NOT NULL,
  event_type VARCHAR(64) NOT NULL,
  message TEXT NOT NULL,
  host VARCHAR(128) NOT NULL DEFAULT 'edge-gateway-01',
  ip VARCHAR(64),
  correlation_id VARCHAR(64),
  metadata TEXT,
  raw_log TEXT,
  agent_id VARCHAR(64),
  created_at ${CREATED_AT},
  CONSTRAINT fk_logs_org FOREIGN KEY (organization_id) REFERENCES organizations(id) ON DELETE CASCADE
) ${TABLE_OPTIONS};

CREATE TABLE IF NOT EXISTS malware_scans (
  id VARCHAR(64) NOT NULL PRIMARY KEY,
  organization_id VARCHAR(64) NOT NULL,
  application_id VARCHAR(64),
  agent_id VARCHAR(64),
  timestamp VARCHAR(40) NOT NULL,
  file_name VARCHAR(512) NOT NULL,
  file_path VARCHAR(2048),
  file_size BIGINT NOT NULL DEFAULT 0,
  sha256 VARCHAR(64) NOT NULL,
  md5 VARCHAR(32),
  mime_type VARCHAR(128),
  verdict VARCHAR(16) NOT NULL DEFAULT 'clean',
  score INT NOT NULL DEFAULT 0,
  family VARCHAR(255),
  severity VARCHAR(16) NOT NULL DEFAULT 'Low',
  status VARCHAR(32) NOT NULL DEFAULT 'DETECTED',
  action VARCHAR(32) NOT NULL DEFAULT 'NONE',
  action_status VARCHAR(16) NOT NULL DEFAULT 'NONE',
  source VARCHAR(32) NOT NULL DEFAULT 'agent',
  source_ip VARCHAR(64),
  request_uri TEXT,
  engines TEXT,
  c2 TEXT,
  sample_preview TEXT,
  metadata TEXT,
  quarantined_path VARCHAR(2048),
  created_at ${CREATED_AT},
  updated_at ${UPDATED_AT},
  CONSTRAINT fk_malware_org FOREIGN KEY (organization_id) REFERENCES organizations(id) ON DELETE CASCADE
) ${TABLE_OPTIONS};

CREATE TABLE IF NOT EXISTS malware_signatures (
  id VARCHAR(64) NOT NULL PRIMARY KEY,
  organization_id VARCHAR(64),
  sha256 VARCHAR(64) NOT NULL,
  label VARCHAR(255) NOT NULL,
  verdict VARCHAR(16) NOT NULL DEFAULT 'malicious',
  severity VARCHAR(16) NOT NULL DEFAULT 'High',
  description TEXT,
  created_by VARCHAR(255),
  created_at ${CREATED_AT},
  UNIQUE KEY uniq_malware_signature (organization_id, sha256)
) ${TABLE_OPTIONS};

CREATE TABLE IF NOT EXISTS contact_messages (
  id VARCHAR(64) NOT NULL PRIMARY KEY,
  organization_id VARCHAR(64),
  user_id VARCHAR(64),
  name VARCHAR(255) NOT NULL,
  email VARCHAR(255) NOT NULL,
  company VARCHAR(255),
  topic VARCHAR(64) NOT NULL DEFAULT 'General',
  severity VARCHAR(32) NOT NULL DEFAULT 'Normal',
  message TEXT NOT NULL,
  status VARCHAR(32) NOT NULL DEFAULT 'OPEN',
  source VARCHAR(32) NOT NULL DEFAULT 'console',
  created_at ${CREATED_AT},
  updated_at ${UPDATED_AT}
) ${TABLE_OPTIONS};

CREATE TABLE IF NOT EXISTS reports (
  id VARCHAR(64) NOT NULL PRIMARY KEY,
  organization_id VARCHAR(64) NOT NULL,
  title VARCHAR(255) NOT NULL,
  category VARCHAR(128) NOT NULL DEFAULT 'Executive',
  period VARCHAR(64) NOT NULL DEFAULT 'Last 30 Days',
  format VARCHAR(16) NOT NULL DEFAULT 'PDF',
  status VARCHAR(32) NOT NULL DEFAULT 'READY',
  summary TEXT,
  file_size VARCHAR(32) NOT NULL DEFAULT '14 KB',
  sha256 VARCHAR(64),
  content LONGTEXT,
  generated_by VARCHAR(255),
  created_at ${CREATED_AT},
  CONSTRAINT fk_reports_org FOREIGN KEY (organization_id) REFERENCES organizations(id) ON DELETE CASCADE
) ${TABLE_OPTIONS};

CREATE TABLE IF NOT EXISTS fail2ban_config (
  id VARCHAR(64) NOT NULL PRIMARY KEY,
  organization_id VARCHAR(64) NOT NULL UNIQUE,
  enabled TINYINT NOT NULL DEFAULT 1,
  bantime INT NOT NULL DEFAULT 3600,
  findtime INT NOT NULL DEFAULT 600,
  maxretry INT NOT NULL DEFAULT 5,
  ignore_ips TEXT,
  created_at ${CREATED_AT},
  updated_at ${UPDATED_AT}
) ${TABLE_OPTIONS};

CREATE TABLE IF NOT EXISTS fail2ban_bans (
  id VARCHAR(64) NOT NULL PRIMARY KEY,
  organization_id VARCHAR(64) NOT NULL,
  ip VARCHAR(64) NOT NULL,
  jail VARCHAR(64) NOT NULL DEFAULT 'sshd',
  reason VARCHAR(255),
  banned_at ${CREATED_AT},
  status VARCHAR(16) NOT NULL DEFAULT 'BANNED',
  unbanned_at VARCHAR(40)
) ${TABLE_OPTIONS};

CREATE TABLE IF NOT EXISTS nat_rules (
  id VARCHAR(64) NOT NULL PRIMARY KEY,
  organization_id VARCHAR(64) NOT NULL,
  name VARCHAR(128) NOT NULL,
  external_vip VARCHAR(64) NOT NULL DEFAULT '0.0.0.0',
  external_port VARCHAR(32) NOT NULL,
  internal_ip VARCHAR(64) NOT NULL,
  internal_port VARCHAR(32) NOT NULL,
  protocol VARCHAR(16) NOT NULL DEFAULT 'TCP',
  nat_mode VARCHAR(32) NOT NULL DEFAULT 'DNAT',
  enabled TINYINT NOT NULL DEFAULT 1,
  description TEXT,
  created_at ${CREATED_AT}
) ${TABLE_OPTIONS};

`;

/**
 * MySQL has no CREATE INDEX IF NOT EXISTS. runMigrations() tries each of these
 * and ignores ER_DUP_KEYNAME (1061), so restarts remain idempotent.
 */
export const MYSQL_INDEXES = [
  'CREATE INDEX idx_nat_rules_org ON nat_rules(organization_id)',
  'CREATE INDEX idx_reports_created ON reports(created_at)',
  'CREATE INDEX idx_reports_org ON reports(organization_id)',
  'CREATE INDEX idx_events_timestamp ON security_events(timestamp)',
  'CREATE INDEX idx_events_severity ON security_events(severity)',
  'CREATE INDEX idx_events_source_ip ON security_events(source_ip)',
  'CREATE INDEX idx_events_type ON security_events(event_type)',
  'CREATE INDEX idx_events_org ON security_events(organization_id)',
  'CREATE INDEX idx_events_agent ON security_events(agent_id)',
  'CREATE INDEX idx_threats_timestamp ON threats(timestamp)',
  'CREATE INDEX idx_threats_org ON threats(organization_id)',
  'CREATE INDEX idx_threats_status ON threats(status)',
  'CREATE INDEX idx_logs_timestamp ON logs(timestamp)',
  'CREATE INDEX idx_logs_org ON logs(organization_id)',
  'CREATE INDEX idx_logs_level ON logs(level)',
  'CREATE INDEX idx_logs_source ON logs(source)',
  'CREATE INDEX idx_logs_correlation ON logs(correlation_id)',
  'CREATE INDEX idx_logs_agent ON logs(agent_id)',
  'CREATE INDEX idx_audit_timestamp ON audit_logs(timestamp)',
  'CREATE INDEX idx_audit_org ON audit_logs(organization_id)',
  'CREATE INDEX idx_agents_org ON agents(organization_id)',
  'CREATE INDEX idx_agents_last_seen ON agents(last_seen)',
  'CREATE INDEX idx_agents_application ON agents(application_id)',
  'CREATE INDEX idx_agent_waf_org ON agent_waf_status(organization_id)',
  'CREATE INDEX idx_agent_waf_application ON agent_waf_status(application_id)',
  'CREATE INDEX idx_agent_tokens_org ON agent_enrollment_tokens(organization_id)',
  'CREATE INDEX idx_agent_tokens_hash ON agent_enrollment_tokens(token_hash)',
  'CREATE INDEX idx_agent_tokens_application ON agent_enrollment_tokens(application_id)',
  'CREATE INDEX idx_malware_timestamp ON malware_scans(timestamp)',
  'CREATE INDEX idx_malware_org ON malware_scans(organization_id)',
  'CREATE INDEX idx_malware_verdict ON malware_scans(verdict)',
  'CREATE INDEX idx_malware_status ON malware_scans(status)',
  'CREATE INDEX idx_malware_sha ON malware_scans(sha256)',
  'CREATE INDEX idx_malware_agent ON malware_scans(agent_id)',
  'CREATE INDEX idx_malware_signature_sha ON malware_signatures(sha256)',
  'CREATE INDEX idx_contact_org ON contact_messages(organization_id)',
  'CREATE INDEX idx_contact_status ON contact_messages(status)',
  'CREATE INDEX idx_contact_created ON contact_messages(created_at)',
  'CREATE INDEX idx_fail2ban_org ON fail2ban_bans(organization_id)',
  'CREATE INDEX idx_fail2ban_ip ON fail2ban_bans(ip)'
];
