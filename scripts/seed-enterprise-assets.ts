import { db } from '../server/database/db';

async function seedEnterpriseAssets() {
  const orgId = 'org_oat_enterprise';

  console.log('[OAT Security] Checking baseline assets for org:', orgId);

  // 1. Ensure Applications
  const apps = [
    {
      id: 'app_oat_portal',
      name: 'OAT Enterprise Production Portal',
      domain: 'portal.oatsecurity.com',
      origin_ip: '192.168.1.10',
      environment: 'Production',
      status: 'ONLINE',
      owner: 'Platform SecOps',
      protocol: 'HTTPS',
      port: 443
    },
    {
      id: 'app_oat_api',
      name: 'Core Identity & SSO API Gateway',
      domain: 'api.oatsecurity.com',
      origin_ip: '192.168.1.12',
      environment: 'Production',
      status: 'ONLINE',
      owner: 'Identity SecOps',
      protocol: 'HTTPS',
      port: 443
    }
  ];

  for (const app of apps) {
    const existing = db.prepare('SELECT id FROM applications WHERE id = ?').get(app.id) as any;
    if (!existing) {
      db.prepare(`
        INSERT INTO applications (id, organization_id, name, domain, origin_ip, environment, status, owner, protocol, port, created_at)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, UTC_TIMESTAMP())
      `).run(app.id, orgId, app.name, app.domain, app.origin_ip, app.environment, app.status, app.owner, app.protocol, app.port);
      console.log('✓ Added application asset:', app.name);
    }
  }

  // 2. Ensure Endpoint Agent
  const agentId = 'agent_prod_srv_01';
  const existingAgent = db.prepare('SELECT id FROM agents WHERE id = ?').get(agentId) as any;
  if (!existingAgent) {
    db.prepare(`
      INSERT INTO agents (
        id, organization_id, application_id, name, hostname, os, arch, version,
        ip, status, public_key, host_info, last_seen, created_at
      ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, 'ONLINE', ?, ?, UTC_TIMESTAMP(), UTC_TIMESTAMP())
    `).run(
      agentId,
      orgId,
      'app_oat_portal',
      'srv-prod-edge01',
      'srv-prod-edge01.internal',
      'linux',
      'amd64',
      '2.4.1',
      '192.168.1.10',
      'dummy-key-for-local-agent-01',
      JSON.stringify({ cpu: '4 Cores', memory: '16GB', distro: 'Ubuntu 22.04 LTS' })
    );

    db.prepare(`
      INSERT INTO agent_firewall_status (
        agent_id, organization_id, desired_revision, applied_revision, status, target, rules_applied, updated_at
      ) VALUES (?, ?, 1, 1, 'ACTIVE', '192.168.1.10', 0, UTC_TIMESTAMP())
      ON DUPLICATE KEY UPDATE status = 'ACTIVE'
    `).run(agentId, orgId);

    console.log('✓ Added endpoint security agent:', agentId);
  }

  // 3. Ensure Baseline Real Incident
  const incidentId = 'INC-2026-001';
  const existingInc = db.prepare('SELECT id FROM incidents WHERE id = ?').get(incidentId) as any;
  if (!existingInc) {
    const timeline = [
      {
        time: new Date(Date.now() - 3600000).toISOString(),
        note: 'Ingestion trigger: WAF rate-limit violation and correlated authentication anomaly.',
        author: 'System Telemetry Detector',
        tier: 'L1'
      },
      {
        time: new Date(Date.now() - 1800000).toISOString(),
        note: 'Tier 1 Triage confirmed threat pattern: Distributed Credential Stuffing. Escalated to Tier 2 Deep Forensics.',
        author: 'analyst@oatsecurity.com',
        tier: 'L2'
      }
    ];

    db.prepare(`
      INSERT INTO incidents (
        id, organization_id, title, severity, status, tier, assigned_to,
        affected_asset, notes, timeline, created_at, updated_at
      ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, UTC_TIMESTAMP(), UTC_TIMESTAMP())
    `).run(
      incidentId,
      orgId,
      'Distributed Credential Stuffing & High-Volume Brute Force',
      'High',
      'IN_PROGRESS',
      'L2',
      'analyst@oatsecurity.com',
      'Core Identity & SSO API Gateway (api.oatsecurity.com)',
      'Detected 142 failed login requests within 60s originating from rotating VPN/Tor exit relays (185.220.101.42, 185.220.101.45). Pattern matches credential stuffing attack against SSO endpoint /api/auth/v1/tokens.',
      JSON.stringify(timeline)
    );
    console.log('✓ Added baseline enterprise incident:', incidentId);
  }

  console.log('[OAT Security] Enterprise assets and incident seeding complete!');
  process.exit(0);
}

seedEnterpriseAssets().catch(err => {
  console.error('Error seeding enterprise assets:', err);
  process.exit(1);
});
