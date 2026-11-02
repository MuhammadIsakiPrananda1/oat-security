import bcrypt from 'bcryptjs';
import { db } from '../server/database/db';

async function main() {
  console.log('[OAT Security] Starting manual database user creation with isolated workspaces...');

  const orgs = [
    {
      id: 'org_superadmin',
      name: 'SuperAdmin Master Operations',
      domain: 'oatsecurity.neverlandstudio.ai.id',
      industry: 'Cybersecurity',
      tier: 'Enterprise'
    },
    {
      id: 'org_admin_01',
      name: 'Admin Workspace 1',
      domain: 'admin1.neverlandstudio.ai.id',
      industry: 'Technology',
      tier: 'Enterprise'
    },
    {
      id: 'org_admin_02',
      name: 'Admin Workspace 2',
      domain: 'admin2.neverlandstudio.ai.id',
      industry: 'E-Commerce',
      tier: 'Enterprise'
    }
  ];

  for (const org of orgs) {
    db.prepare(`
      INSERT INTO organizations (id, name, domain, industry, tier, created_at)
      VALUES (?, ?, ?, ?, ?, UTC_TIMESTAMP())
      ON DUPLICATE KEY UPDATE name = VALUES(name), domain = VALUES(domain), tier = VALUES(tier)
    `).run(org.id, org.name, org.domain, org.industry, org.tier);
  }

  // 2. Hash passwords
  const superAdminPasswordHash = await bcrypt.hash('zakykece', 10);
  const adminPasswordHash = await bcrypt.hash('zakykeceterus', 10);
  const admin2PasswordHash = await bcrypt.hash('admin2', 10);

  // 3. User 1: Super Admin -> org_superadmin
  db.prepare(`
    INSERT INTO users (
      id, organization_id, name, email, password_hash, role, mfa_enabled, username, created_at
    ) VALUES (?, ?, ?, ?, ?, ?, 0, ?, UTC_TIMESTAMP())
    ON DUPLICATE KEY UPDATE organization_id = VALUES(organization_id), password_hash = VALUES(password_hash), role = VALUES(role), username = VALUES(username), mfa_enabled = 0
  `).run(
    'usr_superadmin_01',
    'org_superadmin',
    'Super Administrator',
    'superadmin@oatsecurity.com',
    superAdminPasswordHash,
    'Super Admin',
    'superadmin'
  );

  // 4. User 2: Admin 1 -> org_admin_01
  db.prepare(`
    INSERT INTO users (
      id, organization_id, name, email, password_hash, role, mfa_enabled, username, created_at
    ) VALUES (?, ?, ?, ?, ?, ?, 0, ?, UTC_TIMESTAMP())
    ON DUPLICATE KEY UPDATE organization_id = VALUES(organization_id), password_hash = VALUES(password_hash), role = VALUES(role), username = VALUES(username), mfa_enabled = 0
  `).run(
    'usr_admin_01',
    'org_admin_01',
    'Administrator 1',
    'admin@oatsecurity.com',
    adminPasswordHash,
    'Admin',
    'admin'
  );

  // 5. User 3: Admin 2 -> org_admin_02
  db.prepare(`
    INSERT INTO users (
      id, organization_id, name, email, password_hash, role, mfa_enabled, username, created_at
    ) VALUES (?, ?, ?, ?, ?, ?, 0, ?, UTC_TIMESTAMP())
    ON DUPLICATE KEY UPDATE organization_id = VALUES(organization_id), password_hash = VALUES(password_hash), role = VALUES(role), username = VALUES(username), mfa_enabled = 0
  `).run(
    'usr_admin_02',
    'org_admin_02',
    'Administrator 2',
    'admin2@oatsecurity.com',
    admin2PasswordHash,
    'Admin',
    'admin2'
  );

  const users = db.prepare(`
    SELECT u.id, u.name, u.username, u.email, u.role, u.organization_id, o.name as workspace_name
    FROM users u
    LEFT JOIN organizations o ON u.organization_id = o.id
  `).all();
  console.log('\n[OAT Security] Current Database Users:');
  console.table(users);
}

main().catch((err) => {
  console.error('[OAT Security] Error creating seed users:', err);
  process.exit(1);
});
