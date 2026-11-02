import mysql from 'mysql2/promise';
import bcrypt from 'bcryptjs';

async function seed() {
  const conn = await mysql.createConnection({
    host: process.env.DB_HOST || '127.0.0.1',
    port: Number(process.env.DB_PORT) || 3306,
    user: process.env.DB_USER || 'oat',
    password: process.env.DB_PASSWORD || 'oat_security_2026',
    database: process.env.DB_NAME || 'oat_security'
  });

  console.log('[OAT Security] Setting up isolated user workspaces...');

  // 1. Buat organisasi masing-masing agar data antar user terisolasi dan tidak bercampur
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
    await conn.execute(
      `INSERT INTO organizations (id, name, domain, industry, tier, created_at)
       VALUES (?, ?, ?, ?, ?, UTC_TIMESTAMP())
       ON DUPLICATE KEY UPDATE name = VALUES(name), domain = VALUES(domain), tier = VALUES(tier)`,
      [org.id, org.name, org.domain, org.industry, org.tier]
    );
  }

  // 2. Hash passwords
  const hashSuper = await bcrypt.hash('zakykece', 10);
  const hashAdmin1 = await bcrypt.hash('zakykeceterus', 10);
  const hashAdmin2 = await bcrypt.hash('admin2', 10);

  // 3. Masukkan / Update masing-masing User dengan Organisasi Sendiri
  // User 1: Super Admin -> org_superadmin
  await conn.execute(
    `INSERT INTO users (id, organization_id, name, email, password_hash, role, mfa_enabled, username, created_at)
     VALUES (?, ?, ?, ?, ?, ?, 0, ?, UTC_TIMESTAMP())
     ON DUPLICATE KEY UPDATE organization_id = VALUES(organization_id), password_hash = VALUES(password_hash), role = VALUES(role), username = VALUES(username), mfa_enabled = 0`,
    ['usr_superadmin_01', 'org_superadmin', 'Super Administrator', 'superadmin@oatsecurity.com', hashSuper, 'Super Admin', 'superadmin']
  );

  // User 2: Admin 1 -> org_admin_01
  await conn.execute(
    `INSERT INTO users (id, organization_id, name, email, password_hash, role, mfa_enabled, username, created_at)
     VALUES (?, ?, ?, ?, ?, ?, 0, ?, UTC_TIMESTAMP())
     ON DUPLICATE KEY UPDATE organization_id = VALUES(organization_id), password_hash = VALUES(password_hash), role = VALUES(role), username = VALUES(username), mfa_enabled = 0`,
    ['usr_admin_01', 'org_admin_01', 'Administrator 1', 'admin@oatsecurity.com', hashAdmin1, 'Admin', 'admin']
  );

  // User 3: Admin 2 -> org_admin_02
  await conn.execute(
    `INSERT INTO users (id, organization_id, name, email, password_hash, role, mfa_enabled, username, created_at)
     VALUES (?, ?, ?, ?, ?, ?, 0, ?, UTC_TIMESTAMP())
     ON DUPLICATE KEY UPDATE organization_id = VALUES(organization_id), password_hash = VALUES(password_hash), role = VALUES(role), username = VALUES(username), mfa_enabled = 0`,
    ['usr_admin_02', 'org_admin_02', 'Administrator 2', 'admin2@oatsecurity.com', hashAdmin2, 'Admin', 'admin2']
  );

  const [rows] = await conn.execute(`
    SELECT u.id, u.name, u.username, u.email, u.role, u.organization_id, o.name as workspace_name
    FROM users u
    LEFT JOIN organizations o ON u.organization_id = o.id
  `);

  console.log('\n✅ User dan Workspace Terisolasi Berhasil Disetup:');
  console.table(rows);
  await conn.end();
}

seed().catch(console.error);
