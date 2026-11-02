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

  const orgId = 'org_oat_enterprise';
  await conn.execute(
    `INSERT INTO organizations (id, name, domain, industry, tier, created_at)
     VALUES (?, ?, ?, ?, ?, UTC_TIMESTAMP())
     ON DUPLICATE KEY UPDATE name = VALUES(name), domain = VALUES(domain)`,
    [orgId, 'OAT Security Corp', 'oatsecurity.neverlandstudio.ai.id', 'Technology', 'Enterprise']
  );

  const hashSuper = await bcrypt.hash('zakykece', 10);
  const hashAdmin = await bcrypt.hash('zakykeceterus', 10);
  const hashAdmin2 = await bcrypt.hash('admin2', 10);

  // 1. Super Admin
  await conn.execute(
    `INSERT INTO users (id, organization_id, name, email, password_hash, role, mfa_enabled, username, created_at)
     VALUES (?, ?, ?, ?, ?, ?, 0, ?, UTC_TIMESTAMP())
     ON DUPLICATE KEY UPDATE password_hash = VALUES(password_hash), role = VALUES(role), username = VALUES(username), mfa_enabled = 0`,
    ['usr_superadmin_01', orgId, 'Super Administrator', 'superadmin@oatsecurity.com', hashSuper, 'Super Admin', 'superadmin']
  );

  // 2. Admin / User Biasa 1
  await conn.execute(
    `INSERT INTO users (id, organization_id, name, email, password_hash, role, mfa_enabled, username, created_at)
     VALUES (?, ?, ?, ?, ?, ?, 0, ?, UTC_TIMESTAMP())
     ON DUPLICATE KEY UPDATE password_hash = VALUES(password_hash), role = VALUES(role), username = VALUES(username), mfa_enabled = 0`,
    ['usr_admin_01', orgId, 'Administrator', 'admin@oatsecurity.com', hashAdmin, 'Admin', 'admin']
  );

  // 3. Admin 2 (User Biasa 2)
  await conn.execute(
    `INSERT INTO users (id, organization_id, name, email, password_hash, role, mfa_enabled, username, created_at)
     VALUES (?, ?, ?, ?, ?, ?, 0, ?, UTC_TIMESTAMP())
     ON DUPLICATE KEY UPDATE password_hash = VALUES(password_hash), role = VALUES(role), username = VALUES(username), mfa_enabled = 0`,
    ['usr_admin_02', orgId, 'Admin 2', 'admin2@oatsecurity.com', hashAdmin2, 'Admin', 'admin2']
  );

  const [rows] = await conn.execute('SELECT id, name, username, email, role, mfa_enabled FROM users');
  console.log('\n✅ User OAT Security berhasil dibuat/diperbarui:');
  console.table(rows);
  await conn.end();
}

seed().catch(console.error);

