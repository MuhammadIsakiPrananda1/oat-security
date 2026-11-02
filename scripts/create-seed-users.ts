import bcrypt from 'bcryptjs';
import { db } from '../server/database/db';

async function main() {
  console.log('[OAT Security] Starting manual database user creation...');

  // 1. Ensure an organization exists for foreign key constraint
  const orgId = 'org_oat_enterprise';
  const existingOrg = db.prepare('SELECT id FROM organizations WHERE id = ?').get(orgId) as any;

  if (!existingOrg) {
    db.prepare(`
      INSERT INTO organizations (id, name, domain, industry, tier, created_at)
      VALUES (?, ?, ?, ?, ?, UTC_TIMESTAMP())
    `).run(
      orgId,
      'OAT Security Corp',
      'oatsecurity.neverlandstudio.ai.id',
      'Technology',
      'Enterprise'
    );
    console.log('[OAT Security] Created organization:', orgId);
  } else {
    console.log('[OAT Security] Existing organization found:', orgId);
  }

  // 2. Hash passwords
  const superAdminPasswordHash = await bcrypt.hash('zakykece', 10);
  const adminPasswordHash = await bcrypt.hash('zakykeceterus', 10);
  const admin2PasswordHash = await bcrypt.hash('admin2', 10);

  // 3. User 1: Super Admin (username: superadmin, password: zakykece)
  const superAdminEmail = 'superadmin@oatsecurity.com';
  const superAdminId = 'usr_superadmin_01';
  const existingSuperAdmin = db.prepare('SELECT id FROM users WHERE email = ? OR username = ?').get(superAdminEmail, 'superadmin') as any;

  if (existingSuperAdmin) {
    db.prepare(`
      UPDATE users 
      SET password_hash = ?, role = 'Super Admin', name = 'Super Administrator', organization_id = ?, username = 'superadmin'
      WHERE id = ?
    `).run(superAdminPasswordHash, orgId, existingSuperAdmin.id);
    console.log('[OAT Security] Updated existing Super Admin:', superAdminEmail);
  } else {
    db.prepare(`
      INSERT INTO users (
        id, organization_id, name, email, password_hash, role, mfa_enabled, username, created_at
      ) VALUES (?, ?, ?, ?, ?, ?, 0, ?, UTC_TIMESTAMP())
    `).run(
      superAdminId,
      orgId,
      'Super Administrator',
      superAdminEmail,
      superAdminPasswordHash,
      'Super Admin',
      'superadmin'
    );
    console.log('[OAT Security] Created Super Admin user:', superAdminEmail);
  }

  // 4. User 2: Admin / User Biasa 1 (username: admin, password: zakykeceterus)
  const adminEmail = 'admin@oatsecurity.com';
  const adminId = 'usr_admin_01';
  const existingAdmin = db.prepare('SELECT id FROM users WHERE email = ? OR username = ?').get(adminEmail, 'admin') as any;

  if (existingAdmin) {
    db.prepare(`
      UPDATE users 
      SET password_hash = ?, role = 'Admin', name = 'Administrator', organization_id = ?, username = 'admin'
      WHERE id = ?
    `).run(adminPasswordHash, orgId, existingAdmin.id);
    console.log('[OAT Security] Updated existing Admin:', adminEmail);
  } else {
    db.prepare(`
      INSERT INTO users (
        id, organization_id, name, email, password_hash, role, mfa_enabled, username, created_at
      ) VALUES (?, ?, ?, ?, ?, ?, 0, ?, UTC_TIMESTAMP())
    `).run(
      adminId,
      orgId,
      'Administrator',
      adminEmail,
      adminPasswordHash,
      'Admin',
      'admin'
    );
    console.log('[OAT Security] Created Admin user:', adminEmail);
  }

  // 5. User 3: Admin 2 (username: admin2, password: admin2)
  const admin2Email = 'admin2@oatsecurity.com';
  const admin2Id = 'usr_admin_02';
  const existingAdmin2 = db.prepare('SELECT id FROM users WHERE email = ? OR username = ?').get(admin2Email, 'admin2') as any;

  if (existingAdmin2) {
    db.prepare(`
      UPDATE users 
      SET password_hash = ?, role = 'Admin', name = 'Admin 2', organization_id = ?, username = 'admin2'
      WHERE id = ?
    `).run(admin2PasswordHash, orgId, existingAdmin2.id);
    console.log('[OAT Security] Updated existing Admin 2:', admin2Email);
  } else {
    db.prepare(`
      INSERT INTO users (
        id, organization_id, name, email, password_hash, role, mfa_enabled, username, created_at
      ) VALUES (?, ?, ?, ?, ?, ?, 0, ?, UTC_TIMESTAMP())
    `).run(
      admin2Id,
      orgId,
      'Admin 2',
      admin2Email,
      admin2PasswordHash,
      'Admin',
      'admin2'
    );
    console.log('[OAT Security] Created Admin 2 user:', admin2Email);
  }

  // 5. Verification
  const users = db.prepare('SELECT id, name, username, email, role, organization_id, created_at FROM users').all();
  console.log('\n[OAT Security] Current Database Users:');
  console.table(users);
}

main().catch((err) => {
  console.error('[OAT Security] Error creating seed users:', err);
  process.exit(1);
});
