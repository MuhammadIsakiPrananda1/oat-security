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
      'oatsecurity.com',
      'Technology',
      'Enterprise'
    );
    console.log('[OAT Security] Created organization:', orgId);
  } else {
    console.log('[OAT Security] Existing organization found:', orgId);
  }

  // 2. Hash default passwords
  const defaultPassword = 'Password123!';
  const passwordHash = await bcrypt.hash(defaultPassword, 10);

  // 3. User 1: Super Admin
  const superAdminEmail = 'superadmin@oatsecurity.com';
  const superAdminId = 'usr_superadmin_01';
  const existingSuperAdmin = db.prepare('SELECT id FROM users WHERE email = ?').get(superAdminEmail) as any;

  if (existingSuperAdmin) {
    db.prepare(`
      UPDATE users 
      SET password_hash = ?, role = 'Super Admin', name = 'Super Administrator', organization_id = ?
      WHERE email = ?
    `).run(passwordHash, orgId, superAdminEmail);
    console.log('[OAT Security] Updated existing Super Admin:', superAdminEmail);
  } else {
    db.prepare(`
      INSERT INTO users (
        id, organization_id, name, email, password_hash, role, mfa_enabled, username, created_at
      ) VALUES (?, ?, ?, ?, ?, ?, 1, ?, UTC_TIMESTAMP())
    `).run(
      superAdminId,
      orgId,
      'Super Administrator',
      superAdminEmail,
      passwordHash,
      'Super Admin',
      'superadmin'
    );
    console.log('[OAT Security] Created Super Admin user:', superAdminEmail);
  }

  // 4. User 2: Security Analyst (role lain)
  const analystEmail = 'analyst@oatsecurity.com';
  const analystId = 'usr_analyst_01';
  const existingAnalyst = db.prepare('SELECT id FROM users WHERE email = ?').get(analystEmail) as any;

  if (existingAnalyst) {
    db.prepare(`
      UPDATE users 
      SET password_hash = ?, role = 'Security Analyst', name = 'Security Analyst Team', organization_id = ?
      WHERE email = ?
    `).run(passwordHash, orgId, analystEmail);
    console.log('[OAT Security] Updated existing Security Analyst:', analystEmail);
  } else {
    db.prepare(`
      INSERT INTO users (
        id, organization_id, name, email, password_hash, role, mfa_enabled, username, created_at
      ) VALUES (?, ?, ?, ?, ?, ?, 1, ?, UTC_TIMESTAMP())
    `).run(
      analystId,
      orgId,
      'Security Analyst Team',
      analystEmail,
      passwordHash,
      'Security Analyst',
      'analyst'
    );
    console.log('[OAT Security] Created Security Analyst user:', analystEmail);
  }

  // 5. Verification
  const users = db.prepare('SELECT id, name, email, role, organization_id, created_at FROM users').all();
  console.log('\n[OAT Security] Current Database Users:');
  console.table(users);
}

main().catch((err) => {
  console.error('[OAT Security] Error creating seed users:', err);
  process.exit(1);
});
