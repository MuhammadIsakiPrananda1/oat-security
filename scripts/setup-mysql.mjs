#!/usr/bin/env node
/**
 * Creates the MySQL database and application user declared in .env.
 *
 *   npm run db:setup
 *
 * Connects as root (Laragon's default root has no password) unless
 * MYSQL_ROOT_USER / MYSQL_ROOT_PASSWORD are provided.
 */
import dotenv from 'dotenv';
import mysql from 'mysql2/promise';

dotenv.config();

const DB_HOST = process.env.DB_HOST || '127.0.0.1';
const DB_PORT = Number(process.env.DB_PORT || '3306');
const DB_NAME = process.env.DB_NAME || 'oat_security';
const DB_USER = process.env.DB_USER || 'oat';
const DB_PASSWORD = process.env.DB_PASSWORD || '';

const ROOT_USER = process.env.MYSQL_ROOT_USER || 'root';
const ROOT_PASSWORD = process.env.MYSQL_ROOT_PASSWORD ?? '';

const escapeIdent = value => `\`${value.replace(/`/g, '``')}\``;
const escapeLiteral = value => `'${value.replace(/'/g, "''")}'`;

async function main() {
  const conn = await mysql.createConnection({
    host: DB_HOST,
    port: DB_PORT,
    user: ROOT_USER,
    password: ROOT_PASSWORD,
    multipleStatements: true
  });

  try {
    await conn.query(
      `CREATE DATABASE IF NOT EXISTS ${escapeIdent(DB_NAME)} CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci`
    );
    await conn.query(
      `CREATE USER IF NOT EXISTS ${escapeIdent(DB_USER)}@${escapeLiteral('%')} IDENTIFIED BY ${escapeLiteral(DB_PASSWORD)}`
    );
    await conn.query(
      `GRANT ALL PRIVILEGES ON ${escapeIdent(DB_NAME)}.* TO ${escapeIdent(DB_USER)}@${escapeLiteral('%')}`
    );
    await conn.query(`ALTER USER ${escapeIdent(DB_USER)}@${escapeLiteral('%')} IDENTIFIED BY ${escapeLiteral(DB_PASSWORD)}`);
    console.log(`[db:setup] Database "${DB_NAME}" ready — user "${DB_USER}" can read/write it.`);
    console.log('[db:setup] Server migrations run automatically on the next `npm run dev`.');
  } finally {
    await conn.end();
  }
}

main().catch(err => {
  if (err && (err.code === 'ECONNREFUSED' || err.code === 'ER_ACCESS_DENIED_ERROR')) {
    console.error('[db:setup] Could not reach MySQL as root — start Laragon, or set MYSQL_ROOT_USER / MYSQL_ROOT_PASSWORD in the environment.');
    console.error(`[db:setup] (${err.code})`, err.message);
  } else {
    console.error('[db:setup] Failed:', err);
  }
  process.exit(1);
});
