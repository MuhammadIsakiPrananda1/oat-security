import path from 'path';
import dotenv from 'dotenv';

dotenv.config();

export const CONFIG = {
  PORT: Number(process.env.PORT) || 3000,
  HOST: process.env.HOST || '0.0.0.0',
  NODE_ENV: process.env.NODE_ENV || 'development',
  // MySQL (Laragon). Run `npm run db:setup` once to create the database and
  // the dedicated application user.
  DB_HOST: process.env.DB_HOST || '127.0.0.1',
  DB_PORT: Number(process.env.DB_PORT) || 3306,
  DB_USER: process.env.DB_USER || 'oat',
  DB_PASSWORD: process.env.DB_PASSWORD || 'oat_security_2026',
  DB_NAME: process.env.DB_NAME || 'oat_security',
  JWT_SECRET: process.env.JWT_SECRET || 'oat_security_enterprise_jwt_secret_key_2026',
  SESSION_SECRET: process.env.SESSION_SECRET || 'oat_security_session_key_2026',
  CORS_ORIGINS: process.env.CORS_ORIGINS || '*',
  AGENT_BIN_DIR: process.env.AGENT_BIN_DIR || path.join(process.cwd(), 'agent', 'dist'),
  LOG_LEVEL: process.env.LOG_LEVEL || 'info',
  GEMINI_API_KEY: process.env.GEMINI_API_KEY || '',
  GROQ_API_KEY: process.env.GROQ_API_KEY || ''
};
