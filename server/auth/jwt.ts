import jwt from 'jsonwebtoken';
import bcrypt from 'bcryptjs';
import { CONFIG } from '../config';

export interface AuthPayload {
  userId: string;
  email: string;
  role: string;
  organizationId: string;
  /** Assigned SOC response tier (L1/L2/L3). Null means unrestricted. */
  socTier?: string | null;
}

export function signToken(payload: AuthPayload): string {
  return jwt.sign(payload, CONFIG.JWT_SECRET, { expiresIn: '24h' });
}

export function verifyToken(token: string): AuthPayload | null {
  try {
    return jwt.verify(token, CONFIG.JWT_SECRET) as AuthPayload;
  } catch {
    return null;
  }
}

export async function hashPassword(password: string): Promise<string> {
  return bcrypt.hash(password, 10);
}

export async function comparePassword(password: string, hash: string): Promise<boolean> {
  return bcrypt.compare(password, hash);
}
