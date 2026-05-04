import crypto from 'crypto';
import { env } from '../config/env';

export function sha256Base64Url(value: string): string {
  return crypto.createHash('sha256').update(value).digest('base64url');
}

export function sha256Hex(value: string): string {
  return crypto.createHash('sha256').update(value).digest('hex');
}

export function hmacTokenHash(value: string): string {
  return crypto.createHmac('sha256', env.AUTH_TOKEN_HASH_SECRET).update(value).digest('hex');
}

export function hashSensitive(value?: string | null): string | null {
  if (!value) return null;
  return hmacTokenHash(value.trim().toLowerCase());
}

export function timingSafeEqualString(left: string, right: string): boolean {
  const leftBuffer = Buffer.from(left);
  const rightBuffer = Buffer.from(right);
  if (leftBuffer.length !== rightBuffer.length) return false;
  return crypto.timingSafeEqual(leftBuffer, rightBuffer);
}

export function verifyPkceS256(verifier: string, challenge: string): boolean {
  if (!verifier || !challenge) return false;
  return timingSafeEqualString(sha256Base64Url(verifier), challenge);
}
