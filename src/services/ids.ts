import crypto from 'crypto';

export function newId(prefix: string): string {
  return `${prefix}_${crypto.randomUUID().replace(/-/g, '')}`;
}

export function randomBase64Url(bytes = 32): string {
  return crypto.randomBytes(bytes).toString('base64url');
}

export function randomOpaqueToken(prefix: string, bytes = 48): string {
  return `${prefix}_${randomBase64Url(bytes)}`;
}

export function randomNumericCode(length = 6): string {
  const max = 10 ** length;
  return crypto.randomInt(0, max).toString().padStart(length, '0');
}
