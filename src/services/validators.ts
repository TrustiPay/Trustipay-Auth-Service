import { OAuthClientConfig } from '../types/auth';

const EMAIL_RE = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;

export function normalizeEmail(email?: string | null): string | null {
  if (!email) return null;
  const normalized = email.trim().toLowerCase();
  return normalized.length > 0 ? normalized : null;
}

export function normalizePhone(phone?: string | null): string | null {
  if (!phone) return null;
  const raw = phone.trim();
  if (!raw) return null;
  if (raw.startsWith('+')) return `+${raw.slice(1).replace(/[^\d]/g, '')}`;

  const digits = raw.replace(/[^\d]/g, '');
  if (digits.startsWith('94') && digits.length === 11) return `+${digits}`;
  if (digits.startsWith('0') && digits.length === 10) return `+94${digits.slice(1)}`;
  if (digits.length === 9) return `+94${digits}`;
  return digits ? `+${digits}` : null;
}

export function isEmail(identifier: string): boolean {
  return EMAIL_RE.test(identifier.trim().toLowerCase());
}

export function assertValidEmail(email: string | null): void {
  if (!email || !EMAIL_RE.test(email)) {
    throw Object.assign(new Error('A valid email address is required.'), { status: 400, code: 'invalid_email' });
  }
}

export function assertValidPassword(password?: string): void {
  if (!password || password.length < 8) {
    throw Object.assign(new Error('Password must be at least 8 characters long.'), {
      status: 400,
      code: 'weak_password',
    });
  }
  if (!/[A-Za-z]/.test(password) || !/[0-9]/.test(password)) {
    throw Object.assign(new Error('Password must include letters and numbers.'), {
      status: 400,
      code: 'weak_password',
    });
  }
}

export function parseScope(scope?: string | string[] | null): string[] {
  const value = Array.isArray(scope) ? scope.join(' ') : scope || '';
  return Array.from(new Set(value.split(/\s+/).map((item) => item.trim()).filter(Boolean)));
}

export function scopeString(scopes: string[]): string {
  return Array.from(new Set(scopes)).join(' ');
}

export function assertScopesAllowed(client: OAuthClientConfig, requested: string[]): string[] {
  const scopes = requested.length > 0 ? requested : ['openid', 'profile'];
  const disallowed = scopes.filter((scope) => !client.allowedScopes.includes(scope));
  if (disallowed.length > 0) {
    throw Object.assign(new Error(`Unsupported scope: ${disallowed.join(' ')}`), {
      status: 400,
      code: 'invalid_scope',
    });
  }
  return scopes;
}

export function parseJsonArray(value?: string | null): string[] {
  if (!value) return [];
  try {
    const parsed = JSON.parse(value);
    return Array.isArray(parsed) ? parsed.filter((item) => typeof item === 'string') : [];
  } catch {
    return value.split(/\s+/).filter(Boolean);
  }
}

export function stringifyJsonArray(values: string[]): string {
  return JSON.stringify(Array.from(new Set(values)));
}

export function pickFirstString(value: unknown): string | undefined {
  if (Array.isArray(value)) return typeof value[0] === 'string' ? value[0] : undefined;
  return typeof value === 'string' ? value : undefined;
}
