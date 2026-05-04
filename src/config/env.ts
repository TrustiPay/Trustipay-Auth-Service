import dotenv from 'dotenv';

dotenv.config();

function intFromEnv(name: string, fallback: number): number {
  const value = process.env[name];
  if (!value) return fallback;
  const parsed = Number.parseInt(value, 10);
  return Number.isFinite(parsed) ? parsed : fallback;
}

function boolFromEnv(name: string, fallback: boolean): boolean {
  const value = process.env[name];
  if (value === undefined) return fallback;
  return ['1', 'true', 'yes', 'on'].includes(value.toLowerCase());
}

function csvFromEnv(name: string, fallback: string[]): string[] {
  const value = process.env[name];
  if (!value) return fallback;
  return value
    .split(',')
    .map((item) => item.trim())
    .filter(Boolean);
}

const port = intFromEnv('PORT', 3001);
const databaseUrl =
  process.env.AUTH_DATABASE_URL ||
  process.env.DATABASE_URL ||
  'file:../data/trustipay_auth.sqlite';

process.env.DATABASE_URL = databaseUrl;

const issuer = (process.env.AUTH_ISSUER_URL || `http://localhost:${port}/auth`).replace(/\/+$/, '');

export const env = {
  NODE_ENV: process.env.NODE_ENV || 'development',
  SERVICE_NAME: process.env.SERVICE_NAME || 'trustipay-auth-service',
  PORT: port,
  DATABASE_URL: databaseUrl,
  SQLITE_BUSY_TIMEOUT_MS: intFromEnv('SQLITE_BUSY_TIMEOUT_MS', 5000),
  SQLITE_WAL_ENABLED: boolFromEnv('SQLITE_WAL_ENABLED', true),

  AUTH_ISSUER_URL: issuer,
  AUTH_ACCESS_TOKEN_AUDIENCE: process.env.AUTH_ACCESS_TOKEN_AUDIENCE || 'trustipay-api',
  AUTH_INTERNAL_TOKEN_AUDIENCE: process.env.AUTH_INTERNAL_TOKEN_AUDIENCE || 'trustipay-internal-api',
  AUTH_ACCESS_TOKEN_TTL_SECONDS: intFromEnv('AUTH_ACCESS_TOKEN_TTL_SECONDS', 900),
  AUTH_ID_TOKEN_TTL_SECONDS: intFromEnv('AUTH_ID_TOKEN_TTL_SECONDS', 900),
  AUTH_REFRESH_TOKEN_TTL_DAYS: intFromEnv('AUTH_REFRESH_TOKEN_TTL_DAYS', 30),
  AUTH_AUTH_CODE_TTL_SECONDS: intFromEnv('AUTH_AUTH_CODE_TTL_SECONDS', 300),
  AUTH_PASSWORD_RESET_TTL_SECONDS: intFromEnv('AUTH_PASSWORD_RESET_TTL_SECONDS', 900),
  AUTH_VERIFICATION_CODE_TTL_SECONDS: intFromEnv('AUTH_VERIFICATION_CODE_TTL_SECONDS', 600),
  AUTH_DEVICE_CHALLENGE_TTL_SECONDS: intFromEnv('AUTH_DEVICE_CHALLENGE_TTL_SECONDS', 300),
  AUTH_TOKEN_HASH_SECRET:
    process.env.AUTH_TOKEN_HASH_SECRET ||
    process.env.JWT_TOKEN_HASH_SECRET ||
    'dev-only-change-me-token-hash-secret',
  AUTH_PASSWORD_PEPPER: process.env.AUTH_PASSWORD_PEPPER || '',

  AUTH_JWT_KID: process.env.AUTH_JWT_KID || 'trustipay-auth-dev-rs256',
  AUTH_JWT_PRIVATE_KEY: process.env.AUTH_JWT_PRIVATE_KEY || process.env.JWT_PRIVATE_KEY,
  AUTH_JWT_PUBLIC_KEY: process.env.AUTH_JWT_PUBLIC_KEY || process.env.JWT_PUBLIC_KEY,
  AUTH_JWT_PRIVATE_KEY_PATH:
    process.env.AUTH_JWT_PRIVATE_KEY_PATH || process.env.JWT_PRIVATE_KEY_PATH || './keys/private.pem',
  AUTH_JWT_PUBLIC_KEY_PATH:
    process.env.AUTH_JWT_PUBLIC_KEY_PATH || process.env.JWT_PUBLIC_KEY_PATH || './keys/public.pem',

  AUTH_ANDROID_CLIENT_ID: process.env.AUTH_ANDROID_CLIENT_ID || 'trustipay-android',
  AUTH_ANDROID_REDIRECT_URIS: csvFromEnv('AUTH_ANDROID_REDIRECT_URIS', [
    'trustipay://oauth/callback',
    'https://app.trustipay.example/oauth/callback',
  ]),
  AUTH_ALLOWED_ORIGINS: csvFromEnv('AUTH_ALLOWED_ORIGINS', ['*']),

  AUTH_ANALYTICS_CLIENT_SECRET: process.env.AUTH_ANALYTICS_CLIENT_SECRET || 'analytics-dev-secret',
  AUTH_OFFLINE_SERVICE_CLIENT_SECRET:
    process.env.AUTH_OFFLINE_SERVICE_CLIENT_SECRET || 'offline-payment-dev-secret',

  AUTH_DEV_RETURN_CODES: boolFromEnv('AUTH_DEV_RETURN_CODES', process.env.NODE_ENV !== 'production'),
  AUTH_DEV_OAUTH_PASSWORD_AUTHORIZE: boolFromEnv(
    'AUTH_DEV_OAUTH_PASSWORD_AUTHORIZE',
    process.env.NODE_ENV !== 'production',
  ),

  AUTH_FEATURE_MFA_ENABLED: boolFromEnv('AUTH_FEATURE_MFA_ENABLED', false),
  AUTH_FEATURE_PASSKEYS_ENABLED: boolFromEnv('AUTH_FEATURE_PASSKEYS_ENABLED', false),
  AUTH_FEATURE_DPOP_ENABLED: boolFromEnv('AUTH_FEATURE_DPOP_ENABLED', false),

  AUTH_RATE_LIMIT_LOGIN_MAX: intFromEnv('AUTH_RATE_LIMIT_LOGIN_MAX', 5),
  AUTH_RATE_LIMIT_REGISTER_MAX: intFromEnv('AUTH_RATE_LIMIT_REGISTER_MAX', 10),
  AUTH_RATE_LIMIT_TOKEN_MAX: intFromEnv('AUTH_RATE_LIMIT_TOKEN_MAX', 60),
  AUTH_RATE_LIMIT_PASSWORD_RESET_MAX: intFromEnv('AUTH_RATE_LIMIT_PASSWORD_RESET_MAX', 3),
  AUTH_RATE_LIMIT_WINDOW_MS: intFromEnv('AUTH_RATE_LIMIT_WINDOW_MS', 15 * 60 * 1000),
};

export type Env = typeof env;

export function issuerUrl(path = ''): string {
  const normalizedPath = path.startsWith('/') ? path : `/${path}`;
  return `${env.AUTH_ISSUER_URL}${normalizedPath}`;
}
