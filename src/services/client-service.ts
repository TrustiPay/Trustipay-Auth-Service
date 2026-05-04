import * as argon2 from 'argon2';
import { Request } from 'express';
import { env } from '../config/env';
import { prisma } from '../db/prisma';
import { HttpError } from '../http';
import { OAuthClientConfig } from '../types/auth';
import { parseJsonArray, stringifyJsonArray } from './validators';

function toConfig(row: any): OAuthClientConfig {
  return {
    clientId: row.clientId,
    clientName: row.clientName,
    clientType: row.clientType,
    status: row.status,
    redirectUris: parseJsonArray(row.redirectUrisJson),
    allowedScopes: parseJsonArray(row.allowedScopesJson),
    allowedGrantTypes: parseJsonArray(row.allowedGrantTypesJson),
    tokenEndpointAuthMethod: row.tokenEndpointAuthMethod,
    clientSecretHash: row.clientSecretHash,
    pkceRequired: row.pkceRequired,
  };
}

async function secretHash(secret: string): Promise<string> {
  return argon2.hash(secret);
}

export async function seedDefaultClients(): Promise<void> {
  await prisma.oauthClient.upsert({
    where: { clientId: env.AUTH_ANDROID_CLIENT_ID },
    update: {
      redirectUrisJson: stringifyJsonArray(env.AUTH_ANDROID_REDIRECT_URIS),
      allowedScopesJson: stringifyJsonArray([
        'openid',
        'profile',
        'email',
        'phone',
        'wallet:read',
        'wallet:transfer',
        'offline:sync',
        'offline:tokens:request',
        'devices:read',
        'devices:write',
        'mfa:read',
        'mfa:write',
      ]),
      allowedGrantTypesJson: stringifyJsonArray(['authorization_code', 'refresh_token']),
      status: 'ACTIVE',
      pkceRequired: true,
    },
    create: {
      clientId: env.AUTH_ANDROID_CLIENT_ID,
      clientName: 'TrustiPay Android App',
      clientType: 'PUBLIC_MOBILE',
      status: 'ACTIVE',
      redirectUrisJson: stringifyJsonArray(env.AUTH_ANDROID_REDIRECT_URIS),
      allowedScopesJson: stringifyJsonArray([
        'openid',
        'profile',
        'email',
        'phone',
        'wallet:read',
        'wallet:transfer',
        'offline:sync',
        'offline:tokens:request',
        'devices:read',
        'devices:write',
        'mfa:read',
        'mfa:write',
      ]),
      allowedGrantTypesJson: stringifyJsonArray(['authorization_code', 'refresh_token']),
      tokenEndpointAuthMethod: 'none',
      pkceRequired: true,
    },
  });

  const analyticsHash = await secretHash(env.AUTH_ANALYTICS_CLIENT_SECRET);
  await prisma.oauthClient.upsert({
    where: { clientId: 'analytics-service' },
    update: {
      clientSecretHash: analyticsHash,
      status: 'ACTIVE',
      allowedScopesJson: stringifyJsonArray(['analytics:write', 'auth-events:read']),
      allowedGrantTypesJson: stringifyJsonArray(['client_credentials']),
    },
    create: {
      clientId: 'analytics-service',
      clientName: 'TrustiPay Analytics Service',
      clientType: 'CONFIDENTIAL_SERVICE',
      status: 'ACTIVE',
      redirectUrisJson: stringifyJsonArray([]),
      allowedScopesJson: stringifyJsonArray(['analytics:write', 'auth-events:read']),
      allowedGrantTypesJson: stringifyJsonArray(['client_credentials']),
      tokenEndpointAuthMethod: 'client_secret_basic',
      clientSecretHash: analyticsHash,
      pkceRequired: false,
    },
  });

  const offlineHash = await secretHash(env.AUTH_OFFLINE_SERVICE_CLIENT_SECRET);
  await prisma.oauthClient.upsert({
    where: { clientId: 'offline-payment-service' },
    update: {
      clientSecretHash: offlineHash,
      status: 'ACTIVE',
      allowedScopesJson: stringifyJsonArray(['auth-context:read', 'devices:read']),
      allowedGrantTypesJson: stringifyJsonArray(['client_credentials']),
    },
    create: {
      clientId: 'offline-payment-service',
      clientName: 'TrustiPay Offline Payment Service',
      clientType: 'CONFIDENTIAL_SERVICE',
      status: 'ACTIVE',
      redirectUrisJson: stringifyJsonArray([]),
      allowedScopesJson: stringifyJsonArray(['auth-context:read', 'devices:read']),
      allowedGrantTypesJson: stringifyJsonArray(['client_credentials']),
      tokenEndpointAuthMethod: 'client_secret_basic',
      clientSecretHash: offlineHash,
      pkceRequired: false,
    },
  });
}

export async function getClient(clientId?: string | null): Promise<OAuthClientConfig> {
  if (!clientId) throw new HttpError(400, 'invalid_client', 'client_id is required.');
  const row = await prisma.oauthClient.findUnique({ where: { clientId } });
  if (!row || row.status !== 'ACTIVE') {
    throw new HttpError(401, 'invalid_client', 'Unknown or inactive client.');
  }
  return toConfig(row);
}

export function assertGrantAllowed(client: OAuthClientConfig, grantType: string): void {
  if (!client.allowedGrantTypes.includes(grantType)) {
    throw new HttpError(400, 'unsupported_grant_type', 'Grant type is not allowed for this client.');
  }
}

export function assertRedirectUriAllowed(client: OAuthClientConfig, redirectUri?: string | null): string {
  if (!redirectUri || !client.redirectUris.includes(redirectUri)) {
    throw new HttpError(400, 'invalid_request', 'redirect_uri is not registered for this client.');
  }
  return redirectUri;
}

function basicCredentials(req: Request): { clientId: string; clientSecret: string } | null {
  const header = req.header('authorization');
  if (!header?.startsWith('Basic ')) return null;
  const decoded = Buffer.from(header.slice('Basic '.length), 'base64').toString('utf8');
  const separator = decoded.indexOf(':');
  if (separator < 0) return null;
  return {
    clientId: decodeURIComponent(decoded.slice(0, separator)),
    clientSecret: decodeURIComponent(decoded.slice(separator + 1)),
  };
}

export async function authenticateConfidentialClient(req: Request, requestedClientId?: string): Promise<OAuthClientConfig> {
  const basic = basicCredentials(req);
  const clientId = basic?.clientId || requestedClientId || req.body?.client_id;
  const clientSecret = basic?.clientSecret || req.body?.client_secret;
  const client = await getClient(clientId);

  if (client.tokenEndpointAuthMethod === 'none') {
    return client;
  }
  if (!client.clientSecretHash || !clientSecret) {
    throw new HttpError(401, 'invalid_client', 'Client authentication failed.');
  }

  const valid = await argon2.verify(client.clientSecretHash, clientSecret);
  if (!valid) throw new HttpError(401, 'invalid_client', 'Client authentication failed.');
  return client;
}
