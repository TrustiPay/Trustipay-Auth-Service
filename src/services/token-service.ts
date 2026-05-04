import crypto, { KeyObject } from 'crypto';
import fs from 'fs';
import jwt, { JwtPayload } from 'jsonwebtoken';
import { env } from '../config/env';
import { AuthContext } from '../types/auth';
import { newId } from './ids';

interface SigningMaterial {
  privateKey: KeyObject;
  publicKey: KeyObject;
}

function pemFromEnvOrFile(envValue?: string, pathValue?: string): string | null {
  if (envValue) return envValue.replace(/\\n/g, '\n');
  if (pathValue && fs.existsSync(pathValue)) return fs.readFileSync(pathValue, 'utf8');
  return null;
}

function loadSigningMaterial(): SigningMaterial {
  const privatePem = pemFromEnvOrFile(env.AUTH_JWT_PRIVATE_KEY, env.AUTH_JWT_PRIVATE_KEY_PATH);
  const publicPem = pemFromEnvOrFile(env.AUTH_JWT_PUBLIC_KEY, env.AUTH_JWT_PUBLIC_KEY_PATH);

  if (privatePem) {
    const privateKey = crypto.createPrivateKey(privatePem);
    return {
      privateKey,
      publicKey: publicPem ? crypto.createPublicKey(publicPem) : crypto.createPublicKey(privateKey),
    };
  }

  const generated = crypto.generateKeyPairSync('rsa', { modulusLength: 2048 });
  if (env.NODE_ENV === 'production') {
    console.warn('AUTH_JWT_PRIVATE_KEY is missing; generated an ephemeral signing key for this process.');
  }
  return generated;
}

class TokenService {
  private readonly keys = loadSigningMaterial();

  jwks() {
    const jwk = this.keys.publicKey.export({ format: 'jwk' }) as JsonWebKey;
    return {
      keys: [
        {
          ...jwk,
          kid: env.AUTH_JWT_KID,
          alg: 'RS256',
          use: 'sig',
        },
      ],
    };
  }

  signAccessToken(input: {
    userId: string;
    sessionId: string;
    clientId: string;
    scopes: string;
    deviceId?: string | null;
    roles?: string[];
    aal?: number;
    amr?: string[];
    riskLevel?: string;
  }): string {
    const now = Math.floor(Date.now() / 1000);
    const payload: AuthContext = {
      iss: env.AUTH_ISSUER_URL,
      sub: input.userId,
      aud: env.AUTH_ACCESS_TOKEN_AUDIENCE,
      iat: now,
      nbf: now,
      exp: now + env.AUTH_ACCESS_TOKEN_TTL_SECONDS,
      jti: newId('atk'),
      sid: input.sessionId,
      azp: input.clientId,
      client_id: input.clientId,
      scope: input.scopes,
      device_id: input.deviceId || undefined,
      amr: input.amr || ['pwd'],
      acr: input.aal && input.aal >= 2 ? 'urn:trustipay:aal2' : 'urn:trustipay:aal1',
      aal: input.aal || 1,
      roles: input.roles || ['user'],
      risk_level: (input.riskLevel as any) || 'normal',
      token_use: 'access',
    };

    return jwt.sign(payload, this.keys.privateKey, {
      algorithm: 'RS256',
      keyid: env.AUTH_JWT_KID,
    });
  }

  signIdToken(input: {
    userId: string;
    clientId: string;
    nonce?: string | null;
    authTime: Date;
    email?: string | null;
    phone?: string | null;
    displayName?: string | null;
  }): string {
    const now = Math.floor(Date.now() / 1000);
    const payload: JwtPayload = {
      iss: env.AUTH_ISSUER_URL,
      sub: input.userId,
      aud: input.clientId,
      iat: now,
      nbf: now,
      exp: now + env.AUTH_ID_TOKEN_TTL_SECONDS,
      auth_time: Math.floor(input.authTime.getTime() / 1000),
      nonce: input.nonce || undefined,
      email: input.email || undefined,
      phone_number: input.phone || undefined,
      name: input.displayName || undefined,
      token_use: 'id',
    };

    return jwt.sign(payload, this.keys.privateKey, {
      algorithm: 'RS256',
      keyid: env.AUTH_JWT_KID,
    });
  }

  signServiceToken(input: { clientId: string; scopes: string; audience?: string; subject?: string }): string {
    const now = Math.floor(Date.now() / 1000);
    const payload: JwtPayload = {
      iss: env.AUTH_ISSUER_URL,
      sub: input.subject || `svc_${input.clientId}`,
      aud: input.audience || env.AUTH_INTERNAL_TOKEN_AUDIENCE,
      iat: now,
      nbf: now,
      exp: now + env.AUTH_ACCESS_TOKEN_TTL_SECONDS,
      jti: newId('sat'),
      client_id: input.clientId,
      scope: input.scopes,
      roles: ['service'],
      token_use: 'service',
    };

    return jwt.sign(payload, this.keys.privateKey, {
      algorithm: 'RS256',
      keyid: env.AUTH_JWT_KID,
    });
  }

  signDeviceCertificate(input: {
    userId: string;
    deviceId: string;
    publicSigningKey?: string | null;
    keyAlgorithm?: string | null;
  }): string {
    const now = Math.floor(Date.now() / 1000);
    const payload: JwtPayload = {
      iss: env.AUTH_ISSUER_URL,
      sub: input.deviceId,
      aud: 'trustipay-device',
      iat: now,
      nbf: now,
      exp: now + 365 * 24 * 60 * 60,
      jti: newId('dcert'),
      user_id: input.userId,
      device_id: input.deviceId,
      public_signing_key_hash: input.publicSigningKey
        ? crypto.createHash('sha256').update(input.publicSigningKey).digest('base64url')
        : undefined,
      key_algorithm: input.keyAlgorithm || undefined,
      token_use: 'device_certificate',
    };

    return jwt.sign(payload, this.keys.privateKey, {
      algorithm: 'RS256',
      keyid: env.AUTH_JWT_KID,
    });
  }

  verifyAccessToken(token: string): AuthContext {
    const payload = jwt.verify(token, this.keys.publicKey, {
      algorithms: ['RS256'],
      issuer: env.AUTH_ISSUER_URL,
      audience: env.AUTH_ACCESS_TOKEN_AUDIENCE,
      clockTolerance: 30,
    });

    if (typeof payload === 'string') {
      throw Object.assign(new Error('Invalid token payload.'), { status: 401, code: 'invalid_token' });
    }

    const auth = payload as AuthContext;
    if (auth.token_use && auth.token_use !== 'access') {
      throw Object.assign(new Error('Token is not an access token.'), { status: 401, code: 'invalid_token' });
    }
    return auth;
  }

  verifyAnyJwt(token: string): JwtPayload {
    const payload = jwt.verify(token, this.keys.publicKey, {
      algorithms: ['RS256'],
      issuer: env.AUTH_ISSUER_URL,
      clockTolerance: 30,
      ignoreExpiration: false,
    });
    if (typeof payload === 'string') {
      throw Object.assign(new Error('Invalid token payload.'), { status: 401, code: 'invalid_token' });
    }
    return payload;
  }
}

export const tokenService = new TokenService();
