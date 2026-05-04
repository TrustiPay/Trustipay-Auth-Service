import * as argon2 from 'argon2';
import { Request } from 'express';
import jwt from 'jsonwebtoken';
import { env } from '../config/env';
import { prisma } from '../db/prisma';
import { HttpError } from '../http';
import { DeviceInfo, OAuthClientConfig, TokenSet } from '../types/auth';
import { audit } from './audit';
import {
  assertGrantAllowed,
  assertRedirectUriAllowed,
  authenticateConfidentialClient,
  getClient,
} from './client-service';
import { hashSensitive, hmacTokenHash, timingSafeEqualString, verifyPkceS256 } from './crypto';
import { newId, randomNumericCode, randomOpaqueToken } from './ids';
import { incrementMetric } from './metrics';
import { tokenService } from './token-service';
import {
  assertScopesAllowed,
  assertValidEmail,
  assertValidPassword,
  isEmail,
  normalizeEmail,
  normalizePhone,
  parseScope,
  pickFirstString,
  scopeString,
} from './validators';

function plusSeconds(seconds: number): Date {
  return new Date(Date.now() + seconds * 1000);
}

function plusDays(days: number): Date {
  return plusSeconds(days * 24 * 60 * 60);
}

function requestIp(req: Request): string | null {
  return req.header('x-forwarded-for')?.split(',')[0]?.trim() || req.ip || req.socket.remoteAddress || null;
}

function userAgent(req: Request): string | null {
  return req.header('user-agent') || null;
}

function passwordMaterial(password: string): string {
  return `${password}${env.AUTH_PASSWORD_PEPPER}`;
}

function firstPrimary(rows: any[]): any | null {
  if (!rows?.length) return null;
  return rows.find((row) => row.isPrimary) || rows[0];
}

function asDeviceInfo(input: any): DeviceInfo {
  return input?.device_info || input?.deviceInfo || input || {};
}

function deviceInfoValue(deviceInfo: DeviceInfo, snake: keyof DeviceInfo, camel: keyof DeviceInfo): string | undefined {
  const value = deviceInfo[snake] || deviceInfo[camel];
  return typeof value === 'string' && value.trim() ? value.trim() : undefined;
}

function safeJsonParseArray(value?: string | null): string[] {
  if (!value) return [];
  try {
    const parsed = JSON.parse(value);
    return Array.isArray(parsed) ? parsed : [];
  } catch {
    return [];
  }
}

export class AuthService {
  private async hashPassword(password: string): Promise<string> {
    return argon2.hash(passwordMaterial(password), {
      type: argon2.argon2id,
    });
  }

  private async verifyPassword(userId: string, password: string): Promise<boolean> {
    const credential = await prisma.passwordCredential.findFirst({
      where: { userId, mustChange: false },
      orderBy: { createdAt: 'desc' },
    });
    if (!credential) return false;
    return argon2.verify(credential.passwordHash, passwordMaterial(password));
  }

  private async loadUser(userId: string): Promise<any> {
    const user = await prisma.user.findUnique({
      where: { userId },
      include: {
        emails: true,
        phones: true,
        passwordCredentials: {
          orderBy: { createdAt: 'desc' },
          take: 1,
        },
      },
    });
    if (!user || user.deletedAt) throw new HttpError(404, 'user_not_found', 'User was not found.');
    return user;
  }

  private async findUserByIdentifier(identifier?: string | null): Promise<any | null> {
    if (!identifier) return null;
    const normalized = identifier.trim();
    if (!normalized) return null;

    if (isEmail(normalized)) {
      const email = await prisma.userEmail.findUnique({
        where: { emailNormalized: normalizeEmail(normalized) || '' },
      });
      return email ? this.loadUser(email.userId) : null;
    }

    const phone = normalizePhone(normalized);
    const phoneRow = phone ? await prisma.userPhone.findUnique({ where: { phoneE164: phone } }) : null;
    return phoneRow ? this.loadUser(phoneRow.userId) : null;
  }

  private async existingUser(email?: string | null, phone?: string | null): Promise<any | null> {
    const byEmail = email ? await prisma.userEmail.findUnique({ where: { emailNormalized: email } }) : null;
    if (byEmail) return this.loadUser(byEmail.userId);
    const byPhone = phone ? await prisma.userPhone.findUnique({ where: { phoneE164: phone } }) : null;
    return byPhone ? this.loadUser(byPhone.userId) : null;
  }

  private async createUser(input: {
    email?: string | null;
    phone?: string | null;
    password: string;
    displayName?: string | null;
    status: string;
    emailVerified?: boolean;
    phoneVerified?: boolean;
  }): Promise<any> {
    const passwordHash = await this.hashPassword(input.password);
    const now = new Date();
    const userId = newId('user');

    await prisma.$transaction(async (tx) => {
      await tx.user.create({
        data: {
          userId,
          status: input.status,
          displayName: input.displayName || null,
        },
      });

      if (input.email) {
        await tx.userEmail.create({
          data: {
            emailId: newId('email'),
            userId,
            emailNormalized: input.email,
            emailDisplay: input.email,
            isPrimary: true,
            isVerified: Boolean(input.emailVerified),
            verifiedAt: input.emailVerified ? now : null,
          },
        });
      }

      if (input.phone) {
        await tx.userPhone.create({
          data: {
            phoneId: newId('phone'),
            userId,
            phoneE164: input.phone,
            isPrimary: true,
            isVerified: Boolean(input.phoneVerified),
            verifiedAt: input.phoneVerified ? now : null,
          },
        });
      }

      await tx.passwordCredential.create({
        data: {
          credentialId: newId('pwd'),
          userId,
          passwordHash,
          hashAlgorithm: 'argon2id',
          hashParamsJson: JSON.stringify({ version: 1, peppered: Boolean(env.AUTH_PASSWORD_PEPPER) }),
          passwordVersion: 1,
          lastChangedAt: now,
        },
      });
    });

    return this.loadUser(userId);
  }

  private async createVerificationChallenge(input: {
    userId?: string | null;
    identifier?: string | null;
    challengeType: string;
    purpose: string;
    ttlSeconds?: number;
  }): Promise<{ challengeId: string; code: string }> {
    const code = randomNumericCode(6);
    const challengeId = newId('chal');
    await prisma.verificationChallenge.create({
      data: {
        challengeId,
        userId: input.userId || null,
        identifierHash: hashSensitive(input.identifier),
        challengeType: input.challengeType,
        purpose: input.purpose,
        challengeHash: hmacTokenHash(`${input.purpose}:${code}`),
        status: 'ACTIVE',
        maxAttempts: 5,
        expiresAt: plusSeconds(input.ttlSeconds || env.AUTH_VERIFICATION_CODE_TTL_SECONDS),
      },
    });
    return { challengeId, code };
  }

  private async verifyChallenge(challengeId: string, code: string, purpose: string): Promise<any> {
    const challenge = await prisma.verificationChallenge.findUnique({ where: { challengeId } });
    if (!challenge || challenge.purpose !== purpose) {
      throw new HttpError(400, 'invalid_challenge', 'Invalid or expired challenge.');
    }
    if (challenge.status !== 'ACTIVE' || challenge.consumedAt || challenge.expiresAt <= new Date()) {
      if (challenge.status === 'ACTIVE') {
        await prisma.verificationChallenge.update({
          where: { challengeId },
          data: { status: 'EXPIRED' },
        });
      }
      throw new HttpError(400, 'invalid_challenge', 'Invalid or expired challenge.');
    }
    if (challenge.attemptCount >= challenge.maxAttempts) {
      await prisma.verificationChallenge.update({
        where: { challengeId },
        data: { status: 'LOCKED' },
      });
      throw new HttpError(429, 'challenge_locked', 'Too many challenge attempts.');
    }

    const valid = timingSafeEqualString(challenge.challengeHash, hmacTokenHash(`${purpose}:${code}`));
    if (!valid) {
      await prisma.verificationChallenge.update({
        where: { challengeId },
        data: { attemptCount: { increment: 1 } },
      });
      throw new HttpError(400, 'invalid_challenge', 'Invalid or expired challenge.');
    }

    return prisma.verificationChallenge.update({
      where: { challengeId },
      data: { status: 'CONSUMED', consumedAt: new Date() },
    });
  }

  async registerStart(body: any, req: Request): Promise<any> {
    const email = normalizeEmail(body.email);
    const phone = normalizePhone(body.phone || body.phoneNumber);
    const displayName = body.display_name || body.displayName || body.fullName || null;
    assertValidEmail(email);
    assertValidPassword(body.password);

    if (await this.existingUser(email, phone)) {
      await audit({ eventType: 'auth.register.started', result: 'failure', req, metadata: { reason: 'exists' } });
      throw new HttpError(409, 'user_exists', 'A user with this email or phone already exists.');
    }

    const user = await this.createUser({
      email,
      phone,
      password: body.password,
      displayName,
      status: 'PENDING_VERIFICATION',
      emailVerified: false,
      phoneVerified: false,
    });

    const emailChallenge = email
      ? await this.createVerificationChallenge({
          userId: user.userId,
          identifier: email,
          challengeType: 'EMAIL_OTP',
          purpose: 'REGISTER_EMAIL',
        })
      : null;
    const phoneChallenge = phone
      ? await this.createVerificationChallenge({
          userId: user.userId,
          identifier: phone,
          challengeType: 'SMS_OTP',
          purpose: 'REGISTER_PHONE',
        })
      : null;

    await audit({ eventType: 'auth.register.started', result: 'success', req, userId: user.userId });
    incrementMetric('auth_registration_started_total');

    return {
      success: true,
      user_id: user.userId,
      status: user.status,
      email_challenge_id: emailChallenge?.challengeId,
      phone_challenge_id: phoneChallenge?.challengeId,
      dev_verification_codes: env.AUTH_DEV_RETURN_CODES
        ? {
            email: emailChallenge?.code,
            phone: phoneChallenge?.code,
          }
        : undefined,
    };
  }

  async registerCompat(body: any, req: Request): Promise<any> {
    const email = normalizeEmail(body.email);
    const phone = normalizePhone(body.phone || body.phoneNumber);
    const displayName = body.display_name || body.displayName || body.fullName || null;
    assertValidEmail(email);
    assertValidPassword(body.password);

    if (await this.existingUser(email, phone)) {
      await audit({ eventType: 'auth.register.completed', result: 'failure', req, metadata: { reason: 'exists' } });
      throw new HttpError(409, 'user_exists', 'A user with this email or phone already exists.');
    }

    const user = await this.createUser({
      email,
      phone,
      password: body.password,
      displayName,
      status: 'ACTIVE',
      emailVerified: true,
      phoneVerified: Boolean(phone),
    });

    const tokenSet = await this.issuePasswordTokenSet(user, body, req);
    await audit({ eventType: 'auth.register.completed', result: 'success', req, userId: user.userId });
    incrementMetric('auth_registration_success_total');
    return this.toAndroidTokenResponse(tokenSet, user);
  }

  async verifyRegistration(kind: 'email' | 'phone', body: any, req: Request): Promise<any> {
    const purpose = kind === 'email' ? 'REGISTER_EMAIL' : 'REGISTER_PHONE';
    const challengeId = body.challenge_id || body.challengeId;
    const code = body.code || body.otp;
    if (!challengeId || !code) throw new HttpError(400, 'invalid_request', 'challenge_id and code are required.');

    const challenge = await this.verifyChallenge(challengeId, code, purpose);
    if (!challenge.userId) throw new HttpError(400, 'invalid_challenge', 'Invalid challenge.');

    const now = new Date();
    if (kind === 'email') {
      await prisma.userEmail.updateMany({
        where: { userId: challenge.userId, isPrimary: true },
        data: { isVerified: true, verifiedAt: now },
      });
    } else {
      await prisma.userPhone.updateMany({
        where: { userId: challenge.userId, isPrimary: true },
        data: { isVerified: true, verifiedAt: now },
      });
    }
    await prisma.user.update({
      where: { userId: challenge.userId },
      data: { status: 'ACTIVE' },
    });

    const user = await this.loadUser(challenge.userId);
    await audit({
      eventType: kind === 'email' ? 'auth.email.verified' : 'auth.phone.verified',
      result: 'success',
      req,
      userId: user.userId,
    });

    if (body.issue_tokens === false) {
      return { success: true, user_id: user.userId, status: user.status };
    }

    const tokenSet = await this.issuePasswordTokenSet(user, body, req);
    return { success: true, user_id: user.userId, status: user.status, ...tokenSet };
  }

  async resendRegistrationCode(body: any, req: Request): Promise<any> {
    const userId = body.user_id || body.userId;
    const channel = body.channel || 'email';
    if (!userId) throw new HttpError(400, 'invalid_request', 'user_id is required.');

    const user = await this.loadUser(userId);
    const email = firstPrimary(user.emails)?.emailNormalized;
    const phone = firstPrimary(user.phones)?.phoneE164;
    const target = channel === 'phone' ? phone : email;
    if (!target) throw new HttpError(400, 'invalid_request', 'No destination is available for this user.');

    const challenge = await this.createVerificationChallenge({
      userId,
      identifier: target,
      challengeType: channel === 'phone' ? 'SMS_OTP' : 'EMAIL_OTP',
      purpose: channel === 'phone' ? 'REGISTER_PHONE' : 'REGISTER_EMAIL',
    });
    await audit({ eventType: 'auth.register.code_resent', result: 'success', req, userId });
    return {
      success: true,
      challenge_id: challenge.challengeId,
      dev_code: env.AUTH_DEV_RETURN_CODES ? challenge.code : undefined,
    };
  }

  private async upsertDevice(userId: string, input?: DeviceInfo | null): Promise<any> {
    const deviceInfo = asDeviceInfo(input);
    const providedDeviceId = deviceInfoValue(deviceInfo, 'device_id', 'deviceId');
    let deviceId = providedDeviceId || newId('dev');
    const existing = await prisma.device.findUnique({ where: { deviceId } });

    if (existing && existing.userId !== userId) {
      deviceId = newId('dev');
    } else if (existing?.status === 'REVOKED' || existing?.status === 'LOST') {
      throw new HttpError(403, 'device_not_trusted', 'This device is not trusted.');
    }

    const platform = deviceInfoValue(deviceInfo, 'platform', 'platform') || 'UNKNOWN';
    const deviceName = deviceInfoValue(deviceInfo, 'device_name', 'deviceName') || null;
    const appVersion = deviceInfoValue(deviceInfo, 'app_version', 'appVersion') || null;
    const osVersion = deviceInfoValue(deviceInfo, 'os_version', 'osVersion') || null;
    const publicSigningKey = deviceInfoValue(deviceInfo, 'public_signing_key', 'publicSigningKey') || null;
    const keyAlgorithm = deviceInfoValue(deviceInfo, 'key_algorithm', 'keyAlgorithm') || null;
    const pushTokenHash = deviceInfoValue(deviceInfo, 'push_token_hash', 'pushTokenHash') || null;

    return prisma.device.upsert({
      where: { deviceId },
      update: {
        platform,
        deviceName,
        appVersion,
        osVersion,
        publicSigningKey,
        keyAlgorithm,
        pushTokenHash,
        lastSeenAt: new Date(),
      },
      create: {
        deviceId,
        userId,
        status: 'ACTIVE',
        platform,
        deviceName,
        appVersion,
        osVersion,
        publicSigningKey,
        keyAlgorithm,
        pushTokenHash,
        lastSeenAt: new Date(),
      },
    });
  }

  private async createSession(input: {
    userId: string;
    clientId: string;
    deviceId?: string | null;
    req: Request;
    aal?: number;
    amr?: string[];
    riskLevel?: string;
  }): Promise<any> {
    return prisma.session.create({
      data: {
        sessionId: newId('sess'),
        userId: input.userId,
        clientId: input.clientId,
        deviceId: input.deviceId || null,
        status: 'ACTIVE',
        authTime: new Date(),
        lastSeenAt: new Date(),
        expiresAt: plusDays(env.AUTH_REFRESH_TOKEN_TTL_DAYS),
        ipHash: hashSensitive(requestIp(input.req)),
        userAgentHash: hashSensitive(userAgent(input.req)),
        aal: input.aal || 1,
        amrJson: JSON.stringify(input.amr || ['pwd']),
        riskLevel: input.riskLevel || 'normal',
      },
    });
  }

  private async createRefreshFamily(input: {
    userId: string;
    clientId: string;
    sessionId: string;
    deviceId?: string | null;
    req: Request;
  }): Promise<{ family: any; refreshToken: string; tokenId: string }> {
    const refreshToken = randomOpaqueToken('rt', 48);
    const tokenId = newId('rtok');
    const family = await prisma.refreshTokenFamily.create({
      data: {
        familyId: newId('rtfam'),
        userId: input.userId,
        clientId: input.clientId,
        sessionId: input.sessionId,
        deviceId: input.deviceId || null,
        status: 'ACTIVE',
        refreshTokens: {
          create: {
            tokenId,
            tokenHash: hmacTokenHash(refreshToken),
            status: 'ACTIVE',
            expiresAt: plusDays(env.AUTH_REFRESH_TOKEN_TTL_DAYS),
            ipHash: hashSensitive(requestIp(input.req)),
            userAgentHash: hashSensitive(userAgent(input.req)),
          },
        },
      },
    });
    return { family, refreshToken, tokenId };
  }

  private async tokenSetFor(input: {
    user: any;
    client: OAuthClientConfig;
    session: any;
    scopes: string[];
    refreshToken?: string;
    nonce?: string | null;
  }): Promise<TokenSet> {
    const scopes = scopeString(input.scopes);
    const accessToken = tokenService.signAccessToken({
      userId: input.user.userId,
      sessionId: input.session.sessionId,
      clientId: input.client.clientId,
      scopes,
      deviceId: input.session.deviceId,
      roles: ['user'],
      aal: input.session.aal,
      amr: safeJsonParseArray(input.session.amrJson),
      riskLevel: input.session.riskLevel,
    });

    const email = firstPrimary(input.user.emails)?.emailNormalized || null;
    const phone = firstPrimary(input.user.phones)?.phoneE164 || null;
    const tokenSet: TokenSet = {
      access_token: accessToken,
      token_type: 'Bearer',
      expires_in: env.AUTH_ACCESS_TOKEN_TTL_SECONDS,
      refresh_token: input.refreshToken,
      scope: scopes,
    };

    if (input.scopes.includes('openid')) {
      tokenSet.id_token = tokenService.signIdToken({
        userId: input.user.userId,
        clientId: input.client.clientId,
        nonce: input.nonce,
        authTime: input.session.authTime,
        email,
        phone,
        displayName: input.user.displayName,
      });
    }

    return tokenSet;
  }

  private async issuePasswordTokenSet(user: any, body: any, req: Request): Promise<TokenSet> {
    const client = await getClient(body.client_id || body.clientId || env.AUTH_ANDROID_CLIENT_ID);
    const requestedScopes = parseScope(body.scope || body.scopes);
    const scopes = assertScopesAllowed(client, requestedScopes.length ? requestedScopes : client.allowedScopes);
    const device = await this.upsertDevice(user.userId, body.device_info || body.deviceInfo);
    const session = await this.createSession({
      userId: user.userId,
      clientId: client.clientId,
      deviceId: device?.deviceId,
      req,
      aal: 1,
      amr: ['pwd'],
      riskLevel: 'normal',
    });
    const family = await this.createRefreshFamily({
      userId: user.userId,
      clientId: client.clientId,
      sessionId: session.sessionId,
      deviceId: device?.deviceId,
      req,
    });
    return this.tokenSetFor({
      user,
      client,
      session,
      scopes,
      refreshToken: family.refreshToken,
      nonce: body.nonce,
    });
  }

  async loginWithPassword(body: any, req: Request): Promise<{ tokenSet: TokenSet; user: any }> {
    const identifier = body.email || body.phone || body.phoneNumber || body.identifier || body.login_hint;
    const password = body.password;
    if (!identifier || !password) throw new HttpError(400, 'invalid_request', 'Identifier and password are required.');

    const user = await this.findUserByIdentifier(identifier);
    if (!user || user.status !== 'ACTIVE') {
      await audit({ eventType: 'auth.login.failed', result: 'failure', req, metadata: { reason: 'invalid' } });
      incrementMetric('auth_login_failure_total');
      throw new HttpError(401, 'invalid_credentials', 'Invalid credentials.');
    }

    const valid = await this.verifyPassword(user.userId, password);
    if (!valid) {
      await audit({ eventType: 'auth.login.failed', result: 'failure', req, userId: user.userId });
      incrementMetric('auth_login_failure_total');
      throw new HttpError(401, 'invalid_credentials', 'Invalid credentials.');
    }

    const tokenSet = await this.issuePasswordTokenSet(user, body, req);
    await audit({
      eventType: 'auth.login.succeeded',
      result: 'success',
      req,
      userId: user.userId,
      clientId: body.client_id || body.clientId || env.AUTH_ANDROID_CLIENT_ID,
    });
    incrementMetric('auth_login_success_total');
    return { tokenSet, user };
  }

  toAndroidTokenResponse(tokenSet: TokenSet, user: any): any {
    return {
      accessToken: tokenSet.access_token,
      refreshToken: tokenSet.refresh_token,
      expiresIn: tokenSet.expires_in,
      userId: user.userId,
      displayName: user.displayName || firstPrimary(user.emails)?.emailDisplay || 'TrustiPay User',
      tokenType: tokenSet.token_type,
      scope: tokenSet.scope,
      idToken: tokenSet.id_token,
    };
  }

  async authorize(params: any, req: Request): Promise<any> {
    const responseType = pickFirstString(params.response_type);
    const clientId = pickFirstString(params.client_id);
    const redirectUri = pickFirstString(params.redirect_uri);
    const state = pickFirstString(params.state);
    const nonce = pickFirstString(params.nonce);
    const codeChallenge = pickFirstString(params.code_challenge);
    const codeChallengeMethod = pickFirstString(params.code_challenge_method);

    if (responseType !== 'code') throw new HttpError(400, 'unsupported_response_type', 'Only response_type=code is supported.');
    const client = await getClient(clientId);
    assertGrantAllowed(client, 'authorization_code');
    const safeRedirectUri = assertRedirectUriAllowed(client, redirectUri);
    if (client.pkceRequired && (!codeChallenge || codeChallengeMethod !== 'S256')) {
      throw new HttpError(400, 'invalid_request', 'PKCE S256 is required.');
    }
    const scopes = assertScopesAllowed(client, parseScope(params.scope));

    let user: any | null = null;
    let session: any | null = null;
    const bearer = req.header('authorization')?.startsWith('Bearer ')
      ? req.header('authorization')!.slice('Bearer '.length)
      : null;

    if (bearer) {
      const auth = tokenService.verifyAccessToken(bearer);
      user = await this.loadUser(auth.sub);
      session = auth.sid ? await prisma.session.findUnique({ where: { sessionId: auth.sid } }) : null;
      if (!session || session.status !== 'ACTIVE') throw new HttpError(401, 'login_required', 'A valid login is required.');
    } else if (env.AUTH_DEV_OAUTH_PASSWORD_AUTHORIZE && (params.password || params.login_hint || params.email)) {
      const login = await this.loginWithPassword(
        {
          email: pickFirstString(params.email),
          login_hint: pickFirstString(params.login_hint),
          password: pickFirstString(params.password),
          client_id: client.clientId,
          scope: scopeString(scopes),
          device_info: {},
        },
        req,
      );
      user = login.user;
      const decoded = jwt.decode(login.tokenSet.access_token) as any;
      session = decoded?.sid ? await prisma.session.findUnique({ where: { sessionId: decoded.sid } }) : null;
    }

    if (!user || !session) throw new HttpError(401, 'login_required', 'A valid login is required.');

    const code = randomOpaqueToken('authcode', 32);
    await prisma.authorizationCode.create({
      data: {
        codeId: newId('code'),
        codeHash: hmacTokenHash(code),
        userId: user.userId,
        clientId: client.clientId,
        redirectUri: safeRedirectUri,
        scope: scopeString(scopes),
        codeChallenge: codeChallenge || '',
        codeChallengeMethod: codeChallengeMethod || 'S256',
        nonce: nonce || null,
        stateHash: state ? hashSensitive(state) : null,
        sessionId: session.sessionId,
        deviceId: session.deviceId || null,
        expiresAt: plusSeconds(env.AUTH_AUTH_CODE_TTL_SECONDS),
      },
    });

    await audit({
      eventType: 'auth.oauth.code_issued',
      result: 'success',
      req,
      userId: user.userId,
      sessionId: session.sessionId,
      clientId: client.clientId,
    });

    const redirect = new URL(safeRedirectUri);
    redirect.searchParams.set('code', code);
    if (state) redirect.searchParams.set('state', state);
    return {
      redirect_to: redirect.toString(),
      code,
      state,
      expires_in: env.AUTH_AUTH_CODE_TTL_SECONDS,
    };
  }

  async token(body: any, req: Request): Promise<TokenSet> {
    const grantType = body.grant_type || body.grantType;
    if (grantType === 'authorization_code') return this.exchangeAuthorizationCode(body, req);
    if (grantType === 'refresh_token') return this.refresh(body.refresh_token || body.refreshToken, body.client_id || body.clientId, req);
    if (grantType === 'client_credentials') return this.clientCredentials(body, req);
    throw new HttpError(400, 'unsupported_grant_type', 'Unsupported grant type.');
  }

  private async exchangeAuthorizationCode(body: any, req: Request): Promise<TokenSet> {
    const client = await authenticateConfidentialClient(req, body.client_id || body.clientId);
    assertGrantAllowed(client, 'authorization_code');
    const code = body.code;
    const redirectUri = body.redirect_uri || body.redirectUri;
    const codeVerifier = body.code_verifier || body.codeVerifier;
    if (!code || !redirectUri || !codeVerifier) {
      throw new HttpError(400, 'invalid_request', 'code, redirect_uri, and code_verifier are required.');
    }

    const row = await prisma.authorizationCode.findUnique({
      where: { codeHash: hmacTokenHash(code) },
      include: {
        session: true,
      },
    });
    if (!row || row.clientId !== client.clientId || row.redirectUri !== redirectUri) {
      throw new HttpError(400, 'invalid_grant', 'Invalid authorization code.');
    }
    if (row.consumedAt || row.expiresAt <= new Date()) {
      throw new HttpError(400, 'invalid_grant', 'Authorization code is expired or already used.');
    }
    if (row.codeChallengeMethod !== 'S256' || !verifyPkceS256(codeVerifier, row.codeChallenge)) {
      throw new HttpError(400, 'invalid_grant', 'PKCE verification failed.');
    }
    if (!row.session || row.session.status !== 'ACTIVE') {
      throw new HttpError(400, 'invalid_grant', 'Session is not active.');
    }

    await prisma.authorizationCode.update({
      where: { codeId: row.codeId },
      data: { consumedAt: new Date() },
    });

    const user = await this.loadUser(row.userId);
    const family = await this.createRefreshFamily({
      userId: row.userId,
      clientId: client.clientId,
      sessionId: row.sessionId,
      deviceId: row.deviceId,
      req,
    });

    await audit({
      eventType: 'auth.oauth.token_issued',
      result: 'success',
      req,
      userId: row.userId,
      sessionId: row.sessionId,
      clientId: client.clientId,
    });
    incrementMetric('auth_token_issued_total');

    return this.tokenSetFor({
      user,
      client,
      session: row.session,
      scopes: parseScope(row.scope),
      refreshToken: family.refreshToken,
      nonce: row.nonce,
    });
  }

  async refresh(refreshToken?: string, clientId?: string, req?: Request): Promise<TokenSet> {
    if (!refreshToken) throw new HttpError(400, 'invalid_request', 'refresh_token is required.');
    const tokenHash = hmacTokenHash(refreshToken);
    const row = await prisma.refreshToken.findUnique({
      where: { tokenHash },
      include: {
        family: {
          include: {
            session: true,
            client: true,
            user: {
              include: {
                emails: true,
                phones: true,
              },
            },
            device: true,
          },
        },
      },
    });

    if (!row) {
      if (req) await audit({ eventType: 'auth.refresh.failed', result: 'failure', req, metadata: { reason: 'not_found' } });
      incrementMetric('auth_refresh_failure_total');
      throw new HttpError(400, 'invalid_grant', 'Invalid refresh token.');
    }

    if (clientId && row.family.clientId !== clientId) {
      throw new HttpError(400, 'invalid_grant', 'Refresh token does not belong to this client.');
    }

    if (row.status !== 'ACTIVE') {
      await this.revokeRefreshFamily(row.familyId, 'refresh_token_reuse');
      await prisma.refreshToken.update({
        where: { tokenId: row.tokenId },
        data: { status: 'REUSED' },
      }).catch(() => undefined);
      if (req) {
        await audit({
          eventType: 'auth.refresh.reuse_detected',
          result: 'blocked',
          req,
          userId: row.family.userId,
          sessionId: row.family.sessionId,
          clientId: row.family.clientId,
        });
      }
      incrementMetric('auth_refresh_reuse_detected_total');
      throw new HttpError(400, 'invalid_grant', 'Refresh token reuse detected.');
    }

    if (
      row.expiresAt <= new Date() ||
      row.family.status !== 'ACTIVE' ||
      row.family.session.status !== 'ACTIVE' ||
      row.family.user.status !== 'ACTIVE' ||
      row.family.device?.status === 'REVOKED' ||
      row.family.device?.status === 'LOST'
    ) {
      await prisma.refreshToken.update({
        where: { tokenId: row.tokenId },
        data: { status: row.expiresAt <= new Date() ? 'EXPIRED' : 'REVOKED' },
      }).catch(() => undefined);
      if (req) await audit({ eventType: 'auth.refresh.failed', result: 'failure', req, userId: row.family.userId });
      incrementMetric('auth_refresh_failure_total');
      throw new HttpError(400, 'invalid_grant', 'Refresh token is no longer active.');
    }

    const nextRefreshToken = randomOpaqueToken('rt', 48);
    const nextTokenId = newId('rtok');
    await prisma.$transaction(async (tx) => {
      await tx.refreshToken.update({
        where: { tokenId: row.tokenId },
        data: {
          status: 'CONSUMED',
          consumedAt: new Date(),
          replacedByTokenId: nextTokenId,
        },
      });
      await tx.refreshToken.create({
        data: {
          tokenId: nextTokenId,
          familyId: row.familyId,
          tokenHash: hmacTokenHash(nextRefreshToken),
          status: 'ACTIVE',
          expiresAt: plusDays(env.AUTH_REFRESH_TOKEN_TTL_DAYS),
          ipHash: req ? hashSensitive(requestIp(req)) : null,
          userAgentHash: req ? hashSensitive(userAgent(req)) : null,
        },
      });
      await tx.session.update({
        where: { sessionId: row.family.sessionId },
        data: { lastSeenAt: new Date() },
      });
    });

    if (req) {
      await audit({
        eventType: 'auth.refresh.succeeded',
        result: 'success',
        req,
        userId: row.family.userId,
        sessionId: row.family.sessionId,
        clientId: row.family.clientId,
      });
    }
    incrementMetric('auth_refresh_success_total');

    const client = {
      clientId: row.family.client.clientId,
      clientName: row.family.client.clientName,
      clientType: row.family.client.clientType,
      status: row.family.client.status,
      redirectUris: [],
      allowedScopes: [],
      allowedGrantTypes: [],
      tokenEndpointAuthMethod: row.family.client.tokenEndpointAuthMethod,
      pkceRequired: row.family.client.pkceRequired,
    };

    return this.tokenSetFor({
      user: row.family.user,
      client,
      session: row.family.session,
      scopes: safeJsonParseArray(row.family.client.allowedScopesJson).length
        ? safeJsonParseArray(row.family.client.allowedScopesJson)
        : ['openid', 'profile'],
      refreshToken: nextRefreshToken,
    });
  }

  private async clientCredentials(body: any, req: Request): Promise<TokenSet> {
    const client = await authenticateConfidentialClient(req, body.client_id || body.clientId);
    assertGrantAllowed(client, 'client_credentials');
    const scopes = assertScopesAllowed(client, parseScope(body.scope || body.scopes));
    const audience = body.audience || env.AUTH_INTERNAL_TOKEN_AUDIENCE;
    const accessToken = tokenService.signServiceToken({
      clientId: client.clientId,
      scopes: scopeString(scopes),
      audience,
    });
    await audit({ eventType: 'auth.service_token.issued', result: 'success', req, clientId: client.clientId });
    return {
      access_token: accessToken,
      token_type: 'Bearer',
      expires_in: env.AUTH_ACCESS_TOKEN_TTL_SECONDS,
      scope: scopeString(scopes),
    };
  }

  async forgotPassword(body: any, req: Request): Promise<any> {
    const identifier = body.email || body.phone || body.phoneNumber || body.identifier;
    const user = await this.findUserByIdentifier(identifier);
    let challenge: { challengeId: string; code: string } | null = null;
    if (user) {
      challenge = await this.createVerificationChallenge({
        userId: user.userId,
        identifier,
        challengeType: 'PASSWORD_RESET',
        purpose: 'PASSWORD_RESET',
        ttlSeconds: env.AUTH_PASSWORD_RESET_TTL_SECONDS,
      });
      await audit({ eventType: 'auth.password.reset.requested', result: 'success', req, userId: user.userId });
    } else {
      await audit({ eventType: 'auth.password.reset.requested', result: 'info', req });
    }

    return {
      success: true,
      message: 'If the account exists, a reset code has been sent.',
      challenge_id: env.AUTH_DEV_RETURN_CODES ? challenge?.challengeId : undefined,
      dev_reset_code: env.AUTH_DEV_RETURN_CODES ? challenge?.code : undefined,
    };
  }

  async resetPassword(body: any, req: Request): Promise<any> {
    assertValidPassword(body.password || body.new_password || body.newPassword);
    const challenge = await this.verifyChallenge(
      body.challenge_id || body.challengeId,
      body.code || body.token || body.reset_code,
      'PASSWORD_RESET',
    );
    if (!challenge.userId) throw new HttpError(400, 'invalid_challenge', 'Invalid challenge.');
    await this.updatePassword(challenge.userId, body.password || body.new_password || body.newPassword);
    await this.revokeUserSessions(challenge.userId, 'password_reset');
    await audit({ eventType: 'auth.password.reset.completed', result: 'success', req, userId: challenge.userId });
    return { success: true };
  }

  async changePassword(userId: string, body: any, req: Request): Promise<any> {
    const currentPassword = body.current_password || body.currentPassword;
    const nextPassword = body.new_password || body.newPassword || body.password;
    assertValidPassword(nextPassword);
    const valid = await this.verifyPassword(userId, currentPassword || '');
    if (!valid) throw new HttpError(401, 'invalid_credentials', 'Invalid credentials.');
    await this.updatePassword(userId, nextPassword);
    await audit({ eventType: 'auth.password.changed', result: 'success', req, userId });
    return { success: true };
  }

  private async updatePassword(userId: string, password: string): Promise<void> {
    const passwordHash = await this.hashPassword(password);
    await prisma.passwordCredential.create({
      data: {
        credentialId: newId('pwd'),
        userId,
        passwordHash,
        hashAlgorithm: 'argon2id',
        hashParamsJson: JSON.stringify({ version: 1, peppered: Boolean(env.AUTH_PASSWORD_PEPPER) }),
        passwordVersion: 1,
        lastChangedAt: new Date(),
      },
    });
  }

  async me(userId: string): Promise<any> {
    const user = await this.loadUser(userId);
    return {
      user_id: user.userId,
      display_name: user.displayName,
      status: user.status,
      email: firstPrimary(user.emails)?.emailDisplay || null,
      email_verified: Boolean(firstPrimary(user.emails)?.isVerified),
      phone: firstPrimary(user.phones)?.phoneE164 || null,
      phone_verified: Boolean(firstPrimary(user.phones)?.isVerified),
      created_at: user.createdAt,
      updated_at: user.updatedAt,
    };
  }

  async updateMe(userId: string, body: any, req: Request): Promise<any> {
    const user = await prisma.user.update({
      where: { userId },
      data: {
        displayName: body.display_name || body.displayName,
      },
    });
    await audit({ eventType: 'auth.user.updated', result: 'success', req, userId });
    return { user_id: user.userId, display_name: user.displayName, status: user.status };
  }

  async userInfo(userId: string): Promise<any> {
    const me = await this.me(userId);
    return {
      sub: me.user_id,
      name: me.display_name,
      email: me.email,
      email_verified: me.email_verified,
      phone_number: me.phone,
      phone_number_verified: me.phone_verified,
    };
  }

  async sessions(userId: string): Promise<any> {
    const sessions = await prisma.session.findMany({
      where: { userId },
      orderBy: { createdAt: 'desc' },
      include: { device: true },
    });
    return {
      sessions: sessions.map((session) => ({
        session_id: session.sessionId,
        client_id: session.clientId,
        device_id: session.deviceId,
        device_name: session.device?.deviceName,
        status: session.status,
        aal: session.aal,
        risk_level: session.riskLevel,
        auth_time: session.authTime,
        last_seen_at: session.lastSeenAt,
        expires_at: session.expiresAt,
        revoked_at: session.revokedAt,
      })),
    };
  }

  async currentSession(sessionId?: string): Promise<any> {
    if (!sessionId) throw new HttpError(404, 'session_not_found', 'No current session.');
    const session = await prisma.session.findUnique({ where: { sessionId }, include: { device: true } });
    if (!session) throw new HttpError(404, 'session_not_found', 'No current session.');
    return {
      session_id: session.sessionId,
      client_id: session.clientId,
      device_id: session.deviceId,
      device_name: session.device?.deviceName,
      status: session.status,
      aal: session.aal,
      risk_level: session.riskLevel,
      auth_time: session.authTime,
      last_seen_at: session.lastSeenAt,
      expires_at: session.expiresAt,
    };
  }

  async logout(auth: any, req: Request): Promise<any> {
    if (auth?.sid) {
      await this.revokeSession(auth.sid, auth.sub, 'logout');
    }
    if (auth?.jti) {
      await prisma.accessTokenJti.upsert({
        where: { jti: auth.jti },
        update: { revokedAt: new Date(), revokeReason: 'logout' },
        create: {
          jti: auth.jti,
          userId: auth.sub,
          sessionId: auth.sid || '',
          clientId: auth.client_id || auth.azp || '',
          expiresAt: new Date((auth.exp || Math.floor(Date.now() / 1000)) * 1000),
          revokedAt: new Date(),
          revokeReason: 'logout',
        },
      });
    }
    await audit({ eventType: 'auth.logout.succeeded', result: 'success', req, userId: auth.sub, sessionId: auth.sid });
    return { success: true };
  }

  async logoutAll(userId: string, req: Request): Promise<any> {
    await this.revokeUserSessions(userId, 'logout_all');
    await audit({ eventType: 'auth.logout_all.succeeded', result: 'success', req, userId });
    return { success: true };
  }

  async revokeSession(sessionId: string, userId: string, reason = 'user_revoked'): Promise<void> {
    await prisma.session.updateMany({
      where: { sessionId, userId },
      data: { status: 'REVOKED', revokedAt: new Date(), revokeReason: reason },
    });
    await prisma.refreshTokenFamily.updateMany({
      where: { sessionId, userId },
      data: { status: 'REVOKED', revokedAt: new Date(), revokeReason: reason },
    });
    await prisma.refreshToken.updateMany({
      where: { family: { is: { sessionId, userId } } },
      data: { status: 'REVOKED' },
    });
  }

  private async revokeUserSessions(userId: string, reason: string): Promise<void> {
    await prisma.session.updateMany({
      where: { userId, status: 'ACTIVE' },
      data: { status: 'REVOKED', revokedAt: new Date(), revokeReason: reason },
    });
    await prisma.refreshTokenFamily.updateMany({
      where: { userId, status: 'ACTIVE' },
      data: { status: 'REVOKED', revokedAt: new Date(), revokeReason: reason },
    });
    await prisma.refreshToken.updateMany({
      where: { family: { is: { userId } }, status: 'ACTIVE' },
      data: { status: 'REVOKED' },
    });
  }

  private async revokeRefreshFamily(familyId: string, reason: string): Promise<void> {
    await prisma.refreshTokenFamily.update({
      where: { familyId },
      data: { status: 'REVOKED', revokedAt: new Date(), revokeReason: reason },
    }).catch(() => undefined);
    await prisma.refreshToken.updateMany({
      where: { familyId },
      data: { status: 'REVOKED' },
    });
    const family = await prisma.refreshTokenFamily.findUnique({ where: { familyId } });
    if (family) {
      await prisma.session.update({
        where: { sessionId: family.sessionId },
        data: { status: 'REVOKED', revokedAt: new Date(), revokeReason: reason },
      }).catch(() => undefined);
    }
  }

  async revokeToken(body: any, req: Request): Promise<any> {
    const token = body.token;
    if (!token) return { success: true };

    const refresh = await prisma.refreshToken.findUnique({
      where: { tokenHash: hmacTokenHash(token) },
    });
    if (refresh) {
      await this.revokeRefreshFamily(refresh.familyId, 'oauth_revocation');
      await audit({ eventType: 'auth.token.revoked', result: 'success', req, metadata: { hint: 'refresh_token' } });
      return { success: true };
    }

    try {
      const payload = tokenService.verifyAnyJwt(token) as any;
      if (payload.jti) {
        await prisma.accessTokenJti.upsert({
          where: { jti: payload.jti },
          update: { revokedAt: new Date(), revokeReason: 'oauth_revocation' },
          create: {
            jti: payload.jti,
            userId: payload.sub || '',
            sessionId: payload.sid || '',
            clientId: payload.client_id || payload.azp || '',
            expiresAt: new Date((payload.exp || Math.floor(Date.now() / 1000)) * 1000),
            revokedAt: new Date(),
            revokeReason: 'oauth_revocation',
          },
        });
      }
    } catch {
      // RFC 7009 keeps token revocation responses intentionally quiet.
    }
    return { success: true };
  }

  async introspect(body: any, req: Request): Promise<any> {
    const token = body.token;
    if (!token) return { active: false };

    const refresh = await prisma.refreshToken.findUnique({
      where: { tokenHash: hmacTokenHash(token) },
      include: { family: true },
    });
    if (refresh) {
      const active =
        refresh.status === 'ACTIVE' &&
        refresh.expiresAt > new Date() &&
        refresh.family.status === 'ACTIVE';
      await audit({ eventType: 'auth.introspection', result: 'success', req, clientId: refresh.family.clientId });
      return {
        active,
        token_type: 'refresh_token',
        client_id: refresh.family.clientId,
        sub: refresh.family.userId,
        sid: refresh.family.sessionId,
        exp: Math.floor(refresh.expiresAt.getTime() / 1000),
      };
    }

    try {
      const payload = tokenService.verifyAnyJwt(token) as any;
      const revoked = payload.jti
        ? await prisma.accessTokenJti.findUnique({ where: { jti: payload.jti } })
        : null;
      const session = payload.sid ? await prisma.session.findUnique({ where: { sessionId: payload.sid } }) : null;
      const active = !revoked?.revokedAt && (!payload.sid || session?.status === 'ACTIVE');
      await audit({ eventType: 'auth.introspection', result: 'success', req, userId: payload.sub, clientId: payload.client_id });
      return {
        active,
        ...payload,
      };
    } catch {
      return { active: false };
    }
  }

  async deviceRegistrationStart(auth: any, req: Request): Promise<any> {
    const challenge = await this.createVerificationChallenge({
      userId: auth.sub,
      identifier: auth.device_id || auth.sub,
      challengeType: 'DEVICE_CHALLENGE',
      purpose: 'DEVICE_REGISTRATION',
      ttlSeconds: env.AUTH_DEVICE_CHALLENGE_TTL_SECONDS,
    });
    await audit({ eventType: 'auth.device.registration_started', result: 'success', req, userId: auth.sub });
    return {
      challenge_id: challenge.challengeId,
      challenge: challenge.code,
      expires_in: env.AUTH_DEVICE_CHALLENGE_TTL_SECONDS,
    };
  }

  async deviceRegistrationComplete(auth: any, body: any, req: Request): Promise<any> {
    const challengeId = body.challenge_id || body.challengeId;
    const challengeCode = body.challenge || body.code;
    if (challengeId && challengeCode) {
      await this.verifyChallenge(challengeId, challengeCode, 'DEVICE_REGISTRATION');
    }

    const device = await this.upsertDevice(auth.sub, body);
    const certificate = tokenService.signDeviceCertificate({
      userId: auth.sub,
      deviceId: device.deviceId,
      publicSigningKey: device.publicSigningKey,
      keyAlgorithm: device.keyAlgorithm,
    });
    await prisma.device.update({
      where: { deviceId: device.deviceId },
      data: { deviceCertificate: certificate, status: 'ACTIVE', lastSeenAt: new Date() },
    });
    await audit({
      eventType: 'auth.device.registered',
      result: 'success',
      req,
      userId: auth.sub,
      deviceId: device.deviceId,
    });
    incrementMetric('auth_device_registered_total');
    return {
      device_id: device.deviceId,
      status: 'ACTIVE',
      device_certificate: certificate,
      expires_in: 365 * 24 * 60 * 60,
    };
  }

  async listDevices(userId: string): Promise<any> {
    const devices = await prisma.device.findMany({
      where: { userId },
      orderBy: { firstSeenAt: 'desc' },
    });
    return {
      devices: devices.map((device) => ({
        device_id: device.deviceId,
        status: device.status,
        platform: device.platform,
        device_name: device.deviceName,
        app_version: device.appVersion,
        os_version: device.osVersion,
        first_seen_at: device.firstSeenAt,
        last_seen_at: device.lastSeenAt,
        revoked_at: device.revokedAt,
        risk_score: device.riskScore,
      })),
    };
  }

  async currentDevice(userId: string, deviceId?: string): Promise<any> {
    if (!deviceId) throw new HttpError(404, 'device_not_found', 'No current device.');
    const device = await prisma.device.findFirst({ where: { userId, deviceId } });
    if (!device) throw new HttpError(404, 'device_not_found', 'No current device.');
    return {
      device_id: device.deviceId,
      status: device.status,
      platform: device.platform,
      device_name: device.deviceName,
      app_version: device.appVersion,
      os_version: device.osVersion,
      first_seen_at: device.firstSeenAt,
      last_seen_at: device.lastSeenAt,
      risk_score: device.riskScore,
    };
  }

  async updateDevice(userId: string, deviceId: string, body: any, req: Request): Promise<any> {
    const device = await prisma.device.updateMany({
      where: { userId, deviceId },
      data: {
        deviceName: body.device_name || body.deviceName,
        appVersion: body.app_version || body.appVersion,
        osVersion: body.os_version || body.osVersion,
        lastSeenAt: new Date(),
      },
    });
    if (!device.count) throw new HttpError(404, 'device_not_found', 'Device was not found.');
    await audit({ eventType: 'auth.device.updated', result: 'success', req, userId, deviceId });
    return this.currentDevice(userId, deviceId);
  }

  async revokeDevice(userId: string, deviceId: string, reason: string, req: Request): Promise<any> {
    const result = await prisma.device.updateMany({
      where: { userId, deviceId },
      data: {
        status: reason === 'lost' ? 'LOST' : 'REVOKED',
        revokedAt: new Date(),
        revokeReason: reason,
      },
    });
    if (!result.count) throw new HttpError(404, 'device_not_found', 'Device was not found.');
    await prisma.refreshTokenFamily.updateMany({
      where: { userId, deviceId, status: 'ACTIVE' },
      data: { status: 'REVOKED', revokedAt: new Date(), revokeReason: `device_${reason}` },
    });
    await prisma.refreshToken.updateMany({
      where: { family: { is: { userId, deviceId } }, status: 'ACTIVE' },
      data: { status: 'REVOKED' },
    });
    await audit({ eventType: 'auth.device.revoked', result: 'success', req, userId, deviceId });
    incrementMetric('auth_device_revoked_total');
    return { success: true };
  }
}

export const authService = new AuthService();
