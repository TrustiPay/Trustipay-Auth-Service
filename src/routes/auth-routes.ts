import { Router } from 'express';
import { env, issuerUrl } from '../config/env';
import { asyncHandler } from '../http';
import { requireAccessToken } from '../middleware/authenticate';
import { rateLimit } from '../middleware/rate-limit';
import { authService } from '../services/auth-service';
import { tokenService } from '../services/token-service';

export const authRouter = Router();

authRouter.get('/jwks.json', (_req, res) => {
  res.json(tokenService.jwks());
});

authRouter.post(
  '/register/start',
  rateLimit('register', env.AUTH_RATE_LIMIT_REGISTER_MAX, env.AUTH_RATE_LIMIT_WINDOW_MS),
  asyncHandler(async (req, res) => {
    res.status(201).json(await authService.registerStart(req.body, req));
  }),
);

authRouter.post(
  '/register/verify-email',
  rateLimit('verify-email', env.AUTH_RATE_LIMIT_REGISTER_MAX, env.AUTH_RATE_LIMIT_WINDOW_MS),
  asyncHandler(async (req, res) => {
    res.json(await authService.verifyRegistration('email', req.body, req));
  }),
);

authRouter.post(
  '/register/verify-phone',
  rateLimit('verify-phone', env.AUTH_RATE_LIMIT_REGISTER_MAX, env.AUTH_RATE_LIMIT_WINDOW_MS),
  asyncHandler(async (req, res) => {
    res.json(await authService.verifyRegistration('phone', req.body, req));
  }),
);

authRouter.post(
  '/register/resend-code',
  rateLimit('resend-code', env.AUTH_RATE_LIMIT_REGISTER_MAX, env.AUTH_RATE_LIMIT_WINDOW_MS),
  asyncHandler(async (req, res) => {
    res.json(await authService.resendRegistrationCode(req.body, req));
  }),
);

authRouter.post(
  '/register',
  rateLimit('register-compat', env.AUTH_RATE_LIMIT_REGISTER_MAX, env.AUTH_RATE_LIMIT_WINDOW_MS),
  asyncHandler(async (req, res) => {
    res.status(201).json(await authService.registerCompat(req.body, req));
  }),
);

authRouter.post(
  '/login',
  rateLimit('login', env.AUTH_RATE_LIMIT_LOGIN_MAX, env.AUTH_RATE_LIMIT_WINDOW_MS),
  asyncHandler(async (req, res) => {
    const result = await authService.loginWithPassword(req.body, req);
    res.json(authService.toAndroidTokenResponse(result.tokenSet, result.user));
  }),
);

authRouter.post(
  '/legacy/mobile-login',
  rateLimit('legacy-mobile-login', env.AUTH_RATE_LIMIT_LOGIN_MAX, env.AUTH_RATE_LIMIT_WINDOW_MS),
  asyncHandler(async (req, res) => {
    const result = await authService.loginWithPassword(req.body, req);
    res.json(result.tokenSet);
  }),
);

authRouter.get(
  '/oauth/authorize',
  rateLimit('oauth-authorize', env.AUTH_RATE_LIMIT_LOGIN_MAX, env.AUTH_RATE_LIMIT_WINDOW_MS),
  asyncHandler(async (req, res) => {
    const result = await authService.authorize(req.query, req);
    res.redirect(result.redirect_to);
  }),
);

authRouter.post(
  '/oauth/authorize',
  rateLimit('oauth-authorize-post', env.AUTH_RATE_LIMIT_LOGIN_MAX, env.AUTH_RATE_LIMIT_WINDOW_MS),
  asyncHandler(async (req, res) => {
    res.json(await authService.authorize(req.body, req));
  }),
);

authRouter.post(
  '/oauth/token',
  rateLimit('oauth-token', env.AUTH_RATE_LIMIT_TOKEN_MAX, env.AUTH_RATE_LIMIT_WINDOW_MS),
  asyncHandler(async (req, res) => {
    res.json(await authService.token(req.body, req));
  }),
);

authRouter.post(
  '/oauth/revoke',
  rateLimit('oauth-revoke', env.AUTH_RATE_LIMIT_TOKEN_MAX, env.AUTH_RATE_LIMIT_WINDOW_MS),
  asyncHandler(async (req, res) => {
    res.json(await authService.revokeToken(req.body, req));
  }),
);

authRouter.post(
  '/oauth/introspect',
  rateLimit('oauth-introspect', env.AUTH_RATE_LIMIT_TOKEN_MAX, env.AUTH_RATE_LIMIT_WINDOW_MS),
  asyncHandler(async (req, res) => {
    res.json(await authService.introspect(req.body, req));
  }),
);

authRouter.post(
  '/refresh',
  rateLimit('refresh-compat', env.AUTH_RATE_LIMIT_TOKEN_MAX, env.AUTH_RATE_LIMIT_WINDOW_MS),
  asyncHandler(async (req, res) => {
    const tokenSet = await authService.refresh(req.body.refreshToken || req.body.refresh_token, req.body.client_id, req);
    res.json({
      accessToken: tokenSet.access_token,
      refreshToken: tokenSet.refresh_token,
      expiresIn: tokenSet.expires_in,
      tokenType: tokenSet.token_type,
      scope: tokenSet.scope,
      idToken: tokenSet.id_token,
    });
  }),
);

authRouter.post(
  '/password/forgot',
  rateLimit('password-forgot', env.AUTH_RATE_LIMIT_PASSWORD_RESET_MAX, 60 * 60 * 1000),
  asyncHandler(async (req, res) => {
    res.json(await authService.forgotPassword(req.body, req));
  }),
);

authRouter.post(
  '/password/reset',
  rateLimit('password-reset', env.AUTH_RATE_LIMIT_PASSWORD_RESET_MAX, 60 * 60 * 1000),
  asyncHandler(async (req, res) => {
    res.json(await authService.resetPassword(req.body, req));
  }),
);

authRouter.post(
  '/password/change',
  requireAccessToken(),
  asyncHandler(async (req, res) => {
    res.json(await authService.changePassword(req.auth!.sub, req.body, req));
  }),
);

authRouter.get(
  '/me',
  requireAccessToken(),
  asyncHandler(async (req, res) => {
    res.json(await authService.me(req.auth!.sub));
  }),
);

authRouter.patch(
  '/me',
  requireAccessToken(),
  asyncHandler(async (req, res) => {
    res.json(await authService.updateMe(req.auth!.sub, req.body, req));
  }),
);

authRouter.get(
  '/userinfo',
  requireAccessToken(),
  asyncHandler(async (req, res) => {
    res.json(await authService.userInfo(req.auth!.sub));
  }),
);

authRouter.get(
  '/sessions',
  requireAccessToken(),
  asyncHandler(async (req, res) => {
    res.json(await authService.sessions(req.auth!.sub));
  }),
);

authRouter.get(
  '/sessions/current',
  requireAccessToken(),
  asyncHandler(async (req, res) => {
    res.json(await authService.currentSession(req.auth!.sid));
  }),
);

authRouter.post(
  '/sessions/:sessionId/revoke',
  requireAccessToken(),
  asyncHandler(async (req, res) => {
    await authService.revokeSession(String(req.params.sessionId), req.auth!.sub);
    res.json({ success: true });
  }),
);

authRouter.post(
  '/logout',
  requireAccessToken(),
  asyncHandler(async (req, res) => {
    res.json(await authService.logout(req.auth!, req));
  }),
);

authRouter.post(
  '/logout-all',
  requireAccessToken(),
  asyncHandler(async (req, res) => {
    res.json(await authService.logoutAll(req.auth!.sub, req));
  }),
);

authRouter.post(
  '/devices/register/start',
  requireAccessToken(['devices:write']),
  asyncHandler(async (req, res) => {
    res.json(await authService.deviceRegistrationStart(req.auth!, req));
  }),
);

authRouter.post(
  '/devices/register/complete',
  requireAccessToken(['devices:write']),
  asyncHandler(async (req, res) => {
    res.status(201).json(await authService.deviceRegistrationComplete(req.auth!, req.body, req));
  }),
);

authRouter.get(
  '/devices',
  requireAccessToken(['devices:read']),
  asyncHandler(async (req, res) => {
    res.json(await authService.listDevices(req.auth!.sub));
  }),
);

authRouter.get(
  '/devices/current',
  requireAccessToken(['devices:read']),
  asyncHandler(async (req, res) => {
    res.json(await authService.currentDevice(req.auth!.sub, req.auth!.device_id));
  }),
);

authRouter.patch(
  '/devices/:deviceId',
  requireAccessToken(['devices:write']),
  asyncHandler(async (req, res) => {
    res.json(await authService.updateDevice(req.auth!.sub, String(req.params.deviceId), req.body, req));
  }),
);

authRouter.post(
  '/devices/:deviceId/revoke',
  requireAccessToken(['devices:write']),
  asyncHandler(async (req, res) => {
    res.json(await authService.revokeDevice(req.auth!.sub, String(req.params.deviceId), 'revoked', req));
  }),
);

authRouter.post(
  '/devices/:deviceId/mark-lost',
  requireAccessToken(['devices:write']),
  asyncHandler(async (req, res) => {
    res.json(await authService.revokeDevice(req.auth!.sub, String(req.params.deviceId), 'lost', req));
  }),
);

authRouter.post('/mfa/challenge/start', requireAccessToken(), (_req, res) => {
  res.status(env.AUTH_FEATURE_MFA_ENABLED ? 501 : 404).json({
    error: env.AUTH_FEATURE_MFA_ENABLED ? 'not_implemented' : 'feature_disabled',
    message: 'MFA is not enabled in this deployment.',
  });
});

authRouter.post('/mfa/challenge/verify', (_req, res) => {
  res.status(env.AUTH_FEATURE_MFA_ENABLED ? 501 : 404).json({
    error: env.AUTH_FEATURE_MFA_ENABLED ? 'not_implemented' : 'feature_disabled',
    message: 'MFA is not enabled in this deployment.',
  });
});

authRouter.post('/passkeys/registration/options', requireAccessToken(), (_req, res) => {
  res.status(env.AUTH_FEATURE_PASSKEYS_ENABLED ? 501 : 404).json({
    error: env.AUTH_FEATURE_PASSKEYS_ENABLED ? 'not_implemented' : 'feature_disabled',
    message: 'Passkeys are not enabled in this deployment.',
  });
});

authRouter.get('/configuration', (_req, res) => {
  res.json({
    issuer: env.AUTH_ISSUER_URL,
    jwks_uri: issuerUrl('/jwks.json'),
    mfa_enabled: env.AUTH_FEATURE_MFA_ENABLED,
    passkeys_enabled: env.AUTH_FEATURE_PASSKEYS_ENABLED,
    dpop_enabled: env.AUTH_FEATURE_DPOP_ENABLED,
  });
});
