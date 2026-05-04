import cors from 'cors';
import express from 'express';
import { env, issuerUrl } from './config/env';
import { checkDatabase } from './db/prisma';
import { runMigrations } from './db/migrate';
import { errorHandler, notFound, requestContext } from './http';
import { requireAccessToken } from './middleware/authenticate';
import { authRouter } from './routes/auth-routes';
import { authService } from './services/auth-service';
import { seedDefaultClients } from './services/client-service';
import { renderPrometheusMetrics } from './services/metrics';
import { tokenService } from './services/token-service';

export async function bootstrap(): Promise<void> {
  await runMigrations();
  await seedDefaultClients();
}

export function buildApp() {
  const app = express();

  app.disable('x-powered-by');
  app.use(requestContext);
  app.use(
    cors({
      origin: env.AUTH_ALLOWED_ORIGINS.includes('*') ? true : env.AUTH_ALLOWED_ORIGINS,
      credentials: false,
    }),
  );
  app.use(express.json({ limit: '256kb' }));
  app.use(express.urlencoded({ extended: false }));

  app.get('/', (_req, res) => {
    res.json({
      service: env.SERVICE_NAME,
      status: 'ok',
      issuer: env.AUTH_ISSUER_URL,
    });
  });

  app.get('/health/live', (_req, res) => {
    res.json({ status: 'ok', timestamp: new Date().toISOString() });
  });

  app.get('/health/ready', async (_req, res) => {
    try {
      await checkDatabase();
      res.json({ status: 'ready', database: 'ok', timestamp: new Date().toISOString() });
    } catch (error) {
      res.status(503).json({ status: 'not_ready', database: 'error', timestamp: new Date().toISOString() });
    }
  });

  app.get('/metrics', (_req, res) => {
    res.type('text/plain; version=0.0.4').send(renderPrometheusMetrics());
  });

  app.get('/.well-known/oauth-authorization-server', (_req, res) => {
    res.json(discoveryMetadata());
  });

  app.get('/.well-known/openid-configuration', (_req, res) => {
    res.json({
      ...discoveryMetadata(),
      userinfo_endpoint: issuerUrl('/userinfo'),
      id_token_signing_alg_values_supported: ['RS256'],
      claims_supported: ['sub', 'name', 'email', 'email_verified', 'phone_number', 'phone_number_verified'],
    });
  });

  app.get('/.well-known/jwks.json', (_req, res) => {
    res.json(tokenService.jwks());
  });

  app.use('/auth', authRouter);

  // Compatibility alias for the existing Android API surface.
  app.post('/devices/register', requireAccessToken(['devices:write']), async (req, res, next) => {
    try {
      res.status(201).json(await authService.deviceRegistrationComplete(req.auth!, req.body, req));
    } catch (error) {
      next(error);
    }
  });

  app.use(notFound);
  app.use(errorHandler);

  return app;
}

function discoveryMetadata() {
  return {
    issuer: env.AUTH_ISSUER_URL,
    authorization_endpoint: issuerUrl('/oauth/authorize'),
    token_endpoint: issuerUrl('/oauth/token'),
    revocation_endpoint: issuerUrl('/oauth/revoke'),
    introspection_endpoint: issuerUrl('/oauth/introspect'),
    userinfo_endpoint: issuerUrl('/userinfo'),
    jwks_uri: issuerUrl('/jwks.json'),
    response_types_supported: ['code'],
    grant_types_supported: ['authorization_code', 'refresh_token', 'client_credentials'],
    code_challenge_methods_supported: ['S256'],
    subject_types_supported: ['public'],
    token_endpoint_auth_methods_supported: ['none', 'client_secret_basic'],
    scopes_supported: [
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
      'analytics:write',
      'auth-events:read',
      'auth-context:read',
    ],
  };
}
