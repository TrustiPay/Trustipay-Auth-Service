import { NextFunction, Request, Response } from 'express';
import { prisma } from '../db/prisma';
import { HttpError } from '../http';
import { tokenService } from '../services/token-service';
import { parseScope } from '../services/validators';

function bearerToken(req: Request): string | null {
  const header = req.header('authorization');
  if (!header?.startsWith('Bearer ')) return null;
  return header.slice('Bearer '.length).trim();
}

export function requireAccessToken(requiredScopes: string[] = []) {
  return async (req: Request, _res: Response, next: NextFunction): Promise<void> => {
    try {
      const token = bearerToken(req);
      if (!token) throw new HttpError(401, 'missing_token', 'Bearer access token is required.');

      const auth = tokenService.verifyAccessToken(token);
      const revoked = await prisma.accessTokenJti.findUnique({ where: { jti: auth.jti } });
      if (revoked?.revokedAt) throw new HttpError(401, 'invalid_token', 'Token has been revoked.');

      if (auth.sid) {
        const session = await prisma.session.findUnique({ where: { sessionId: auth.sid } });
        if (!session || session.status !== 'ACTIVE') {
          throw new HttpError(401, 'invalid_token', 'Session is not active.');
        }
        await prisma.session.update({
          where: { sessionId: auth.sid },
          data: { lastSeenAt: new Date() },
        }).catch(() => undefined);
      }

      if (auth.device_id) {
        const device = await prisma.device.findUnique({ where: { deviceId: auth.device_id } });
        if (device?.status === 'REVOKED' || device?.status === 'LOST') {
          throw new HttpError(403, 'device_not_trusted', 'Device is not trusted.');
        }
      }

      const tokenScopes = parseScope(auth.scope);
      const missing = requiredScopes.filter((scope) => !tokenScopes.includes(scope));
      if (missing.length > 0) {
        throw new HttpError(403, 'insufficient_scope', `Missing required scope: ${missing.join(' ')}`);
      }

      req.auth = auth;
      next();
    } catch (error) {
      next(error);
    }
  };
}
