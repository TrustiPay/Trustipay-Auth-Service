import { NextFunction, Request, Response } from 'express';
import { hashSensitive } from '../services/crypto';

interface Bucket {
  count: number;
  resetAt: number;
}

const buckets = new Map<string, Bucket>();

function clientIp(req: Request): string {
  const forwarded = req.header('x-forwarded-for')?.split(',')[0]?.trim();
  return forwarded || req.ip || req.socket.remoteAddress || 'unknown';
}

export function identifierKey(req: Request): string {
  const body = req.body || {};
  const query = req.query || {};
  const identifier =
    body.email ||
    body.phone ||
    body.phoneNumber ||
    body.identifier ||
    query.login_hint ||
    query.email ||
    query.phone ||
    'anonymous';
  return hashSensitive(String(identifier)) || 'anonymous';
}

export function rateLimit(
  name: string,
  max: number,
  windowMs: number,
  keyer: (req: Request) => string = (req) => `${clientIp(req)}:${identifierKey(req)}`,
) {
  return (req: Request, res: Response, next: NextFunction): void => {
    const now = Date.now();
    const key = `${name}:${keyer(req)}`;
    const bucket = buckets.get(key);

    if (!bucket || bucket.resetAt <= now) {
      buckets.set(key, { count: 1, resetAt: now + windowMs });
      next();
      return;
    }

    if (bucket.count >= max) {
      const retryAfter = Math.max(1, Math.ceil((bucket.resetAt - now) / 1000));
      res.setHeader('Retry-After', String(retryAfter));
      res.status(429).json({
        error: 'rate_limited',
        message: 'Too many attempts. Please retry later.',
        retry_after_seconds: retryAfter,
        request_id: req.requestId,
      });
      return;
    }

    bucket.count += 1;
    next();
  };
}
