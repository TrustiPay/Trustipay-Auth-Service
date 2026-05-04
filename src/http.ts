import { NextFunction, Request, Response } from 'express';
import { newId } from './services/ids';

export class HttpError extends Error {
  status: number;
  code: string;

  constructor(status: number, code: string, message: string) {
    super(message);
    this.status = status;
    this.code = code;
  }
}

export function asyncHandler(
  handler: (req: Request, res: Response, next: NextFunction) => Promise<unknown>,
) {
  return (req: Request, res: Response, next: NextFunction) => {
    handler(req, res, next).catch(next);
  };
}

export function requestContext(req: Request, res: Response, next: NextFunction): void {
  const requestIdHeader = req.header('x-request-id');
  req.requestId = requestIdHeader && requestIdHeader.length < 128 ? requestIdHeader : newId('req');
  res.setHeader('X-Request-Id', req.requestId);
  next();
}

export function notFound(req: Request, res: Response): void {
  res.status(404).json({
    error: 'not_found',
    message: `No route for ${req.method} ${req.path}`,
    request_id: req.requestId,
  });
}

export function errorHandler(error: unknown, req: Request, res: Response, _next: NextFunction): void {
  const status = typeof (error as any)?.status === 'number' ? (error as any).status : 500;
  const code = typeof (error as any)?.code === 'string' ? (error as any).code : 'internal_error';
  const message =
    status >= 500 ? 'Internal server error' : (error as any)?.message || 'Request failed';

  if (status >= 500) {
    console.error({ requestId: req.requestId, error });
  }

  res.status(status).json({
    error: code,
    message,
    request_id: req.requestId,
  });
}
