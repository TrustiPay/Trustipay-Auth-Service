import { AuthContext } from './auth';

declare global {
  namespace Express {
    interface Request {
      auth?: AuthContext;
      requestId?: string;
    }
  }
}
