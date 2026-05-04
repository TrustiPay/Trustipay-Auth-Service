import fs from 'fs';
import path from 'path';
import { PrismaClient } from '@prisma/client';
import { env } from '../config/env';

function ensureSqliteDirectory(databaseUrl: string): void {
  if (!databaseUrl.startsWith('file:')) return;

  const sqlitePath = databaseUrl.replace(/^file:/, '');
  if (!sqlitePath || sqlitePath === ':memory:') return;

  const resolved = path.isAbsolute(sqlitePath)
    ? sqlitePath
    : path.resolve(process.cwd(), 'prisma', sqlitePath);
  const directory = path.dirname(resolved);
  if (!fs.existsSync(directory)) {
    fs.mkdirSync(directory, { recursive: true });
  }
}

ensureSqliteDirectory(env.DATABASE_URL);

export const prisma = new PrismaClient({
  log: env.NODE_ENV === 'development' ? ['warn', 'error'] : ['error'],
});

export async function checkDatabase(): Promise<void> {
  await prisma.$queryRaw`SELECT 1`;
}
