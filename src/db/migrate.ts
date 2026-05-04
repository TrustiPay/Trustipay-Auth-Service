import fs from 'fs';
import path from 'path';
import { prisma } from './prisma';

function splitSql(sql: string): string[] {
  return sql
    .split(';')
    .map((statement) => statement.trim())
    .filter(Boolean)
    .filter((statement) => !statement.toUpperCase().startsWith('PRAGMA FOREIGN_KEY_CHECK'));
}

export async function runMigrations(): Promise<void> {
  await prisma.$executeRawUnsafe(`
    CREATE TABLE IF NOT EXISTS schema_migrations (
      version TEXT PRIMARY KEY,
      name TEXT NOT NULL,
      applied_at TEXT NOT NULL
    )
  `);

  const migrationsDir = path.resolve(process.cwd(), 'prisma', 'migrations');
  if (!fs.existsSync(migrationsDir)) return;

  const files = fs
    .readdirSync(migrationsDir, { withFileTypes: true })
    .filter((entry) => entry.isDirectory())
    .map((entry) => entry.name)
    .sort();

  for (const directory of files) {
    const versionMatch = directory.match(/^(\d+)/);
    if (!versionMatch) continue;
    const version = versionMatch[1];
    const applied = await prisma.$queryRawUnsafe<Array<{ version: string }>>(
      'SELECT version FROM schema_migrations WHERE version = ?',
      version,
    );
    if (applied.length > 0) continue;

    const migrationPath = path.join(migrationsDir, directory, 'migration.sql');
    if (!fs.existsSync(migrationPath)) continue;

    const sql = fs.readFileSync(migrationPath, 'utf8');
    for (const statement of splitSql(sql)) {
      await prisma.$executeRawUnsafe(statement);
    }

    await prisma.$executeRawUnsafe(
      'INSERT INTO schema_migrations (version, name, applied_at) VALUES (?, ?, ?)',
      version,
      directory,
      new Date().toISOString(),
    );
  }
}

if (require.main === module) {
  runMigrations()
    .then(async () => {
      await prisma.$disconnect();
      console.log('Auth database migrations complete.');
    })
    .catch(async (error) => {
      await prisma.$disconnect();
      console.error(error);
      process.exit(1);
    });
}
