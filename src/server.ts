import { env } from './config/env';
import { bootstrap, buildApp } from './app';
import { prisma } from './db/prisma';

export async function start(): Promise<void> {
  await bootstrap();
  const app = buildApp();
  const server = app.listen(env.PORT, () => {
    console.log(`${env.SERVICE_NAME} listening on port ${env.PORT}`);
  });

  const shutdown = async (signal: string) => {
    console.log(`Received ${signal}. Shutting down ${env.SERVICE_NAME}.`);
    server.close(async () => {
      await prisma.$disconnect();
      process.exit(0);
    });
  };

  process.on('SIGINT', () => shutdown('SIGINT'));
  process.on('SIGTERM', () => shutdown('SIGTERM'));
}

if (require.main === module) {
  start().catch((error) => {
    console.error(error);
    process.exit(1);
  });
}
