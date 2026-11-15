import express from 'express';
import helmet from 'helmet';
import { randomUUID } from 'node:crypto';
import { apiRouter } from './routes.js';
import { errorHandler, notFound } from './common/middleware/error-handler.js';

/** Prisma BigInt columns (e.g. BackupArtifact.sizeBytes) are not JSON-serializable by default. */
export function jsonReplacer(_key, value) {
  if (typeof value !== 'bigint') return value;
  return value <= BigInt(Number.MAX_SAFE_INTEGER) && value >= BigInt(Number.MIN_SAFE_INTEGER) ? Number(value) : value.toString();
}

export function createApp() {
  const app = express();
  app.set('json replacer', jsonReplacer);
  app.disable('x-powered-by');
  app.use(helmet());
  app.use((req, res, next) => {
    req.requestId = randomUUID();
    res.set('X-Request-Id', req.requestId);
    next();
  });
  app.use(express.json({ limit: '64kb' }));
  app.use('/api/v1', apiRouter);
  app.use(notFound);
  app.use(errorHandler);
  return app;
}
