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

/** Routes that parse their own larger bodies: server file editor/upload, project env vars bulk set/import. */
const LARGE_BODY_ROUTE = /^\/api\/v1\/(servers\/[^/]+\/files\/(content|upload)|projects\/[^/]+\/environments\/[^/]+\/vars(\/import)?)$/;

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
  // 64 KB JSON everywhere except the two file routes, which parse their own larger bodies.
  const json = express.json({ limit: '64kb' });
  app.use((req, res, next) => (LARGE_BODY_ROUTE.test(req.path) ? next() : json(req, res, next)));
  app.use('/api/v1', apiRouter);
  app.use(notFound);
  app.use(errorHandler);
  return app;
}
