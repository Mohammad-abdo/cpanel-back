import express from 'express';
import helmet from 'helmet';
import { randomUUID } from 'node:crypto';
import { apiRouter } from './routes.js';
import { errorHandler, notFound } from './common/middleware/error-handler.js';
export function createApp() {
  const app = express();
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
