import express from 'express';
import helmet from 'helmet';
import { randomUUID } from 'node:crypto';
import { existsSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { errorHandler, notFound } from './common/middleware/error-handler.js';
import { webmailAuthRouter } from './modules/webmail-auth/webmail-auth.routes.js';
import { webmailMailRouter } from './modules/webmail-mail/webmail-mail.routes.js';
import { jsonReplacer } from './app.js';

const here = dirname(fileURLToPath(import.meta.url));
const spaDir = join(here, '../../webmail/dist');

/**
 * Separate Express app for TASK-037 webmail (:2096).
 * Mounts only /wm/v1 — never /api/v1 Owner routes.
 */
export function createWebmailApp() {
  const app = express();
  app.set('json replacer', jsonReplacer);
  app.disable('x-powered-by');
  app.use(
    helmet({
      contentSecurityPolicy: {
        directives: {
          defaultSrc: ["'self'"],
          scriptSrc: ["'self'"],
          styleSrc: ["'self'", "'unsafe-inline'"],
          imgSrc: ["'self'", 'data:', 'blob:'],
          connectSrc: ["'self'"],
          fontSrc: ["'self'", 'data:'],
          objectSrc: ["'none'"],
          frameAncestors: ["'none'"],
          baseUri: ["'self'"],
          formAction: ["'self'"],
        },
      },
      crossOriginEmbedderPolicy: false,
    }),
  );
  app.use((req, res, next) => {
    req.requestId = randomUUID();
    res.set('X-Request-Id', req.requestId);
    res.set('X-Content-Type-Options', 'nosniff');
    next();
  });
  app.use(express.json({ limit: '2mb' }));

  app.get('/wm/v1/health', (_req, res) => {
    res.status(200).json({ data: { ok: true, service: 'webmail' } });
  });

  app.use('/wm/v1/auth', webmailAuthRouter);
  app.use('/wm/v1/mail', webmailMailRouter);

  if (existsSync(spaDir)) {
    app.use(express.static(spaDir, { index: false, maxAge: '1h' }));
    app.get(/^(?!\/wm\/).*/, (_req, res) => {
      res.sendFile(join(spaDir, 'index.html'));
    });
  } else {
    app.get('/', (_req, res) => {
      res.status(200).type('html').send(`<!doctype html><html><body style="font-family:system-ui;background:#0B1220;color:#e8eef7;padding:2rem">
<h1>NodeTeam Webmail</h1>
<p>API is up on <code>/wm/v1</code>. Build the SPA with <code>npm run build:webmail</code> or run <code>npm run dev:webmail</code> (Vite :5196).</p>
</body></html>`);
    });
  }

  app.use(notFound);
  app.use(errorHandler);
  return app;
}
