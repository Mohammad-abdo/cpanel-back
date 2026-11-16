import { Router } from 'express';
import { rateLimit } from '../../common/middleware/rate-limit.js';
import { validate } from '../../common/middleware/validate.js';
import { requireWebmailSession, wrap } from '../webmail-mail/webmail-session.js';
import { createWebmailAuthController } from './webmail-auth.controller.js';
import { webmailLoginBodySchema } from './webmail-auth.validator.js';
import { webmailAuthService } from './webmail-auth.wiring.js';

const ip = (req) => req.ip || req.socket?.remoteAddress || 'unknown';
const loginLimiters = [
  rateLimit({ windowMs: 15 * 60_000, max: 40, keyFn: (req) => `wm:login:ip:${ip(req)}` }),
  rateLimit({
    windowMs: 15 * 60_000,
    max: 8,
    keyFn: (req) => `wm:login:${ip(req)}:${String(req.body?.address ?? '').toLowerCase()}`,
    code: 'WEBMAIL_LOGIN_RATE',
  }),
];

const controller = createWebmailAuthController(webmailAuthService);

export const webmailAuthRouter = Router();
export { webmailAuthService };

webmailAuthRouter.post('/login', ...loginLimiters, validate(webmailLoginBodySchema), wrap(controller.login));
webmailAuthRouter.post('/logout', requireWebmailSession(webmailAuthService, { optional: true }), wrap(controller.logout));
webmailAuthRouter.get('/me', requireWebmailSession(webmailAuthService), wrap(controller.me));
