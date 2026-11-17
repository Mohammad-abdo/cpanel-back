import express, { Router } from 'express';
import { validate } from '../../common/middleware/validate.js';
import { rateLimit } from '../../common/middleware/rate-limit.js';
import { requireSession } from '../../common/middleware/require-session.js';
import { prisma } from '../../config/prisma.js';
import { createAuditService } from '../audit/audit.service.js';
import { getDeps } from '../platform/platform.wiring.js';
import { createDeploymentsService } from '../deployments/deployments.service.js';
import { operationsService } from '../operations/operations.routes.js';
import { createWebhooksController } from './webhooks.controller.js';
import { createWebhooksService } from './webhooks.service.js';
import { hookParamsSchema, hookTokenParamsSchema, createHookBodySchema, projectIdParamsSchema, triggerHookBodySchema, updateSettingsBodySchema } from './webhooks.validator.js';
import { hashHookToken } from './webhooks.crypto.js';

const auditService = createAuditService({ prisma });
const deploymentsService = createDeploymentsService({ prisma, auditService, operationsService });
const svc = createWebhooksService({ prisma, auditService, deploymentsService, platform: getDeps().platform });
const c = createWebhooksController(svc);
const mfa = requireSession({ requireMfa: true });
const wrap = (fn) => (req, res, next) => fn(req, res).catch(next);
const ip = (req) => req.ip || req.socket?.remoteAddress || 'unknown';

/** Per-process limits (see rate-limit.js). GitHub delivers bursts, so its ceiling is higher than the hook ceiling. */
export const githubLimiters = [ rateLimit({ windowMs: 60_000, max: 120, keyFn: (req) => `gh:${ip(req)}` })];
export const hookLimiters = [
  rateLimit({ windowMs: 60_000, max: 30, keyFn: (req) => `hook:ip:${ip(req)}` }),
  rateLimit({ windowMs: 60_000, max: 6, keyFn: (req) => `hook:tok:${hashHookToken(req.params.token ?? '')}` }),
];

const rawBody = express.raw({ type: () => true, limit: '1mb' });
const jsonBody = express.json({ limit: '4kb' });

/** Public, unauthenticated: mounted at /webhooks. Authentication is the HMAC signature or the hook token. */
export const webhooksRouter = Router();
webhooksRouter.post('/github', ...githubLimiters, rawBody, wrap(c.github));
webhooksRouter.post('/deploy/:token', ...hookLimiters, validate(hookTokenParamsSchema, 'params'), jsonBody, validate(triggerHookBodySchema, 'body'), wrap(c.trigger));

/** Owner-managed: mounted at /projects. */
const params = validate(projectIdParamsSchema, 'params');
const hookParams = validate(hookParamsSchema, 'params');
export const deploySettingsRouter = Router();
deploySettingsRouter.get('/:id/deploy-settings', requireSession(), params, wrap(c.getSettings));
deploySettingsRouter.put('/:id/deploy-settings', mfa, params, validate(updateSettingsBodySchema, 'body'), wrap(c.updateSettings));
deploySettingsRouter.get('/:id/deploy-hooks', mfa, params, wrap(c.listHooks));
deploySettingsRouter.post('/:id/deploy-hooks', mfa, params, validate(createHookBodySchema, 'body'), wrap(c.createHook));
deploySettingsRouter.post('/:id/deploy-hooks/:hookId/rotate', mfa, hookParams, wrap(c.rotateHook));
deploySettingsRouter.delete('/:id/deploy-hooks/:hookId', mfa, hookParams, wrap(c.revokeHook));
