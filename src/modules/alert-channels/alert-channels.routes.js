import { Router } from 'express';
import { validate } from '../../common/middleware/validate.js';
import { requireSession } from '../../common/middleware/require-session.js';
import { rateLimit } from '../../common/middleware/rate-limit.js';
import { getDeps } from '../platform/platform.wiring.js';
import { createAlertChannelsController } from './alert-channels.controller.js';
import { createAlertChannelsService } from './alert-channels.service.js';
import {
  channelIdParamsSchema,
  createChannelBodySchema,
  deliveriesQuerySchema,
  emptyBodySchema,
  updateChannelBodySchema,
} from './alert-channels.validator.js';

const deps = getDeps();
export const alertChannelsService = createAlertChannelsService({ prisma: deps.prisma, rbac: deps.rbac, auditService: deps.auditService });
const c = createAlertChannelsController(alertChannelsService);
const read = requireSession();
const write = requireSession({ requireMfa: true });
const wrap = (fn) => (req, res, next) => fn(req, res).catch(next);
const params = validate(channelIdParamsSchema, 'params');
const testLimiter = rateLimit({ windowMs: 60_000, max: 10, keyFn: (req) => `alert-channel-test:${req.user?.id ?? req.ip}` });

/** Mount at /notification-channels. RBAC (Owner or notifications.manage) is enforced in the service. */
export const alertChannelsRouter = Router();
alertChannelsRouter.get('/', read, wrap(c.list));
alertChannelsRouter.post('/', write, validate(createChannelBodySchema, 'body'), wrap(c.create));
alertChannelsRouter.get('/:id', read, params, wrap(c.get));
alertChannelsRouter.patch('/:id', write, params, validate(updateChannelBodySchema, 'body'), wrap(c.update));
alertChannelsRouter.delete('/:id', write, params, wrap(c.remove));
alertChannelsRouter.post('/:id/test', write, testLimiter, params, validate(emptyBodySchema, 'body'), wrap(c.test));
alertChannelsRouter.get('/:id/deliveries', read, params, validate(deliveriesQuerySchema, 'query'), wrap(c.deliveries));
