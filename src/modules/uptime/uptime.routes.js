import { Router } from 'express';
import { validate } from '../../common/middleware/validate.js';
import { requireSession } from '../../common/middleware/require-session.js';
import { getDeps } from '../platform/platform.wiring.js';
import { wrap } from '../platform/platform.http.js';
import { createUptimeController } from './uptime.controller.js';
import { createUptimeService } from './uptime.service.js';
import {
  createUptimeBodySchema,
  emptyBodySchema,
  listUptimeQuerySchema,
  updateUptimeBodySchema,
  uptimeIdParamsSchema,
} from './uptime.validator.js';

const deps = getDeps();
export const uptimeService = createUptimeService({ prisma: deps.prisma });
const c = createUptimeController(uptimeService);
const read = requireSession();
const write = requireSession({ requireMfa: true });

/** Mount at /uptime. List/get for any authenticated session; writes require MFA. */
export const uptimeRouter = Router();
uptimeRouter.get('/', read, validate(listUptimeQuerySchema, 'query'), wrap(c.list));
uptimeRouter.post('/', write, validate(createUptimeBodySchema, 'body'), wrap(c.create));
uptimeRouter.get('/:id', read, validate(uptimeIdParamsSchema, 'params'), wrap(c.get));
uptimeRouter.patch('/:id', write, validate(uptimeIdParamsSchema, 'params'), validate(updateUptimeBodySchema, 'body'), wrap(c.update));
uptimeRouter.delete('/:id', write, validate(uptimeIdParamsSchema, 'params'), wrap(c.remove));
uptimeRouter.post('/:id/check', write, validate(uptimeIdParamsSchema, 'params'), validate(emptyBodySchema, 'body'), wrap(c.checkNow));