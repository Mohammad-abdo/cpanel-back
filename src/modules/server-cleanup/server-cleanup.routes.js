import { Router } from 'express';
import { validate } from '../../common/middleware/validate.js';
import { requireSession } from '../../common/middleware/require-session.js';
import { prisma } from '../../config/prisma.js';
import { getDeps } from '../platform/platform.wiring.js';
import { wrap } from '../platform/platform.http.js';
import { serverAccessService } from '../server-access/server-access.routes.js';
import { createServerCleanupController } from './server-cleanup.controller.js';
import { createServerCleanupService } from './server-cleanup.service.js';
import { applyBodySchema, previewBodySchema, serverParamsSchema } from './server-cleanup.validator.js';

const deps = getDeps();
const c = createServerCleanupController(createServerCleanupService({ ...deps, prisma, serverAccessService }));
const owner = requireSession({ requireMfa: true });
const params = validate(serverParamsSchema, 'params');

/** Mount at /servers (paths are /:serverId/cleanup...). Owner only; apply is approval gated. */
export const serverCleanupRouter = Router();
serverCleanupRouter.get('/:serverId/cleanup/tasks', owner, params, wrap(c.tasks));
serverCleanupRouter.post('/:serverId/cleanup/preview', owner, params, validate(previewBodySchema, 'body'), wrap(c.preview));
serverCleanupRouter.post('/:serverId/cleanup/apply', owner, params, validate(applyBodySchema, 'body'), wrap(c.apply));
