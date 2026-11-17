import { Router } from 'express';
import { validate } from '../../common/middleware/validate.js';
import { requireSession } from '../../common/middleware/require-session.js';
import { prisma } from '../../config/prisma.js';
import { wrap } from '../platform/platform.http.js';
import { serverAccessService } from '../server-access/server-access.routes.js';
import { createServerWebsitesController } from './server-websites.controller.js';
import { createServerWebsitesService } from './server-websites.service.js';
import { serverIdParamsSchema } from './server-websites.validator.js';

const svc = createServerWebsitesService({ prisma, serverAccessService });
const c = createServerWebsitesController(svc);
const owner = requireSession({ requireMfa: true });

/** Mount under /servers → GET /servers/:serverId/websites */
export const serverWebsitesRouter = Router({ mergeParams: true });
serverWebsitesRouter.get('/:serverId/websites', owner, validate(serverIdParamsSchema, 'params'), wrap(c.list));
