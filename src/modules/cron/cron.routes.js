import { Router } from 'express';
import { validate } from '../../common/middleware/validate.js';
import { requireSession } from '../../common/middleware/require-session.js';
import { prisma } from '../../config/prisma.js';
import { getDeps } from '../platform/platform.wiring.js';
import { wrap } from '../platform/platform.http.js';
import { serverAccessService } from '../server-access/server-access.routes.js';
import { createCronController } from './cron.controller.js';
import { createCronService } from './cron.service.js';
import { createBodySchema, jobParamsSchema, previewBodySchema, projectParamsSchema, runBodySchema, runsQuerySchema, updateBodySchema } from './cron.validator.js';

const deps = getDeps();
export const cronService = createCronService({ ...deps, prisma, serverAccessService });
const c = createCronController(cronService);
const write = requireSession({ requireMfa: true });
const project = validate(projectParamsSchema, 'params');
const job = validate(jobParamsSchema, 'params');

/** Mount at /projects (paths are /:projectId/cron-jobs...). */
export const cronRouter = Router();
cronRouter.get('/cron-commands', requireSession(), wrap(c.commands));
cronRouter.post('/cron-schedule/preview', requireSession(), validate(previewBodySchema, 'body'), wrap(c.preview));
cronRouter.get('/:projectId/cron-jobs', requireSession(), project, wrap(c.list));
cronRouter.post('/:projectId/cron-jobs', write, project, validate(createBodySchema, 'body'), wrap(c.create));
cronRouter.patch('/:projectId/cron-jobs/:jobId', write, job, validate(updateBodySchema, 'body'), wrap(c.update));
cronRouter.delete('/:projectId/cron-jobs/:jobId', write, job, wrap(c.remove));
cronRouter.post('/:projectId/cron-jobs/:jobId/run', write, job, validate(runBodySchema, 'body'), wrap(c.run));
cronRouter.get('/:projectId/cron-jobs/:jobId/runs', requireSession(), job, validate(runsQuerySchema, 'query'), wrap(c.runs));
