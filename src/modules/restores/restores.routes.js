import { Router } from 'express';
import { validate } from '../../common/middleware/validate.js';
import { requireSession } from '../../common/middleware/require-session.js';
import { executeRestoreBodySchema, listRestorePointsQuerySchema, requestRestoreBodySchema, restoreIdParamsSchema } from './restores.validator.js';
import { createRestoresController } from './restores.controller.js';
import { createRestoresService } from './restores.service.js';
import { createBackupsService } from '../backups/backups.service.js';
import { getDeps } from '../platform/platform.wiring.js';
import { wrap } from '../platform/platform.http.js';
import { serverAccessService } from '../server-access/server-access.routes.js';

const deps = getDeps();
const c = createRestoresController(
  createRestoresService({ ...deps, backups: createBackupsService({ ...deps, serverAccessService }) }),
);
const write = requireSession({ requireMfa: true });

/** Mount at /restores */
export const restoresRouter = Router();

restoresRouter.get('/points', requireSession(), validate(listRestorePointsQuerySchema, 'query'), wrap(c.points));
restoresRouter.post('/', write, validate(requestRestoreBodySchema, 'body'), wrap(c.request));
restoresRouter.get('/:id', requireSession(), validate(restoreIdParamsSchema, 'params'), wrap(c.get));
restoresRouter.post('/:id/execute', write, validate(restoreIdParamsSchema, 'params'), validate(executeRestoreBodySchema, 'body'), wrap(c.execute));
