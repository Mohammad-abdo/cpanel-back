import { Router } from 'express';
import { validate } from '../../common/middleware/validate.js';
import { requireSession } from '../../common/middleware/require-session.js';
import {
  artifactIdParamsSchema,
  createPolicyBodySchema,
  listPoliciesQuerySchema,
  listRunsQuerySchema,
  policyIdParamsSchema,
  retentionBodySchema,
  runBackupBodySchema,
} from './backups.validator.js';
import { createBackupsController } from './backups.controller.js';
import { createBackupsService } from './backups.service.js';
import { getDeps } from '../platform/platform.wiring.js';
import { wrap } from '../platform/platform.http.js';
import { serverAccessService } from '../server-access/server-access.routes.js';

const c = createBackupsController(createBackupsService({ ...getDeps(), serverAccessService }));
const write = requireSession({ requireMfa: true });

/** Mount at /backups */
export const backupsRouter = Router();

backupsRouter.get('/policies', requireSession(), validate(listPoliciesQuerySchema, 'query'), wrap(c.listPolicies));
backupsRouter.post('/policies', write, validate(createPolicyBodySchema, 'body'), wrap(c.createPolicy));
backupsRouter.get('/policies/:id/rpo', requireSession(), validate(policyIdParamsSchema, 'params'), wrap(c.rpoStatus));
backupsRouter.get('/policies/:id/destination', requireSession(), validate(policyIdParamsSchema, 'params'), wrap(c.destinationStatus));
backupsRouter.post('/policies/:id/run', write, validate(policyIdParamsSchema, 'params'), validate(runBackupBodySchema, 'body'), wrap(c.run));
backupsRouter.get('/policies/:id/retention', requireSession(), validate(policyIdParamsSchema, 'params'), wrap(c.planRetention));
backupsRouter.post('/policies/:id/retention', write, validate(policyIdParamsSchema, 'params'), validate(retentionBodySchema, 'body'), wrap(c.applyRetention));
backupsRouter.get('/runs', requireSession(), validate(listRunsQuerySchema, 'query'), wrap(c.listRuns));
backupsRouter.post('/artifacts/:id/verify', write, validate(artifactIdParamsSchema, 'params'), wrap(c.verifyArtifact));
