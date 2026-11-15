import { Router } from 'express';
import { validate } from '../../common/middleware/validate.js';
import { requireSession } from '../../common/middleware/require-session.js';
import {
  createDeploymentBodySchema,
  deploymentIdParamsSchema,
  listDeploymentsQuerySchema,
  rollbackBodySchema,
} from './deployments.validator.js';
import { createDeploymentsController } from './deployments.controller.js';
import { createDeploymentsService } from './deployments.service.js';
import { prisma } from '../../config/prisma.js';
import { createAuditService } from '../audit/audit.service.js';
import { operationsService } from '../operations/operations.routes.js';

const c = createDeploymentsController(
  createDeploymentsService({ prisma, auditService: createAuditService({ prisma }), operationsService }),
);
const mfa = requireSession({ requireMfa: true });
const wrap = (fn) => (req, res, next) => fn(req, res).catch(next);
const params = validate(deploymentIdParamsSchema, 'params');

export const deploymentsRouter = Router();

deploymentsRouter.get('/', requireSession(), validate(listDeploymentsQuerySchema, 'query'), wrap(c.list));
deploymentsRouter.post('/', mfa, validate(createDeploymentBodySchema, 'body'), wrap(c.create));
deploymentsRouter.get('/:id', requireSession(), params, wrap(c.get));
deploymentsRouter.post('/:id/run', mfa, params, wrap(c.run));
deploymentsRouter.post('/:id/rollback', mfa, params, validate(rollbackBodySchema, 'body'), wrap(c.rollback));
