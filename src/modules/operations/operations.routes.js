import { Router } from 'express';
import { validate } from '../../common/middleware/validate.js';
import { requireSession } from '../../common/middleware/require-session.js';
import {
  decisionBodySchema,
  enqueueBodySchema,
  listApprovalsQuerySchema,
  operationIdParamsSchema,
} from './operations.validator.js';
import { createOperationsController } from './operations.controller.js';
import { createOperationsService } from './operations.service.js';
import { prisma } from '../../config/prisma.js';
import { createAuditService } from '../audit/audit.service.js';
import { createDeploymentExecutor } from '../deployments/deployments.executor.js';
import { resolveDeploymentAdapters } from '../deployments/deployments.ssh-runner.js';
import { githubService } from '../github/github.routes.js';

const operationsService = createOperationsService({
  prisma,
  auditService: createAuditService({ prisma }),
  // DEPLOY_EXECUTOR=simulated (default) | ssh. ssh runs real git/build/pm2 over SSH and is NOT_RUN in this repo.
  executor: createDeploymentExecutor({ prisma, ...resolveDeploymentAdapters({ prisma, cloneCredential: (url, opts) => githubService.cloneCredential(url, opts) }) }),
});
const c = createOperationsController(operationsService);
const mfa = requireSession({ requireMfa: true });
const wrap = (fn) => (req, res, next) => fn(req, res).catch(next);

export { operationsService };
export const operationsRouter = Router();

operationsRouter.post('/', mfa, validate(enqueueBodySchema, 'body'), wrap(c.enqueue));
operationsRouter.get('/approvals', requireSession(), validate(listApprovalsQuerySchema, 'query'), wrap(c.listApprovals));
operationsRouter.get('/:id', requireSession(), validate(operationIdParamsSchema, 'params'), wrap(c.get));
operationsRouter.get('/:id/impact', requireSession(), validate(operationIdParamsSchema, 'params'), wrap(c.impact));
operationsRouter.post('/:id/cancel', mfa, validate(operationIdParamsSchema, 'params'), wrap(c.cancel));
operationsRouter.post(
  '/:id/approve',
  mfa,
  validate(operationIdParamsSchema, 'params'),
  validate(decisionBodySchema, 'body'),
  wrap(c.approve),
);
operationsRouter.post(
  '/:id/deny',
  mfa,
  validate(operationIdParamsSchema, 'params'),
  validate(decisionBodySchema, 'body'),
  wrap(c.deny),
);
operationsRouter.post('/:id/execute', mfa, validate(operationIdParamsSchema, 'params'), wrap(c.execute));
