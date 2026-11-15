import { Router } from 'express';
import { validate } from '../../common/middleware/validate.js';
import { requireSession } from '../../common/middleware/require-session.js';
import { agentIdParamsSchema, enrollBodySchema, reportBodySchema } from './agents.validator.js';
import { createAgentsController } from './agents.controller.js';
import { createAgentsService } from './agents.service.js';
import { prisma } from '../../config/prisma.js';
import { createAuditService } from '../audit/audit.service.js';
import { enrollLimiters } from '../../common/middleware/rate-limit.js';

const agentsService = createAgentsService({ prisma, auditService: createAuditService({ prisma }) });
const agentsController = createAgentsController(agentsService);

function requireAgent(req, _res, next) {
  agentsService
    .authenticate(req.get('authorization'))
    .then((agent) => {
      req.agent = agent;
      next();
    })
    .catch(next);
}

export const agentsRouter = Router();

agentsRouter.post('/enroll', ...enrollLimiters, validate(enrollBodySchema, 'body'), (req, res, next) => {
  agentsController.enroll(req, res).catch(next);
});

agentsRouter.post('/report', requireAgent, validate(reportBodySchema, 'body'), (req, res, next) => {
  agentsController.report(req, res).catch(next);
});

agentsRouter.delete(
  '/:id',
  requireSession({ requireMfa: true }),
  validate(agentIdParamsSchema, 'params'),
  (req, res, next) => {
    agentsController.revoke(req, res).catch(next);
  },
);
