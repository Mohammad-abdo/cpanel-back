import { Router } from 'express';
import { validate } from '../../common/middleware/validate.js';
import { requireSession } from '../../common/middleware/require-session.js';
import { grantBodySchema, grantIdParamsSchema, listGrantsQuerySchema } from './rbac.validator.js';
import { createRbacController } from './rbac.controller.js';
import { createRbacService } from './rbac.service.js';
import { prisma } from '../../config/prisma.js';
import { createAuditService } from '../audit/audit.service.js';

const rbacService = createRbacService({ prisma, auditService: createAuditService({ prisma }) });
const rbacController = createRbacController(rbacService);

export const rbacRouter = Router();

rbacRouter.post('/grants', requireSession({ requireMfa: true }), validate(grantBodySchema, 'body'), (req, res, next) => {
  rbacController.grant(req, res).catch(next);
});

rbacRouter.delete('/grants/:id', requireSession({ requireMfa: true }), validate(grantIdParamsSchema, 'params'), (req, res, next) => {
  rbacController.revoke(req, res).catch(next);
});

rbacRouter.get('/grants', requireSession(), validate(listGrantsQuerySchema, 'query'), (req, res, next) => {
  rbacController.list(req, res).catch(next);
});
