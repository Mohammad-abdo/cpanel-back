import { Router } from 'express';
import { validate } from '../../common/middleware/validate.js';
import { requireSession } from '../../common/middleware/require-session.js';
import { listAuditQuerySchema } from './audit.validator.js';
import { createAuditController } from './audit.controller.js';
import { createAuditService } from './audit.service.js';
import { createRbacService } from '../rbac/rbac.service.js';
import { prisma } from '../../config/prisma.js';

const auditService = createAuditService({ prisma, rbac: createRbacService({ prisma }) });
const auditController = createAuditController(auditService);

export const auditRouter = Router();

auditRouter.get('/events', requireSession(), validate(listAuditQuerySchema, 'query'), (req, res, next) => {
  auditController.list(req, res).catch(next);
});
