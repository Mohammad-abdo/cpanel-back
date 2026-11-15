import { Router } from 'express';
import { validate } from '../../common/middleware/validate.js';
import { requireSession } from '../../common/middleware/require-session.js';
import {
  errorGroupIdParamsSchema,
  fleetQuerySchema,
  listErrorsQuerySchema,
  serverMetricsParamsSchema,
  serverMetricsQuerySchema,
} from './monitoring.validator.js';
import { createMonitoringController } from './monitoring.controller.js';
import { createMonitoringService } from './monitoring.service.js';
import { createErrorsService } from './monitoring.errors.js';
import { alertsRouter } from './monitoring.alerts.routes.js';
import { prisma } from '../../config/prisma.js';
import { createAuditService } from '../audit/audit.service.js';

const auditService = createAuditService({ prisma });
const monitoringService = createMonitoringService({ prisma });
const errorsService = createErrorsService({ prisma, auditService });
const monitoringController = createMonitoringController(monitoringService, errorsService);

export const monitoringRouter = Router();

/** Alert rules, lifecycle and deployment error comparison (TASK-013). */
monitoringRouter.use(alertsRouter);

monitoringRouter.get(
  '/servers/:id/health',
  requireSession(),
  validate(serverMetricsParamsSchema, 'params'),
  validate(serverMetricsQuerySchema, 'query'),
  (req, res, next) => {
    monitoringController.serverHealth(req, res).catch(next);
  },
);

monitoringRouter.get('/fleet', requireSession(), validate(fleetQuerySchema, 'query'), (req, res, next) => {
  monitoringController.fleet(req, res).catch(next);
});

monitoringRouter.get('/errors', requireSession(), validate(listErrorsQuerySchema, 'query'), (req, res, next) => {
  monitoringController.listErrors(req, res).catch(next);
});

monitoringRouter.get(
  '/errors/:id',
  requireSession(),
  validate(errorGroupIdParamsSchema, 'params'),
  (req, res, next) => {
    monitoringController.getError(req, res).catch(next);
  },
);
