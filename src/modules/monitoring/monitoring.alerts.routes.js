import { Router } from 'express';
import { validate } from '../../common/middleware/validate.js';
import { requireSession } from '../../common/middleware/require-session.js';
import {
  alertIdParamsSchema,
  compareParamsSchema,
  compareQuerySchema,
  createRuleBodySchema,
  listAlertsQuerySchema,
  listRulesQuerySchema,
  noteBodySchema,
  ruleIdParamsSchema,
} from './monitoring.alerts.validator.js';
import { createAlertsController } from './monitoring.alerts.controller.js';
import { createAlertsService } from './monitoring.alerts.js';
import { createComparisonService } from './monitoring.compare.js';
import { prisma } from '../../config/prisma.js';
import { createAuditService } from '../audit/audit.service.js';
import { logsService } from '../logs/logs.routes.js';

const auditService = createAuditService({ prisma });
const alertsService = createAlertsService({ prisma, auditService, store: logsService.store });
const comparisonService = createComparisonService({ prisma, store: logsService.store });
const c = createAlertsController(alertsService, comparisonService);
const mfa = requireSession({ requireMfa: true });
const wrap = (fn) => (req, res, next) => fn(req, res).catch(next);

export { alertsService };

/** Mount at /monitoring (paths: /rules, /alerts, /deployments/:id/error-comparison). */
export const alertsRouter = Router();

alertsRouter.get('/rules', requireSession(), validate(listRulesQuerySchema, 'query'), wrap(c.listRules));
alertsRouter.post('/rules', mfa, validate(createRuleBodySchema, 'body'), wrap(c.createRule));
alertsRouter.post(
  '/rules/:id/evaluate',
  mfa,
  validate(ruleIdParamsSchema, 'params'),
  validate(listRulesQuerySchema, 'query'),
  wrap(c.evaluateRule),
);
alertsRouter.get('/alerts', requireSession(), validate(listAlertsQuerySchema, 'query'), wrap(c.listAlerts));
alertsRouter.post('/alerts/:id/ack', mfa, validate(alertIdParamsSchema, 'params'), validate(noteBodySchema, 'body'), wrap(c.acknowledge));
alertsRouter.post('/alerts/:id/resolve', mfa, validate(alertIdParamsSchema, 'params'), validate(noteBodySchema, 'body'), wrap(c.resolve));
alertsRouter.get(
  '/deployments/:id/error-comparison',
  requireSession(),
  validate(compareParamsSchema, 'params'),
  validate(compareQuerySchema, 'query'),
  wrap(c.compare),
);
