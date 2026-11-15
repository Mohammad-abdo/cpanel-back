import { Router } from 'express';
import { validate } from '../../common/middleware/validate.js';
import { requireSession } from '../../common/middleware/require-session.js';
import {
  createDefinitionBodySchema,
  createRunBodySchema,
  createScheduleBodySchema,
  idParamsSchema,
  listReportsQuerySchema,
  previewQuerySchema,
  scheduleEnabledBodySchema,
} from './reports.validator.js';
import { createReportsController } from './reports.controller.js';
import { createReportsService } from './reports.service.js';
import { prisma } from '../../config/prisma.js';
import { createAuditService } from '../audit/audit.service.js';

const reportsService = createReportsService({ prisma, auditService: createAuditService({ prisma }) });
const c = createReportsController(reportsService);
const mfa = requireSession({ requireMfa: true });
const wrap = (fn) => (req, res, next) => fn(req, res).catch(next);
const params = validate(idParamsSchema, 'params');

export { reportsService };
export const reportsRouter = Router();

reportsRouter.get('/', requireSession(), validate(listReportsQuerySchema, 'query'), wrap(c.listDefinitions));
reportsRouter.get('/definitions', requireSession(), validate(listReportsQuerySchema, 'query'), wrap(c.listDefinitions));
reportsRouter.post('/definitions', mfa, validate(createDefinitionBodySchema, 'body'), wrap(c.createDefinition));
reportsRouter.get('/preview', requireSession(), validate(previewQuerySchema, 'query'), wrap(c.preview));
reportsRouter.post('/runs', mfa, validate(createRunBodySchema, 'body'), wrap(c.createRun));
reportsRouter.get('/runs/:id', requireSession(), params, wrap(c.getRun));
reportsRouter.get('/artifacts/:id/download', mfa, params, wrap(c.download));
reportsRouter.get('/schedules', requireSession(), wrap(c.listSchedules));
reportsRouter.post('/schedules', mfa, validate(createScheduleBodySchema, 'body'), wrap(c.createSchedule));
reportsRouter.patch('/schedules/:id', mfa, params, validate(scheduleEnabledBodySchema, 'body'), wrap(c.setScheduleEnabled));
