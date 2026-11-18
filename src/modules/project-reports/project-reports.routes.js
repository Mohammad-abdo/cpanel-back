import { Router } from 'express';
import { validate } from '../../common/middleware/validate.js';
import { requireSession } from '../../common/middleware/require-session.js';
import { prisma } from '../../config/prisma.js';
import { createProjectReportsController } from './project-reports.controller.js';
import { createProjectReportsService } from './project-reports.service.js';
import { projectReportExportQuerySchema, projectReportParamsSchema, projectReportQuerySchema } from './project-reports.validator.js';

export const projectReportsService = createProjectReportsService({ prisma });
const c = createProjectReportsController(projectReportsService);
const wrap = (fn) => (req, res, next) => fn(req, res).catch(next);
const params = validate(projectReportParamsSchema, 'params');

/** Mounted at /projects. Reads are scope-aware (404 outside scope); export requires MFA like other exports. */
export const projectReportsRouter = Router();
projectReportsRouter.get('/:id/report', requireSession(), params, validate(projectReportQuerySchema, 'query'), wrap(c.report));
projectReportsRouter.get('/:id/report/export', requireSession({ requireMfa: true }), params, validate(projectReportExportQuerySchema, 'query'), wrap(c.export));
