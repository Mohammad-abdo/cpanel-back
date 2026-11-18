import { Router } from 'express';
import { validate } from '../../common/middleware/validate.js';
import { requireSession } from '../../common/middleware/require-session.js';
import { createProjectReportsController } from './project-reports.controller.js';
import { projectsOverviewQuerySchema } from './project-reports.validator.js';
import { projectReportsService } from './project-reports.routes.js';

const c = createProjectReportsController(projectReportsService);
const wrap = (fn) => (req, res, next) => fn(req, res).catch(next);

/** Mounted at /reports before the generic reports router. */
export const projectReportsFleetRouter = Router();
projectReportsFleetRouter.get('/projects-overview', requireSession(), validate(projectsOverviewQuerySchema, 'query'), wrap(c.overview));
