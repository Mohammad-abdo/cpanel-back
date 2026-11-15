import { Router } from 'express';
import { validate } from '../../common/middleware/validate.js';
import { requireSession } from '../../common/middleware/require-session.js';
import { myTimelineQuerySchema, projectTimelineQuerySchema } from './activity.validator.js';
import { createActivityController } from './activity.controller.js';
import { createActivityService } from './activity.service.js';
import { prisma } from '../../config/prisma.js';

const c = createActivityController(createActivityService({ prisma }));

/** Mount at /activity. */
export const activityRouter = Router();

activityRouter.get('/me', requireSession(), validate(myTimelineQuerySchema, 'query'), (req, res, next) => {
  c.myTimeline(req, res).catch(next);
});

activityRouter.get('/project-timeline', requireSession(), validate(projectTimelineQuerySchema, 'query'), (req, res, next) => {
  c.projectTimeline(req, res).catch(next);
});
