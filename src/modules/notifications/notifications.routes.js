import { Router } from 'express';
import { validate } from '../../common/middleware/validate.js';
import { requireSession } from '../../common/middleware/require-session.js';
import {
  emptyBodySchema,
  listNotificationsQuerySchema,
  notificationIdParamsSchema,
  updatePreferencesBodySchema,
} from './notifications.validator.js';
import { createNotificationsController } from './notifications.controller.js';
import { createNotificationsService } from './notifications.service.js';
import { prisma } from '../../config/prisma.js';

const c = createNotificationsController(createNotificationsService({ prisma }));
const wrap = (fn) => (req, res, next) => fn(req, res).catch(next);

/** Mount at /notifications. Every endpoint is scoped to the calling user. */
export const notificationsRouter = Router();

notificationsRouter.get('/', requireSession(), validate(listNotificationsQuerySchema, 'query'), wrap(c.list));
notificationsRouter.get('/preferences', requireSession(), wrap(c.getPreferences));
notificationsRouter.put('/preferences', requireSession(), validate(updatePreferencesBodySchema, 'body'), wrap(c.updatePreferences));
notificationsRouter.post('/read-all', requireSession(), validate(emptyBodySchema, 'body'), wrap(c.markAllRead));
notificationsRouter.post(
  '/:id/read',
  requireSession(),
  validate(notificationIdParamsSchema, 'params'),
  validate(emptyBodySchema, 'body'),
  wrap(c.markRead),
);
