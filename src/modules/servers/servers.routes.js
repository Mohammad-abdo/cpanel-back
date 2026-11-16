import { Router } from 'express';
import { validate } from '../../common/middleware/validate.js';
import { requireSession } from '../../common/middleware/require-session.js';
import {
  archiveServerBodySchema,
  createServerBodySchema,
  fleetReadQuerySchema,
  listServersQuerySchema,
  metricsQuerySchema,
  runtimesQuerySchema,
  serverIdParamsSchema,
  updateServerBodySchema,
} from './servers.validator.js';
import { createServersController } from './servers.controller.js';
import { createServersService } from './servers.service.js';
import { prisma } from '../../config/prisma.js';
import { createAuditService } from '../audit/audit.service.js';

const serversService = createServersService({ prisma, auditService: createAuditService({ prisma }) });
const serversController = createServersController(serversService);

export const serversRouter = Router();

serversRouter.get('/', requireSession(), validate(listServersQuerySchema, 'query'), (req, res, next) => {
  serversController.list(req, res).catch(next);
});

// Fleet-wide read endpoints. Registered before '/:id' so the literal paths win.
serversRouter.get('/services', requireSession(), validate(fleetReadQuerySchema, 'query'), (req, res, next) => {
  serversController.services(req, res).catch(next);
});
serversRouter.get('/ports', requireSession(), validate(fleetReadQuerySchema, 'query'), (req, res, next) => {
  serversController.ports(req, res).catch(next);
});
serversRouter.get('/runtimes', requireSession(), validate(runtimesQuerySchema, 'query'), (req, res, next) => {
  serversController.runtimes(req, res).catch(next);
});

serversRouter.post('/', requireSession({ requireMfa: true }), validate(createServerBodySchema, 'body'), (req, res, next) => {
  serversController.create(req, res).catch(next);
});

serversRouter.get('/:id', requireSession(), validate(serverIdParamsSchema, 'params'), (req, res, next) => {
  serversController.get(req, res).catch(next);
});

serversRouter.patch(
  '/:id',
  requireSession({ requireMfa: true }),
  validate(serverIdParamsSchema, 'params'),
  validate(updateServerBodySchema, 'body'),
  (req, res, next) => {
    serversController.update(req, res).catch(next);
  },
);

serversRouter.post(
  '/:id/archive',
  requireSession({ requireMfa: true }),
  validate(serverIdParamsSchema, 'params'),
  validate(archiveServerBodySchema, 'body'),
  (req, res, next) => {
    serversController.archive(req, res).catch(next);
  },
);

serversRouter.post(
  '/:id/enrollment',
  requireSession({ requireMfa: true }),
  validate(serverIdParamsSchema, 'params'),
  (req, res, next) => {
    serversController.issueEnrollment(req, res).catch(next);
  },
);

serversRouter.get(
  '/:id/metrics',
  requireSession(),
  validate(serverIdParamsSchema, 'params'),
  validate(metricsQuerySchema, 'query'),
  (req, res, next) => {
    serversController.metrics(req, res).catch(next);
  },
);
