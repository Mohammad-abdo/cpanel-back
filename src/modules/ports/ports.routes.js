import { Router } from 'express';
import { validate } from '../../common/middleware/validate.js';
import { requireSession } from '../../common/middleware/require-session.js';
import { prisma } from '../../config/prisma.js';
import { createAuditService } from '../audit/audit.service.js';
import { wrap } from '../platform/platform.http.js';
import { createPortsController } from './ports.controller.js';
import { createPortsService } from './ports.service.js';
import {
  checkQuerySchema,
  reservationIdParamsSchema,
  reserveBodySchema,
  serverIdParamsSchema,
} from './ports.validator.js';

const svc = createPortsService({ prisma, auditService: createAuditService({ prisma }) });
const c = createPortsController(svc);
const write = requireSession({ requireMfa: true });
const read = requireSession();

/**
 * Mount under /servers so paths are:
 *   GET  /servers/:serverId/ports/overview
 *   GET  /servers/:serverId/ports/check?port=
 *   GET  /servers/:serverId/port-reservations
 *   POST /servers/:serverId/port-reservations
 *   DELETE /servers/:serverId/port-reservations/:reservationId
 */
export const portsRouter = Router({ mergeParams: true });

portsRouter.get('/:serverId/ports/overview', read, validate(serverIdParamsSchema, 'params'), wrap(c.overview));
portsRouter.get('/:serverId/ports/check', read, validate(serverIdParamsSchema, 'params'), validate(checkQuerySchema, 'query'), wrap(c.check));
portsRouter.get('/:serverId/port-reservations', read, validate(serverIdParamsSchema, 'params'), wrap(c.listReservations));
portsRouter.post('/:serverId/port-reservations', write, validate(serverIdParamsSchema, 'params'), validate(reserveBodySchema, 'body'), wrap(c.reserve));
portsRouter.delete(
  '/:serverId/port-reservations/:reservationId',
  write,
  validate(reservationIdParamsSchema, 'params'),
  wrap(c.unreserve),
);
