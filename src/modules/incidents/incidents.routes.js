import { Router } from 'express';
import { validate } from '../../common/middleware/validate.js';
import { requireSession } from '../../common/middleware/require-session.js';
import {
  assignBodySchema,
  createIncidentBodySchema,
  escalateBodySchema,
  evidenceBodySchema,
  incidentIdParamsSchema,
  listIncidentsQuerySchema,
  reopenBodySchema,
  transitionBodySchema,
} from './incidents.validator.js';
import { createIncidentsController } from './incidents.controller.js';
import { createIncidentsService } from './incidents.service.js';
import { getDeps } from '../platform/platform.wiring.js';
import { wrap } from '../platform/platform.http.js';

const c = createIncidentsController(createIncidentsService(getDeps()));
const write = requireSession({ requireMfa: true });
const params = validate(incidentIdParamsSchema, 'params');

/** Mount at /incidents */
export const incidentsRouter = Router();

incidentsRouter.get('/', requireSession(), validate(listIncidentsQuerySchema, 'query'), wrap(c.list));
incidentsRouter.post('/', write, validate(createIncidentBodySchema, 'body'), wrap(c.create));
incidentsRouter.get('/:id', requireSession(), params, wrap(c.get));
incidentsRouter.get('/:id/timeline', requireSession(), params, wrap(c.timeline));
incidentsRouter.get('/:id/evidence/verify', requireSession(), params, wrap(c.verifyEvidence));
incidentsRouter.post('/:id/transition', write, params, validate(transitionBodySchema, 'body'), wrap(c.transition));
incidentsRouter.post('/:id/assign', write, params, validate(assignBodySchema, 'body'), wrap(c.assign));
incidentsRouter.post('/:id/evidence', write, params, validate(evidenceBodySchema, 'body'), wrap(c.addEvidence));
incidentsRouter.post('/:id/escalate', write, params, validate(escalateBodySchema, 'body'), wrap(c.escalate));
incidentsRouter.post('/:id/reopen', write, params, validate(reopenBodySchema, 'body'), wrap(c.reopen));
