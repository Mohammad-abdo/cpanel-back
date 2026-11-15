import { Router } from 'express';
import { validate } from '../../common/middleware/validate.js';
import { requireSession } from '../../common/middleware/require-session.js';
import { listEventsQuerySchema, listIncidentsQuerySchema, syncBodySchema } from './security.validator.js';
import { createSecurityController } from './security.controller.js';
import { createSecurityService } from './security.service.js';
import { createIncidentsService } from '../incidents/incidents.service.js';
import { getDeps } from '../platform/platform.wiring.js';
import { wrap } from '../platform/platform.http.js';

const deps = getDeps();
const c = createSecurityController(createSecurityService({ ...deps, incidents: createIncidentsService(deps) }));

/** Mount at /security */
export const securityRouter = Router();

securityRouter.get('/incidents', requireSession(), validate(listIncidentsQuerySchema, 'query'), wrap(c.listIncidents));
securityRouter.get('/events', requireSession(), validate(listEventsQuerySchema, 'query'), wrap(c.listEvents));
securityRouter.get('/summary', requireSession(), wrap(c.summary));
securityRouter.get('/connection', requireSession(), wrap(c.connection));
securityRouter.post('/sync', requireSession({ requireMfa: true }), validate(syncBodySchema, 'body'), wrap(c.sync));
