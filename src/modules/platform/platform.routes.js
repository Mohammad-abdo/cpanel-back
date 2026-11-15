import { Router } from 'express';
import { validate } from '../../common/middleware/validate.js';
import { requireSession } from '../../common/middleware/require-session.js';
import {
  approvalIdParamsSchema,
  breakGlassBodySchema,
  breakGlassEndBodySchema,
  decideBodySchema,
  fleetProbeBodySchema,
  fleetQuerySchema,
  listApprovalsQuerySchema,
} from './platform.validator.js';
import { createPlatformController } from './platform.controller.js';
import { createFleetService } from './platform.fleet.js';
import { createEmergencyService } from './platform.emergency.js';
import { getDeps } from './platform.wiring.js';
import { wrap } from './platform.http.js';
import { createIntegrationsService } from './platform.integrations.js';

const deps = getDeps();
const c = createPlatformController({
  platformService: deps.platform,
  fleet: createFleetService(deps),
  emergency: createEmergencyService(deps),
});
const write = requireSession({ requireMfa: true });

/** Mount at /platform */
export const platformRouter = Router();

platformRouter.get('/approvals', requireSession(), validate(listApprovalsQuerySchema, 'query'), wrap(c.listApprovals));
platformRouter.post('/approvals/:id/decision', write, validate(approvalIdParamsSchema, 'params'), validate(decideBodySchema, 'body'), wrap(c.decide));
platformRouter.get('/fleet', requireSession(), validate(fleetQuerySchema, 'query'), wrap(c.fleetOverview));
platformRouter.post('/fleet/probe', write, validate(fleetProbeBodySchema, 'body'), wrap(c.fleetProbe));
const integrations = createIntegrationsService(deps);
platformRouter.get('/integrations', requireSession(), wrap(async (req, res) => {
  res.status(200).json({ data: await integrations.list() });
}));
platformRouter.get('/readiness', requireSession(), wrap(c.readiness));
platformRouter.get('/break-glass', requireSession(), wrap(c.breakGlassStatus));
platformRouter.post('/break-glass/activate', write, validate(breakGlassBodySchema, 'body'), wrap(c.breakGlassActivate));
platformRouter.post('/break-glass/end', write, validate(breakGlassEndBodySchema, 'body'), wrap(c.breakGlassEnd));
