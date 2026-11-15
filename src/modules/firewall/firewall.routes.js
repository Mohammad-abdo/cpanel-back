import { Router } from 'express';
import { validate } from '../../common/middleware/validate.js';
import { requireSession } from '../../common/middleware/require-session.js';
import { historyQuerySchema, applyBodySchema, previewBodySchema, serverParamsSchema } from './firewall.validator.js';
import { createFirewallController } from './firewall.controller.js';
import { createFirewallService } from './firewall.service.js';
import { getDeps } from '../platform/platform.wiring.js';
import { wrap } from '../platform/platform.http.js';

const c = createFirewallController(createFirewallService(getDeps()));
const write = requireSession({ requireMfa: true });
const params = validate(serverParamsSchema, 'params');

/** Mount at /firewall */
export const firewallRouter = Router();

firewallRouter.get('/history', requireSession(), validate(historyQuerySchema, 'query'), wrap(c.history));
firewallRouter.get('/servers/:serverId/rules', requireSession(), params, wrap(c.rules));
firewallRouter.post('/servers/:serverId/preview', write, params, validate(previewBodySchema, 'body'), wrap(c.preview));
firewallRouter.post('/servers/:serverId/apply', write, params, validate(applyBodySchema, 'body'), wrap(c.apply));
