import { Router } from 'express';
import { validate } from '../../common/middleware/validate.js';
import { requireSession } from '../../common/middleware/require-session.js';
import { historyQuerySchema, applyBodySchema, previewBodySchema, serverParamsSchema } from './firewall.validator.js';
import { createFirewallController } from './firewall.controller.js';
import { createFirewallService } from './firewall.service.js';
import { getDeps } from '../platform/platform.wiring.js';
import { wrap } from '../platform/platform.http.js';
import { serverAccessService } from '../server-access/server-access.routes.js';
import { createUfwExecutor, DEADMAN_DEFAULT_SECONDS } from './firewall.ufw.js';

/**
 * FIREWALL_EXECUTOR=simulated (default) | ssh. `ssh` runs real ufw over the stored SSH login with the lockout guards and
 * the dead-man switch from firewall.ufw.js. It never runs unless explicitly selected.
 */
export function selectFirewallDeps(deps, env = process.env) {
  if (String(env.FIREWALL_EXECUTOR ?? 'simulated').toLowerCase() !== 'ssh') return deps;
  const executor = createUfwExecutor({
    runRemote: (id, fn) => serverAccessService.runRemote(id, fn),
    probeSsh: (id) => serverAccessService.runRemote(id, ({ run }) => run('echo nt-probe', { timeoutMs: 15_000 })),
    deadmanSeconds: Number(env.FIREWALL_DEADMAN_SECONDS) || DEADMAN_DEFAULT_SECONDS,
  });
  return { ...deps, adapters: { ...deps.adapters, simulated: false, firewall: executor, fleet: { probe: (id) => executor.probe(id) } } };
}

const c = createFirewallController(createFirewallService(selectFirewallDeps(getDeps())));
const write = requireSession({ requireMfa: true });
const params = validate(serverParamsSchema, 'params');

/** Mount at /firewall */
export const firewallRouter = Router();

firewallRouter.get('/history', requireSession(), validate(historyQuerySchema, 'query'), wrap(c.history));
firewallRouter.get('/servers/:serverId/rules', requireSession(), params, wrap(c.rules));
firewallRouter.get('/servers/:serverId/state', requireSession(), params, wrap(c.state));
firewallRouter.post('/servers/:serverId/preview', write, params, validate(previewBodySchema, 'body'), wrap(c.preview));
firewallRouter.post('/servers/:serverId/apply', write, params, validate(applyBodySchema, 'body'), wrap(c.apply));
