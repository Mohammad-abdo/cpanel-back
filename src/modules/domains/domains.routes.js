import { Router } from 'express';
import { validate } from '../../common/middleware/validate.js';
import { requireSession } from '../../common/middleware/require-session.js';
import {
  applyVhostBodySchema,
  createDomainBodySchema,
  dnsChangeBodySchema,
  domainIdParamsSchema,
  listDomainsQuerySchema,
  vhostBodySchema,
  domainConfBodySchema,
  caddyBodySchema,
  applyCaddyBodySchema,
  detectWebserverBodySchema,
} from './domains.validator.js';
import { createDomainsController } from './domains.controller.js';
import { createDomainsService } from './domains.service.js';
import { getDeps } from '../platform/platform.wiring.js';
import { wrap } from '../platform/platform.http.js';
import { serverAccessService } from '../server-access/server-access.routes.js';
import { createScriptRunner } from '../server-access/ssh-script.runner.js';
import { createSshConnector } from '../server-access/ssh.connector.js';
import { prisma } from '../../config/prisma.js';

const domainsController = createDomainsController(createDomainsService({ ...getDeps(), scriptRunner: createScriptRunner({ prisma, connector: createSshConnector({ timeoutMs: 30_000 }) }) }), { serverAccess: serverAccessService });
const write = requireSession({ requireMfa: true });

/** Mount at /domains */
export const domainsRouter = Router();

domainsRouter.get('/', requireSession(), validate(listDomainsQuerySchema, 'query'), wrap(domainsController.list));
domainsRouter.post('/', write, validate(createDomainBodySchema, 'body'), wrap(domainsController.create));
domainsRouter.get('/:id', requireSession(), validate(domainIdParamsSchema, 'params'), wrap(domainsController.get));
domainsRouter.get('/:id/conf', write, validate(domainIdParamsSchema, 'params'), wrap(domainsController.readConf));
domainsRouter.put('/:id/conf', write, validate(domainIdParamsSchema, 'params'), validate(domainConfBodySchema, 'body'), wrap(domainsController.writeConf));
domainsRouter.post('/:id/vhost/preview', write, validate(domainIdParamsSchema, 'params'), validate(vhostBodySchema, 'body'), wrap(domainsController.previewVhost));
domainsRouter.post('/:id/vhost/apply', write, validate(domainIdParamsSchema, 'params'), validate(applyVhostBodySchema, 'body'), wrap(domainsController.applyVhost));
domainsRouter.post('/:id/dns', write, validate(domainIdParamsSchema, 'params'), validate(dnsChangeBodySchema, 'body'), wrap(domainsController.changeDns));
domainsRouter.post('/:id/caddy/preview', write, validate(domainIdParamsSchema, 'params'), validate(caddyBodySchema, 'body'), wrap(domainsController.previewCaddy));
domainsRouter.post('/:id/caddy/apply', write, validate(domainIdParamsSchema, 'params'), validate(applyCaddyBodySchema, 'body'), wrap(domainsController.applyCaddy));
domainsRouter.post('/:id/webserver/detect', write, validate(domainIdParamsSchema, 'params'), validate(detectWebserverBodySchema, 'body'), wrap(domainsController.detectWebserver));
