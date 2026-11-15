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
} from './domains.validator.js';
import { createDomainsController } from './domains.controller.js';
import { createDomainsService } from './domains.service.js';
import { getDeps } from '../platform/platform.wiring.js';
import { wrap } from '../platform/platform.http.js';

const domainsController = createDomainsController(createDomainsService(getDeps()));
const write = requireSession({ requireMfa: true });

/** Mount at /domains */
export const domainsRouter = Router();

domainsRouter.get('/', requireSession(), validate(listDomainsQuerySchema, 'query'), wrap(domainsController.list));
domainsRouter.post('/', write, validate(createDomainBodySchema, 'body'), wrap(domainsController.create));
domainsRouter.get('/:id', requireSession(), validate(domainIdParamsSchema, 'params'), wrap(domainsController.get));
domainsRouter.post('/:id/vhost/preview', write, validate(domainIdParamsSchema, 'params'), validate(vhostBodySchema, 'body'), wrap(domainsController.previewVhost));
domainsRouter.post('/:id/vhost/apply', write, validate(domainIdParamsSchema, 'params'), validate(applyVhostBodySchema, 'body'), wrap(domainsController.applyVhost));
domainsRouter.post('/:id/dns', write, validate(domainIdParamsSchema, 'params'), validate(dnsChangeBodySchema, 'body'), wrap(domainsController.changeDns));
