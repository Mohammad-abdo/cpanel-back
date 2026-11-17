import { Router } from 'express';
import { validate } from '../../common/middleware/validate.js';
import { requireSession } from '../../common/middleware/require-session.js';
import { prisma } from '../../config/prisma.js';
import { getDeps } from '../platform/platform.wiring.js';
import { wrap } from '../platform/platform.http.js';
import { createRootDomainsController } from './root-domains.controller.js';
import { createRootDomainsService } from './root-domains.service.js';
import { connectBodySchema, idParamsSchema, listRecordsQuerySchema, recordBodySchema, rotateTokenBodySchema, wildcardBodySchema } from './root-domains.validator.js';

const deps = getDeps();
export const rootDomainsService = createRootDomainsService({ ...deps, prisma });
const c = createRootDomainsController(rootDomainsService);
const write = requireSession({ requireMfa: true });
const params = validate(idParamsSchema, 'params');

/** Mount at /root-domains. Owner only; the provider token is accepted in bodies and never returned. */
export const rootDomainsRouter = Router();
rootDomainsRouter.get('/', write, wrap(c.list));
rootDomainsRouter.post('/', write, validate(connectBodySchema, 'body'), wrap(c.connect));
rootDomainsRouter.put('/:id/token', write, params, validate(rotateTokenBodySchema, 'body'), wrap(c.rotateToken));
rootDomainsRouter.delete('/:id', write, params, wrap(c.remove));
rootDomainsRouter.get('/:id/records', write, params, validate(listRecordsQuerySchema, 'query'), wrap(c.listRecords));
rootDomainsRouter.post('/:id/records', write, params, validate(recordBodySchema, 'body'), wrap(c.changeRecord));
rootDomainsRouter.post('/:id/wildcard-certificate/preview', write, params, validate(wildcardBodySchema.partial({ serverId: true }), 'body'), wrap(c.previewWildcard));
rootDomainsRouter.post('/:id/wildcard-certificate', write, params, validate(wildcardBodySchema, 'body'), wrap(c.issueWildcard));
