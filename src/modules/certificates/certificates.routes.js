import { Router } from 'express';
import { validate } from '../../common/middleware/validate.js';
import { requireSession } from '../../common/middleware/require-session.js';
import { certParamsSchema, domainParamsSchema, expiringQuerySchema, issueBodySchema, listCertsQuerySchema, renewBodySchema } from './certificates.validator.js';
import { createCertificatesController } from './certificates.controller.js';
import { createCertificatesService } from './certificates.service.js';
import { getDeps } from '../platform/platform.wiring.js';
import { wrap } from '../platform/platform.http.js';

const c = createCertificatesController(createCertificatesService(getDeps()));
const write = requireSession({ requireMfa: true });

/** Mount at /certificates */
export const certificatesRouter = Router();

certificatesRouter.get('/', requireSession(), validate(listCertsQuerySchema, 'query'), wrap(c.list));
certificatesRouter.get('/expiring', requireSession(), validate(expiringQuerySchema, 'query'), wrap(c.expiring));
certificatesRouter.post('/domains/:domainId/issue', write, validate(domainParamsSchema, 'params'), validate(issueBodySchema, 'body'), wrap(c.issue));
certificatesRouter.post('/:id/renew', write, validate(certParamsSchema, 'params'), validate(renewBodySchema, 'body'), wrap(c.renew));
