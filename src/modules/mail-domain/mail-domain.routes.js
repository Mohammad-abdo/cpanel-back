import { Router } from 'express';
import { validate } from '../../common/middleware/validate.js';
import { requireSession } from '../../common/middleware/require-session.js';
import {
  disableMailDomainBodySchema,
  enableMailDomainBodySchema,
  mailDomainIdParamsSchema,
  updateMailDomainBodySchema,
} from './mail-domain.validator.js';
import { createMailDomainController } from './mail-domain.controller.js';
import { createMailDomainService } from './mail-domain.service.js';
import { getDeps } from '../platform/platform.wiring.js';
import { wrap } from '../platform/platform.http.js';

const controller = createMailDomainController(createMailDomainService(getDeps()));
const write = requireSession({ requireMfa: true });

/** Mount at /domains (paths are /:id/mail...). */
export const mailDomainRouter = Router();

mailDomainRouter.get('/:id/mail', requireSession(), validate(mailDomainIdParamsSchema, 'params'), wrap(controller.get));
mailDomainRouter.get('/:id/mail/dns', requireSession(), validate(mailDomainIdParamsSchema, 'params'), wrap(controller.dns));
mailDomainRouter.post('/:id/mail/enable', write, validate(mailDomainIdParamsSchema, 'params'), validate(enableMailDomainBodySchema, 'body'), wrap(controller.enable));
mailDomainRouter.post('/:id/mail/disable', write, validate(mailDomainIdParamsSchema, 'params'), validate(disableMailDomainBodySchema, 'body'), wrap(controller.disable));
mailDomainRouter.patch('/:id/mail', write, validate(mailDomainIdParamsSchema, 'params'), validate(updateMailDomainBodySchema, 'body'), wrap(controller.update));
