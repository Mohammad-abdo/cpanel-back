import { Router } from 'express';
import { validate } from '../../common/middleware/validate.js';
import { requireSession } from '../../common/middleware/require-session.js';
import {
  disableMailDomainBodySchema,
  enableMailDomainBodySchema,
  mailDomainIdParamsSchema,
  publishMailDnsBodySchema,
  updateMailDomainBodySchema,
} from './mail-domain.validator.js';
import { createMailDomainController } from './mail-domain.controller.js';
import { createMailDomainService } from './mail-domain.service.js';
import { getDeps } from '../platform/platform.wiring.js';
import { wrap } from '../platform/platform.http.js';
import { createMailRemote } from '../../common/mail-remote.js';
import { serverAccessService } from '../server-access/server-access.routes.js';

const config = { provisioningDisabled: process.env.MAIL_PROVISIONING_DISABLED === 'true' };
const deps = getDeps();
const controller = createMailDomainController(createMailDomainService({ ...deps, remote: createMailRemote({ prisma: deps.prisma, ssh: serverAccessService, config }) }));
const write = requireSession({ requireMfa: true });

/** Mount at /domains (paths are /:id/mail...). */
export const mailDomainRouter = Router();

mailDomainRouter.get('/:id/mail', requireSession(), validate(mailDomainIdParamsSchema, 'params'), wrap(controller.get));
mailDomainRouter.get('/:id/mail/dns', requireSession(), validate(mailDomainIdParamsSchema, 'params'), wrap(controller.dns));
mailDomainRouter.post('/:id/mail/enable', write, validate(mailDomainIdParamsSchema, 'params'), validate(enableMailDomainBodySchema, 'body'), wrap(controller.enable));
mailDomainRouter.post('/:id/mail/disable', write, validate(mailDomainIdParamsSchema, 'params'), validate(disableMailDomainBodySchema, 'body'), wrap(controller.disable));
mailDomainRouter.patch('/:id/mail', write, validate(mailDomainIdParamsSchema, 'params'), validate(updateMailDomainBodySchema, 'body'), wrap(controller.update));
mailDomainRouter.post('/:id/mail/sync', write, validate(mailDomainIdParamsSchema, 'params'), wrap(controller.sync));
mailDomainRouter.post(
  '/:id/mail/dns/publish',
  write,
  validate(mailDomainIdParamsSchema, 'params'),
  validate(publishMailDnsBodySchema, 'body'),
  wrap(controller.publishDns),
);
