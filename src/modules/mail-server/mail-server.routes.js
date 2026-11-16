import { Router } from 'express';
import { validate } from '../../common/middleware/validate.js';
import { requireSession } from '../../common/middleware/require-session.js';
import {
  disableMailServerBodySchema,
  enableMailServerBodySchema,
  firewallApplyBodySchema,
  firewallPreviewBodySchema,
  mailServerIdParamsSchema,
  provisionApplyBodySchema,
  provisionPreviewBodySchema,
} from './mail-server.validator.js';
import { createMailServerController } from './mail-server.controller.js';
import { createMailServerService } from './mail-server.service.js';
import { getDeps } from '../platform/platform.wiring.js';
import { wrap } from '../platform/platform.http.js';
import { serverAccessService } from '../server-access/server-access.routes.js';

/** Operator kill switch: MAIL_PROVISIONING_DISABLED=true blocks every remote mail action (default: not set). */
const config = { provisioningDisabled: process.env.MAIL_PROVISIONING_DISABLED === 'true' };

const controller = createMailServerController(createMailServerService({ ...getDeps(), config, ssh: serverAccessService }));
const write = requireSession({ requireMfa: true });

/** Mount at /servers (paths are /:id/mail...). */
export const mailServerRouter = Router();

mailServerRouter.get('/:id/mail', requireSession(), validate(mailServerIdParamsSchema, 'params'), wrap(controller.get));
mailServerRouter.get('/:id/mail/health', requireSession(), validate(mailServerIdParamsSchema, 'params'), wrap(controller.health));
mailServerRouter.post('/:id/mail/enable', write, validate(mailServerIdParamsSchema, 'params'), validate(enableMailServerBodySchema, 'body'), wrap(controller.enable));
mailServerRouter.post('/:id/mail/disable', write, validate(mailServerIdParamsSchema, 'params'), validate(disableMailServerBodySchema, 'body'), wrap(controller.disable));
mailServerRouter.post('/:id/mail/provision/preview', write, validate(mailServerIdParamsSchema, 'params'), validate(provisionPreviewBodySchema, 'body'), wrap(controller.previewProvision));
mailServerRouter.post('/:id/mail/provision/apply', write, validate(mailServerIdParamsSchema, 'params'), validate(provisionApplyBodySchema, 'body'), wrap(controller.applyProvision));
mailServerRouter.post('/:id/mail/health/probe', write, validate(mailServerIdParamsSchema, 'params'), wrap(controller.probeHealth));
mailServerRouter.post('/:id/mail/firewall/preview', write, validate(mailServerIdParamsSchema, 'params'), validate(firewallPreviewBodySchema, 'body'), wrap(controller.previewFirewall));
mailServerRouter.post('/:id/mail/firewall', write, validate(mailServerIdParamsSchema, 'params'), validate(firewallApplyBodySchema, 'body'), wrap(controller.applyFirewall));
