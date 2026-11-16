import { Router } from 'express';
import { validate } from '../../common/middleware/validate.js';
import { requireSession } from '../../common/middleware/require-session.js';
import {
  disableMailServerBodySchema,
  enableMailServerBodySchema,
  mailServerIdParamsSchema,
  provisionApplyBodySchema,
  provisionPreviewBodySchema,
} from './mail-server.validator.js';
import { createMailServerController } from './mail-server.controller.js';
import { createMailServerService } from './mail-server.service.js';
import { getDeps } from '../platform/platform.wiring.js';
import { wrap } from '../platform/platform.http.js';

/** Provisioning stays closed unless BOTH are set: MAIL_PROVISIONING_ENABLED=true and the server id is in MAIL_LAB_SERVER_IDS. */
const config = {
  provisioningEnabled: process.env.MAIL_PROVISIONING_ENABLED === 'true',
  labServerIds: (process.env.MAIL_LAB_SERVER_IDS ?? '').split(',').map((s) => s.trim()).filter(Boolean),
};

const controller = createMailServerController(createMailServerService({ ...getDeps(), config }));
const write = requireSession({ requireMfa: true });

/** Mount at /servers (paths are /:id/mail...). */
export const mailServerRouter = Router();

mailServerRouter.get('/:id/mail', requireSession(), validate(mailServerIdParamsSchema, 'params'), wrap(controller.get));
mailServerRouter.get('/:id/mail/health', requireSession(), validate(mailServerIdParamsSchema, 'params'), wrap(controller.health));
mailServerRouter.post('/:id/mail/enable', write, validate(mailServerIdParamsSchema, 'params'), validate(enableMailServerBodySchema, 'body'), wrap(controller.enable));
mailServerRouter.post('/:id/mail/disable', write, validate(mailServerIdParamsSchema, 'params'), validate(disableMailServerBodySchema, 'body'), wrap(controller.disable));
mailServerRouter.post('/:id/mail/provision/preview', write, validate(mailServerIdParamsSchema, 'params'), validate(provisionPreviewBodySchema, 'body'), wrap(controller.previewProvision));
mailServerRouter.post('/:id/mail/provision/apply', write, validate(mailServerIdParamsSchema, 'params'), validate(provisionApplyBodySchema, 'body'), wrap(controller.applyProvision));
