import { Router } from 'express';
import { validate } from '../../common/middleware/validate.js';
import { requireSession } from '../../common/middleware/require-session.js';
import { rateLimit } from '../../common/middleware/rate-limit.js';
import {
  createMailboxBodySchema,
  deleteMailboxQuerySchema,
  listMailboxesQuerySchema,
  mailboxAuditQuerySchema,
  mailboxIdParamsSchema,
  mailboxReasonBodySchema,
  setMailboxPasswordBodySchema,
  updateMailboxBodySchema,
} from './mailboxes.validator.js';
import { createMailboxesController } from './mailboxes.controller.js';
import { createMailboxesService } from './mailboxes.service.js';
import { getDeps } from '../platform/platform.wiring.js';
import { wrap } from '../platform/platform.http.js';
import { createMailRemote } from '../../common/mail-remote.js';
import { serverAccessService } from '../server-access/server-access.routes.js';

const config = { provisioningDisabled: process.env.MAIL_PROVISIONING_DISABLED === 'true' };
const deps = getDeps();
const controller = createMailboxesController(createMailboxesService({ ...deps, remote: createMailRemote({ prisma: deps.prisma, ssh: serverAccessService, config }) }));
const write = requireSession({ requireMfa: true });

// Mailbox password changes are an account-takeover primitive: 20 per 15 minutes per actor (in-memory, per process).
const passwordLimiter = rateLimit({ windowMs: 15 * 60_000, max: 20, keyFn: (req) => `mailbox-pw:${req.user?.id ?? req.ip}` });

/** Mount at /mailboxes */
export const mailboxesRouter = Router();

mailboxesRouter.get('/', requireSession(), validate(listMailboxesQuerySchema, 'query'), wrap(controller.list));
mailboxesRouter.post('/', write, validate(createMailboxBodySchema, 'body'), wrap(controller.create));
mailboxesRouter.get('/:id', requireSession(), validate(mailboxIdParamsSchema, 'params'), wrap(controller.get));
mailboxesRouter.patch('/:id', write, validate(mailboxIdParamsSchema, 'params'), validate(updateMailboxBodySchema, 'body'), wrap(controller.update));
mailboxesRouter.post('/:id/password', write, passwordLimiter, validate(mailboxIdParamsSchema, 'params'), validate(setMailboxPasswordBodySchema, 'body'), wrap(controller.setPassword));
mailboxesRouter.post('/:id/suspend', write, validate(mailboxIdParamsSchema, 'params'), validate(mailboxReasonBodySchema, 'body'), wrap(controller.suspend));
mailboxesRouter.post('/:id/unsuspend', write, validate(mailboxIdParamsSchema, 'params'), validate(mailboxReasonBodySchema, 'body'), wrap(controller.unsuspend));
mailboxesRouter.delete('/:id', write, validate(mailboxIdParamsSchema, 'params'), validate(deleteMailboxQuerySchema, 'query'), wrap(controller.remove));
mailboxesRouter.get('/:id/audit', requireSession(), validate(mailboxIdParamsSchema, 'params'), validate(mailboxAuditQuerySchema, 'query'), wrap(controller.auditEvents));
